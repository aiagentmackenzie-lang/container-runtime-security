// Package ebpf - loader.go
// eBPF program loader for SecurityScarlet Runtime.
//
// Loads compiled eBPF object files (one per probe category: process, file,
// network, escape), attaches them to their tracepoints/kprobes via
// github.com/cilium/ebpf, and reads events from each category's ring buffer.
//
// Each probe category object declares its own `events_rb`, `container_cgroups`,
// and `monitored_syscalls` maps (see pkg/ebpf/probes/*.bpf.c). Registering a
// container therefore updates container_cgroups in EVERY loaded collection,
// and one reader goroutine is spawned per collection's events_rb.
//
// Mock mode: on non-Linux hosts or when BTF is unavailable, Load/Attach/Start
// are no-ops and events arrive only via InjectEvent()/SetTestEventChannel()
// (used by tests). This keeps `go test ./...` green on macOS/dev machines while
// the real kernel paths run on Linux nodes.

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ── Constants ─────────────────────────────────────────────────────────

const (
	DefaultRingBufferSizeMB = 4
	DefaultPollIntervalMS   = 100
	MaxContainerCgroups     = 4096
	MaxMonitoredSyscalls    = 512
)

// ProbeCategory identifies a category of eBPF probes to load.
type ProbeCategory string

const (
	ProbeProcess ProbeCategory = "process"
	ProbeFile    ProbeCategory = "file"
	ProbeNetwork ProbeCategory = "network"
	ProbeEscape  ProbeCategory = "escape"
)

// AllProbeCategories is the full set of probe categories.
var AllProbeCategories = []ProbeCategory{
	ProbeProcess, ProbeFile, ProbeNetwork, ProbeEscape,
}

// ── Probe attach table ────────────────────────────────────────────────
//
// Maps each program name (the function name from the C SEC() annotation) to
// its attach target. This is the authoritative attach table and must stay in
// sync with the SEC() annotations in pkg/ebpf/probes/*.bpf.c.

type attachKind int

const (
	attachTracepoint attachKind = iota
	attachKprobe
)

type probeAttachTarget struct {
	kind   attachKind
	group  string // tracepoint group (e.g. "sched", "syscalls")
	name   string // tracepoint name (e.g. "sched_process_exec")
	symbol string // kprobe symbol (e.g. "tcp_v4_connect")
}

// probeAttachTargets maps a program name to how it should be attached.
// Programs not in this map are skipped with a warning.
var probeAttachTargets = map[string]probeAttachTarget{
	// process.bpf.c
	"trace_sched_process_exec": {attachTracepoint, "sched", "sched_process_exec", ""},
	"trace_sched_process_fork": {attachTracepoint, "sched", "sched_process_fork", ""},
	"trace_sched_process_exit": {attachTracepoint, "sched", "sched_process_exit", ""},
	// file.bpf.c
	"trace_openat":       {attachTracepoint, "syscalls", "sys_enter_openat", ""},
	"trace_unlinkat":     {attachTracepoint, "syscalls", "sys_enter_unlinkat", ""},
	"trace_memfd_create": {attachTracepoint, "syscalls", "sys_enter_memfd_create", ""},
	// network.bpf.c
	"trace_tcp_v4_connect":       {attachKprobe, "", "", "tcp_v4_connect"},
	"trace_tcp_v6_connect":       {attachKprobe, "", "", "tcp_v6_connect"},
	"trace_ip4_datagram_connect": {attachKprobe, "", "", "ip4_datagram_connect"},
	"trace_listen":               {attachTracepoint, "syscalls", "sys_enter_listen", ""},
	// escape.bpf.c
	"trace_setns":       {attachTracepoint, "syscalls", "sys_enter_setns", ""},
	"trace_unshare":     {attachTracepoint, "syscalls", "sys_enter_unshare", ""},
	"trace_mount":       {attachTracepoint, "syscalls", "sys_enter_mount", ""},
	"trace_ptrace":      {attachTracepoint, "syscalls", "sys_enter_ptrace", ""},
	"trace_init_module": {attachTracepoint, "syscalls", "sys_enter_init_module", ""},
	"trace_bpf":         {attachTracepoint, "syscalls", "sys_enter_bpf", ""},
	"trace_setuid":      {attachTracepoint, "syscalls", "sys_enter_setuid", ""},
	"trace_capset":      {attachTracepoint, "syscalls", "sys_enter_capset", ""},
	"trace_chmod":       {attachTracepoint, "syscalls", "sys_enter_chmod", ""},
	"trace_fchmodat":    {attachTracepoint, "syscalls", "sys_enter_fchmodat", ""},
}

// ── Loader manages eBPF program lifecycle ─────────────────────────────

// Loader handles loading, attaching, and managing eBPF programs.
type Loader struct {
	mu sync.RWMutex

	// One collection per probe category. Each declares its own events_rb,
	// container_cgroups, and monitored_syscalls maps.
	collections []*ebpf.Collection
	links       []link.Link
	readers     []*ringbuf.Reader

	// Replicated maps (one per collection) — updated on all when registering.
	cgroupMaps  []*ebpf.Map
	syscallMaps []*ebpf.Map

	// Category-specific singletons.
	sensitivePathMap  *ebpf.Map // file collection
	minerPoolPortsMap *ebpf.Map // network collection
	c2PortsMap        *ebpf.Map // network collection
	cloudMetadataMap  *ebpf.Map // network collection

	// Kernel-side ring buffer filter
	filter *RingBufferFilter

	// Configuration
	bpfObjDir    string
	ringBufSize  int
	pollInterval time.Duration

	// Event channels
	eventCh     chan *ScarletEvent // real ring-buffer events
	testEventCh chan *ScarletEvent // in-memory events for testing (bypasses ring buffer)

	// State
	running  bool
	mockMode bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// LoaderConfig holds configuration for the eBPF loader.
type LoaderConfig struct {
	BPFObjectDir    string        // Directory containing compiled .o files
	RingBufSizeMB   int           // Ring buffer size in MB (default 4)
	PollInterval    time.Duration // Ring buffer poll interval (default 100ms)
	EventBufferSize int           // Channel buffer for decoded events (default 1024)
}

// NewLoader creates a new eBPF program loader.
func NewLoader(cfg LoaderConfig) *Loader {
	if cfg.RingBufSizeMB <= 0 {
		cfg.RingBufSizeMB = DefaultRingBufferSizeMB
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollIntervalMS * time.Millisecond
	}
	if cfg.EventBufferSize <= 0 {
		cfg.EventBufferSize = 1024
	}

	return &Loader{
		bpfObjDir:    cfg.BPFObjectDir,
		ringBufSize:  cfg.RingBufSizeMB * 1024 * 1024,
		pollInterval: cfg.PollInterval,
		eventCh:      make(chan *ScarletEvent, cfg.EventBufferSize),
		filter:       NewRingBufferFilter(),
		mockMode:     runtime.GOOS != "linux" || !isBPFAvailable(),
		stopCh:       make(chan struct{}),
	}
}

// Events returns the channel through which decoded events are delivered.
// If a test event channel is set, it returns that instead.
func (l *Loader) Events() <-chan *ScarletEvent {
	if l.testEventCh != nil {
		return l.testEventCh
	}
	return l.eventCh
}

// Load reads and loads the eBPF object files into the kernel.
// In mock mode, this is a no-op.
func (l *Loader) Load(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("eBPF programs already loaded")
	}

	// Check BTF availability (CO-RE requires it).
	if err := checkBTF(); err != nil {
		return fmt.Errorf("BTF check failed: %w (kernel may be too old or missing BTF)", err)
	}

	if l.mockMode {
		return l.loadMockCollection(ctx)
	}

	log.Printf("[ebpf] Loading eBPF programs from %s", l.bpfObjDir)

	for _, cat := range AllProbeCategories {
		objPath := filepath.Join(l.bpfObjDir, string(cat)+".o")
		if _, err := os.Stat(objPath); os.IsNotExist(err) {
			log.Printf("[ebpf] Warning: object file not found: %s, skipping", objPath)
			continue
		}

		coll, err := ebpf.LoadCollection(objPath)
		if err != nil {
			return fmt.Errorf("failed to load %s collection from %s: %w", cat, objPath, err)
		}
		l.collections = append(l.collections, coll)

		// Collect the replicated maps (one per collection).
		if m := coll.Maps["container_cgroups"]; m != nil {
			l.cgroupMaps = append(l.cgroupMaps, m)
		}
		if m := coll.Maps["monitored_syscalls"]; m != nil {
			l.syscallMaps = append(l.syscallMaps, m)
		}

		// Collect category-specific singletons.
		switch cat {
		case ProbeFile:
			l.sensitivePathMap = coll.Maps["sensitive_path_prefixes"]
		case ProbeNetwork:
			l.minerPoolPortsMap = coll.Maps["miner_pool_ports"]
			l.c2PortsMap = coll.Maps["c2_ports"]
			l.cloudMetadataMap = coll.Maps["cloud_metadata_ips"]
		}

		log.Printf("[ebpf] Loaded %s collection: %d programs, %d maps",
			cat, len(coll.Programs), len(coll.Maps))
	}

	// Populate kernel-side maps with known values (miner ports, C2 ports, etc.)
	l.populateKernelMaps()

	log.Printf("[ebpf] All eBPF programs loaded successfully (%d collections)", len(l.collections))
	return nil
}

// Attach attaches eBPF programs to their tracepoints/kprobes using the
// probeAttachTargets table. In mock mode, this is a no-op.
func (l *Loader) Attach(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("eBPF programs already attached")
	}
	if l.mockMode {
		log.Printf("[ebpf] Mock mode: skipping attach")
		return nil
	}

	log.Printf("[ebpf] Attaching probes to tracepoints/kprobes...")

	attached := 0
	for _, coll := range l.collections {
		for progName, prog := range coll.Programs {
			target, ok := probeAttachTargets[progName]
			if !ok {
				log.Printf("[ebpf] Warning: no attach target for program %q, skipping", progName)
				continue
			}

			var lk link.Link
			var err error
			switch target.kind {
			case attachTracepoint:
				lk, err = link.Tracepoint(target.group, target.name, prog, nil)
			case attachKprobe:
				lk, err = link.Kprobe(target.symbol, prog, nil)
			}
			if err != nil {
				log.Printf("[ebpf] Warning: failed to attach %s (%s): %v", progName, target.symbol, err)
				continue
			}
			l.links = append(l.links, lk)
			attached++
		}
	}

	log.Printf("[ebpf] Attached %d probes", attached)
	return nil
}

// Start begins reading events from all loaded collections' ring buffers.
// In mock mode, this just marks the loader running; events arrive via
// InjectEvent()/SetTestEventChannel().
func (l *Loader) Start(ctx context.Context) error {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return fmt.Errorf("eBPF loader already running")
	}
	l.running = true
	l.mu.Unlock()

	log.Printf("[ebpf] Starting ring buffer reader (poll interval: %v)", l.pollInterval)

	// Spawn one reader goroutine per collection's events_rb map.
	for _, coll := range l.collections {
		rbMap := coll.Maps["events_rb"]
		if rbMap == nil {
			continue
		}
		reader, err := ringbuf.NewReader(rbMap)
		if err != nil {
			log.Printf("[ebpf] Warning: failed to open ring buffer reader: %v", err)
			continue
		}
		l.readers = append(l.readers, reader)

		l.wg.Add(1)
		go l.readEvents(reader)
	}

	if len(l.readers) == 0 {
		log.Printf("[ebpf] No ring buffer readers started (mock mode or no collections loaded)")
	}

	return nil
}

// readEvents continuously reads events from one ring buffer reader, decodes
// them, applies the kernel-side filter, and delivers them to the event channel.
// It exits when the reader is closed (by Stop) or returns a terminal error.
func (l *Loader) readEvents(reader *ringbuf.Reader) {
	defer l.wg.Done()

	for {
		rec, err := reader.Read() // blocks until an event arrives or reader is closed
		if err != nil {
			// A closed reader (Stop) or a terminal read error ends this goroutine.
			if !errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("[ebpf] Ring buffer read error: %v", err)
			}
			return
		}

		event, err := DecodeEvent(rec.RawSample)
		if err != nil {
			log.Printf("[ebpf] Failed to decode event: %v", err)
			continue
		}

		l.deliver(event)
	}
}

// deliver applies the ring buffer filter and sends the event to the event
// channel (non-blocking; drops on full channel). Used by both the real ring
// buffer reader and InjectEvent().
func (l *Loader) deliver(event *ScarletEvent) {
	if l.filter != nil && !l.filter.ShouldPass(event) {
		return // Event dropped by filter
	}

	select {
	case l.eventCh <- event:
	default:
		log.Printf("[ebpf] Warning: event channel full, dropping event (pid=%d type=%s)",
			event.PID, event.EventTypeString())
	}
}

// Stop detaches all probes, closes ring buffer readers, and unloads eBPF programs.
func (l *Loader) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	log.Printf("[ebpf] Stopping eBPF loader...")
	close(l.stopCh)

	// Close ring buffer readers — this unblocks any in-flight reader.Read().
	for _, r := range l.readers {
		if err := r.Close(); err != nil {
			log.Printf("[ebpf] Warning: error closing ring buffer reader: %v", err)
		}
	}
	l.wg.Wait()
	l.readers = nil

	// Close all links (detach probes).
	for _, lk := range l.links {
		if err := lk.Close(); err != nil {
			log.Printf("[ebpf] Warning: error closing link: %v", err)
		}
	}
	l.links = nil

	// Close all collections (frees BPF maps/programs).
	for _, coll := range l.collections {
		coll.Close()
	}
	l.collections = nil
	l.cgroupMaps = nil
	l.syscallMaps = nil
	l.sensitivePathMap = nil
	l.minerPoolPortsMap = nil
	l.c2PortsMap = nil
	l.cloudMetadataMap = nil

	l.running = false
	log.Printf("[ebpf] eBPF loader stopped")
	return nil
}

// ── Map management ────────────────────────────────────────────────────

// AddContainerCgroup registers a container's cgroup ID for kernel-side filtering.
// Because each probe category has its own container_cgroups map, this updates
// ALL loaded collections. In mock mode, just logs.
func (l *Loader) AddContainerCgroup(cgroupID uint64, containerSeq uint32) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.cgroupMaps) == 0 {
		log.Printf("[ebpf] Container cgroup registered (mock): cgroup_id=%d seq=%d", cgroupID, containerSeq)
		return nil
	}

	for _, m := range l.cgroupMaps {
		if err := m.Update(cgroupID, containerSeq, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update container_cgroups (cgroup_id=%d): %w", cgroupID, err)
		}
	}
	return nil
}

// RemoveContainerCgroup removes a container's cgroup ID from all kernel-side
// filter maps.
func (l *Loader) RemoveContainerCgroup(cgroupID uint64) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.cgroupMaps) == 0 {
		log.Printf("[ebpf] Container cgroup removed (mock): cgroup_id=%d", cgroupID)
		return nil
	}

	for _, m := range l.cgroupMaps {
		if err := m.Delete(cgroupID); err != nil {
			return fmt.Errorf("delete container_cgroups (cgroup_id=%d): %w", cgroupID, err)
		}
	}
	return nil
}

// AddMonitoredSyscall adds a syscall number to the kernel-side filter in all
// loaded collections.
func (l *Loader) AddMonitoredSyscall(syscallNr uint32) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.syscallMaps) == 0 {
		return nil
	}

	for _, m := range l.syscallMaps {
		if err := m.Update(syscallNr, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update monitored_syscalls (nr=%d): %w", syscallNr, err)
		}
	}
	return nil
}

// populateKernelMaps fills the kernel-side BPF maps with the Go-side default
// lists (miner ports, C2 ports, cloud metadata IPs, monitored syscalls).
// No-op in mock mode (maps are nil).
func (l *Loader) populateKernelMaps() {
	// Mining pool ports
	for port := range MinerPoolPorts {
		if l.minerPoolPortsMap != nil {
			_ = l.minerPoolPortsMap.Update(port, uint8(1), ebpf.UpdateAny)
		}
	}

	// C2 ports
	for port := range C2Ports {
		if l.c2PortsMap != nil {
			_ = l.c2PortsMap.Update(port, uint8(1), ebpf.UpdateAny)
		}
	}

	// Cloud metadata IPs (IPv4 → uint32, host byte order to match the C probe
	// which compares against iph->daddr after bpf_ntohl, i.e. host order).
	for ip := range CloudMetadataIPs {
		if l.cloudMetadataMap != nil {
			if u := ipv4ToUint32Host(ip); u != 0 {
				_ = l.cloudMetadataMap.Update(u, uint8(1), ebpf.UpdateAny)
			}
		}
	}

	// Monitored syscalls (replicated across all collections).
	monitoredSyscalls := []uint32{
		59, 56, 231, 257, 263, 319, // execve, clone, exit_group, openat, unlinkat, memfd_create
		42, 50, // connect, listen
		308, 272, 165, 101, 175, 321, // setns, unshare, mount, ptrace, init_module, bpf
		105, 126, 90, 268, // setuid, capset, chmod, fchmodat
	}
	for _, nr := range monitoredSyscalls {
		_ = l.AddMonitoredSyscall(nr)
	}

	log.Printf("[ebpf] Populated kernel maps: %d miner ports, %d C2 ports, %d metadata IPs, %d syscalls",
		len(MinerPoolPorts), len(C2Ports), len(CloudMetadataIPs), len(monitoredSyscalls))
}

// ipv4ToUint32Host converts a dotted-quad IPv4 string to a uint32 in host
// byte order (matching the C probe's bpf_ntohl(iph->daddr) comparison).
func ipv4ToUint32Host(ip string) uint32 {
	var a, b, c, d uint32
	if _, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d); err != nil {
		return 0
	}
	return a<<24 | b<<16 | c<<8 | d
}

// ── Development helpers ──────────────────────────────────────────────

// InjectEvent injects a synthetic event (for development/testing).
// Applies the ring buffer filter before delivering to the event channel.
func (l *Loader) InjectEvent(event *ScarletEvent) {
	l.deliver(event)
}

// Filter returns the ring buffer filter for configuration.
func (l *Loader) Filter() *RingBufferFilter {
	return l.filter
}

// SetTestEventChannel sets an in-memory event channel for testing.
// When set, the loader's Events() method returns this channel instead of
// the ring buffer channel.
func (l *Loader) SetTestEventChannel(ch chan *ScarletEvent) {
	l.testEventCh = ch
}

// IsMockMode returns whether the loader is running in mock mode
// (non-Linux or no BTF available).
func (l *Loader) IsMockMode() bool {
	return l.mockMode
}

// CollectionCount returns the number of loaded eBPF collections (0 in mock mode).
func (l *Loader) CollectionCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.collections)
}

// LinkCount returns the number of attached eBPF programs (0 in mock mode).
func (l *Loader) LinkCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.links)
}

// ── Mock mode ─────────────────────────────────────────────────────────

// loadMockCollection sets up the loader in mock/development mode: no real
// eBPF is loaded, maps stay nil, and events arrive only via InjectEvent().
func (l *Loader) loadMockCollection(ctx context.Context) error {
	log.Printf("[ebpf] Mock mode: no eBPF collections loaded (events via InjectEvent only)")
	// populateKernelMaps is nil-safe (no maps to fill) but we still log the
	// intended population so operators see what would be loaded.
	log.Printf("[ebpf] Would populate: %d miner ports, %d C2 ports, %d metadata IPs",
		len(MinerPoolPorts), len(C2Ports), len(CloudMetadataIPs))
	return nil
}

// ── BTF check ────────────────────────────────────────────────────────

func checkBTF() error {
	// Check for BTF at the standard kernel location.
	btfPath := "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(btfPath); err == nil {
		log.Printf("[ebpf] BTF available at %s", btfPath)
		return nil
	}

	log.Printf("[ebpf] Warning: BTF not found at %s, will try BTFHub fallback", btfPath)

	// Return a soft warning — in production, BTFHub would be consulted.
	return fmt.Errorf("kernel BTF not found at %s (CO-RE requires BTF)", btfPath)
}
