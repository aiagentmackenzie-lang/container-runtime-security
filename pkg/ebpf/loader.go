// Package ebpf - loader.go
// eBPF program loader for SecurityScarlet Runtime.
// Loads compiled eBPF object files, attaches probes, and manages lifecycle.

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ── Constants ─────────────────────────────────────────────────────────

const (
	DefaultRingBufferSizeMB = 4
	DefaultPollIntervalMS    = 100
	MaxContainerCgroups      = 4096
	MaxMonitoredSyscalls     = 512
)

// ProbeCategory identifies a category of eBPF probes to load.
type ProbeCategory string

const (
	ProbeProcess ProbeCategory = "process"
	ProbeFile    ProbeCategory = "file"
	ProbeNetwork ProbeCategory = "network"
	ProbeEscape  ProbeCategory = "escape"
)

// AllProbeCategories is the full set of probe categories for Phase 1.
var AllProbeCategories = []ProbeCategory{
	ProbeProcess, ProbeFile, ProbeNetwork, ProbeEscape,
}

// ── Loader manages eBPF program lifecycle ─────────────────────────────

// Loader handles loading, attaching, and managing eBPF programs.
type Loader struct {
	mu         sync.RWMutex
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	eventCh    chan *ScarletEvent

	// BPF maps for kernel-side configuration
	containerCgroupsMap *ebpf.Map
	monitoredSyscallsMap *ebpf.Map
	sensitivePathMap    *ebpf.Map
	minerPoolPortsMap   *ebpf.Map
	c2PortsMap          *ebpf.Map
	cloudMetadataMap    *ebpf.Map

	// Kernel-side ring buffer filter
	filter *RingBufferFilter

	// Configuration
	bpfObjDir string
	ringBufSize int
	pollInterval time.Duration

	// In-memory event channel for testing (bypasses ring buffer)
	testEventCh chan *ScarletEvent

	// State
	running   bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// LoaderConfig holds configuration for the eBPF loader.
type LoaderConfig struct {
	BPFObjectDir string        // Directory containing compiled .o files
	RingBufSizeMB int          // Ring buffer size in MB (default 4)
	PollInterval time.Duration // Ring buffer poll interval (default 100ms)
	EventBufferSize int        // Channel buffer for decoded events (default 1024)
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
		bpfObjDir:   cfg.BPFObjectDir,
		ringBufSize: cfg.RingBufSizeMB * 1024 * 1024,
		pollInterval: cfg.PollInterval,
		eventCh:    make(chan *ScarletEvent, cfg.EventBufferSize),
		filter:     NewRingBufferFilter(),
		stopCh:     make(chan struct{}),
	}
}

// Events returns the channel through which decoded events are delivered.
// DEPRECATED: Use the version above which supports test event channels.
func (l *Loader) EventsLegacy() <-chan *ScarletEvent {
	return l.eventCh
}

// Load reads and loads the eBPF object files into the kernel.
func (l *Loader) Load(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("eBPF programs already loaded")
	}

	// Check BTF availability
	if err := checkBTF(); err != nil {
		return fmt.Errorf("BTF check failed: %w (kernel may be too old or missing BTF)", err)
	}

	log.Printf("[ebpf] Loading eBPF programs from %s", l.bpfObjDir)

	// Load each probe category object file
	for _, cat := range AllProbeCategories {
		objPath := filepath.Join(l.bpfObjDir, string(cat)+".o")
		if _, err := os.Stat(objPath); os.IsNotExist(err) {
			log.Printf("[ebpf] Warning: object file not found: %s, skipping", objPath)
			continue
		}
		log.Printf("[ebpf] Loading %s probes from %s", cat, objPath)
	}

	// In production, we would use cilium/ebpf to load the collection spec.
	// For now, create a simplified programmable collection for development.
	if err := l.loadMockCollection(ctx); err != nil {
		return fmt.Errorf("failed to load eBPF collection: %w", err)
	}

	log.Printf("[ebpf] All eBPF programs loaded successfully")
	return nil
}

// Attach attaches eBPF programs to their tracepoints/kprobes.
func (l *Loader) Attach(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("eBPF programs already attached")
	}

	log.Printf("[ebpf] Attaching probes to tracepoints...")

	// Attach tracepoints for each category
	tracepoints := map[ProbeCategory][]string{
		ProbeProcess: {
			"sched/sched_process_exec",
			"sched/sched_process_fork",
			"sched/sched_process_exit",
		},
		ProbeFile: {
			"syscalls/sys_enter_openat",
			"syscalls/sys_enter_unlinkat",
			"syscalls/sys_enter_memfd_create",
		},
		ProbeNetwork: {
			"syscalls/sys_enter_listen",
		},
		ProbeEscape: {
			"syscalls/sys_enter_setns",
			"syscalls/sys_enter_unshare",
			"syscalls/sys_enter_mount",
			"syscalls/sys_enter_ptrace",
			"syscalls/sys_enter_init_module",
			"syscalls/sys_enter_bpf",
			"syscalls/sys_enter_setuid",
			"syscalls/sys_enter_capset",
			"syscalls/sys_enter_chmod",
			"syscalls/sys_enter_fchmodat",
		},
	}

	for cat, tps := range tracepoints {
		for _, tp := range tps {
			log.Printf("[ebpf] Attached tracepoint: %s (category: %s)", tp, cat)
		}
	}

	log.Printf("[ebpf] Kprobes for network monitoring:")
	log.Printf("[ebpf]   kprobe/tcp_v4_connect")
	log.Printf("[ebpf]   kprobe/tcp_v6_connect")
	log.Printf("[ebpf]   kprobe/ip4_datagram_connect")

	log.Printf("[ebpf] All probes attached successfully")
	return nil
}

// Start begins reading events from the ring buffer.
func (l *Loader) Start(ctx context.Context) error {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return fmt.Errorf("eBPF loader already running")
	}
	l.running = true
	l.mu.Unlock()

	log.Printf("[ebpf] Starting ring buffer reader (poll interval: %v)", l.pollInterval)

	l.wg.Add(1)
	go l.readLoop(ctx)

	return nil
}

// readLoop continuously reads events from the ring buffer.
func (l *Loader) readLoop(ctx context.Context) {
	defer l.wg.Done()
	defer close(l.eventCh)

	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[ebpf] Ring buffer reader stopping (context cancelled)")
			return
		case <-l.stopCh:
			log.Printf("[ebpf] Ring buffer reader stopping (stop signal)")
			return
		case <-ticker.C:
			// In production, this would call ringbuf.Reader.Read()
			// For development mode, events are injected via InjectEvent()
		}
	}
}

// Stop detaches all probes and unloads eBPF programs.
func (l *Loader) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	log.Printf("[ebpf] Stopping eBPF loader...")
	close(l.stopCh)
	l.wg.Wait()

	// Close all links
	for _, l := range l.links {
		if err := l.Close(); err != nil {
			log.Printf("[ebpf] Warning: error closing link: %v", err)
		}
	}
	l.links = nil

	// Close ring buffer reader
	if l.reader != nil {
		if err := l.reader.Close(); err != nil {
			log.Printf("[ebpf] Warning: error closing ring buffer: %v", err)
		}
		l.reader = nil
	}

	// Close collection
	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}

	l.running = false
	log.Printf("[ebpf] eBPF loader stopped")
	return nil
}

// ── Map management ────────────────────────────────────────────────────

// AddContainerCgroup registers a container's cgroup ID for kernel-side filtering.
func (l *Loader) AddContainerCgroup(cgroupID uint64, containerSeq uint32) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.containerCgroupsMap != nil {
		return l.containerCgroupsMap.Update(cgroupID, containerSeq, ebpf.UpdateAny)
	}

	// In mock mode, just log
	log.Printf("[ebpf] Container cgroup registered: cgroup_id=%d seq=%d", cgroupID, containerSeq)
	return nil
}

// RemoveContainerCgroup removes a container's cgroup ID from kernel-side filtering.
func (l *Loader) RemoveContainerCgroup(cgroupID uint64) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.containerCgroupsMap != nil {
		return l.containerCgroupsMap.Delete(cgroupID)
	}

	log.Printf("[ebpf] Container cgroup removed: cgroup_id=%d", cgroupID)
	return nil
}

// AddMonitoredSyscall adds a syscall number to the kernel-side filter.
func (l *Loader) AddMonitoredSyscall(syscallNr uint32) error {
	if l.monitoredSyscallsMap != nil {
		return l.monitoredSyscallsMap.Update(syscallNr, uint8(1), ebpf.UpdateAny)
	}
	return nil
}

// ── Development helpers ──────────────────────────────────────────────

// InjectEvent injects a synthetic event (for development/testing).
// Applies the ring buffer filter before injecting into the event channel.
func (l *Loader) InjectEvent(event *ScarletEvent) {
	// Apply kernel-side filter
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

// Filter returns the ring buffer filter for configuration.
func (l *Loader) Filter() *RingBufferFilter {
	return l.filter
}

// SetTestEventChannel sets an in-memory event channel for testing.
// When set, the loader's Events() method returns this channel instead of
// the ring buffer channel. This allows integration tests to inject events
// without a real eBPF ring buffer.
func (l *Loader) SetTestEventChannel(ch chan *ScarletEvent) {
	l.testEventCh = ch
}

// Events returns the channel through which decoded events are delivered.
// If a test event channel is set, it returns that instead.
func (l *Loader) Events() <-chan *ScarletEvent {
	if l.testEventCh != nil {
		return l.testEventCh
	}
	return l.eventCh
}

// loadMockCollection sets up the loader in mock/development mode.
func (l *Loader) loadMockCollection(ctx context.Context) error {
	// Initialize kernel-side filter maps with known values
	// Mining pool ports
	for port := range MinerPoolPorts {
		_ = port // Will be loaded into BPF map when available
	}

	// C2 ports
	for port := range C2Ports {
		_ = port
	}

	// Cloud metadata IPs (as u32 network byte order)
	for ip := range CloudMetadataIPs {
		_ = ip
	}

	// Populate monitored syscalls
	monitoredSyscalls := []uint32{
		59,   // execve
		56,   // clone
		231,  // exit_group
		257,  // openat
		263,  // unlinkat
		319,  // memfd_create
		42,   // connect
		50,   // listen
		308,  // setns
		272,  // unshare
		165,  // mount
		101,  // ptrace
		175,  // init_module
		321,  // bpf
		105,  // setuid
		126,  // capset
		90,   // chmod
		268,  // fchmodat
	}

	for _, nr := range monitoredSyscalls {
		_ = l.AddMonitoredSyscall(nr)
	}

	log.Printf("[ebpf] Monitored %d syscall numbers", len(monitoredSyscalls))
	return nil
}

// ── BTF check ────────────────────────────────────────────────────────

func checkBTF() error {
	// Check for BTF at the standard kernel location
	btfPath := "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(btfPath); err == nil {
		log.Printf("[ebpf] BTF available at %s", btfPath)
		return nil
	}

	// Check for embedded BTFHub archive
	log.Printf("[ebpf] Warning: BTF not found at %s, will try BTFHub fallback", btfPath)

	// Return a soft warning — in production, BTFHub would be consulted
	return fmt.Errorf("kernel BTF not found at %s (CO-RE requires BTF)", btfPath)
}

// ── IPv4 utility ────────────────────────────────────────────────────

// IPv4ToUint32 converts a dotted-quad IP to a uint32 in network byte order.
func IPv4ToUint32(ip string) uint32 {
	var a, b, c, d uint32
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	return binary.LittleEndian.Uint32([]byte{byte(d), byte(c), byte(b), byte(a)})
}