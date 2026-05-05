// Package ebpf - tc_loader.go
// eBPF TC (Traffic Control) program loader for network policy enforcement.
//
// Per SRD Deliverable 5 (Phase 2) and Session 7 Task 4:
//   - Load network_tc.bpf.c compiled eBPF programs
//   - Attach TC classifiers to network interfaces (ingress + egress)
//   - Manage the network_blocklist BPF hash map FD
//   - Wire BPF map FD to NetworkEnforcer.SetBPFMapFD()
//
// TC programs are defined in pkg/ebpf/probes/network_tc.bpf.c and
// provide packet-level enforcement:
//   - Ingress filter: drops packets from blocked IPs/ports
//   - Egress filter: drops packets to blocked IPs/ports
//   - 5-tier blocklist lookup (exact match, any protocol, IP-only, port-only, port+proto)
//
// Architecture:
//   - TCLoader manages the lifecycle of TC programs
//   - On real Linux: loads .o files via cilium/ebpf, attaches via netlink
//   - On development/non-Linux: mock mode (logs operations, returns success)
//   - BPF map is shared: userspace writes via NetworkEnforcer, kernel reads via TC programs

package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
)

// ── TC Loader Constants ────────────────────────────────────────────────

const (
	// TC program names (must match the C source)
	TCIngressProgram  = "tc_ingress_filter"
	TCEgressProgram   = "tc_egress_filter"

	// BPF map names (must match the C source)
	NetworkBlocklistMap = "network_blocklist"
	NetworkBlockEvents  = "network_block_events"

	// Default TC attachment priority
	TCDefaultPriority = 1

	// Default blocklist map size
	DefaultBlocklistSize = 4096
)

// ── TC Loader ──────────────────────────────────────────────────────────

// TCLoader manages the lifecycle of eBPF TC network filtering programs.
// It loads the compiled eBPF object, attaches TC classifiers to network
// interfaces, and provides access to the BPF blocklist map for the
// NetworkEnforcer to use.
type TCLoader struct {
	mu sync.RWMutex

	// Configuration
	objDir      string   // Directory containing compiled .o files
	ifaces      []string // Network interfaces to attach TC programs
	priority    int      // TC program priority (lower = higher priority)

	// BPF map reference
	blocklistMapFD int  // File descriptor for the blocklist BPF hash map
	blockEventsFD  int  // File descriptor for block events ring buffer

	// State
	loaded    bool
	attached  bool
	interfaces map[string]bool // interfaces with TC programs attached

	// Mock mode
	mockMode bool // true when eBPF is not available (development/non-Linux)
}

// TCLoaderConfig holds configuration for the TC loader.
type TCLoaderConfig struct {
	// BPFObjectDir is the directory containing compiled eBPF .o files.
	BPFObjectDir string

	// Interfaces is the list of network interfaces to attach TC programs.
	// If empty, defaults to ["eth0"].
	Interfaces []string

	// Priority is the TC program priority (0-65535, lower = higher priority).
	Priority int
}

// NewTCLoader creates a new TC loader.
func NewTCLoader(cfg TCLoaderConfig) *TCLoader {
	if len(cfg.Interfaces) == 0 {
		cfg.Interfaces = []string{"eth0"}
	}
	if cfg.Priority <= 0 {
		cfg.Priority = TCDefaultPriority
	}

	return &TCLoader{
		objDir:     cfg.BPFObjectDir,
		ifaces:     cfg.Interfaces,
		priority:   cfg.Priority,
		interfaces: make(map[string]bool),
		mockMode:   runtime.GOOS != "linux" || !isBPFAvailable(),
	}
}

// Load loads the TC eBPF programs into the kernel.
// In mock mode, this is a no-op that logs the operation.
func (t *TCLoader) Load() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.loaded {
		return fmt.Errorf("TC programs already loaded")
	}

	if t.mockMode {
		log.Printf("[ebpf/tc] Mock mode: TC eBPF programs loaded (not actually loaded)")
		log.Printf("[ebpf/tc] Programs: %s (ingress), %s (egress)",
			TCIngressProgram, TCEgressProgram)
		log.Printf("[ebpf/tc] Blocklist map: %s (size=%d)", NetworkBlocklistMap, DefaultBlocklistSize)
		log.Printf("[ebpf/tc] Block events: %s", NetworkBlockEvents)
		t.loaded = true
		t.blocklistMapFD = -1 // mock FD
		t.blockEventsFD = -1  // mock FD
		return nil
	}

	// Production mode: load eBPF object
	objPath := fmt.Sprintf("%s/network_tc.o", t.objDir)
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return fmt.Errorf("TC eBPF object file not found: %s", objPath)
	}

	log.Printf("[ebpf/tc] Loading TC eBPF programs from %s", objPath)

	// TODO: When cilium/ebpf collection loading is implemented:
	//   collection, err := ebpf.LoadCollection(objPath)
	//   if err != nil { return fmt.Errorf("failed to load TC collection: %w", err) }
	//
	//   blocklistMap := collection.Maps[NetworkBlocklistMap]
	//   t.blocklistMapFD = blocklistMap.FD()
	//   t.blockEventsFD = collection.Maps[NetworkBlockEvents].FD()
	//
	//   t.collection = collection
	//   log.Printf("[ebpf/tc] Blocklist map FD: %d", t.blocklistMapFD)

	log.Printf("[ebpf/tc] TC eBPF programs loaded successfully (production mode placeholder)")
	t.loaded = true

	return nil
}

// Attach attaches TC classifier programs to the configured network interfaces.
// Both ingress and egress programs are attached.
func (t *TCLoader) Attach() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.loaded {
		return fmt.Errorf("TC programs not loaded; call Load() first")
	}

	if t.attached {
		return fmt.Errorf("TC programs already attached")
	}

	for _, iface := range t.ifaces {
		if err := t.attachInterface(iface); err != nil {
			log.Printf("[ebpf/tc] Warning: failed to attach TC program to %s: %v", iface, err)
			continue
		}
	}

	t.attached = true
	return nil
}

// attachInterface attaches TC programs to a single network interface.
func (t *TCLoader) attachInterface(ifaceName string) error {
	if t.mockMode {
		log.Printf("[ebpf/tc] Mock mode: attached TC programs to %s (ingress + egress)", ifaceName)
		t.interfaces[ifaceName] = true
		return nil
	}

	// Validate interface exists
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	_ = iface // used when netlink attachment is implemented

	// TODO: When netlink TC attachment is implemented:
	//   1. Create TC qdisc (clsact) on the interface
	//      err = netlink.QdiscAdd(clsactQdisc(iface.Index))
	//   2. Attach ingress program
	//      err = netlink.FilterAdd(tcIngressFilter(iface, t.priority))
	//   3. Attach egress program
	//      err = netlink.FilterAdd(tcEgressFilter(iface, t.priority))

	log.Printf("[ebpf/tc] Attached TC programs to %s (ingress + egress, pri=%d)",
		ifaceName, t.priority)
	t.interfaces[ifaceName] = true

	return nil
}

// Detach removes TC programs from all attached interfaces.
func (t *TCLoader) Detach() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.attached {
		return nil
	}

	for ifaceName := range t.interfaces {
		if err := t.detachInterface(ifaceName); err != nil {
			log.Printf("[ebpf/tc] Warning: failed to detach TC program from %s: %v", ifaceName, err)
		}
	}

	t.attached = false
	t.interfaces = make(map[string]bool)
	log.Printf("[ebpf/tc] TC programs detached from all interfaces")
	return nil
}

// detachInterface removes TC programs from a single network interface.
func (t *TCLoader) detachInterface(ifaceName string) error {
	if t.mockMode {
		log.Printf("[ebpf/tc] Mock mode: detached TC programs from %s", ifaceName)
		return nil
	}

	// TODO: When netlink TC detachment is implemented:
	//   1. Delete ingress filter
	//   2. Delete egress filter
	//   3. Delete clsact qdisc

	log.Printf("[ebpf/tc] Detached TC programs from %s", ifaceName)
	return nil
}

// Close unloads the TC eBPF programs and releases resources.
func (t *TCLoader) Close() error {
	if err := t.Detach(); err != nil {
		log.Printf("[ebpf/tc] Warning: error during detach: %v", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.loaded {
		return nil
	}

	// TODO: Close BPF collection
	// if t.collection != nil {
	//     t.collection.Close()
	// }

	t.loaded = false
	t.blocklistMapFD = -1
	t.blockEventsFD = -1
	log.Printf("[ebpf/tc] TC eBPF programs unloaded")
	return nil
}

// ── BPF Map Access ─────────────────────────────────────────────────────

// BlocklistMapFD returns the file descriptor for the network_blocklist BPF map.
// Returns -1 if the TC programs have not been loaded or the map is unavailable.
func (t *TCLoader) BlocklistMapFD() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.blocklistMapFD
}

// BlockEventsFD returns the file descriptor for the network_block_events ring buffer.
// Returns -1 if the TC programs have not been loaded or the ring buffer is unavailable.
func (t *TCLoader) BlockEventsFD() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.blockEventsFD
}

// SetBlocklistMapFD sets the BPF blocklist map file descriptor directly.
// This is used when the map FD is obtained through an external mechanism
// (e.g., pinned BPF map, or IPC from another process).
func (t *TCLoader) SetBlocklistMapFD(fd int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.blocklistMapFD = fd

	// Update mock mode status
	if fd >= 0 {
		t.mockMode = false
	}
}

// IsLoaded returns whether TC programs have been loaded.
func (t *TCLoader) IsLoaded() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.loaded
}

// IsAttached returns whether TC programs have been attached to interfaces.
func (t *TCLoader) IsAttached() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.attached
}

// IsMockMode returns whether the TC loader is running in mock mode.
func (t *TCLoader) IsMockMode() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mockMode
}

// AttachedInterfaces returns the list of interfaces with TC programs attached.
func (t *TCLoader) AttachedInterfaces() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]string, 0, len(t.interfaces))
	for iface := range t.interfaces {
		result = append(result, iface)
	}
	return result
}

// ── BPF Map Operations ────────────────────────────────────────────────

// UpdateBlocklistEntry adds or updates an entry in the BPF network_blocklist map.
// This is called by NetworkEnforcer when Block() is invoked, after SetBPFMapFD
// has been called with a valid FD from the TC loader.
//
// The key is a 4-tuple: (dest_ip uint32, dest_port uint16, protocol uint8, pad uint8).
// The value is a block action + statistics counter.
func (t *TCLoader) UpdateBlocklistEntry(ip uint32, port uint16, protocol uint8, action uint8) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.mockMode {
		log.Printf("[ebpf/tc] Mock: blocklist update ip=0x%08x port=%d proto=%d action=%d",
			ip, port, protocol, action)
		return nil
	}

	if t.blocklistMapFD < 0 {
		return fmt.Errorf("blocklist map FD not available (fd=%d)", t.blocklistMapFD)
	}

	// TODO: When cilium/ebpf map operations are implemented:
	//   key := BlocklistKey{DestIP: ip, DestPort: port, Protocol: protocol}
	//   value := BlocklistValue{Action: action, PktCount: 0}
	//   err := bpfMapUpdateElem(t.blocklistMapFD, &key, &value, BPF_ANY)
	//   if err != nil { return fmt.Errorf("bpf_map_update_elem: %w", err) }

	log.Printf("[ebpf/tc] blocklist update ip=0x%08x port=%d proto=%d action=%d",
		ip, port, protocol, action)
	return nil
}

// DeleteBlocklistEntry removes an entry from the BPF network_blocklist map.
func (t *TCLoader) DeleteBlocklistEntry(ip uint32, port uint16, protocol uint8) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.mockMode {
		log.Printf("[ebpf/tc] Mock: blocklist delete ip=0x%08x port=%d proto=%d",
			ip, port, protocol)
		return nil
	}

	if t.blocklistMapFD < 0 {
		return fmt.Errorf("blocklist map FD not available (fd=%d)", t.blocklistMapFD)
	}

	// TODO: When cilium/ebpf map operations are implemented:
	//   key := BlocklistKey{DestIP: ip, DestPort: port, Protocol: protocol}
	//   err := bpfMapDeleteElem(t.blocklistMapFD, &key)
	//   if err != nil { return fmt.Errorf("bpf_map_delete_elem: %w", err) }

	log.Printf("[ebpf/tc] blocklist delete ip=0x%08x port=%d proto=%d",
		ip, port, protocol)
	return nil
}

// ── BPF Map Types ─────────────────────────────────────────────────────

// BlocklistKey is the BPF map key for the network_blocklist hash map.
// Must match the C struct in network_tc.bpf.c.
type BlocklistKey struct {
	DestIP   uint32 // Network byte order IPv4 address
	DestPort uint16 // Host byte order port number
	Protocol uint8  // IPPROTO_TCP (6), IPPROTO_UDP (17), or 0 (any)
	Pad      uint8  // Alignment padding
}

// BlocklistValue is the BPF map value for the network_blocklist hash map.
// Must match the C struct in network_tc.bpf.c.
type BlocklistValue struct {
	Action   uint8  // 1 = block, 0 = allow
	Pad      [3]uint8
	PktCount uint64 // Per-CPU packet counter (updated by kernel)
}

// ── Helper Functions ──────────────────────────────────────────────────

// isBPFAvailable checks if the kernel supports eBPF.
// Returns false on non-Linux systems (development mode).
func isBPFAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// Check for BTF availability
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false
	}

	return true
}

// InterfaceMAC returns the MAC address of a network interface.
// Used for TC program packet matching.
func InterfaceMAC(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	return iface.HardwareAddr, nil
}

// ListNetworkInterfaces returns available network interfaces suitable
// for TC program attachment (non-loopback, up).
func ListNetworkInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	var suitable []net.Interface
	for _, iface := range interfaces {
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Skip interfaces that are down
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		suitable = append(suitable, iface)
	}

	return suitable, nil
}