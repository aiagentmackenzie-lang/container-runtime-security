// Package ebpf - tc_loader.go
// eBPF TC (Traffic Control) program loader for network policy enforcement.
//
// Loads the compiled network_tc.bpf.c object, attaches the TC ingress/egress
// classifiers to network interfaces, and exposes the network_blocklist BPF
// hash map so NetworkEnforcer can add/remove kernel-level blocks.
//
// Real path (Linux + BTF): uses github.com/cilium/ebpf to load the collection,
// link.AttachTCX to attach the ingress/egress programs, and the blocklist
// map's Update/Delete for kernel-side enforcement.
//
// Mock path (non-Linux or no BTF): all operations log and return nil so the
// agent and `go test ./...` work on macOS/dev machines.

package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ── TC Loader Constants ────────────────────────────────────────────────

const (
	// TC program names (must match the C source).
	TCIngressProgram = "tc_ingress_filter"
	TCEgressProgram  = "tc_egress_filter"

	// BPF map names (must match the C source).
	NetworkBlocklistMap = "network_blocklist"
	NetworkBlockEvents  = "network_block_events"

	// Default TC attachment priority.
	TCDefaultPriority = 1

	// Default blocklist map size.
	DefaultBlocklistSize = 4096
)

// ── TC Loader ──────────────────────────────────────────────────────────

// TCLoader manages the lifecycle of eBPF TC network filtering programs.
type TCLoader struct {
	mu sync.RWMutex

	// Configuration
	objDir   string   // Directory containing compiled .o files
	ifaces   []string // Network interfaces to attach TC programs
	priority int      // TC program priority (lower = higher priority)

	// Loaded collection + maps
	collection    *ebpf.Collection
	blocklistMap  *ebpf.Map
	blocklistMapFD int  // File descriptor for the blocklist BPF hash map

	// Attached links (ingress + egress per interface)
	links []link.Link

	// State
	loaded   bool
	attached bool
	mockMode bool
}

// TCLoaderConfig holds configuration for the TC loader.
type TCLoaderConfig struct {
	BPFObjectDir string   // Directory containing compiled eBPF .o files
	Interfaces   []string // Network interfaces to attach TC programs (default ["eth0"])
	Priority     int      // TC program priority (0-65535, lower = higher priority)
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
		objDir:   cfg.BPFObjectDir,
		ifaces:   cfg.Interfaces,
		priority: cfg.Priority,
		mockMode: runtime.GOOS != "linux" || !isBPFAvailable(),
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
		t.loaded = true
		t.blocklistMapFD = -1
		return nil
	}

	objPath := fmt.Sprintf("%s/network_tc.o", t.objDir)
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return fmt.Errorf("TC eBPF object file not found: %s", objPath)
	}

	log.Printf("[ebpf/tc] Loading TC eBPF programs from %s", objPath)

	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("failed to load TC collection: %w", err)
	}
	t.collection = coll

	// Acquire the blocklist map and its FD.
	if m := coll.Maps[NetworkBlocklistMap]; m != nil {
		t.blocklistMap = m
		t.blocklistMapFD = m.FD()
		log.Printf("[ebpf/tc] Blocklist map FD: %d", t.blocklistMapFD)
	} else {
		log.Printf("[ebpf/tc] Warning: %s map not found in collection", NetworkBlocklistMap)
	}

	log.Printf("[ebpf/tc] TC eBPF programs loaded successfully (%d programs, %d maps)",
		len(coll.Programs), len(coll.Maps))
	t.loaded = true
	return nil
}

// Attach attaches TC classifier programs to the configured network interfaces.
// Uses link.AttachTCX (kernel 6.6+). On kernels without TCX, attach fails
// gracefully and the loader falls back to userspace-only blocklist tracking.
func (t *TCLoader) Attach() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.loaded {
		return fmt.Errorf("TC programs not loaded; call Load() first")
	}
	if t.attached {
		return fmt.Errorf("TC programs already attached")
	}
	if t.mockMode {
		log.Printf("[ebpf/tc] Mock mode: attached TC programs to %v", t.ifaces)
		t.attached = true
		return nil
	}

	ingressProg := t.collection.Programs[TCIngressProgram]
	egressProg := t.collection.Programs[TCEgressProgram]
	if ingressProg == nil || egressProg == nil {
		return fmt.Errorf("TC programs %q/%q not found in collection", TCIngressProgram, TCEgressProgram)
	}

	for _, ifaceName := range t.ifaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("[ebpf/tc] Warning: interface %s not found: %v", ifaceName, err)
			continue
		}

		// Attach ingress classifier.
		inLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   ingressProg,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.Printf("[ebpf/tc] Warning: TCX ingress attach on %s failed: %v "+
				"(needs kernel 6.6+ for TCX; classic clsact attach is a follow-up)", ifaceName, err)
			continue
		}
		t.links = append(t.links, inLink)

		// Attach egress classifier.
		egLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   egressProg,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Printf("[ebpf/tc] Warning: TCX egress attach on %s failed: %v", ifaceName, err)
			inLink.Close()
			continue
		}
		t.links = append(t.links, egLink)

		log.Printf("[ebpf/tc] Attached TC ingress+egress to %s (ifindex=%d)", ifaceName, iface.Index)
	}

	t.attached = true
	return nil
}

// Detach removes TC programs from all attached interfaces.
func (t *TCLoader) Detach() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.attached {
		return nil
	}

	for _, lk := range t.links {
		if err := lk.Close(); err != nil {
			log.Printf("[ebpf/tc] Warning: error detaching link: %v", err)
		}
	}
	t.links = nil
	t.attached = false
	log.Printf("[ebpf/tc] TC programs detached from all interfaces")
	return nil
}

// Close unloads the TC eBPF programs and releases resources.
func (t *TCLoader) Close() error {
	if err := t.Detach(); err != nil {
		log.Printf("[ebpf/tc] Warning: error during detach: %v", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.collection != nil {
		t.collection.Close()
		t.collection = nil
	}
	t.blocklistMap = nil
	t.blocklistMapFD = -1
	t.loaded = false
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

// AttachedInterfaces returns the list of configured interfaces.
func (t *TCLoader) AttachedInterfaces() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, len(t.ifaces))
	copy(out, t.ifaces)
	return out
}

// ── BPF Map Operations (implements BlocklistUpdater) ───────────────────

// UpdateBlocklistEntry adds or updates an entry in the BPF network_blocklist map.
// Called by NetworkEnforcer when Block() is invoked. No-op (returns nil) in
// mock mode or when the map is unavailable.
func (t *TCLoader) UpdateBlocklistEntry(ip uint32, port uint16, protocol uint8, action uint8) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.mockMode {
		log.Printf("[ebpf/tc] Mock: blocklist update ip=0x%08x port=%d proto=%d action=%d",
			ip, port, protocol, action)
		return nil
	}
	if t.blocklistMap == nil {
		return fmt.Errorf("blocklist map not available")
	}

	key := BlocklistKey{DestIP: ip, DestPort: port, Protocol: protocol}
	value := BlocklistValue{
		BlockTimeNs: 0, // userspace doesn't know bpf_ktime; kernel ignores for presence check
		TTLSeconds:  0,
		RuleID:      uint32FromAction(action),
		BlockType:   scarletNetBlockCombined, // SCARLET_NET_BLOCK_COMBINED
		Reason:       action,
	}
	if err := t.blocklistMap.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("blocklist map update: %w", err)
	}
	return nil
}

// DeleteBlocklistEntry removes an entry from the BPF network_blocklist map.
func (t *TCLoader) DeleteBlocklistEntry(ip uint32, port uint16, protocol uint8) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.mockMode {
		log.Printf("[ebpf/tc] Mock: blocklist delete ip=0x%08x port=%d proto=%d", ip, port, protocol)
		return nil
	}
	if t.blocklistMap == nil {
		return fmt.Errorf("blocklist map not available")
	}

	key := BlocklistKey{DestIP: ip, DestPort: port, Protocol: protocol}
	if err := t.blocklistMap.Delete(key); err != nil {
		return fmt.Errorf("blocklist map delete: %w", err)
	}
	return nil
}

// Block type constants (must match network_tc.bpf.c SCARLET_NET_BLOCK_*).
const (
	scarletNetBlockIPv4     uint8 = 1
	scarletNetBlockIPv6     uint8 = 2
	scarletNetBlockPort     uint8 = 3
	scarletNetBlockCombined uint8 = 4
)

// ── BPF Map Types (must match network_tc.bpf.c) ──────────────────────

// BlocklistKey is the BPF map key for the network_blocklist hash map.
// Must match struct network_block_key in network_tc.bpf.c.
//
// Byte order: dest_ip and dest_port are in HOST byte order, matching the C
// TC program which compares against bpf_ntohl(iph->daddr)/bpf_ntohs(tcp->dest).
type BlocklistKey struct {
	DestIP   uint32 // Host byte order IPv4 address
	DestPort uint16 // Host byte order destination port
	Protocol uint8  // IPPROTO_TCP (6), IPPROTO_UDP (17), or 0 (any)
	Pad      uint8  // Alignment padding
}

// BlocklistValue is the BPF map value for the network_blocklist hash map.
// Must match struct network_block_value in network_tc.bpf.c.
// The C check_blocklist() only tests for map presence (val != NULL), so the
// field values are metadata; the struct size must still match exactly.
type BlocklistValue struct {
	BlockTimeNs uint64 // bpf_ktime_get_ns() when the block was added
	TTLSeconds  uint32  // Block duration in seconds
	RuleID      uint32  // Rule that triggered the block (e.g., R009)
	BlockType   uint8  // SCARLET_NET_BLOCK_*
	Reason      uint8  // Reason code
	Pad         uint16 // Alignment padding
}

// uint32FromAction is a placeholder mapping from a block action byte to a
// rule-id slot. Real rule IDs are strings; the kernel map stores a numeric
// placeholder. This keeps the value non-zero for diagnostics.
func uint32FromAction(action uint8) uint32 {
	return uint32(action)
}

// ── Helper Functions ──────────────────────────────────────────────────

// isBPFAvailable checks if the kernel supports eBPF (BTF present, Linux).
func isBPFAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false
	}
	return true
}

// InterfaceMAC returns the MAC address of a network interface.
func InterfaceMAC(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	return iface.HardwareAddr, nil
}

// ListNetworkInterfaces returns available non-loopback, up interfaces.
func ListNetworkInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	var suitable []net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		suitable = append(suitable, iface)
	}
	return suitable, nil
}