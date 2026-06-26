// Package enforcement - network.go
// Network policy enforcement via eBPF TC (Traffic Control) hooks.
//
// Per SRD Deliverable 5 (Phase 2):
//   - Go enforcer loads TC programs, manages the blocklist map
//   - Integrates with rule engine: R009/R027 match in enforce mode → add IP/port to blocklist
//   - Blocklist TTL (default 5 minutes) prevents stale blocks
//   - Metrics: scarlet_network_blocks_total{rule,reason}
//
// Architecture:
//   - NetworkEnforcer is the top-level manager
//   - BlocklistEntry describes an IP/port/protocol block
//   - Userspace adds/removes entries from the BPF hash map
//   - TC ingress/egress programs check the map for every packet
//   - When a match is found in enforce mode, the rule engine calls
//     NetworkEnforcer.Block() to add the entry
//
// The eBPF TC programs are defined in pkg/ebpf/probes/network_tc.bpf.c
// and require Linux kernel headers to compile (won't compile on macOS).
// The Go enforcer uses build tags for cross-platform compatibility.

package enforcement

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// ── Network Block Types ─────────────────────────────────────────────────

// BlockType describes what kind of network block this is.
type BlockType uint8

const (
	BlockTypeIPv4     BlockType = 1 // Block by destination IPv4 address
	BlockTypeIPv6     BlockType = 2 // Block by destination IPv6 address (future)
	BlockTypePort     BlockType = 3 // Block by destination port (any IP)
	BlockTypeCombined BlockType = 4 // Block by IP + port + protocol
)

// Protocol specifies the network protocol to block.
type Protocol uint8

const (
	ProtocolAny Protocol = 0  // Any protocol
	ProtocolTCP Protocol = 6  // TCP
	ProtocolUDP Protocol = 17 // UDP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolAny:
		return "ANY"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", p)
	}
}

// ── Blocklist Entry ──────────────────────────────────────────────────────

// BlocklistEntry represents a network block rule.
// It specifies what destination (IP, port, protocol) to block, why it
// was blocked (rule ID, reason), and how long the block should last.
type BlocklistEntry struct {
	DestIP    net.IP        `json:"dest_ip"`
	DestPort  uint16        `json:"dest_port"`
	Protocol  Protocol      `json:"protocol"`
	BlockType BlockType     `json:"block_type"`
	RuleID    string        `json:"rule_id"`
	Reason    string        `json:"reason"`
	TTL       time.Duration `json:"ttl"`
	AddedAt   time.Time     `json:"added_at"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// BlocklistKey is the BPF map key for looking up blocks.
type BlocklistKey struct {
	DestIP   uint32 // Network byte order
	DestPort uint16 // Host byte order
	Protocol uint8  // IPPROTO value
	Pad      uint8
}

// ── Network Enforcer ─────────────────────────────────────────────────

// NetworkEnforcer manages eBPF TC-based network blocking.
// It maintains a blocklist of IP/port/protocol combinations and
// updates the BPF map accordingly.
//
// When the rule engine matches R009 (mining pool connection) or R027
// (C2 port connection) in enforce mode, it calls Block() to add the
// destination to the blocklist. The TC programs then drop matching packets.
// BlocklistUpdater is an interface for updating the kernel BPF blocklist map.
// This decouples NetworkEnforcer from the eBPF package, avoiding import cycles.
// The TCLoader in pkg/ebpf implements this interface.
type BlocklistUpdater interface {
	// UpdateBlocklistEntry adds or updates an entry in the BPF network_blocklist map.
	UpdateBlocklistEntry(ip uint32, port uint16, protocol uint8, action uint8) error
	// DeleteBlocklistEntry removes an entry from the BPF network_blocklist map.
	DeleteBlocklistEntry(ip uint32, port uint16, protocol uint8) error
}

type NetworkEnforcer struct {
	// Blocklist entries (userspace tracking)
	entries map[BlocklistKey]*BlocklistEntry
	mu      sync.RWMutex

	// Configuration
	defaultTTL time.Duration // Default block duration (5 min)
	ifaceName  string        // Network interface to attach TC programs

	// BPF map reference (nil when eBPF not available)
	bpfMapFD int // File descriptor for the BPF blocklist map

	// TC loader for kernel-side BPF map operations
	tcLoader BlocklistUpdater

	// Stats
	blocksAdded   map[string]int64 // rule_id → count
	blocksExpired int64
	blocksRemoved int64

	// Lifecycle
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewNetworkEnforcer creates a new network enforcer with default settings.
func NewNetworkEnforcer() *NetworkEnforcer {
	return &NetworkEnforcer{
		entries:     make(map[BlocklistKey]*BlocklistEntry),
		defaultTTL:  5 * time.Minute,
		ifaceName:   "eth0",
		bpfMapFD:    -1, // Not connected to BPF map yet
		blocksAdded: make(map[string]int64),
		stopCh:      make(chan struct{}),
	}
}

// SetInterface sets the network interface for TC program attachment.
func (ne *NetworkEnforcer) SetInterface(iface string) {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.ifaceName = iface
}

// SetDefaultTTL sets the default block duration.
func (ne *NetworkEnforcer) SetDefaultTTL(ttl time.Duration) {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.defaultTTL = ttl
}

// SetBPFMapFD sets the BPF map file descriptor for kernel-side blocklist updates.
// When set, Block()/Unblock() will also update the kernel BPF map.
func (ne *NetworkEnforcer) SetBPFMapFD(fd int) {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.bpfMapFD = fd
}

// SetTCLoader sets the TC loader for kernel-side BPF map operations.
// When set, Block()/Unblock() forward BPF map updates to the TC loader,
// which handles the actual kernel-side map operations.
// The TC loader is the preferred way to update the BPF map — it replaces
// the direct bpfMapFD approach with a clean interface.
func (ne *NetworkEnforcer) SetTCLoader(loader BlocklistUpdater) {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.tcLoader = loader
}

// Start begins the blocklist expiry goroutine.
func (ne *NetworkEnforcer) Start() {
	ne.mu.Lock()
	if ne.running {
		ne.mu.Unlock()
		return
	}
	// Recreate the stop channel so Start can be called again after Stop
	// (e.g. agent restart, integration tests). A closed stopCh from a prior
	// lifecycle would otherwise make expireBlocks return immediately.
	ne.stopCh = make(chan struct{})
	ne.running = true
	ne.mu.Unlock()

	ne.wg.Add(1)
	go ne.expireBlocks()
	log.Printf("[enforcement/network] Started network enforcer (interface=%s, defaultTTL=%v)",
		ne.ifaceName, ne.defaultTTL)
}

// Stop gracefully stops the network enforcer.
func (ne *NetworkEnforcer) Stop() {
	ne.mu.Lock()
	if !ne.running {
		ne.mu.Unlock()
		return
	}
	ne.running = false
	ne.mu.Unlock()

	close(ne.stopCh)
	ne.wg.Wait()

	log.Printf("[enforcement/network] Stopped network enforcer. Blocks added: %d, expired: %d, removed: %d",
		ne.totalBlocks(), ne.blocksExpired, ne.blocksRemoved)
}

// ── Block Operations ─────────────────────────────────────────────────

// Block adds a destination to the network blocklist.
// The block will expire after the TTL (default: 5 minutes).
func (ne *NetworkEnforcer) Block(ip net.IP, port uint16, protocol Protocol, ruleID, reason string) error {
	return ne.BlockWithTTL(ip, port, protocol, ruleID, reason, ne.defaultTTL)
}

// BlockWithTTL adds a destination to the blocklist with a specific TTL.
func (ne *NetworkEnforcer) BlockWithTTL(ip net.IP, port uint16, protocol Protocol, ruleID, reason string, ttl time.Duration) error {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	// Convert IP to uint32 (network byte order for IPv4)
	ipUint32 := IPToUint32(ip)
	if ipUint32 == 0 && !ip.IsUnspecified() {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	key := BlocklistKey{
		DestIP:   ipUint32,
		DestPort: port,
		Protocol: uint8(protocol),
	}

	now := time.Now()
	entry := &BlocklistEntry{
		DestIP:    ip,
		DestPort:  port,
		Protocol:  protocol,
		BlockType: BlockTypeCombined,
		RuleID:    ruleID,
		Reason:    reason,
		TTL:       ttl,
		AddedAt:   now,
		ExpiresAt: now.Add(ttl),
	}

	ne.entries[key] = entry
	ne.blocksAdded[ruleID]++

	// Update BPF map: prefer TC loader, fall back to direct BPF map FD
	if ne.tcLoader != nil || ne.bpfMapFD >= 0 {
		if err := ne.updateBPFMap(key, entry); err != nil {
			log.Printf("[enforcement/network] Warning: failed to update BPF map: %v", err)
		}
	}

	log.Printf("[enforcement/network] Blocked %s:%d/%s (rule=%s reason=%s ttl=%v expires=%v)",
		ip, port, protocol, ruleID, reason, ttl, entry.ExpiresAt.Format(time.RFC3339))

	return nil
}

// Unblock removes a destination from the network blocklist.
func (ne *NetworkEnforcer) Unblock(ip net.IP, port uint16, protocol Protocol) error {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	ipUint32 := IPToUint32(ip)
	key := BlocklistKey{
		DestIP:   ipUint32,
		DestPort: port,
		Protocol: uint8(protocol),
	}

	if _, exists := ne.entries[key]; exists {
		delete(ne.entries, key)
		ne.blocksRemoved++

		// Remove from BPF map: prefer TC loader, fall back to direct BPF map FD
		if ne.tcLoader != nil || ne.bpfMapFD >= 0 {
			if err := ne.deleteFromBPFMap(key); err != nil {
				log.Printf("[enforcement/network] Warning: failed to delete from BPF map: %v", err)
			}
		}

		log.Printf("[enforcement/network] Unblocked %s:%d/%s", ip, port, protocol)
	}

	return nil
}

// ── Block Check ───────────────────────────────────────────────────────

// IsBlocked checks if a destination is currently in the blocklist.
func (ne *NetworkEnforcer) IsBlocked(ip net.IP, port uint16, protocol Protocol) bool {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	ipUint32 := IPToUint32(ip)

	// Check exact match (IP + port + protocol)
	key := BlocklistKey{DestIP: ipUint32, DestPort: port, Protocol: uint8(protocol)}
	if entry, ok := ne.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
		return true
	}

	// Check IP + port, any protocol
	key = BlocklistKey{DestIP: ipUint32, DestPort: port, Protocol: 0}
	if entry, ok := ne.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
		return true
	}

	// Check IP only, any port
	key = BlocklistKey{DestIP: ipUint32, DestPort: 0, Protocol: 0}
	if entry, ok := ne.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
		return true
	}

	// Check port only, any IP
	key = BlocklistKey{DestIP: 0, DestPort: port, Protocol: uint8(protocol)}
	if entry, ok := ne.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
		return true
	}

	key = BlocklistKey{DestIP: 0, DestPort: port, Protocol: 0}
	if entry, ok := ne.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
		return true
	}

	return false
}

// ── Blocklist Management ─────────────────────────────────────────────

// ListBlocks returns all currently active blocklist entries.
func (ne *NetworkEnforcer) ListBlocks() []BlocklistEntry {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	now := time.Now()
	var result []BlocklistEntry
	for _, entry := range ne.entries {
		if now.Before(entry.ExpiresAt) {
			result = append(result, *entry)
		}
	}
	return result
}

// BlockCount returns the number of active blocks.
func (ne *NetworkEnforcer) BlockCount() int {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, entry := range ne.entries {
		if now.Before(entry.ExpiresAt) {
			count++
		}
	}
	return count
}

// BlocksByRule returns the number of blocks added per rule ID.
func (ne *NetworkEnforcer) BlocksByRule() map[string]int64 {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	result := make(map[string]int64)
	for k, v := range ne.blocksAdded {
		result[k] = v
	}
	return result
}

// ── Expiry ───────────────────────────────────────────────────────────

// expireBlocks periodically removes expired blocklist entries.
func (ne *NetworkEnforcer) expireBlocks() {
	defer ne.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ne.stopCh:
			return
		case <-ticker.C:
			ne.removeExpiredBlocks()
		}
	}
}

// removeExpiredBlocks removes entries that have exceeded their TTL.
func (ne *NetworkEnforcer) removeExpiredBlocks() {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	now := time.Now()
	var expired int

	for key, entry := range ne.entries {
		if now.After(entry.ExpiresAt) {
			delete(ne.entries, key)
			expired++

			// Remove from BPF map if available
			if ne.tcLoader != nil || ne.bpfMapFD >= 0 {
				if err := ne.deleteFromBPFMap(key); err != nil {
					log.Printf("[enforcement/network] Warning: failed to delete expired entry from BPF map: %v", err)
				}
			}
		}
	}

	ne.blocksExpired += int64(expired)
	if expired > 0 {
		log.Printf("[enforcement/network] Expired %d blocklist entries (total expired: %d)", expired, ne.blocksExpired)
	}
}

// ── BPF Map Operations ───────────────────────────────────────────────

// updateBPFMap adds or updates an entry in the kernel BPF blocklist map.
// When a TC loader is set, the update is forwarded to the loader.
// Otherwise, falls back to direct BPF map operations via bpfMapFD.
func (ne *NetworkEnforcer) updateBPFMap(key BlocklistKey, entry *BlocklistEntry) error {
	// Prefer TC loader for kernel-side operations
	if ne.tcLoader != nil {
		err := ne.tcLoader.UpdateBlocklistEntry(key.DestIP, key.DestPort, key.Protocol, 1)
		if err != nil {
			log.Printf("[enforcement/network] TC loader update failed: %v", err)
		}
		return err
	}

	// Fallback: direct BPF map FD (when no TC loader is configured)
	if ne.bpfMapFD >= 0 {
		// TODO: When cilium/ebpf map operations are implemented:
		//   err := bpfMapUpdateElem(ne.bpfMapFD, &key, &value, BPF_ANY)
		log.Printf("[enforcement/network] BPF map update: key={ip=%08x port=%d proto=%d} rule=%s (fd=%d)",
			key.DestIP, key.DestPort, key.Protocol, entry.RuleID, ne.bpfMapFD)
	}

	return nil
}

// deleteFromBPFMap removes an entry from the kernel BPF blocklist map.
func (ne *NetworkEnforcer) deleteFromBPFMap(key BlocklistKey) error {
	// Prefer TC loader for kernel-side operations
	if ne.tcLoader != nil {
		err := ne.tcLoader.DeleteBlocklistEntry(key.DestIP, key.DestPort, key.Protocol)
		if err != nil {
			log.Printf("[enforcement/network] TC loader delete failed: %v", err)
		}
		return err
	}

	// Fallback: direct BPF map FD
	if ne.bpfMapFD >= 0 {
		// TODO: When cilium/ebpf map operations are implemented:
		//   err := bpfMapDeleteElem(ne.bpfMapFD, &key)
		log.Printf("[enforcement/network] BPF map delete: key={ip=%08x port=%d proto=%d} (fd=%d)",
			key.DestIP, key.DestPort, key.Protocol, ne.bpfMapFD)
	}

	return nil
}

// ── Rule Engine Integration ──────────────────────────────────────────

// BlockFromRule creates a network block from a rule match.
// This is the main entry point called by the response actor when
// a network-related rule (R009, R027, etc.) matches in enforce mode.
//
// Rule mapping:
//   - R009 (Mining Pool Connection): blocks the destination IP:port
//   - R027 (C2 Port Connection): blocks the destination port
//   - R019 (Cloud Metadata SSRF): blocks 169.254.169.254
//   - Custom rules can specify block targets via the match output
func (ne *NetworkEnforcer) BlockFromRule(ruleID string, ip net.IP, port uint16, protocol Protocol, reason string) error {
	// Determine TTL based on rule severity
	ttl := ne.defaultTTL
	switch ruleID {
	case "R009": // Mining pool — longer block
		ttl = 10 * time.Minute
	case "R027": // C2 port — medium block
		ttl = 5 * time.Minute
	case "R019": // Cloud metadata — indefinite block while container runs
		ttl = 30 * time.Minute
	}

	return ne.BlockWithTTL(ip, port, protocol, ruleID, reason, ttl)
}

// BlockMiningPool is a convenience method for blocking mining pool connections (R009).
func (ne *NetworkEnforcer) BlockMiningPool(ip net.IP, port uint16) error {
	return ne.BlockFromRule("R009", ip, port, ProtocolTCP, "mining_pool_connection")
}

// BlockC2Port is a convenience method for blocking C2 port connections (R027).
func (ne *NetworkEnforcer) BlockC2Port(ip net.IP, port uint16) error {
	return ne.BlockFromRule("R027", ip, port, ProtocolTCP, "c2_port_connection")
}

// BlockCloudMetadata is a convenience method for blocking cloud metadata access (R019).
func (ne *NetworkEnforcer) BlockCloudMetadata() error {
	metadataIP := net.ParseIP("169.254.169.254")
	if metadataIP == nil {
		return fmt.Errorf("failed to parse cloud metadata IP")
	}
	return ne.BlockFromRule("R019", metadataIP, 80, ProtocolAny, "cloud_metadata_ssrf")
}

// ── Metrics ──────────────────────────────────────────────────────────

// NetworkEnforcerStats holds statistics about network enforcement.
type NetworkEnforcerStats struct {
	ActiveBlocks int              `json:"active_blocks"`
	TotalAdded   int64            `json:"total_added"`
	TotalExpired int64            `json:"total_expired"`
	TotalRemoved int64            `json:"total_removed"`
	BlocksByRule map[string]int64 `json:"blocks_by_rule"`
}

// Stats returns current network enforcement statistics.
func (ne *NetworkEnforcer) Stats() NetworkEnforcerStats {
	ne.mu.RLock()
	defer ne.mu.RUnlock()

	var total int64
	for _, v := range ne.blocksAdded {
		total += v
	}

	return NetworkEnforcerStats{
		ActiveBlocks: ne.BlockCount(),
		TotalAdded:   total,
		TotalExpired: ne.blocksExpired,
		TotalRemoved: ne.blocksRemoved,
		BlocksByRule: ne.blocksAdded,
	}
}

// ── Helper Functions ──────────────────────────────────────────────────

// IPToUint32 converts a net.IP to a uint32 in host byte order.
// Returns 0 for nil or non-IPv4 addresses.
func IPToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	// net.IP can be 16-byte (IPv6) or 4-byte (IPv4)
	// For IPv4, get the last 4 bytes
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0 // Not IPv4
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
}

// Uint32ToIP converts a uint32 in host byte order to a net.IP.
func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

// totalBlocks sums all rule counters.
func (ne *NetworkEnforcer) totalBlocks() int64 {
	var total int64
	for _, v := range ne.blocksAdded {
		total += v
	}
	return total
}
