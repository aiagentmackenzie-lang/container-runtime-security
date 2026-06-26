// Package enforcement_test — unit tests for network policy enforcement.
package enforcement_test

import (
	"net"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/enforcement"
)

// ── Network Enforcer Creation Tests ────────────────────────────────────

func TestNewNetworkEnforcer(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	if ne == nil {
		t.Fatal("Expected non-nil NetworkEnforcer")
	}
	if ne.BlockCount() != 0 {
		t.Error("New enforcer should have 0 blocks")
	}
}

func TestNetworkEnforcer_SetInterface(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	ne.SetInterface("eth1")
	// Just verify it doesn't panic
}

func TestNetworkEnforcer_SetDefaultTTL(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	ne.SetDefaultTTL(10 * time.Minute)
	// Just verify it doesn't panic
}

// ── Block Operations Tests ────────────────────────────────────────────

func TestNetworkEnforcer_Block(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	ne.SetDefaultTTL(5 * time.Minute)

	ip := net.ParseIP("192.168.1.100")
	err := ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")
	if err != nil {
		t.Fatalf("Failed to block: %v", err)
	}

	if ne.BlockCount() != 1 {
		t.Errorf("Expected 1 block, got %d", ne.BlockCount())
	}
}

func TestNetworkEnforcer_BlockWithTTL(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("10.0.0.1")
	err := ne.BlockWithTTL(ip, 3333, enforcement.ProtocolTCP, "R009", "mining_pool", 10*time.Minute)
	if err != nil {
		t.Fatalf("Failed to block: %v", err)
	}

	if ne.BlockCount() != 1 {
		t.Errorf("Expected 1 block, got %d", ne.BlockCount())
	}

	blocks := ne.ListBlocks()
	if len(blocks) != 1 {
		t.Fatalf("Expected 1 block in list, got %d", len(blocks))
	}

	if blocks[0].RuleID != "R009" {
		t.Errorf("Expected rule R009, got %s", blocks[0].RuleID)
	}
	if blocks[0].Reason != "mining_pool" {
		t.Errorf("Expected reason 'mining_pool', got %s", blocks[0].Reason)
	}
}

func TestNetworkEnforcer_BlockMultiple(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ips := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		net.ParseIP("192.168.1.3"),
	}
	ports := []uint16{4444, 3333, 8080}

	for i, ip := range ips {
		err := ne.Block(ip, ports[i], enforcement.ProtocolTCP, "R027", "c2_port")
		if err != nil {
			t.Fatalf("Failed to block %s:%d: %v", ip, ports[i], err)
		}
	}

	if ne.BlockCount() != 3 {
		t.Errorf("Expected 3 blocks, got %d", ne.BlockCount())
	}
}

// ── Block Check Tests ──────────────────────────────────────────────────

func TestNetworkEnforcer_IsBlocked_Exact(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("192.168.1.100")
	ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")

	if !ne.IsBlocked(ip, 4444, enforcement.ProtocolTCP) {
		t.Error("Expected IP:4444/TCP to be blocked")
	}
}

func TestNetworkEnforcer_IsBlocked_DifferentProtocol(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("192.168.1.100")
	ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")

	// Same IP:port, different protocol — should NOT be blocked (exact match)
	if ne.IsBlocked(ip, 4444, enforcement.ProtocolUDP) {
		t.Error("UDP should not match a TCP-only block")
	}
}

func TestNetworkEnforcer_IsBlocked_DifferentPort(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("192.168.1.100")
	ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")

	// Same IP, different port — should NOT be blocked
	if ne.IsBlocked(ip, 8080, enforcement.ProtocolTCP) {
		t.Error("Different port should not be blocked")
	}
}

func TestNetworkEnforcer_IsBlocked_AnyProtocol(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("192.168.1.100")
	// Block port 4444 on any IP, any protocol
	ne.Block(net.IPv4(0, 0, 0, 0), 4444, enforcement.ProtocolAny, "R027", "c2_port_any")

	// Should match on same port, any IP, any protocol
	if !ne.IsBlocked(ip, 4444, enforcement.ProtocolTCP) {
		t.Error("Port 4444 should be blocked on any IP")
	}
}

func TestNetworkEnforcer_IsBlocked_IPOnly(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("169.254.169.254")
	// Block all traffic to cloud metadata IP
	ne.Block(ip, 0, enforcement.ProtocolAny, "R019", "cloud_metadata")

	// Any port/protocol to this IP should be blocked
	if !ne.IsBlocked(ip, 80, enforcement.ProtocolTCP) {
		t.Error("Port 80 to cloud metadata should be blocked")
	}
	if !ne.IsBlocked(ip, 443, enforcement.ProtocolTCP) {
		t.Error("Port 443 to cloud metadata should be blocked")
	}
}

// ── Unblock Tests ──────────────────────────────────────────────────────

func TestNetworkEnforcer_Unblock(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("192.168.1.100")
	ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")

	if ne.BlockCount() != 1 {
		t.Errorf("Expected 1 block, got %d", ne.BlockCount())
	}

	err := ne.Unblock(ip, 4444, enforcement.ProtocolTCP)
	if err != nil {
		t.Fatalf("Failed to unblock: %v", err)
	}

	if ne.BlockCount() != 0 {
		t.Errorf("Expected 0 blocks after unblock, got %d", ne.BlockCount())
	}

	if ne.IsBlocked(ip, 4444, enforcement.ProtocolTCP) {
		t.Error("IP:4444/TCP should not be blocked after unblock")
	}
}

// ── Expiry Tests ──────────────────────────────────────────────────────

func TestNetworkEnforcer_Expiry(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	ne.SetDefaultTTL(100 * time.Millisecond)

	ip := net.ParseIP("192.168.1.100")
	ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")

	if ne.BlockCount() != 1 {
		t.Errorf("Expected 1 block before expiry, got %d", ne.BlockCount())
	}

	// Wait for TTL to expire
	time.Sleep(200 * time.Millisecond)

	// The block should still be in the map (not yet cleaned up by the expiry goroutine)
	// but IsBlocked should check the expiration time
	if ne.IsBlocked(ip, 4444, enforcement.ProtocolTCP) {
		t.Error("Block should have expired")
	}
}

// ── Convenience Method Tests ──────────────────────────────────────────

func TestNetworkEnforcer_BlockMiningPool(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("pool.minexmr.com")
	if ip != nil {
		// This hostname won't resolve in tests, use a direct IP
		t.Skip("Hostname resolution not available in test")
	}

	// Use a direct IP instead
	ip = net.ParseIP("45.77.1.138")
	err := ne.BlockMiningPool(ip, 3333)
	if err != nil {
		t.Fatalf("Failed to block mining pool: %v", err)
	}

	if !ne.IsBlocked(ip, 3333, enforcement.ProtocolTCP) {
		t.Error("Mining pool should be blocked")
	}

	blocks := ne.ListBlocks()
	if len(blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(blocks))
	}
	if blocks[0].RuleID != "R009" {
		t.Errorf("Expected rule R009, got %s", blocks[0].RuleID)
	}
}

func TestNetworkEnforcer_BlockC2Port(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("10.0.0.5")
	err := ne.BlockC2Port(ip, 4444)
	if err != nil {
		t.Fatalf("Failed to block C2 port: %v", err)
	}

	if !ne.IsBlocked(ip, 4444, enforcement.ProtocolTCP) {
		t.Error("C2 port should be blocked")
	}

	blocks := ne.ListBlocks()
	if blocks[0].RuleID != "R027" {
		t.Errorf("Expected rule R027, got %s", blocks[0].RuleID)
	}
}

func TestNetworkEnforcer_BlockCloudMetadata(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	err := ne.BlockCloudMetadata()
	if err != nil {
		t.Fatalf("Failed to block cloud metadata: %v", err)
	}

	metadataIP := net.ParseIP("169.254.169.254")
	if !ne.IsBlocked(metadataIP, 80, enforcement.ProtocolAny) {
		t.Error("Cloud metadata IP should be blocked")
	}

	blocks := ne.ListBlocks()
	if blocks[0].RuleID != "R019" {
		t.Errorf("Expected rule R019, got %s", blocks[0].RuleID)
	}
}

// ── Stats Tests ────────────────────────────────────────────────────────

func TestNetworkEnforcer_Stats(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	ne.Block(ip1, 4444, enforcement.ProtocolTCP, "R027", "c2")
	ne.Block(ip2, 3333, enforcement.ProtocolTCP, "R009", "mining")

	stats := ne.Stats()
	if stats.ActiveBlocks != 2 {
		t.Errorf("Expected 2 active blocks, got %d", stats.ActiveBlocks)
	}
	if stats.BlocksByRule["R027"] != 1 {
		t.Errorf("Expected 1 R027 block, got %d", stats.BlocksByRule["R027"])
	}
	if stats.BlocksByRule["R009"] != 1 {
		t.Errorf("Expected 1 R009 block, got %d", stats.BlocksByRule["R009"])
	}
}

func TestNetworkEnforcer_BlocksByRule(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("10.0.0.1")
	ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2")
	ne.Block(ip, 3333, enforcement.ProtocolTCP, "R009", "mining")
	ne.Block(ip, 8080, enforcement.ProtocolTCP, "R027", "c2_2")

	byRule := ne.BlocksByRule()
	if byRule["R027"] != 2 {
		t.Errorf("Expected 2 R027 blocks, got %d", byRule["R027"])
	}
	if byRule["R009"] != 1 {
		t.Errorf("Expected 1 R009 block, got %d", byRule["R009"])
	}
}

// ── Protocol String Test ────────────────────────────────────────────────

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		proto    enforcement.Protocol
		expected string
	}{
		{enforcement.ProtocolTCP, "TCP"},
		{enforcement.ProtocolUDP, "UDP"},
		{enforcement.ProtocolAny, "ANY"},
		{enforcement.Protocol(99), "UNKNOWN(99)"},
	}

	for _, tc := range tests {
		result := tc.proto.String()
		if result != tc.expected {
			t.Errorf("Protocol(%d).String() = %s, want %s", tc.proto, result, tc.expected)
		}
	}
}

// ── IP Conversion Tests ────────────────────────────────────────────────

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"192.168.1.1", 0xC0A80101},
		{"10.0.0.1", 0x0A000001},
		{"169.254.169.254", 0xA9FEA9FE},
		{"0.0.0.0", 0x00000000},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := enforcement.IPToUint32(ip)
		if result != tc.expected {
			t.Errorf("ipToUint32(%s) = 0x%08X, want 0x%08X", tc.ip, result, tc.expected)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		n        uint32
		expected string
	}{
		{0xC0A80101, "192.168.1.1"},
		{0x0A000001, "10.0.0.1"},
		{0xA9FEA9FE, "169.254.169.254"},
		{0x00000000, "0.0.0.0"},
	}

	for _, tc := range tests {
		ip := enforcement.Uint32ToIP(tc.n)
		if ip.String() != tc.expected {
			t.Errorf("uint32ToIP(0x%08X) = %s, want %s", tc.n, ip.String(), tc.expected)
		}
	}
}

func TestIPToUint32_RoundTrip(t *testing.T) {
	ips := []string{
		"192.168.1.1",
		"10.0.0.1",
		"169.254.169.254",
		"255.255.255.255",
		"0.0.0.0",
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		n := enforcement.IPToUint32(ip)
		recovered := enforcement.Uint32ToIP(n)
		if !recovered.Equal(ip) {
			t.Errorf("Round trip failed: %s → 0x%08X → %s", ipStr, n, recovered.String())
		}
	}
}

// ── Blocklist Entry Tests ──────────────────────────────────────────────

func TestBlocklistEntry_Fields(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	ip := net.ParseIP("45.77.1.138")
	ne.BlockWithTTL(ip, 3333, enforcement.ProtocolTCP, "R009", "mining_pool", 10*time.Minute)

	blocks := ne.ListBlocks()
	if len(blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(blocks))
	}

	entry := blocks[0]
	if !entry.DestIP.Equal(ip) {
		t.Errorf("Expected IP %s, got %s", ip, entry.DestIP)
	}
	if entry.DestPort != 3333 {
		t.Errorf("Expected port 3333, got %d", entry.DestPort)
	}
	if entry.Protocol != enforcement.ProtocolTCP {
		t.Errorf("Expected TCP protocol, got %d", entry.Protocol)
	}
	if entry.RuleID != "R009" {
		t.Errorf("Expected rule R009, got %s", entry.RuleID)
	}
	if entry.Reason != "mining_pool" {
		t.Errorf("Expected reason 'mining_pool', got %s", entry.Reason)
	}
	if entry.TTL != 10*time.Minute {
		t.Errorf("Expected TTL 10m, got %v", entry.TTL)
	}
}

// ── TC Loader Integration Tests ─────────────────────────────────────────

// mockTCLoader is a test implementation of BlocklistUpdater that records calls.
type mockTCLoader struct {
	updates []mockBPFUpdate
	deletes []mockBPFDelete
}

type mockBPFUpdate struct {
	ip       uint32
	port     uint16
	protocol uint8
	action   uint8
}

type mockBPFDelete struct {
	ip       uint32
	port     uint16
	protocol uint8
}

func (m *mockTCLoader) UpdateBlocklistEntry(ip uint32, port uint16, protocol uint8, action uint8) error {
	m.updates = append(m.updates, mockBPFUpdate{ip: ip, port: port, protocol: protocol, action: action})
	return nil
}

func (m *mockTCLoader) DeleteBlocklistEntry(ip uint32, port uint16, protocol uint8) error {
	m.deletes = append(m.deletes, mockBPFDelete{ip: ip, port: port, protocol: protocol})
	return nil
}

func TestNetworkEnforcer_SetTCLoader(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	mock := &mockTCLoader{}

	ne.SetTCLoader(mock)

	// Block an IP through the enforcer
	ip := net.ParseIP("192.168.1.100")
	err := ne.Block(ip, 4444, enforcement.ProtocolTCP, "R027", "c2_port")
	if err != nil {
		t.Fatalf("Failed to block: %v", err)
	}

	// Verify the mock TC loader received the update
	if len(mock.updates) != 1 {
		t.Fatalf("Expected 1 TC loader update, got %d", len(mock.updates))
	}
	update := mock.updates[0]
	expectedIP := enforcement.IPToUint32(ip)
	if update.ip != expectedIP {
		t.Errorf("Expected IP 0x%08x, got 0x%08x", expectedIP, update.ip)
	}
	if update.port != 4444 {
		t.Errorf("Expected port 4444, got %d", update.port)
	}
	if update.protocol != uint8(enforcement.ProtocolTCP) {
		t.Errorf("Expected protocol TCP(%d), got %d", enforcement.ProtocolTCP, update.protocol)
	}
	if update.action != 1 {
		t.Errorf("Expected action 1 (block), got %d", update.action)
	}
}

func TestNetworkEnforcer_TCLoaderBlockAndUnblock(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	mock := &mockTCLoader{}
	ne.SetTCLoader(mock)

	ip := net.ParseIP("1.2.3.4")

	// Block
	err := ne.Block(ip, 3333, enforcement.ProtocolTCP, "R009", "mining_pool")
	if err != nil {
		t.Fatalf("Block failed: %v", err)
	}
	if len(mock.updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(mock.updates))
	}

	// Unblock
	err = ne.Unblock(ip, 3333, enforcement.ProtocolTCP)
	if err != nil {
		t.Fatalf("Unblock failed: %v", err)
	}
	if len(mock.deletes) != 1 {
		t.Fatalf("Expected 1 delete, got %d", len(mock.deletes))
	}
	delete := mock.deletes[0]
	expectedIP := enforcement.IPToUint32(ip)
	if delete.ip != expectedIP {
		t.Errorf("Expected delete IP 0x%08x, got 0x%08x", expectedIP, delete.ip)
	}
	if delete.port != 3333 {
		t.Errorf("Expected delete port 3333, got %d", delete.port)
	}
}

func TestNetworkEnforcer_TCLoaderBlockFromRule(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	mock := &mockTCLoader{}
	ne.SetTCLoader(mock)

	ip := net.ParseIP("169.254.169.254")

	// Block cloud metadata via R019
	err := ne.BlockFromRule("R019", ip, 80, enforcement.ProtocolAny, "cloud_metadata_ssrf")
	if err != nil {
		t.Fatalf("BlockFromRule failed: %v", err)
	}

	if len(mock.updates) != 1 {
		t.Fatalf("Expected 1 TC loader update, got %d", len(mock.updates))
	}

	update := mock.updates[0]
	expectedIP := enforcement.IPToUint32(ip)
	if update.ip != expectedIP {
		t.Errorf("Expected IP 0x%08x, got 0x%08x", expectedIP, update.ip)
	}
}

func TestNetworkEnforcer_TCLoaderBlockMiningPool(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	mock := &mockTCLoader{}
	ne.SetTCLoader(mock)

	ip := net.ParseIP("45.77.1.138")

	err := ne.BlockMiningPool(ip, 3333)
	if err != nil {
		t.Fatalf("BlockMiningPool failed: %v", err)
	}

	if len(mock.updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(mock.updates))
	}

	// Verify the right rule ID in stats
	stats := ne.Stats()
	if stats.BlocksByRule["R009"] != 1 {
		t.Errorf("Expected 1 block for R009, got %d", stats.BlocksByRule["R009"])
	}
}

func TestNetworkEnforcer_TCLoaderBlockC2Port(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	mock := &mockTCLoader{}
	ne.SetTCLoader(mock)

	ip := net.ParseIP("10.0.0.1")

	err := ne.BlockC2Port(ip, 4444)
	if err != nil {
		t.Fatalf("BlockC2Port failed: %v", err)
	}

	if len(mock.updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(mock.updates))
	}

	stats := ne.Stats()
	if stats.BlocksByRule["R027"] != 1 {
		t.Errorf("Expected 1 block for R027, got %d", stats.BlocksByRule["R027"])
	}
}

func TestNetworkEnforcer_NoTCLoader_NoErrors(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	// Block without a TC loader — should not error
	ip := net.ParseIP("1.2.3.4")
	err := ne.Block(ip, 3333, enforcement.ProtocolTCP, "R009", "mining_pool")
	if err != nil {
		t.Fatalf("Block without TC loader should not error: %v", err)
	}

	if ne.BlockCount() != 1 {
		t.Errorf("Expected 1 block, got %d", ne.BlockCount())
	}
}

func TestNetworkEnforcer_BlocklistUpdaterInterface(t *testing.T) {
	// Verify the BlocklistUpdater interface is satisfied by mockTCLoader
	var _ enforcement.BlocklistUpdater = &mockTCLoader{}
}
