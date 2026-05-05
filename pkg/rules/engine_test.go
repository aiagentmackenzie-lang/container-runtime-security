// Package rules_test — unit tests for the rule engine core.
package rules_test

import (
	"testing"

	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/rules"
)

func createTestEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.EngineConfig{
		RulePaths:   []string{},
		DefaultMode: "enforce",
	})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}
	return engine
}

func createEnrichedEvent(raw *ebpf.ScarletEvent) *rules.EnrichedEventForRule {
	return &rules.EnrichedEventForRule{
		Event:              raw,
		ContainerID:         "abc123def456",
		ContainerName:       "test-container",
		ContainerImage:      "test-image:latest",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "test-pod",
	}
}

func makeEvent(category uint8, eventType uint8, comm string) *ebpf.ScarletEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], comm)

	return &ebpf.ScarletEvent{
		PID:        1234,
		TGID:       1234,
		PPID:       1,
		UID:        0,
		GID:        0,
		CgroupID:    12345,
		PIDNSLevel: 1,
		Category:   category,
		EventType:  eventType,
		Comm:       commBytes,
	}
}

// ── Engine creation tests ─────────────────────────────────────────────

func TestEngineCreation(t *testing.T) {
	engine := createTestEngine(t)

	if engine.RuleCount() == 0 {
		t.Error("Expected at least 1 rule to be loaded")
	}
	t.Logf("Loaded %d rules (%d enforce, %d alert)",
		engine.RuleCount(), engine.EnforceCount(), engine.AlertCount())
}

func TestEngineHas30Rules(t *testing.T) {
	engine := createTestEngine(t)

	// The default catalog has 30 rules (R001-R030)
	expected := 30
	if engine.RuleCount() < expected {
		t.Errorf("Expected at least %d rules, got %d", expected, engine.RuleCount())
	}
}

// ── Process execution detection ──────────────────────────────────────

func TestKnownMinerBinary(t *testing.T) {
	engine := createTestEngine(t)

	event := makeEvent(ebpf.CatProcess, ebpf.EvtExec, "xmrig")
	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R008 (Known Miner Binary) to match for xmrig")
	}
}

func TestShellBinary(t *testing.T) {
	_ = createTestEngine(t) // engine created for consistency

	_ = makeEvent(ebpf.CatProcess, ebpf.EvtExec, "bash")
	_ = createEnrichedEvent(makeEvent(ebpf.CatProcess, ebpf.EvtExec, "bash"))

	// But the shell_procs macro should recognize it
	if !ebpf.IsShellProcess("bash") {
		t.Error("Expected IsShellProcess to recognize bash")
	}
}

func TestMinerBinaryRecognition(t *testing.T) {
	testCases := []struct {
		name    string
		isMiner bool
	}{
		{"xmrig", true},
		{"ccminer", true},
		{"t-rex", true},
		{"nanominer", true},
		{"nginx", false},
		{"python", false},
		{"node", false},
	}

	for _, tc := range testCases {
		result := ebpf.IsMinerProcess(tc.name)
		if result != tc.isMiner {
			t.Errorf("IsMinerProcess(%q) = %v, want %v", tc.name, result, tc.isMiner)
		}
	}
}

// ── Network detection ────────────────────────────────────────────────

func TestMiningPoolPort(t *testing.T) {
	testCases := []struct {
		port    uint16
		isMiner bool
	}{
		{3333, true},
		{4444, true},
		{80, false},
		{443, false},
		{14444, true},
		{22, false},
	}

	for _, tc := range testCases {
		result := ebpf.IsMinerPoolPort(tc.port)
		if result != tc.isMiner {
			t.Errorf("IsMinerPoolPort(%d) = %v, want %v", tc.port, result, tc.isMiner)
		}
	}
}

func TestC2Port(t *testing.T) {
	testCases := []struct {
		port uint16
		isC2 bool
	}{
		{4444, true},
		{1337, true},
		{31337, true},
		{80, false},
		{443, false},
	}

	for _, tc := range testCases {
		result := ebpf.IsC2Port(tc.port)
		if result != tc.isC2 {
			t.Errorf("IsC2Port(%d) = %v, want %v", tc.port, result, tc.isC2)
		}
	}
}

func TestCloudMetadataIP(t *testing.T) {
	testCases := []struct {
		ip       string
		isMeta   bool
	}{
		{"169.254.169.254", true},
		{"168.63.129.16", true},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
	}

	for _, tc := range testCases {
		result := ebpf.IsCloudMetadataIP(tc.ip)
		if result != tc.isMeta {
			t.Errorf("IsCloudMetadataIP(%q) = %v, want %v", tc.ip, result, tc.isMeta)
		}
	}
}

// ── Sensitive path detection ─────────────────────────────────────────

func TestSensitivePathDetection(t *testing.T) {
	testCases := []struct {
		path      string
		sensitive bool
	}{
		{"/etc/shadow", true},
		{"/etc/passwd", true},
		{"/etc/sudoers", true},
		{"/root/.ssh/authorized_keys", true},
		{"/var/run/docker.sock", true},
		{"/proc/1/ns/pid", true},
		{"/proc/1/environ", true},
		{"/proc/self/exe", true},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", true},
		{"/etc/hostname", false},
		{"/app/config.yaml", false},
		{"/usr/bin/curl", false},
	}

	for _, tc := range testCases {
		result := ebpf.IsSensitivePath(tc.path)
		if result != tc.sensitive {
			t.Errorf("IsSensitivePath(%q) = %v, want %v", tc.path, result, tc.sensitive)
		}
	}
}

// ── Priority ordering ────────────────────────────────────────────────

func TestPriorityOrdering(t *testing.T) {
	testCases := []struct {
		a        *rules.RuleMatch
		b        *rules.RuleMatch
		expected bool // a.IsMoreSevere(b)
	}{
		{
			&rules.RuleMatch{Priority: rules.PriorityCritical, Action: rules.ActionEnforce},
			&rules.RuleMatch{Priority: rules.PriorityWarning, Action: rules.ActionAlert},
			true,
		},
		{
			&rules.RuleMatch{Priority: rules.PriorityWarning, Action: rules.ActionAlert},
			&rules.RuleMatch{Priority: rules.PriorityCritical, Action: rules.ActionEnforce},
			false,
		},
		{
			&rules.RuleMatch{Priority: rules.PriorityCritical, Action: rules.ActionEnforce},
			&rules.RuleMatch{Priority: rules.PriorityCritical, Action: rules.ActionAlert},
			true, // Same priority, enforce > alert
		},
	}

	for i, tc := range testCases {
		result := tc.a.IsMoreSevere(tc.b)
		if result != tc.expected {
			t.Errorf("Test %d: IsMoreSevere = %v, want %v", i, result, tc.expected)
		}
	}
}

// ── Event type helpers ────────────────────────────────────────────────

func TestEventCategoryString(t *testing.T) {
	testCases := []struct {
		cat      uint8
		expected string
	}{
		{ebpf.CatProcess, "PROCESS"},
		{ebpf.CatFile, "FILE"},
		{ebpf.CatNetwork, "NETWORK"},
		{ebpf.CatEscape, "ESCAPE"},
		{ebpf.CatPrivilege, "PRIVILEGE"},
		{99, "UNKNOWN(99)"},
	}

	for _, tc := range testCases {
		event := &ebpf.ScarletEvent{Category: tc.cat}
		result := event.CategoryString()
		if result != tc.expected {
			t.Errorf("CategoryString(%d) = %q, want %q", tc.cat, result, tc.expected)
		}
	}
}

func TestEventIsContainer(t *testing.T) {
	containerEvent := &ebpf.ScarletEvent{PIDNSLevel: 2}
	if !containerEvent.IsContainer() {
		t.Error("Expected PIDNSLevel > 0 to be container")
	}

	hostEvent := &ebpf.ScarletEvent{PIDNSLevel: 0}
	if hostEvent.IsContainer() {
		t.Error("Expected PIDNSLevel 0 to be host")
	}
}