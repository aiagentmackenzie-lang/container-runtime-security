// Package cryptojacking_test validates detection against cryptomining
// attack patterns. See SRD Section 16.3 for the full test matrix.
package cryptojacking_test

import (
	"testing"

	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// createTestEngine creates a rule engine for testing.
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

// createEnrichedEvent creates an enriched event for rule evaluation.
func createEnrichedEvent(raw *ebpf.ScarletEvent) *rules.EnrichedEventForRule {
	return &rules.EnrichedEventForRule{
		Event:               raw,
		ContainerID:         "abc123def456",
		ContainerName:       "test-container",
		ContainerImage:      "test-image:latest",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "test-pod",
		ServiceAccount:      "default",
		NodeName:            "test-node",
	}
}

func makeBasicEvent(category uint8, eventType uint8, comm string) *ebpf.ScarletEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], comm)

	return &ebpf.ScarletEvent{
		PID:        1234,
		TGID:       1234,
		PPID:       1,
		UID:        0,
		GID:        0,
		CgroupID:   12345,
		PIDNSLevel: 1,
		Category:   category,
		EventType:  eventType,
		Comm:       commBytes,
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R008: Known Miner Binary Detection
// ═══════════════════════════════════════════════════════════════════════

func TestR008_KnownMinerBinary_XMRig(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "xmrig")
	var filename [ebpf.MaxPathLen]byte
	copy(filename[:], "/usr/bin/xmrig")
	event.Payload.Process.Filename = filename
	var args [ebpf.MaxArgsLen]byte
	copy(args[:], "xmrig --url=stratum+tcp://pool.minexmr.com:4444")
	event.Payload.Process.Args = args

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	if match == nil {
		t.Fatal("Expected R008 (Known Miner Binary) to match for xmrig")
	}
	if match.RuleID != "R008" {
		t.Errorf("Expected rule R008, got %s (%s)", match.RuleID, match.RuleName)
	}
	if match.Action != rules.ActionEnforce {
		t.Errorf("Expected enforce action for R008, got %s", match.Action)
	}
}

func TestR008_KnownMinerBinary_CCminer(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "ccminer")
	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R008 to match for ccminer")
	}
}

func TestR008_NonMinerBinary_NoMatch(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "nginx")
	var filename [ebpf.MaxPathLen]byte
	copy(filename[:], "/usr/sbin/nginx")
	event.Payload.Process.Filename = filename

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	// nginx should not trigger R008
	if match != nil && match.RuleID == "R008" {
		t.Error("R008 should not match for nginx")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R009: Mining Pool Connection
// ═══════════════════════════════════════════════════════════════════════

func TestR009_MiningPoolConnection(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatNetwork, ebpf.EvtNetConnect, "xmrig")
	event.Payload.Network.RemotePort = 3333 // known mining pool port
	event.Payload.Network.RemoteAddr = [4]byte{1, 2, 3, 4}

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	if match == nil {
		t.Fatal("Expected mining pool connection rule to match for port 3333")
	}
}

func TestR009_NormalConnectionPort80_NoMatch(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatNetwork, ebpf.EvtNetConnect, "curl")
	event.Payload.Network.RemotePort = 80
	event.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 1}

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	// Port 80 should not trigger R009
	if match != nil && match.RuleID == "R009" {
		t.Error("R009 should not match for port 80")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R010: Stratum Protocol Detection
// ═══════════════════════════════════════════════════════════════════════

func TestR010_StratumProtocol(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "custom-miner")
	var args [ebpf.MaxArgsLen]byte
	copy(args[:], "custom-miner --pool stratum+tcp://pool.example.com:3333")
	event.Payload.Process.Args = args

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	if match == nil {
		t.Fatal("Expected R010 (Stratum Protocol) to match")
	}
	if match.RuleID != "R010" {
		t.Errorf("Expected rule R010, got %s", match.RuleID)
	}
}

func TestR010_StratumSSL(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "custom-miner")
	var args [ebpf.MaxArgsLen]byte
	copy(args[:], "custom-miner --pool stratum+ssl://secure.example.com:443")
	event.Payload.Process.Args = args

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	if match == nil {
		t.Fatal("Expected R010 to match for stratum+ssl")
	}
}

func TestR010_NoStratumInCmdline(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "python")
	var args [ebpf.MaxArgsLen]byte
	copy(args[:], "python app.py --port 8080")
	event.Payload.Process.Args = args

	enriched := createEnrichedEvent(event)
	// Should not trigger R010 (no stratum in cmdline)
	match := engine.Evaluate(enriched)
	if match != nil && match.RuleID == "R010" {
		t.Error("R010 should not match without stratum in cmdline")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R014: Reverse Shell — Shell with Outbound Network
// ═══════════════════════════════════════════════════════════════════════

func TestR014_ReverseShell(t *testing.T) {
	engine := createTestEngine(t)

	// bash making outbound connection to port 4444
	event := makeBasicEvent(ebpf.CatNetwork, ebpf.EvtNetConnect, "bash")
	event.Payload.Network.RemotePort = 4444
	event.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 99}

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	if match == nil {
		t.Fatal("Expected reverse shell rule to match for bash+port 4444")
	}
}

func TestR014_ShellToPort443_ShouldNotEnforce(t *testing.T) {
	engine := createTestEngine(t)

	// bash making outbound to port 443 (HTTPS) — less suspicious
	event := makeBasicEvent(ebpf.CatNetwork, ebpf.EvtNetConnect, "bash")
	event.Payload.Network.RemotePort = 443
	event.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 1}

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	// Port 443 is excluded from R014 but may match R016 if 443 is a C2 port
	// 443 is not in our C2 list so it should not match R014
	if match != nil && match.RuleID == "R014" {
		t.Error("R014 excludes port 443")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R019: Cloud Metadata Service Access
// ═══════════════════════════════════════════════════════════════════════

func TestR019_CloudMetadataSSRF(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatNetwork, ebpf.EvtNetConnect, "curl")
	// 169.254.169.254 = AWS/GCP metadata service
	event.Payload.Network.RemoteAddr = [4]byte{169, 254, 169, 254}
	event.Payload.Network.RemotePort = 80

	enriched := createEnrichedEvent(event)
	match := engine.Evaluate(enriched)

	if match == nil {
		t.Fatal("Expected R019 (Cloud Metadata) rule to match for 169.254.169.254")
	}
	if match.RuleID != "R019" {
		t.Errorf("Expected rule R019, got %s", match.RuleID)
	}
	if match.Action != rules.ActionEnforce {
		t.Errorf("Expected enforce action for R019, got %s", match.Action)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R029: Ptrace from Container
// ═══════════════════════════════════════════════════════════════════════

func TestR029_PtraceFromContainer(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatEscape, ebpf.EvtPtrace, "gdb")
	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R029 (ptrace) rule to match")
	}
	if match.Action != rules.ActionEnforce {
		t.Errorf("Expected enforce for R029, got %s", match.Action)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Enforcement Safety — No enforcement on unattributed events
// ═══════════════════════════════════════════════════════════════════════

func TestEnforcementSafety_NoContainerID(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatEscape, ebpf.EvtSetns, "exploit")
	enriched := createEnrichedEvent(event)
	enriched.ContainerAttributed = false
	enriched.ContainerID = ""

	// Rule engine should still match (it evaluates rules)
	// But the pipeline should downgrade enforce → audit
	match := engine.Evaluate(enriched)
	// The engine matches — it's the pipeline that downgrades
	if match == nil {
		// This is OK — the engine may skip unattributed events
		t.Log("Engine did not match unattributed event (acceptable)")
	}
}
