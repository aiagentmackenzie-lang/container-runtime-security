// Package escape_scenarios_test validates detection against the 15 container
// escape scenarios from the container-escape-telemetry research project.
// See SRD Section 16.2 for the full test matrix.
package escape_scenarios_test

import (
	"testing"

	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// createTestEngine creates a rule engine for testing.
func createTestEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.EngineConfig{
		RulePaths:   []string{}, // uses built-in default rules
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
		NodeName:            "test-node",
	}
}

// makeBasicEvent creates a minimal ScarletEvent with the given fields.
func makeBasicEvent(category uint8, eventType uint8, comm string) *ebpf.ScarletEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], comm)

	return &ebpf.ScarletEvent{
		PID:        1234,
		TGID:       1234,
		PPID:       100,
		UID:        0,
		GID:        0,
		CgroupID:   12345,
		PIDNSLevel: 1, // container process
		Category:   category,
		EventType:  eventType,
		Comm:       commBytes,
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S01: cgroup release_agent escape
// ═══════════════════════════════════════════════════════════════════════

func TestS01_CgroupReleaseAgent(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: mount(cgroup) then write release_agent
	// Detection: R003 Cgroup Mount
	event := makeBasicEvent(ebpf.CatEscape, ebpf.EvtMount, "exploit")
	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R003 (Cgroup Mount) rule to match, got no match")
	}
	if match.RuleID != "R003" {
		t.Errorf("Expected rule R003, got %s", match.RuleID)
	}
	if match.Action != rules.ActionEnforce {
		t.Errorf("Expected enforce action, got %s", match.Action)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S02: CVE-2022-0492 — unshare + mount cgroup
// ═══════════════════════════════════════════════════════════════════════

func TestS02_CVE2022_0492(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: unshare(CLONE_NEWUSER) then mount cgroup
	// Detection: R002 (unshare) + R003 (mount)
	unshareEvent := makeBasicEvent(ebpf.CatEscape, ebpf.EvtUnshare, "exploit")
	unshareEnriched := createEnrichedEvent(unshareEvent)

	match := engine.Evaluate(unshareEnriched)
	if match == nil {
		t.Fatal("Expected R002 (unshare) rule to match, got no match")
	}
	if match.RuleID != "R002" {
		t.Errorf("Expected rule R002, got %s", match.RuleID)
	}

	mountEvent := makeBasicEvent(ebpf.CatEscape, ebpf.EvtMount, "exploit")
	mountEnriched := createEnrichedEvent(mountEvent)

	match2 := engine.Evaluate(mountEnriched)
	if match2 == nil {
		t.Fatal("Expected R003 (mount) rule to match, got no match")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S03: nsenter host PID namespace
// ═══════════════════════════════════════════════════════════════════════

func TestS03_NsenterHostPID(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: setns() to join host namespace
	// Detection: R001 (setns)
	event := makeBasicEvent(ebpf.CatEscape, ebpf.EvtSetns, "nsenter")
	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R001 (setns) rule to match, got no match")
	}
	if match.RuleID != "R001" {
		t.Errorf("Expected rule R001, got %s", match.RuleID)
	}
	if match.Action != rules.ActionEnforce {
		t.Errorf("Expected enforce action for R001, got %s", match.Action)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S04: docker.sock abuse
// ═══════════════════════════════════════════════════════════════════════

func TestS04_DockerSockAbuse(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: open /var/run/docker.sock from container
	// Detection: R004 (Docker Socket Access)
	event := makeBasicEvent(ebpf.CatFile, ebpf.EvtFileOpen, "docker-cli")
	var pathBytes [ebpf.MaxPathLen]byte
	copy(pathBytes[:], "/var/run/docker.sock")
	event.Payload.File.Path = pathBytes

	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R004 (Docker Socket) or R018/R005 (sensitive file) to match")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S05: /proc/1/root access
// ═══════════════════════════════════════════════════════════════════════

func TestS05_Proc1RootAccess(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: open /proc/1/root from container
	// Detection: R005 (/proc/1 Access)
	event := makeBasicEvent(ebpf.CatFile, ebpf.EvtFileOpen, "exploit")
	var pathBytes [ebpf.MaxPathLen]byte
	copy(pathBytes[:], "/proc/1/root")
	event.Payload.File.Path = pathBytes

	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R005 or R018 rule to match for /proc/1 access")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S06: Baseline (no escape) — should NOT trigger
// ═══════════════════════════════════════════════════════════════════════

func TestS06_BaselineNoEscape(t *testing.T) {
	engine := createTestEngine(t)

	// Normal container process — no escape signals
	event := makeBasicEvent(ebpf.CatProcess, ebpf.EvtExec, "nginx")
	var filename [ebpf.MaxPathLen]byte
	copy(filename[:], "/usr/sbin/nginx")
	event.Payload.Process.Filename = filename

	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	// Normal process execution may still match R013 (drift) or R028
	// but escape-specific rules should NOT match
	if match != nil && (match.RuleID == "R001" || match.RuleID == "R002" ||
		match.RuleID == "R003" || match.RuleID == "R007") {
		t.Errorf("Escape rule %s should not match for normal nginx process", match.RuleID)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S07: CVE-2024-21626 — /proc/self/fd traversal
// ═══════════════════════════════════════════════════════════════════════

func TestS07_CVE2024_21626(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: openat resolving to /proc/self/fd paths
	// Detection: R005 (/proc/self/fd access)
	event := makeBasicEvent(ebpf.CatFile, ebpf.EvtFileOpen, "runc")
	var pathBytes [ebpf.MaxPathLen]byte
	copy(pathBytes[:], "/proc/self/fd/7")
	event.Payload.File.Path = pathBytes

	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R005 or R018 rule to match for /proc/self/fd access")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// S12: CVE-2019-5736 — /proc/self/exe overwrite
// ═══════════════════════════════════════════════════════════════════════

func TestS12_CVE2019_5736(t *testing.T) {
	engine := createTestEngine(t)

	// Attack: write to /proc/self/exe (runc overwrite)
	// Detection: R005 (/proc/self/exe access)
	event := makeBasicEvent(ebpf.CatFile, ebpf.EvtFileOpen, "exploit")
	var pathBytes [ebpf.MaxPathLen]byte
	copy(pathBytes[:], "/proc/self/exe")
	event.Payload.File.Path = pathBytes
	event.Payload.File.Flags = 1 | 2 // O_WRONLY | O_RDWR

	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R005 rule to match for /proc/self/exe write")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// R007: eBPF program load from container
// ═══════════════════════════════════════════════════════════════════════

func TestR007_eBPFLoadFromContainer(t *testing.T) {
	engine := createTestEngine(t)

	event := makeBasicEvent(ebpf.CatEscape, ebpf.EvtBpfLoad, "malicious-tool")
	enriched := createEnrichedEvent(event)

	match := engine.Evaluate(enriched)
	if match == nil {
		t.Fatal("Expected R007 (eBPF Load) rule to match")
	}
	if match.RuleID != "R007" {
		t.Errorf("Expected rule R007, got %s", match.RuleID)
	}
	if match.Action != rules.ActionEnforce {
		t.Errorf("Expected enforce action for R007, got %s", match.Action)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Host process should NOT be detected as container escape
// ═══════════════════════════════════════════════════════════════════════

func TestHostProcessNoFalsePositive(t *testing.T) {
	engine := createTestEngine(t)

	// Host process — PIDNSLevel = 0
	event := makeBasicEvent(ebpf.CatEscape, ebpf.EvtSetns, "systemd")
	event.PIDNSLevel = 0 // host process

	enriched := createEnrichedEvent(event)
	enriched.ContainerAttributed = false // not attributed to a container

	match := engine.Evaluate(enriched)
	// Container rules should not match host processes
	if match != nil && match.RuleID == "R001" {
		t.Error("R001 (setns) should not match host processes")
	}
}
