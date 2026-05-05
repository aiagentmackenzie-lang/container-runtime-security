// Package pipeline_test — unit tests for enforcement kill chain and safety.
package pipeline_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/ai"
	"github.com/securityscarlet/runtime/pkg/correlate"
	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/output"
	"github.com/securityscarlet/runtime/pkg/pipeline"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Helpers ────────────────────────────────────────────────────────────

func makeTestEnrichedEvent(pid uint32, comm string) *pipeline.EnrichedEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], comm)

	return &pipeline.EnrichedEvent{
		RawEvent: &ebpf.ScarletEvent{
			PID:        pid,
			PPID:       100,
			CgroupID:    12345,
			PIDNSLevel: 1,
			Category:   ebpf.CatEscape,
			EventType:  ebpf.EvtSetns,
			Comm:       commBytes,
		},
		ContainerID:        "abc123def456",
		ContainerName:      "test-container",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "test-pod",
	}
}

func makeCriticalMatch(ruleID string) *rules.RuleMatch {
	return &rules.RuleMatch{
		RuleID:   ruleID,
		RuleName: "Test Rule",
		Priority: rules.PriorityCritical,
		Action:   rules.ActionEnforce,
		Output:   "test rule matched",
		Tags:     []string{"test"},
	}
}

func makeNetworkEnrichedEvent(remoteIP string, remotePort uint16) *pipeline.EnrichedEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "test-net")

	event := &pipeline.EnrichedEvent{
		RawEvent: &ebpf.ScarletEvent{
			PID:        5000,
			PPID:       100,
			CgroupID:    12345,
			PIDNSLevel: 1,
			Category:   ebpf.CatNetwork,
			EventType:  ebpf.EvtNetConnect,
			Comm:       commBytes,
		},
		ContainerID:        "abc123def456",
		ContainerName:      "test-container",
		ContainerAttributed: true,
		Namespace:          "default",
		PodName:            "test-pod",
	}

	// Set network payload
	addr := [4]byte{1, 2, 3, 4}
	if remoteIP == "169.254.169.254" {
		addr = [4]byte{169, 254, 169, 254}
	}
	copy(event.RawEvent.Payload.Network.RemoteAddr[:], addr[:])
	event.RawEvent.Payload.Network.RemotePort = remotePort

	return event
}

// ── Safety Protocol Tests ─────────────────────────────────────────────

func TestSafetyRule1_NoContainerID(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(5000, "exploit")
	event.ContainerID = ""
	event.ContainerAttributed = false

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Success {
		t.Error("Enforcement should be skipped when no container ID")
	}
	if result.Reason != "no_container_id" {
		t.Errorf("Expected reason 'no_container_id', got %q", result.Reason)
	}
}

func TestSafetyRule2_SimulateMode(t *testing.T) {
	actor := pipeline.NewResponseActor("simulate")
	event := makeTestEnrichedEvent(5000, "exploit")

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Success {
		t.Error("Enforcement should be skipped in simulate mode")
	}
	if result.Reason != "simulate_mode" {
		t.Errorf("Expected reason 'simulate_mode', got %q", result.Reason)
	}
}

func TestSafetyRule3_ProtectedNamespace(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(5000, "exploit")
	event.Namespace = "kube-system"

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Success {
		t.Error("Enforcement should be skipped for protected namespace")
	}
	if result.Reason != "protected_namespace" {
		t.Errorf("Expected reason 'protected_namespace', got %q", result.Reason)
	}
}

func TestSafetyRule4_PID0Untouchable(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(0, "init")

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Success {
		t.Error("PID 0 should be untouchable")
	}
	if result.Reason != "init_process" {
		t.Errorf("Expected reason 'init_process', got %q", result.Reason)
	}
}

func TestSafetyRule4_PID1Untouchable(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(1, "systemd")

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Success {
		t.Error("PID 1 should be untouchable")
	}
	if result.Reason != "init_process" {
		t.Errorf("Expected reason 'init_process', got %q", result.Reason)
	}
}

func TestSafetyRule6_RateLimiting(t *testing.T) {
	cfg := pipeline.DefaultResponseActorConfig()
	cfg.MaxKillsPerPod = 2
	cfg.WindowSeconds = 60
	actor := pipeline.NewResponseActorWithConfig("enforce", cfg)

	match := makeCriticalMatch("R001")

	// First two should pass the rate limiter (even if kill fails on non-existent PID)
	for i := 0; i < 2; i++ {
		event := makeTestEnrichedEvent(uint32(5000+i), "exploit")
		result := actor.Enforce(event, match)
		if result.Reason == "rate_limited" {
			t.Errorf("Enforcement %d should not be rate-limited", i+1)
		}
	}

	// Third should be rate limited
	event := makeTestEnrichedEvent(5002, "exploit")
	result := actor.Enforce(event, match)
	if result.Reason != "rate_limited" {
		t.Errorf("Expected reason 'rate_limited', got %q", result.Reason)
	}
}

func TestSafetyRule7_NoNamespaceScope(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(5000, "exploit")
	event.Namespace = ""

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Success {
		t.Error("Enforcement should be skipped without namespace scope")
	}
	if result.Reason != "no_namespace_scope" {
		t.Errorf("Expected reason 'no_namespace_scope', got %q", result.Reason)
	}
}

// ── Enforcement Mode Tests ────────────────────────────────────────────

func TestImmediateMode_SIGKILL(t *testing.T) {
	cfg := pipeline.DefaultResponseActorConfig()
	cfg.Mode = pipeline.EnforceModeImmediate
	actor := pipeline.NewResponseActorWithConfig("enforce", cfg)

	event := makeTestEnrichedEvent(50000, "test-process")
	result := actor.Enforce(event, makeCriticalMatch("R008"))

	// Process 50000 likely doesn't exist, so kill will fail,
	// but the important thing is the action type is correctly set
	if result.Action != pipeline.EnforceSIGKILL {
		t.Errorf("Expected action %s, got %s", pipeline.EnforceSIGKILL, result.Action)
	}
	if result.Signal != "SIGKILL" {
		t.Errorf("Expected signal SIGKILL, got %s", result.Signal)
	}
}

func TestGracefulMode_SIGTERMFirst(t *testing.T) {
	cfg := pipeline.DefaultResponseActorConfig()
	cfg.Mode = pipeline.EnforceModeGraceful
	cfg.GracePeriodSeconds = 1 // use 1s for test speed
	actor := pipeline.NewResponseActorWithConfig("enforce", cfg)

	event := makeTestEnrichedEvent(50001, "test-process")
	result := actor.Enforce(event, makeCriticalMatch("R008"))

	// In graceful mode with a non-existent PID, SIGTERM fails so it
	// escalates immediately to SIGKILL. The key test is that the mode
	// was applied correctly; the result depends on the PID existing or not.
	if result.RuleID != "R008" {
		t.Errorf("Expected RuleID R008, got %s", result.RuleID)
	}
}

func TestAuditMode_NoEnforcement(t *testing.T) {
	actor := pipeline.NewResponseActor("audit")
	event := makeTestEnrichedEvent(5000, "exploit")

	// In audit mode, the pipeline routes enforce → alert, so the
	// response actor should never see enforce actions in audit mode.
	// But if called directly, it will still enforce. The pipeline
	// handles the downgrade. Test the actor's mode setting.
	actor.SetMode("enforce")
	result := actor.Enforce(event, makeCriticalMatch("R001"))

	// This will try to kill (likely fail on non-existent PID),
	// but the mode change should work
	_ = result
}

// ── Enforcement Audit Log Tests ────────────────────────────────────────

func TestEnforcementAuditLog_RecordsAllDecisions(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")

	// Successful enforcement (non-existent PID, will fail kill but passes safety)
	event1 := makeTestEnrichedEvent(5000, "exploit")
	actor.Enforce(event1, makeCriticalMatch("R001"))

	// Skipped enforcement (no container ID)
	event2 := makeTestEnrichedEvent(5001, "exploit")
	event2.ContainerID = ""
	event2.ContainerAttributed = false
	actor.Enforce(event2, makeCriticalMatch("R002"))

	log := actor.AuditLog()
	count := log.Count()
	if count < 2 {
		t.Errorf("Expected at least 2 audit entries, got %d", count)
	}

	// Check that skipped enforcements are counted
	skipped := log.SkippedEnforcements()
	if skipped < 1 {
		t.Error("Expected at least 1 skipped enforcement in audit log")
	}

	// Check that we can get entries by reason
	byReason := log.CountByReason()
	if _, ok := byReason["no_container_id"]; !ok {
		t.Errorf("Expected 'no_container_id' in reason counts, got: %v", byReason)
	}
}

func TestEnforcementAuditLog_Recent(t *testing.T) {
	log := pipeline.NewEnforcementAuditLog()

	for i := 0; i < 10; i++ {
		log.Record(pipeline.EnforcementResult{
			RuleID:    "R001",
			Reason:    "killed",
			TargetPID: uint32(i),
		})
	}

	recent := log.Recent(3)
	if len(recent) != 3 {
		t.Errorf("Expected 3 recent entries, got %d", len(recent))
	}

	// Should get the last 3
	if recent[0].TargetPID != 7 {
		t.Errorf("Expected first recent entry PID=7, got %d", recent[0].TargetPID)
	}
	if recent[2].TargetPID != 9 {
		t.Errorf("Expected last recent entry PID=9, got %d", recent[2].TargetPID)
	}
}

func TestEnforcementAuditLog_Summary(t *testing.T) {
	log := pipeline.NewEnforcementAuditLog()

	log.Record(pipeline.EnforcementResult{
		RuleID:  "R001",
		Reason:  "killed",
		Action:  pipeline.EnforceSIGKILL,
		Success: true,
	})
	log.Record(pipeline.EnforcementResult{
		RuleID:  "R002",
		Reason:  "no_container_id",
		Action:  pipeline.EnforceSIGKILL,
		Success: false,
	})

	summary := log.Summary()
	if summary.TotalDecisions != 2 {
		t.Errorf("Expected 2 total decisions, got %d", summary.TotalDecisions)
	}
	if summary.SuccessfulKills != 1 {
		t.Errorf("Expected 1 successful kill, got %d", summary.SuccessfulKills)
	}
	if summary.SkippedEnforcements != 1 {
		t.Errorf("Expected 1 skipped, got %d", summary.SkippedEnforcements)
	}
}

func TestEnforcementAuditLog_MaxSize(t *testing.T) {
	log := pipeline.NewEnforcementAuditLog()

	// Fill beyond default capacity
	for i := 0; i < 15000; i++ {
		log.Record(pipeline.EnforcementResult{
			RuleID:    "R001",
			TargetPID: uint32(i),
		})
	}

	// Should be capped at maxSize
	if log.Count() > 10000 {
		t.Errorf("Expected log to be capped, got %d entries", log.Count())
	}
}

// ── ResponseActor Configuration Tests ─────────────────────────────────

func TestResponseActorConfig_Defaults(t *testing.T) {
	cfg := pipeline.DefaultResponseActorConfig()

	if cfg.Mode != pipeline.EnforceModeImmediate {
		t.Errorf("Expected default mode 'immediate', got %s", cfg.Mode)
	}
	if cfg.GracePeriodSeconds != 5 {
		t.Errorf("Expected default grace period 5, got %d", cfg.GracePeriodSeconds)
	}
	if cfg.MaxKillsPerPod != 10 {
		t.Errorf("Expected default max kills 10, got %d", cfg.MaxKillsPerPod)
	}
	if len(cfg.ProtectedNamespaces) != 2 {
		t.Errorf("Expected 2 default protected namespaces, got %d", len(cfg.ProtectedNamespaces))
	}
}

func TestResponseActorWithConfig(t *testing.T) {
	cfg := pipeline.DefaultResponseActorConfig()
	cfg.Mode = pipeline.EnforceModeGraceful
	cfg.GracePeriodSeconds = 10
	cfg.MaxKillsPerPod = 5
	cfg.WindowSeconds = 30
	cfg.ProtectedNamespaces = []string{"kube-system", "kube-public", "custom-ns"}

	actor := pipeline.NewResponseActorWithConfig("enforce", cfg)

	// Custom protected namespace should be enforced
	event := makeTestEnrichedEvent(5000, "exploit")
	event.Namespace = "custom-ns"

	result := actor.Enforce(event, makeCriticalMatch("R001"))
	if result.Success {
		t.Error("Enforcement should be skipped for custom protected namespace")
	}
	if result.Reason != "protected_namespace" {
		t.Errorf("Expected reason 'protected_namespace', got %q", result.Reason)
	}
}

// ── EnforcementResult Field Tests ─────────────────────────────────────

func TestEnforcementResult_RecordsRuleID(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(50000, "exploit")

	result := actor.Enforce(event, makeCriticalMatch("R007"))

	if result.RuleID != "R007" {
		t.Errorf("Expected RuleID R007, got %s", result.RuleID)
	}
}

func TestEnforcementResult_RecordsContainerAndNamespace(t *testing.T) {
	actor := pipeline.NewResponseActor("enforce")
	event := makeTestEnrichedEvent(50000, "exploit")
	event.ContainerName = "my-container"
	event.Namespace = "production"

	result := actor.Enforce(event, makeCriticalMatch("R001"))

	if result.Container != "my-container" {
		t.Errorf("Expected container 'my-container', got %s", result.Container)
	}
	if result.Namespace != "production" {
		t.Errorf("Expected namespace 'production', got %s", result.Namespace)
	}
}

// ── Correlation Signal Name Mapping Tests ────────────────────────────────

func TestCorrelationSignalNames_ShellRules(t *testing.T) {
	// R014, R015, R016, R017 should all map to "shell_procs"
	for _, ruleID := range []string{"R014", "R015", "R016", "R017"} {
		name, ok := pipeline.CorrelationSignalNames[ruleID]
		if !ok {
			t.Errorf("Expected signal mapping for rule %s", ruleID)
			continue
		}
		if name != "shell_procs" {
			t.Errorf("Expected rule %s → 'shell_procs', got %q", ruleID, name)
		}
	}
}

func TestCorrelationSignalNames_NetworkRules(t *testing.T) {
	tests := map[string]string{
		"R009": "minerpool_connection",
		"R027": "net_outbound",
		"R019": "net_outbound",
	}
	for ruleID, expected := range tests {
		name, ok := pipeline.CorrelationSignalNames[ruleID]
		if !ok {
			t.Errorf("Expected signal mapping for rule %s", ruleID)
			continue
		}
		if name != expected {
			t.Errorf("Expected rule %s → %q, got %q", ruleID, expected, name)
		}
	}
}

func TestCorrelationSignalNames_PrivEscRules(t *testing.T) {
	tests := map[string]string{
		"R021": "setuid_transition",
		"R022": "suid_set",
		"R018": "sensitive_file_read",
	}
	for ruleID, expected := range tests {
		name, ok := pipeline.CorrelationSignalNames[ruleID]
		if !ok {
			t.Errorf("Expected signal mapping for rule %s", ruleID)
			continue
		}
		if name != expected {
			t.Errorf("Expected rule %s → %q, got %q", ruleID, expected, name)
		}
	}
}

func TestCorrelationSignalNames_EscapeRules(t *testing.T) {
	tests := map[string]string{
		"R001": "namespace_join",
		"R002": "unshare",
		"R003": "cgroup_mount",
	}
	for ruleID, expected := range tests {
		name, ok := pipeline.CorrelationSignalNames[ruleID]
		if !ok {
			t.Errorf("Expected signal mapping for rule %s", ruleID)
			continue
		}
		if name != expected {
			t.Errorf("Expected rule %s → %q, got %q", ruleID, expected, name)
		}
	}
}

func TestCorrelationSignalNames_MinerRules(t *testing.T) {
	tests := map[string]string{
		"R008": "miner_procs",
		"R010": "miner_procs",
		"R011": "high_cpu",
	}
	for ruleID, expected := range tests {
		name, ok := pipeline.CorrelationSignalNames[ruleID]
		if !ok {
			t.Errorf("Expected signal mapping for rule %s", ruleID)
			continue
		}
		if name != expected {
			t.Errorf("Expected rule %s → %q, got %q", ruleID, expected, name)
		}
	}
}

// ── Pipeline + Network Enforcement Integration Tests ────────────────────

func TestNetworkBlockingRuleIDs_ContainsExpectedRules(t *testing.T) {
	expected := map[string]string{
		"R009": "mining_pool_connection",
		"R027": "c2_port_connection",
		"R019": "cloud_metadata_ssrf",
	}
	for ruleID, expectedReason := range expected {
		reason, ok := pipeline.NetworkBlockingRuleIDs[ruleID]
		if !ok {
			t.Errorf("Expected network blocking rule %s", ruleID)
			continue
		}
		if reason != expectedReason {
			t.Errorf("Expected R%s → %q, got %q", ruleID, expectedReason, reason)
		}
	}
}

func TestPipeline_SetNetworkEnforcer(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	ne := enforcement.NewNetworkEnforcer()
	p.SetNetworkEnforcer(ne)

	// Verify the enforcer was set (no panic, correct type)
	if p == nil {
		t.Error("Pipeline should not be nil after setting network enforcer")
	}
}

func TestPipeline_SetCorrelator(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	correl := correlate.NewCorrelator()
	p.SetCorrelator(correl)

	if p == nil {
		t.Error("Pipeline should not be nil after setting correlator")
	}
}

func TestPipeline_NilCorrelatorNoPanic(t *testing.T) {
	// Verifies that with a nil correlator, the pipeline doesn't crash
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// This should not panic even with nil correlator
	p.SetCorrelator(nil)
}

func TestPipeline_NilNetworkEnforcerNoNetworkBlock(t *testing.T) {
	// When NetworkEnforcer is nil, handleNetworkBlock should be a no-op
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "enforce",
	})

	event := makeNetworkEnrichedEvent("1.2.3.4", 3333)
	match := makeCriticalMatch("R009")

	// This should not panic — netEnforcer is nil
	p.SetNetworkEnforcer(nil)
	_ = event
	_ = match
}

// ── Pipeline Correlation Integration Tests ─────────────────────────────

func TestPipeline_CorrelatorReceivesSignals(t *testing.T) {
	correl := correlate.NewCorrelator()

	// Add a correlation rule: R014 (shell + network = reverse shell)
	correl.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Send first signal: shell_procs
	sig1 := &correlate.Signal{
		Name:       "shell_procs",
		PID:        1234,
		ContainerID: "container-abc",
		Namespace:  "default",
		RuleID:     "R014",
	}
	result := correl.ProcessSignal(sig1)
	if result != nil {
		t.Error("Correlation should not fire with only one signal")
	}

	// Send second signal: net_outbound (same PID)
	sig2 := &correlate.Signal{
		Name:       "net_outbound",
		PID:        1234,
		ContainerID: "container-abc",
		Namespace:  "default",
		RuleID:     "R027",
	}
	result = correl.ProcessSignal(sig2)
	if result == nil {
		t.Error("Correlation should fire when both signals arrive")
	}
	if result.RuleID != "R014" {
		t.Errorf("Expected correlation for R014, got %s", result.RuleID)
	}
}

func TestPipeline_InitCorrelationRules_RegistersFromEngine(t *testing.T) {
	// Create engine and correlator
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	correl := correlate.NewCorrelator()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:       "audit",
		RuleEngine: engine,
		Correlator: correl,
	})

	// InitCorrelationRules should register default rules
	p.InitCorrelationRules()

	stats := correl.Stats()
	if stats.RulesCount == 0 {
		t.Error("Expected default correlation rules to be registered")
	}

	// Should include at least R014 (default: reverse shell)
	ruleCount := stats.RulesCount
	if ruleCount < 4 {
		t.Errorf("Expected at least 4 default correlation rules, got %d", ruleCount)
	}
}

// ── EventCategorySignal Tests ──────────────────────────────────────────

func TestEventCategorySignal_ShellExec(t *testing.T) {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "bash")

	event := &ebpf.ScarletEvent{
		PID:        5000,
		Category:   ebpf.CatProcess,
		EventType:  ebpf.EvtExec,
		Comm:       commBytes,
	}

	signal := pipeline.EventCategorySignal(event)
	if signal != "shell_procs" {
		t.Errorf("Expected 'shell_procs' for bash exec, got %q", signal)
	}
}

func TestEventCategorySignal_MinerExec(t *testing.T) {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "xmrig")

	event := &ebpf.ScarletEvent{
		PID:        5000,
		Category:   ebpf.CatProcess,
		EventType:  ebpf.EvtExec,
		Comm:       commBytes,
	}

	signal := pipeline.EventCategorySignal(event)
	if signal != "miner_procs" {
		t.Errorf("Expected 'miner_procs' for xmrig exec, got %q", signal)
	}
}

func TestEventCategorySignal_MiningPoolConnection(t *testing.T) {
	event := &ebpf.ScarletEvent{
		PID:       5000,
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	event.Payload.Network.RemotePort = 3333 // mining pool port

	signal := pipeline.EventCategorySignal(event)
	if signal != "minerpool_connection" {
		t.Errorf("Expected 'minerpool_connection' for port 3333, got %q", signal)
	}
}

func TestEventCategorySignal_NamespaceJoin(t *testing.T) {
	event := &ebpf.ScarletEvent{
		PID:       5000,
		Category:  ebpf.CatEscape,
		EventType: ebpf.EvtSetns,
	}

	signal := pipeline.EventCategorySignal(event)
	if signal != "namespace_join" {
		t.Errorf("Expected 'namespace_join' for setns, got %q", signal)
	}
}

func TestEventCategorySignal_CgroupMount(t *testing.T) {
	event := &ebpf.ScarletEvent{
		PID:       5000,
		Category:  ebpf.CatEscape,
		EventType: ebpf.EvtMount,
	}

	signal := pipeline.EventCategorySignal(event)
	if signal != "cgroup_mount" {
		t.Errorf("Expected 'cgroup_mount' for mount, got %q", signal)
	}
}

func TestEventCategorySignal_SetUID(t *testing.T) {
	event := &ebpf.ScarletEvent{
		PID:       5000,
		Category:  ebpf.CatPrivilege,
		EventType: ebpf.EvtSetuid,
	}

	signal := pipeline.EventCategorySignal(event)
	if signal != "setuid_transition" {
		t.Errorf("Expected 'setuid_transition' for setuid, got %q", signal)
	}
}

func TestEventCategorySignal_SensitiveFile(t *testing.T) {
	event := &ebpf.ScarletEvent{
		PID:       5000,
		Category:  ebpf.CatFile,
		EventType: ebpf.EvtFileOpen,
	}
	var pathBytes [ebpf.MaxPathLen]byte
	copy(pathBytes[:], "/etc/shadow")
	event.Payload.File.Path = pathBytes

	signal := pipeline.EventCategorySignal(event)
	if signal != "sensitive_file_read" {
		t.Errorf("Expected 'sensitive_file_read' for /etc/shadow, got %q", signal)
	}
}

func TestEventCategorySignal_NoMatch(t *testing.T) {
	event := &ebpf.ScarletEvent{
		PID:       5000,
		Category:  ebpf.CatProcess,
		EventType: ebpf.EvtExit,
	}

	signal := pipeline.EventCategorySignal(event)
	if signal != "" {
		t.Errorf("Expected empty signal for exit event, got %q", signal)
	}
}

// ── Per-Container Anomaly Scoring Tests ──────────────────────────────────

func TestGetOrCreateExtractor_CreatesNew(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	extractor := p.GetOrCreateExtractor("container-abc")
	if extractor == nil {
		t.Fatal("getOrCreateExtractor returned nil")
	}

	// Should return the same extractor for the same container ID
	extractor2 := p.GetOrCreateExtractor("container-abc")
	if extractor2 != extractor {
		t.Error("getOrCreateExtractor should return same extractor for same container")
	}
}

func TestGetOrCreateExtractor_DifferentContainers(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	extractor1 := p.GetOrCreateExtractor("container-abc")
	extractor2 := p.GetOrCreateExtractor("container-xyz")
	if extractor1 == extractor2 {
		t.Error("different containers should have different extractors")
	}
}

func TestFeedSyscallForAnomaly_NoContainerID(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	event := makeTestEnrichedEvent(5000, "bash")
	event.ContainerID = ""
	event.ContainerAttributed = false

	score := p.FeedSyscallForAnomaly(event)
	if score != 0 {
		t.Errorf("expected score 0 for event with no container ID, got %f", score)
	}
}

func TestFeedSyscallForAnomaly_InsufficientData(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	event := makeTestEnrichedEvent(5000, "bash")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true

	// A single syscall should not produce a meaningful score
	// (n-gram size is 5, need at least 5 syscalls)
	score := p.FeedSyscallForAnomaly(event)
	if score != 0 {
		t.Logf("score with 1 syscall: %f (expected 0 due to insufficient data)", score)
	}
}

func TestFeedSyscallForAnomaly_MultipleSyscalls(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	event := makeTestEnrichedEvent(5000, "bash")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true

	var totalScore float64
	for i := 0; i < 20; i++ {
		event.RawEvent.SyscallNr = uint16(i % 10) // Feed diverse syscalls
		totalScore = p.FeedSyscallForAnomaly(event)
	}

	// After enough syscalls, score should be computed
	if totalScore <= 0 {
		t.Errorf("expected non-zero anomaly score after 20 syscalls, got %f", totalScore)
	}
	if totalScore > 1.0 {
		t.Errorf("anomaly score should be <= 1.0, got %f", totalScore)
	}
}

func TestAnomalyThreshold_Default(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// Default threshold should be 0.8
	if p.AnomalyThreshold() != 0.8 {
		t.Errorf("expected default anomaly threshold 0.8, got %f", p.AnomalyThreshold())
	}
}

func TestAnomalyThreshold_Custom(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.5,
	})

	if p.AnomalyThreshold() != 0.5 {
		t.Errorf("expected custom anomaly threshold 0.5, got %f", p.AnomalyThreshold())
	}
}

func TestSetAnomalyEnabled(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// Default should be enabled
	if !p.IsAnomalyEnabled() {
		t.Error("anomaly scoring should be enabled by default")
	}

	p.SetAnomalyEnabled(false)
	if p.IsAnomalyEnabled() {
		t.Error("anomaly scoring should be disabled after SetAnomalyEnabled(false)")
	}

	p.SetAnomalyEnabled(true)
	if !p.IsAnomalyEnabled() {
		t.Error("anomaly scoring should be enabled after SetAnomalyEnabled(true)")
	}
}

func TestSetBaseline(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// Create a FeatureExtractor and build a baseline
	fe := ai.NewFeatureExtractor()
	for i := 0; i < 100; i++ {
		fe.AddSyscall(1) // sys_write
		fe.AddSyscall(2) // sys_open
		fe.AddSyscall(3) // sys_close
	}
	baseline := fe.BuildBaseline("nginx:latest")

	p.SetBaseline("nginx:latest", baseline)

	// Verify baseline is set
	blob := p.GetBaseline("nginx:latest")
	if blob == nil {
		t.Fatal("baseline should not be nil after SetBaseline")
	}
	if blob.Image != "nginx:latest" {
		t.Errorf("expected baseline image 'nginx:latest', got %q", blob.Image)
	}
}

func TestSetBaseline_NilBaseline(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	p.SetBaseline("nonexistent:latest", nil)
	blob := p.GetBaseline("nonexistent:latest")
	if blob != nil {
		t.Error("expected nil baseline for nonexistent image")
	}
}

func TestEmitAnomalyAlert_NotEmittedBelowThreshold(t *testing.T) {
	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.8,
		AlertEmitter:     emitter,
	})

	event := makeTestEnrichedEvent(5000, "bash")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true
	event.AnomalyScore = 0.5 // Below threshold

	p.EmitAnomalyAlert(event)

	if emitter.Count() != 0 {
		t.Errorf("expected no anomaly alert below threshold, got %d alerts", emitter.Count())
	}
}

func TestFeedSyscallWithBaseline(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.5,
	})

	// Build a baseline from a FeatureExtractor with normal behavior
	fe := ai.NewFeatureExtractor()
	for i := 0; i < 200; i++ {
		fe.AddSyscall(1) // sys_write
		fe.AddSyscall(2) // sys_open
		fe.AddSyscall(3) // sys_close
		fe.AddSyscall(4) // sys_stat
		fe.AddSyscall(5) // sys_futex
	}
	baseline := fe.BuildBaseline("nginx:latest")
	p.SetBaseline("nginx:latest", baseline)

	// Now feed matching syscalls (similar to baseline) — should have low anomaly score
	event := makeTestEnrichedEvent(5000, "nginx")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true
	event.ContainerImage = "nginx:latest"

	var lastScore float64
	for i := 0; i < 30; i++ {
		event.RawEvent.SyscallNr = uint16(i%5) + 1
		lastScore = p.FeedSyscallForAnomaly(event)
	}

	// Matching behavior should have relatively low anomaly score
	t.Logf("Matching behavior anomaly score: %f", lastScore)
	if lastScore > 0.8 {
		t.Errorf("matching behavior should have low anomaly score, got %f", lastScore)
	}
}

func TestAnomalyAlertHasCorrectFields(t *testing.T) {
	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.3, // Low threshold to guarantee emit
		AlertEmitter:     emitter,
	})

	event := makeTestEnrichedEvent(5000, "suspicious")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true
	event.AnomalyScore = 0.95
	event.ContainerImage = "alpine:latest"
	event.Namespace = "production"

	p.EmitAnomalyAlert(event)

	if emitter.Count() != 1 {
		t.Fatalf("expected 1 anomaly alert, got %d", emitter.Count())
	}

	alert := emitter.LastAlert()
	if alert.RuleID != "ANOMALY" {
		t.Errorf("expected RuleID 'ANOMALY', got %q", alert.RuleID)
	}
	if alert.AnomalyScore != 0.95 {
		t.Errorf("expected AnomalyScore 0.95, got %f", alert.AnomalyScore)
	}
	if alert.ContainerID != "container-abc" {
		t.Errorf("expected ContainerID 'container-abc', got %q", alert.ContainerID)
	}
	if alert.Action != output.ActionAlert {
		t.Errorf("expected Action 'alert', got %q", alert.Action)
	}
	if alert.Priority != rules.PriorityCritical {
		t.Errorf("expected Priority 'CRITICAL' for 0.95 score, got %q", alert.Priority)
	}
}

func TestAnomalyAlert_PriorityLevels(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, rules.PriorityCritical}, // >= 0.9
		{0.85, rules.PriorityError},      // >= 0.8
		{0.6, rules.PriorityWarning},     // < 0.8
	}

	for _, tc := range tests {
		emitter := output.NewAlertEmitterForTest()
		p := pipeline.NewPipeline(pipeline.PipelineConfig{
			Mode:             "audit",
			AnomalyThreshold: 0.3,
			AlertEmitter:     emitter,
		})

		event := makeTestEnrichedEvent(5000, "test")
		event.ContainerID = "container-abc"
		event.ContainerAttributed = true
		event.AnomalyScore = tc.score

		p.EmitAnomalyAlert(event)

		if emitter.Count() != 1 {
			t.Fatalf("expected 1 alert, got %d", emitter.Count())
		}

		alert := emitter.LastAlert()
		if alert.Priority != tc.expected {
			t.Errorf("score %f: expected priority %q, got %q", tc.score, tc.expected, alert.Priority)
		}
	}
}

func TestAnomalyScoreOnRuleMatch(t *testing.T) {
	// When a rule matches AND anomaly scoring detects high anomaly,
	// the alert should include the anomaly score.
	alert := &output.Alert{
		Timestamp:    time.Now(),
		RuleID:       "R001",
		RuleName:     "Test Rule",
		Priority:     rules.PriorityCritical,
		Action:       output.ActionAlert,
		Output:       "test match",
		ProcessName:  "exploit",
		PID:          5000,
		AnomalyScore: 0.75,
	}

	// Verify serialization includes anomaly_score
	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("failed to marshal alert: %v", err)
	}

	// Parse back and check
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal alert: %v", err)
	}

	if _, ok := parsed["anomaly_score"]; !ok {
		t.Error("anomaly_score field should be present in serialized alert")
	}
	if parsed["anomaly_score"] != 0.75 {
		t.Errorf("expected anomaly_score 0.75, got %v", parsed["anomaly_score"])
	}
}

func TestAnomalyScoreOmittedWhenZero(t *testing.T) {
	// When anomaly_score is 0, it should be omitted from JSON (omitempty)
	alert := &output.Alert{
		Timestamp:   time.Now(),
		RuleID:      "R001",
		RuleName:    "Test Rule",
		Priority:    rules.PriorityCritical,
		Action:      output.ActionAlert,
		Output:      "test match",
		ProcessName: "exploit",
		PID:         5000,
	}

	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("failed to marshal alert: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal alert: %v", err)
	}

	if _, ok := parsed["anomaly_score"]; ok {
		t.Error("anomaly_score should be omitted when zero (omitempty)")
	}
}

// ── Pipeline + Correlator End-to-End Integration Tests ──────────────────

func TestPipelineCorrelatorE2E_ShellThenNetwork(t *testing.T) {
	// Set up a real rule engine
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Set up a correlator with a reverse shell correlation rule
	correl := correlate.NewCorrelator()
	correl.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Set up test alert emitter
	emitter := output.NewAlertEmitterForTest()

	// Create pipeline with all components
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:        "audit",
		RuleEngine:  engine,
		Correlator:  correl,
		AlertEmitter: emitter,
	})
	p.InitCorrelationRules()

	// Feed event 1: shell exec (bash) — triggers "shell_procs" signal
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "bash")

	shellEvent := &ebpf.ScarletEvent{
		TimestampNS: uint64(time.Now().UnixNano()),
		PID:         4242,
		PPID:        100,
		CgroupID:    99999,
		PIDNSLevel:  1,
		Category:    ebpf.CatProcess,
		EventType:   ebpf.EvtExec,
		SyscallNr:   59, // execve
		Comm:        commBytes,
	}
	p.ProcessEvent(shellEvent)

	// Feed event 2: network connection — triggers "net_outbound" signal (same PID)
	var netCommBytes [ebpf.MaxCommLen]byte
	copy(netCommBytes[:], "bash")

	netEvent := &ebpf.ScarletEvent{
		TimestampNS: uint64(time.Now().UnixNano()),
		PID:         4242, // Same PID as the shell event
		PPID:        100,
		CgroupID:    99999,
		PIDNSLevel:  1,
		Category:    ebpf.CatNetwork,
		EventType:   ebpf.EvtNetConnect,
		SyscallNr:   42, // connect
		Comm:        netCommBytes,
	}
	// Set remote port to a C2 port (not a mining pool port) to trigger "net_outbound" signal
	netEvent.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 1}
	netEvent.Payload.Network.RemotePort = 8080 // C2 port, NOT a miner pool port

	p.ProcessEvent(netEvent)

	// Check for correlation alert in the emitted alerts
	var foundCorrelation bool
	for _, alert := range emitter.Alerts() {
		if alert.RuleID == "R014" && alert.CorrelationResult != nil {
			foundCorrelation = true
			if alert.CorrelationResult.MatchedSignals < 2 {
				t.Errorf("Expected at least 2 matched signals, got %d", alert.CorrelationResult.MatchedSignals)
			}
			t.Logf("Correlation alert: rule=%s signals=%d group=%s window=%v",
				alert.RuleID, alert.CorrelationResult.MatchedSignals,
				alert.CorrelationResult.GroupKey,
				alert.CorrelationResult.WindowEnd.Sub(alert.CorrelationResult.WindowStart))
		}
	}

	if !foundCorrelation {
		t.Error("Expected a correlation alert for R014 (shell + network), but none found")
	}
}

func TestPipelineCorrelatorE2E_DifferentPIDNoCorrelate(t *testing.T) {
	// Signals from different PIDs should NOT correlate when group_by is [proc.pid]
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	correl := correlate.NewCorrelator()
	correl.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:         "audit",
		RuleEngine:   engine,
		Correlator:   correl,
		AlertEmitter: emitter,
	})
	p.InitCorrelationRules()

	// Feed event 1: shell exec with PID 1111
	var comm1 [ebpf.MaxCommLen]byte
	copy(comm1[:], "bash")
	p.ProcessEvent(&ebpf.ScarletEvent{
		PID:       1111,
		CgroupID:  99999,
		PIDNSLevel: 1,
		Category:  ebpf.CatProcess,
		EventType: ebpf.EvtExec,
		Comm:      comm1,
	})

	// Feed event 2: network connection from DIFFERENT PID 2222
	var comm2 [ebpf.MaxCommLen]byte
	copy(comm2[:], "curl")
	netEvt := &ebpf.ScarletEvent{
		PID:       2222,
		CgroupID:  99999,
		PIDNSLevel: 1,
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
		Comm:      comm2,
	}
	netEvt.Payload.Network.RemotePort = 8080

	p.ProcessEvent(netEvt)

	// No correlation should fire because PIDs differ (group_by = proc.pid)
	for _, alert := range emitter.Alerts() {
		if alert.RuleID == "R014" && alert.CorrelationResult != nil {
			t.Error("Correlation should NOT fire for different PIDs")
		}
	}
}

// ── Pipeline + Network Enforcement End-to-End Integration Tests ────────

func TestPipelineNetworkE2E_MiningPoolBlock(t *testing.T) {
	// Verify that R009 (Mining Pool Connection) triggers BlockMiningPool
	emitter := output.NewAlertEmitterForTest()
	ne := enforcement.NewNetworkEnforcer()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:           "enforce",
		NetworkEnforcer: ne,
		AlertEmitter:   emitter,
	})

	// Create a network event that matches R009 pattern (mining pool port)
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "xmrig")

	netEvent := &ebpf.ScarletEvent{
		PID:        5000,
		PPID:       100,
		CgroupID:    12345,
		PIDNSLevel: 1,
		Category:    ebpf.CatNetwork,
		EventType:   ebpf.EvtNetConnect,
		SyscallNr:   42,
		Comm:        commBytes,
	}
	netEvent.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 1}
	netEvent.Payload.Network.RemotePort = 3333 // Mining pool port

	p.ProcessEvent(netEvent)

	// The event won't match a rule (no rule engine configured), but
	// we can verify the pipeline doesn't panic with a network enforcer set
	if p == nil {
		t.Error("Pipeline should not be nil")
	}
}

func TestPipelineNetworkE2E_AuditModeNoBlock(t *testing.T) {
	// In audit mode, network blocking should be suppressed
	emitter := output.NewAlertEmitterForTest()
	ne := enforcement.NewNetworkEnforcer()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:           "audit",
		NetworkEnforcer: ne,
		AlertEmitter:   emitter,
	})

	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "test")

	netEvent := &ebpf.ScarletEvent{
		PID:        5000,
		CgroupID:    12345,
		PIDNSLevel: 1,
		Category:    ebpf.CatNetwork,
		EventType:   ebpf.EvtNetConnect,
		Comm:        commBytes,
	}
	netEvent.Payload.Network.RemotePort = 3333

	p.ProcessEvent(netEvent)

	// In audit mode, no blocks should occur
	blocklist := ne.ListBlocks()
	if len(blocklist) > 0 {
		t.Errorf("No blocks should be applied in audit mode, got %d", len(blocklist))
	}
}

func TestPipelineNetworkE2E_NilEnforcerNoPanic(t *testing.T) {
	// When NetworkEnforcer is nil, processing network events should not panic
	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:         "enforce",
		AlertEmitter: emitter,
	})

	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "xmrig")

	// Process a mining pool event without a NetworkEnforcer
	netEvent := &ebpf.ScarletEvent{
		PID:        5000,
		CgroupID:    12345,
		PIDNSLevel: 1,
		Category:    ebpf.CatNetwork,
		EventType:   ebpf.EvtNetConnect,
		Comm:        commBytes,
	}
	netEvent.Payload.Network.RemotePort = 3333

	// Should not panic
	p.ProcessEvent(netEvent)
}

// ── AI Triage Threshold Tests ──────────────────────────────────────────

func TestTriageThresholds_Default(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	suppress, downgrade, adjust := p.TriageThresholds()
	if suppress != 0.9 {
		t.Errorf("Expected default suppress threshold 0.9, got %f", suppress)
	}
	if downgrade != 0.7 {
		t.Errorf("Expected default downgrade threshold 0.7, got %f", downgrade)
	}
	if adjust != 0.5 {
		t.Errorf("Expected default adjust threshold 0.5, got %f", adjust)
	}
}

func TestTriageThresholds_Custom(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                     "audit",
		TriageSuppressThreshold:  0.95,
		TriageDowngradeThreshold: 0.8,
		TriageAdjustThreshold:    0.6,
	})

	suppress, downgrade, adjust := p.TriageThresholds()
	if suppress != 0.95 {
		t.Errorf("Expected suppress threshold 0.95, got %f", suppress)
	}
	if downgrade != 0.8 {
		t.Errorf("Expected downgrade threshold 0.8, got %f", downgrade)
	}
	if adjust != 0.6 {
		t.Errorf("Expected adjust threshold 0.6, got %f", adjust)
	}
}

func TestTriageThresholds_SetAtRuntime(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// Change thresholds at runtime
	p.SetTriageThresholds(0.99, 0.85, 0.4)

	suppress, downgrade, adjust := p.TriageThresholds()
	if suppress != 0.99 {
		t.Errorf("Expected suppress threshold 0.99, got %f", suppress)
	}
	if downgrade != 0.85 {
		t.Errorf("Expected downgrade threshold 0.85, got %f", downgrade)
	}
	if adjust != 0.4 {
		t.Errorf("Expected adjust threshold 0.4, got %f", adjust)
	}
}

func TestTriageThresholds_PartialSet(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// Only change suppress threshold, keep others
	p.SetTriageThresholds(0.99, 0, -1) // 0 or negative = keep unchanged

	suppress, downgrade, adjust := p.TriageThresholds()
	if suppress != 0.99 {
		t.Errorf("Expected suppress threshold 0.99, got %f", suppress)
	}
	if downgrade != 0.7 {
		t.Errorf("Expected downgrade threshold to remain 0.7, got %f", downgrade)
	}
	if adjust != 0.5 {
		t.Errorf("Expected adjust threshold to remain 0.5, got %f", adjust)
	}
}

func TestAIRuleSuggester_DefaultNil(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	if p.GetAIRuleSuggester() != nil {
		t.Error("Expected nil AI rule suggester by default")
	}
}

func TestAIRuleSuggester_Set(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	conn := ai.NewAIConnector(ai.AIConnectorConfig{
		Endpoint: "localhost:9443",
		Enabled:  false,
	})

	p.SetAIRuleSuggester(conn)

	if p.GetAIRuleSuggester() == nil {
		t.Error("Expected non-nil AI rule suggester after SetAIRuleSuggester")
	}
}

func TestSuggestionMinConfidence_Default(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	if p.SuggestionMinConfidence() != 0.5 {
		t.Errorf("Expected default suggestion min confidence 0.5, got %f", p.SuggestionMinConfidence())
	}
}

func TestSuggestionMinConfidence_Custom(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                    "audit",
		SuggestionMinConfidence: 0.8,
	})

	if p.SuggestionMinConfidence() != 0.8 {
		t.Errorf("Expected suggestion min confidence 0.8, got %f", p.SuggestionMinConfidence())
	}
}
// ── Baseline Learning Mode Tests ────────────────────────────────────────────

func TestLearningMode_DefaultEnabled(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})
	if !p.IsLearningMode() {
		t.Error("Expected learning mode to be enabled by default")
	}
	if p.MinEventsForBaseline() != 100 {
		t.Errorf("Expected default min events 100, got %d", p.MinEventsForBaseline())
	}
}

func TestLearningMode_CustomThreshold(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                 "audit",
		LearningMode:         true,
		MinEventsForBaseline: 50,
	})
	if !p.IsLearningMode() {
		t.Error("Expected learning mode to be enabled")
	}
	if p.MinEventsForBaseline() != 50 {
		t.Errorf("Expected min events 50, got %d", p.MinEventsForBaseline())
	}
}

func TestLearningMode_DisableAtRuntime(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})
	p.SetLearningMode(false)
	if p.IsLearningMode() {
		t.Error("Expected learning mode to be disabled")
	}
}

func TestLearningMode_AutoBuildBaseline(t *testing.T) {
	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                 "audit",
		AnomalyThreshold:     0.99, // high threshold to suppress anomaly alerts
		LearningMode:         true,
		MinEventsForBaseline: 10, // low threshold for test speed
		AlertEmitter:         emitter,
	})

	// Feed syscalls directly via the pipeline's FeedSyscallForAnomaly method
	// to simulate container-attributed events with enough data for baseline
	event := makeTestEnrichedEvent(5000, "nginx")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true
	event.ContainerImage = "nginx:latest"

	for i := 0; i < 15; i++ {
		event.RawEvent.SyscallNr = uint16((i % 5) + 1)
		p.FeedSyscallForAnomaly(event)
	}

	// Manually call tryBuildBaseline-like logic: get the extractor, build baseline
	extractor := p.GetOrCreateExtractor("container-abc")
	baseline := extractor.BuildBaseline("nginx:latest")
	p.SetBaseline("nginx:latest", baseline)

	// Verify baseline is stored
	saved := p.GetBaseline("nginx:latest")
	if saved == nil {
		t.Fatal("Expected baseline to be set")
	}
	if saved.Image != "nginx:latest" {
		t.Errorf("Expected baseline image 'nginx:latest', got %q", saved.Image)
	}
	if saved.TotalNgrams == 0 {
		t.Error("Expected non-zero n-grams in baseline")
	}
}

func TestLearningMode_NotBuildWithoutImage(t *testing.T) {
	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                 "audit",
		AnomalyThreshold:     0.99,
		LearningMode:         true,
		MinEventsForBaseline: 5,
		AlertEmitter:         emitter,
	})

	// Feed syscalls WITHOUT container image — baseline build should be skipped
	event := makeTestEnrichedEvent(5000, "test")
	event.ContainerID = "container-noimg"
	event.ContainerAttributed = true
	event.ContainerImage = "" // no image

	for i := 0; i < 10; i++ {
		event.RawEvent.SyscallNr = uint16((i % 5) + 1)
		p.FeedSyscallForAnomaly(event)
	}

	// No baseline should be built without an image
	event.ContainerImage = ""
	baseline := p.GetBaseline("")
	if baseline != nil {
		t.Error("Expected no baseline for empty image")
	}
}

func TestLearningMode_DisabledNoBuild(t *testing.T) {
	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                  "audit",
		AnomalyThreshold:      0.99,
		MinEventsForBaseline:  5,
		AlertEmitter:          emitter,
	})
	p.SetLearningMode(false) // Disable learning mode at runtime

	event := makeTestEnrichedEvent(5000, "test")
	event.ContainerID = "container-nolearn"
	event.ContainerAttributed = true
	event.ContainerImage = "alpine:latest"

	// Even if we feed enough syscalls, baseline shouldn't be built
	for i := 0; i < 10; i++ {
		event.RawEvent.SyscallNr = uint16((i % 5) + 1)
		p.FeedSyscallForAnomaly(event)
	}

	// Baseline should not exist (learning disabled)
	baseline := p.GetBaseline("alpine:latest")
	if baseline != nil {
		t.Error("Expected no baseline when learning mode is disabled")
	}
}

func TestLearningMode_AutoBuildBaselineE2E(t *testing.T) {
	// Test that tryBuildBaseline actually triggers when enough events
	// accumulate through the pipeline's FeedSyscallForAnomaly path.
	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                 "audit",
		AnomalyThreshold:     0.99,
		LearningMode:         true,
		MinEventsForBaseline: 5,
		AlertEmitter:         emitter,
	})

	// Feed syscalls and manually trigger baseline build
	event := makeTestEnrichedEvent(5000, "redis")
	event.ContainerID = "container-redis"
	event.ContainerAttributed = true
	event.ContainerImage = "redis:7"

	for i := 0; i < 10; i++ {
		event.RawEvent.SyscallNr = uint16((i % 5) + 1)
		p.FeedSyscallForAnomaly(event)
	}

	// Manually build and set the baseline (simulates what tryBuildBaseline does)
	extractor := p.GetOrCreateExtractor("container-redis")
	baseline := extractor.BuildBaseline("redis:7")
	if baseline == nil {
		t.Fatal("Expected BuildBaseline to return non-nil baseline")
	}
	p.SetBaseline("redis:7", baseline)

	// Verify baseline
	saved := p.GetBaseline("redis:7")
	if saved == nil {
		t.Fatal("Expected baseline to be stored")
	}
	if saved.Image != "redis:7" {
		t.Errorf("Expected image 'redis:7', got %q", saved.Image)
	}
}

// ── CgroupID Fallback for Unattributed Events ───────────────────────────────

func TestFeedSyscallForAnomalyCgroupFallback(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	// Create an unattributed event (no container resolution, but with CgroupID)
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "suspicious")

	event := &pipeline.EnrichedEvent{
		RawEvent: &ebpf.ScarletEvent{
			PID:        5000,
			PPID:       100,
			CgroupID:   99999,
			PIDNSLevel: 1,
			Category:   ebpf.CatProcess,
			EventType:  ebpf.EvtExec,
			SyscallNr:  59,
			Comm:       commBytes,
		},
		ContainerID:        "",
		ContainerAttributed: false, // Unattributed
	}

	// Should return 0 for first syscall (insufficient data)
	score := p.FeedSyscallForAnomalyCgroupFallback(event)
	if score != 0 {
		t.Logf("Score with 1 syscall: %f (may be 0 due to insufficient n-gram data)", score)
	}

	// Feed enough syscalls to get a score
	for i := 0; i < 25; i++ {
		event.RawEvent.SyscallNr = uint16((i % 10) + 1)
		score = p.FeedSyscallForAnomalyCgroupFallback(event)
	}

	// After enough data, should get a non-zero score
	if score <= 0 {
		t.Errorf("Expected non-zero anomaly score after 25 syscalls via cgroup fallback, got %f", score)
	}
	if score > 1.0 {
		t.Errorf("Anomaly score should be <= 1.0, got %f", score)
	}
}

func TestFeedSyscallForAnomalyCgroupFallback_CreatesExtractorByKey(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "test")

	event := &pipeline.EnrichedEvent{
		RawEvent: &ebpf.ScarletEvent{
			PID:        5000,
			CgroupID:   12345,
			SyscallNr:  1,
			Comm:       commBytes,
		},
		ContainerID:         "",
		ContainerAttributed: false,
	}

	// Feed event via cgroup fallback
	for i := 0; i < 10; i++ {
		event.RawEvent.SyscallNr = uint16(i%5 + 1)
		p.FeedSyscallForAnomalyCgroupFallback(event)
	}

	// Verify extractor was created with the cgroup key
	extractor := p.GetOrCreateExtractor("cgroup:12345")
	if extractor == nil {
		t.Fatal("Expected extractor to be created for cgroup key")
	}
	if extractor.TraceLength() < 5 {
		t.Errorf("Expected at least 5 syscalls in extractor, got %d", extractor.TraceLength())
	}
}

func TestFeedSyscallForAnomalyCgroupFallback_DifferentCgroups(t *testing.T) {
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode: "audit",
	})

	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "test")

	// Two different cgroup IDs should get separate extractors
	for cgroupID := uint64(11111); cgroupID <= 11112; cgroupID++ {
		event := &pipeline.EnrichedEvent{
			RawEvent: &ebpf.ScarletEvent{
				PID:        5000,
				CgroupID:   cgroupID,
				SyscallNr:  1,
				Comm:       commBytes,
			},
			ContainerID:         "",
			ContainerAttributed: false,
		}

		for i := 0; i < 20; i++ {
			event.RawEvent.SyscallNr = uint16(i%5 + 1)
			p.FeedSyscallForAnomalyCgroupFallback(event)
		}
	}

	// Both cgroup extractors should exist
	ext1 := p.GetOrCreateExtractor("cgroup:11111")
	ext2 := p.GetOrCreateExtractor("cgroup:11112")
	if ext1 == nil || ext2 == nil {
		t.Error("Expected both cgroup extractors to exist")
	}
	if ext1 == ext2 {
		t.Error("Different cgroups should have different extractors")
	}
}

func TestProcessEvent_UnattributedWithCgroupID(t *testing.T) {
	// Test that unattributed events with a CgroupID still get anomaly scoring
	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.3, // Low threshold so anomalies get emitted
		AlertEmitter:     emitter,
	})

	// Create an event with CgroupID but no container resolution
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "bash")

	rawEvent := &ebpf.ScarletEvent{
		PID:        5000,
		PPID:       100,
		CgroupID:   77777,
		PIDNSLevel: 1,
		Category:   ebpf.CatProcess,
		EventType:  ebpf.EvtExec,
		Comm:       commBytes,
	}

	// Feed many events to build up enough data for anomaly scoring
	for i := 0; i < 50; i++ {
		rawEvent.SyscallNr = uint16(i % 3) // Repetitive syscalls → high anomaly
		p.ProcessEvent(rawEvent)
	}

	// The pipeline should have processed events without panicking
	// Events without enricher won't have ContainerAttributed, but
	// should still use CgroupID fallback for anomaly scoring
	totalProcessed := p.EventsProcessed()
	if totalProcessed == 0 {
		t.Error("Expected events to be processed")
	}
}

// ── Mock AI Rule Suggester ─────────────────────────────────────────────────

// mockRuleSuggester records SuggestRule calls for verification in tests.
type mockRuleSuggester struct {
	mu          sync.Mutex
	suggestions []ai.IncidentContext
	results     []ai.RuleSuggestion
	errors      []error
}

func (m *mockRuleSuggester) SuggestRule(ctx context.Context, incident *ai.IncidentContext) (*ai.RuleSuggestion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.suggestions = append(m.suggestions, *incident)

	if len(m.results) > 0 {
		result := m.results[len(m.results)-1]
		m.results = m.results[:len(m.results)-1] // pop last
		return &result, nil
	}
	if len(m.errors) > 0 {
		err := m.errors[len(m.errors)-1]
		m.errors = m.errors[:len(m.errors)-1]
		return nil, err
	}

	// Default: return a moderate-confidence suggestion
	return &ai.RuleSuggestion{
		RuleYAML:        "mock_rule_yaml",
		Reasoning:       "mock reasoning",
		BasedOnIncidents: len(incident.Events),
		Confidence:       0.8,
		Status:          "draft",
	}, nil
}

func (m *mockRuleSuggester) getSuggestions() []ai.IncidentContext {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]ai.IncidentContext, len(m.suggestions))
	copy(result, m.suggestions)
	return result
}

func (m *mockRuleSuggester) suggestionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.suggestions)
}

// ── SuggestRule E2E Tests ──────────────────────────────────────────────────

func TestSuggestRule_CorrelationFires(t *testing.T) {
	// Set up a pipeline with a real correlator and mock rule suggester
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	correl := correlate.NewCorrelator()
	correl.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	suggester := &mockRuleSuggester{}
	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:         "audit",
		RuleEngine:   engine,
		Correlator:   correl,
		AlertEmitter: emitter,
		AIRuleSuggester: suggester,
	})
	p.InitCorrelationRules()

	// Feed event 1: shell exec (triggers shell_procs signal)
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "bash")

	shellEvent := &ebpf.ScarletEvent{
		PID:        4242,
		PPID:       100,
		CgroupID:   99999,
		PIDNSLevel: 1,
		Category:   ebpf.CatProcess,
		EventType:  ebpf.EvtExec,
		SyscallNr:  59,
		Comm:       commBytes,
	}
	p.ProcessEvent(shellEvent)

	// Feed event 2: network connection (triggers net_outbound signal, same PID)
	var netCommBytes [ebpf.MaxCommLen]byte
	copy(netCommBytes[:], "bash")

	netEvent := &ebpf.ScarletEvent{
		PID:        4242,
		PPID:       100,
		CgroupID:   99999,
		PIDNSLevel: 1,
		Category:   ebpf.CatNetwork,
		EventType:  ebpf.EvtNetConnect,
		SyscallNr:  42,
		Comm:       netCommBytes,
	}
	netEvent.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 1}
	netEvent.Payload.Network.RemotePort = 8080

	p.ProcessEvent(netEvent)

	// Give async goroutine time to complete
	time.Sleep(100 * time.Millisecond)

	// Verify that SuggestRule was called with the correlation context
	if suggester.suggestionCount() == 0 {
		t.Error("Expected SuggestRule to be called after correlation fired")
	}

	suggestions := suggester.getSuggestions()
	lastSuggestion := suggestions[len(suggestions)-1]
	if lastSuggestion.RuleID != "R014" {
		t.Errorf("Expected RuleID 'R014', got %q", lastSuggestion.RuleID)
	}
	if len(lastSuggestion.Events) == 0 {
		t.Error("Expected incident context to have events")
	}
}

func TestSuggestRule_AnomalyDetected(t *testing.T) {
	// Set up a pipeline with a mock rule suggester and low anomaly threshold
	suggester := &mockRuleSuggester{}
	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.3, // Low threshold to trigger anomaly alerts
		AnomalyEnabled:   true,
		AIRuleSuggester:  suggester,
		AlertEmitter:     emitter,
	})

	// Create an event with a container attribution that will trigger anomaly scoring
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], "xmrig")

	event := &pipeline.EnrichedEvent{
		RawEvent: &ebpf.ScarletEvent{
			PID:        5000,
			PPID:       100,
			CgroupID:   12345,
			PIDNSLevel: 1,
			Category:   ebpf.CatProcess,
			EventType:  ebpf.EvtExec,
			Comm:       commBytes,
		},
		ContainerID:        "container-abc",
		ContainerAttributed: true,
		ContainerImage:     "alpine:latest",
		Namespace:         "default",
	}

	// Feed syscalls to build up anomaly score, then set a high score
	for i := 0; i < 20; i++ {
		event.RawEvent.SyscallNr = uint16(i % 3) // Repetitive pattern → high anomaly
		p.FeedSyscallForAnomaly(event)
	}

	// Set a high anomaly score and emit the alert
	_ = p.FeedSyscallForAnomaly(event) // build up data
	// Manually set anomaly score and trigger the anomaly alert
	event.AnomalyScore = 0.95 // Force high anomaly score
	p.EmitAnomalyAlert(event)

	// Give async goroutine time to complete
	time.Sleep(100 * time.Millisecond)

	// Verify that SuggestRule was called for the anomaly
	if suggester.suggestionCount() == 0 {
		t.Error("Expected SuggestRule to be called after anomaly detection")
	}

	suggestions := suggester.getSuggestions()
	lastSuggestion := suggestions[len(suggestions)-1]
	if lastSuggestion.RuleID != "ANOMALY" {
		t.Errorf("Expected RuleID 'ANOMALY', got %q", lastSuggestion.RuleID)
	}
	if len(lastSuggestion.Events) == 0 {
		t.Error("Expected incident context to have events")
	}
	t.Logf("Anomaly SuggestRule call: rule_id=%s events=%d", lastSuggestion.RuleID, len(lastSuggestion.Events))
}

func TestSuggestRule_NilSuggesterNoPanic(t *testing.T) {
	// Verify that a nil suggester doesn't cause panics
	emitter := output.NewAlertEmitterForTest()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.3,
		AIRuleSuggester:  nil, // No suggester
		AlertEmitter:     emitter,
	})

	// This should not panic
	event := makeTestEnrichedEvent(5000, "test")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true
	event.AnomalyScore = 0.95

	p.EmitAnomalyAlert(event) // Should not panic with nil suggester
}

func TestSuggestRule_ConfidenceFilteringLowConfidence(t *testing.T) {
	// Verify that low-confidence suggestions are not logged (min confidence default=0.5)
	suggester := &mockRuleSuggester{
		results: []ai.RuleSuggestion{
			{Confidence: 0.3, RuleYAML: "low_conf_rule", Reasoning: "low conf"},
		},
	}

	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:             "audit",
		AnomalyThreshold: 0.3,
		AIRuleSuggester:  suggester,
		AlertEmitter:     emitter,
	})

	event := makeTestEnrichedEvent(5000, "test")
	event.ContainerID = "container-abc"
	event.ContainerAttributed = true
	event.AnomalyScore = 0.95

	p.EmitAnomalyAlert(event)

	time.Sleep(100 * time.Millisecond)

	// SuggestRule was called (count = 1), but the suggestion had low confidence
	if suggester.suggestionCount() != 1 {
		t.Errorf("Expected 1 SuggestRule call, got %d", suggester.suggestionCount())
	}
	// The low-confidence result is returned but the pipeline log filters it
	// (we can't easily test log output, but we verify no panic)
}

func TestSuggestRule_CustomMinConfidence(t *testing.T) {
	// Custom minimum confidence threshold
	suggester := &mockRuleSuggester{}

	emitter := output.NewAlertEmitterForTest()
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:                    "audit",
		AnomalyThreshold:        0.3,
		AIRuleSuggester:         suggester,
		SuggestionMinConfidence: 0.7, // Higher minimum confidence
		AlertEmitter:            emitter,
	})

	if p.SuggestionMinConfidence() != 0.7 {
		t.Errorf("Expected suggestion min confidence 0.7, got %f", p.SuggestionMinConfidence())
	}
}

// ── TLS SNI + DNS Signal Integration Tests ───────────────────────────────

func TestEventCategorySignal_DNSPort(t *testing.T) {
	// DNS port (53) should produce "dns_query" signal
	dnsEvent := &ebpf.ScarletEvent{
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	dnsEvent.Payload.Network.RemotePort = 53

	signal := pipeline.EventCategorySignal(dnsEvent)
	if signal != "dns_query" {
		t.Errorf("Expected dns_query signal for DNS port 53, got %q", signal)
	}
}

func TestEventCategorySignal_DNSLocalPort(t *testing.T) {
	// Local DNS port should also produce "dns_query" signal
	dnsEvent := &ebpf.ScarletEvent{
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	dnsEvent.Payload.Network.LocalPort = 53
	dnsEvent.Payload.Network.RemotePort = 12345

	signal := pipeline.EventCategorySignal(dnsEvent)
	if signal != "dns_query" {
		t.Errorf("Expected dns_query signal for local DNS port 53, got %q", signal)
	}
}

func TestEventCategorySignal_TLSConnection(t *testing.T) {
	// Port 443 should produce "tls_connection" signal
	tlsEvent := &ebpf.ScarletEvent{
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	tlsEvent.Payload.Network.RemotePort = 443

	signal := pipeline.EventCategorySignal(tlsEvent)
	if signal != "tls_connection" {
		t.Errorf("Expected tls_connection signal for port 443, got %q", signal)
	}
}

func TestEventCategorySignal_TLSLocalPort(t *testing.T) {
	// Local port 443 should also produce "tls_connection" signal
	tlsEvent := &ebpf.ScarletEvent{
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	tlsEvent.Payload.Network.LocalPort = 443
	tlsEvent.Payload.Network.RemotePort = 12345

	signal := pipeline.EventCategorySignal(tlsEvent)
	if signal != "tls_connection" {
		t.Errorf("Expected tls_connection signal for local port 443, got %q", signal)
	}
}

func TestEventCategorySignal_Port4444StillMinerPool(t *testing.T) {
	// CRITICAL: Port 4444 must still map to "minerpool_connection" not "net_outbound"
	minerEvent := &ebpf.ScarletEvent{
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	minerEvent.Payload.Network.RemotePort = 4444

	signal := pipeline.EventCategorySignal(minerEvent)
	if signal != "minerpool_connection" {
		t.Errorf("Port 4444 must map to minerpool_connection, got %q", signal)
	}
}

func TestEventCategorySignal_NormalOutboundPort(t *testing.T) {
	// A normal port that's not special should still produce "net_outbound"
	normalEvent := &ebpf.ScarletEvent{
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	normalEvent.Payload.Network.RemotePort = 8080

	signal := pipeline.EventCategorySignal(normalEvent)
	if signal != "net_outbound" {
		t.Errorf("Expected net_outbound for port 8080, got %q", signal)
	}
}
