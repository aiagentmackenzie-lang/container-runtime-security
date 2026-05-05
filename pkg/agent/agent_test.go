// Package agent_test — tests for agent component wiring.
package agent_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/agent"
	"github.com/securityscarlet/runtime/pkg/ai"
	"github.com/securityscarlet/runtime/pkg/correlate"
	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/enrichment"
	"github.com/securityscarlet/runtime/pkg/output"
	"github.com/securityscarlet/runtime/pkg/pipeline"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Agent Wiring Tests ──────────────────────────────────────────────────

func TestAgent_DefaultConfig_Valid(t *testing.T) {
	cfg := agent.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default config should be valid: %v", err)
	}
}

func TestAgent_ConfigAISection(t *testing.T) {
	cfg := agent.DefaultConfig()

	if cfg.AI.Enabled {
		t.Error("AI should be disabled by default")
	}
	if cfg.AI.Endpoint == "" {
		t.Error("AI endpoint should have a default value")
	}
	if cfg.AI.AnomalyThreshold != 0.8 {
		t.Errorf("Expected anomaly threshold 0.8, got %f", cfg.AI.AnomalyThreshold)
	}
}

func TestAgent_ConfigAIValidation(t *testing.T) {
	cfg := agent.DefaultConfig()
	cfg.AI.Enabled = true
	cfg.AI.Endpoint = "" // Missing endpoint

	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation error for missing AI endpoint")
	}
}

func TestAgent_ConfigAIInvalidThreshold(t *testing.T) {
	cfg := agent.DefaultConfig()
	cfg.AI.Enabled = true
	cfg.AI.Endpoint = "scarlet-ai:9443"
	cfg.AI.AnomalyThreshold = 1.5 // Out of range

	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation error for out-of-range anomaly threshold")
	}
}

// ── Component Creation Tests ────────────────────────────────────────────

func TestComponentCreation_TCLoader(t *testing.T) {
	tcLoader := ebpf.NewTCLoader(ebpf.TCLoaderConfig{
		BPFObjectDir: "/opt/scarlet/bpf",
		Interfaces:   []string{"eth0"},
	})

	if tcLoader == nil {
		t.Fatal("Expected non-nil TC loader")
	}
	if !tcLoader.IsMockMode() {
		// On non-Linux, should be in mock mode
		t.Log("TC loader not in mock mode (running on Linux with BPF)")
	}
}

func TestComponentCreation_NetworkEnforcer(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()
	if ne == nil {
		t.Fatal("Expected non-nil network enforcer")
	}
	ne.Start()
	defer ne.Stop()
}

func TestComponentCreation_Correlator(t *testing.T) {
	correl := correlate.NewCorrelator()
	if correl == nil {
		t.Fatal("Expected non-nil correlator")
	}
	correl.Start()
	defer correl.Stop()
}

func TestComponentCreation_AIConnector(t *testing.T) {
	conn := ai.NewAIConnector(ai.AIConnectorConfig{
		Endpoint: "localhost:9443",
		Timeout:  5 * time.Second,
		Enabled:  false,
	})
	if conn == nil {
		t.Fatal("Expected non-nil AI connector")
	}
}

// ── Component Wiring Tests ──────────────────────────────────────────────

func TestWiring_TCLOader_NetworkEnforcer(t *testing.T) {
	// Create TC loader
	tcLoader := ebpf.NewTCLoader(ebpf.TCLoaderConfig{
		BPFObjectDir: "/tmp/nonexistent",
		Interfaces:   []string{"eth0"},
	})
	tcLoader.Load()

	// Create network enforcer
	ne := enforcement.NewNetworkEnforcer()

	// Wire TC loader to network enforcer
	ne.SetTCLoader(tcLoader)

	// Verify the wiring by checking that blocks work
	err := ne.BlockMiningPool(netIP("1.2.3.4"), 3333)
	if err != nil {
		t.Errorf("BlockMiningPool should not error with TC loader: %v", err)
	}

	// Verify block was registered
	if ne.BlockCount() != 1 {
		t.Errorf("Expected 1 block, got %d", ne.BlockCount())
	}
}

func TestWiring_Correlator_DefaultRules(t *testing.T) {
	correl := correlate.NewCorrelator()

	// Register default correlation rules (simulates pipeline InitCorrelationRules)
	for _, spec := range correlate.DefaultCorrelationRules() {
		correl.AddRule(spec)
	}

	stats := correl.Stats()
	if stats.RulesCount < 4 {
		t.Errorf("Expected at least 4 default correlation rules, got %d", stats.RulesCount)
	}
}

func TestWiring_Correlator_ReverseShellPattern(t *testing.T) {
	correl := correlate.NewCorrelator()
	correl.Start()
	defer correl.Stop()

	// Add R014 reverse shell correlation
	correl.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Send shell_procs signal
	result := correl.ProcessSignal(&correlate.Signal{
		Name:       "shell_procs",
		Timestamp:  time.Now(),
		PID:        1234,
		ContainerID: "container-abc",
		Namespace:  "default",
	})
	if result != nil {
		t.Error("Correlation should not fire with only one signal")
	}

	// Send net_outbound signal for same PID
	result = correl.ProcessSignal(&correlate.Signal{
		Name:       "net_outbound",
		Timestamp:  time.Now(),
		PID:        1234,
		ContainerID: "container-abc",
		Namespace:  "default",
	})
	if result == nil {
		t.Error("Correlation should fire when both signals arrive")
	}
	if result.RuleID != "R014" {
		t.Errorf("Expected correlation for R014, got %s", result.RuleID)
	}
}

func TestWiring_AIConnector_TriageAlert(t *testing.T) {
	conn := ai.NewAIConnector(ai.AIConnectorConfig{
		Endpoint: "localhost:9443",
		Timeout:  1 * time.Second,
		Enabled:  false, // Disabled — should return neutral results
	})

	// Triage alert when AI is disabled
	fpScore, priority, reasoning := conn.TriageAlert("R008", "CRITICAL", "default", "test-container")

	if fpScore != 0.5 {
		t.Errorf("Expected neutral FP score 0.5 when AI disabled, got %f", fpScore)
	}
	if priority != "CRITICAL" {
		t.Errorf("Expected original priority 'CRITICAL' when AI disabled, got %s", priority)
	}
	if reasoning == "" {
		t.Error("Expected non-empty reasoning")
	}
}

func TestWiring_AIConnector_DisabledDegradesGracefully(t *testing.T) {
	conn := ai.NewAIConnector(ai.AIConnectorConfig{
		Endpoint: "localhost:9443",
		Timeout:  1 * time.Second,
		Enabled:  false,
	})

	// Analyze event should return neutral result
	result, err := conn.AnalyzeEvent(context.Background(), &ai.AIEvent{
		EventType:   "execve",
		ProcessName: "xmrig",
		PID:         1234,
		Category:    "PROCESS",
	})
	if err != nil {
		t.Errorf("Should not error when AI disabled: %v", err)
	}
	if result.AnomalyScore != 0.0 {
		t.Errorf("Expected 0.0 anomaly score when AI disabled, got %f", result.AnomalyScore)
	}
}

func TestWiring_NetworkEnforcer_BlockFromRule(t *testing.T) {
	ne := enforcement.NewNetworkEnforcer()

	// Block from R009 mining pool
	err := ne.BlockMiningPool(netIP("185.232.21.2"), 3333)
	if err != nil {
		t.Errorf("BlockMiningPool should not error: %v", err)
	}

	// Block from R027 C2 port
	err = ne.BlockC2Port(netIP("10.0.0.5"), 4444)
	if err != nil {
		t.Errorf("BlockC2Port should not error: %v", err)
	}

	// Block from R019 cloud metadata
	err = ne.BlockCloudMetadata()
	if err != nil {
		t.Errorf("BlockCloudMetadata should not error: %v", err)
	}

	if ne.BlockCount() != 3 {
		t.Errorf("Expected 3 blocks, got %d", ne.BlockCount())
	}

	// Verify blocks by rule
	stats := ne.Stats()
	if stats.BlocksByRule["R009"] != 1 {
		t.Errorf("Expected 1 R009 block, got %d", stats.BlocksByRule["R009"])
	}
	if stats.BlocksByRule["R027"] != 1 {
		t.Errorf("Expected 1 R027 block, got %d", stats.BlocksByRule["R027"])
	}
	if stats.BlocksByRule["R019"] != 1 {
		t.Errorf("Expected 1 R019 block, got %d", stats.BlocksByRule["R019"])
	}
}

// ── Full Agent Startup Smoke Test ────────────────────────────────────

func TestAgent_NewAgent(t *testing.T) {
	cfg := agent.DefaultConfig()
	cfg.Agent.Mode = "audit"

	a, err := agent.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	if a == nil {
		t.Fatal("Expected non-nil agent")
	}

	status := a.GetStatus()
	if status.Mode != agent.ModeAudit {
		t.Errorf("Expected audit mode, got %s", status.Mode)
	}
}

func TestAgent_ModeFromString(t *testing.T) {
	tests := map[string]bool{
		"audit":    true,
		"enforce":  true,
		"simulate": true,
		"invalid":  false,
		"":         false,
	}

	for mode, valid := range tests {
		_, err := agent.ModeFromString(mode)
		if valid && err != nil {
			t.Errorf("Mode %q should be valid: %v", mode, err)
		}
		if !valid && err == nil {
			t.Errorf("Mode %q should be invalid", mode)
		}
	}
}

// ── Agent Integration Test ──────────────────────────────────────────

func TestAgent_Integration_AllComponentsWired(t *testing.T) {
	// Create all components manually (mirrors agent.initComponents order)
	// to verify component creation and wiring

	// 1. Metrics exporter
	metrics := output.NewMetricsExporter(0) // port 0 = disabled
	if metrics == nil {
		t.Fatal("Expected non-nil metrics exporter")
	}

	// 2. Alert emitter
	alertEmit, err := output.NewAlertEmitter(output.AlertEmitterConfig{
		AlertFile: "", // empty = use stdout (file-less test)
		Mode:      "audit",
	})
	if err != nil {
		t.Fatalf("Failed to create alert emitter: %v", err)
	}
	defer alertEmit.Close()

	// 3. Enrichment manager
	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/run/containerd/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 100,
		PIDCacheTTL:  30 * time.Second,
	})
	if err != nil {
		t.Logf("Enrichment manager creation returned error (expected in test env): %v", err)
	}

	// 4. Rule engine
	ruleEngine, err := rules.NewEngine(rules.EngineConfig{
		DefaultMode: "audit",
	})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}
	if ruleEngine == nil {
		t.Fatal("Expected non-nil rule engine")
	}
	ruleCount := ruleEngine.RuleCount()
	if ruleCount == 0 {
		t.Error("Expected rule engine to have rules loaded")
	}

	// 5. eBPF loader
	loader := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    "/tmp/nonexistent",
		EventBufferSize: 2048,
	})
	if loader == nil {
		t.Fatal("Expected non-nil eBPF loader")
	}

	// 6. Network enforcer + TC loader
	netEnforcer := enforcement.NewNetworkEnforcer()
	tcLoader := ebpf.NewTCLoader(ebpf.TCLoaderConfig{
		BPFObjectDir: "/tmp/nonexistent",
		Interfaces:   []string{"eth0"},
	})
	tcLoader.Load()
	netEnforcer.SetTCLoader(tcLoader)
	netEnforcer.Start()
	defer netEnforcer.Stop()

	// Verify TC loader is wired
	blockCount := netEnforcer.BlockCount()
	t.Logf("Initial block count: %d", blockCount)

	// 7. Correlator
	correlator := correlate.NewCorrelator()
	correlator.Start()
	defer correlator.Stop()

	// Register default correlation rules
	for _, spec := range correlate.DefaultCorrelationRules() {
		correlator.AddRule(spec)
	}
	correlStats := correlator.Stats()
	if correlStats.RulesCount < 4 {
		t.Errorf("Expected at least 4 default correlation rules, got %d", correlStats.RulesCount)
	}

	// 8. AI connector
	aiConnector := ai.NewAIConnector(ai.AIConnectorConfig{
		Endpoint: "localhost:9443",
		Timeout:  5 * time.Second,
		Enabled:  false, // Disabled for test
	})
	if aiConnector == nil {
		t.Fatal("Expected non-nil AI connector")
	}
	if aiConnector.IsEnabled() {
		t.Error("AI connector should be disabled in test config")
	}

	// 9. Pipeline with all components
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		Mode:            "audit",
		RuleEngine:      ruleEngine,
		Enricher:        enricher,
		AlertEmitter:    alertEmit,
		MetricsExporter: metrics,
		NetworkEnforcer: netEnforcer,
		Correlator:      correlator,
		AIConnector:     aiConnector,
	})

	// Wire intelligence components into pipeline
	p.SetAIAlertTrier(aiConnector)
	p.SetAIRuleSuggester(aiConnector)
	p.InitCorrelationRules()

	if p == nil {
		t.Fatal("Expected non-nil pipeline")
	}

	// Verify all pipeline components
	if !p.IsAnomalyEnabled() {
		t.Error("Expected anomaly scoring to be enabled by default")
	}
	if p.AnomalyThreshold() != 0.8 {
		t.Errorf("Expected default anomaly threshold 0.8, got %f", p.AnomalyThreshold())
	}
	if p.GetAIRuleSuggester() == nil {
		t.Error("Expected AI rule suggester to be wired")
	}
	if p.SuggestionMinConfidence() != 0.5 {
		t.Errorf("Expected default suggestion min confidence 0.5, got %f", p.SuggestionMinConfidence())
	}

	// Verify AI connector satisfies both interfaces
	var _ pipeline.AIAlertTrier = aiConnector    // AIAlertTrier interface
	var _ pipeline.AIRuleSuggester = aiConnector // AIRuleSuggester interface

	t.Logf("All components wired successfully: rules=%d correlator_rules=%d",
		ruleCount, correlStats.RulesCount)
}

func TestAgent_Integration_DefaultConfigValues(t *testing.T) {
	cfg := agent.DefaultConfig()

	// Verify default config values for Phase 3 intelligence features
	if cfg.AI.Enabled {
		t.Error("Expected AI to be disabled by default")
	}
	if cfg.AI.Endpoint != "scarlet-ai:9443" {
		t.Errorf("Expected default AI endpoint 'scarlet-ai:9443', got %q", cfg.AI.Endpoint)
	}
	if cfg.AI.AnomalyThreshold != 0.8 {
		t.Errorf("Expected default anomaly threshold 0.8, got %f", cfg.AI.AnomalyThreshold)
	}
}

// ── Helpers ────────────────────────────────────────────────────────────

func netIP(s string) net.IP {
	return net.ParseIP(s)
}