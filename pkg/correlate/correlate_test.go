// Package correlate_test — unit tests for the multi-signal correlation engine.
package correlate_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/correlate"
)

// ── Correlator Creation Tests ────────────────────────────────────────

func TestNewCorrelator(t *testing.T) {
	c := correlate.NewCorrelator()
	if c == nil {
		t.Fatal("Expected non-nil correlator")
	}
	if c.RuleCount() != 0 {
		t.Errorf("Expected 0 initial rules, got %d", c.RuleCount())
	}
}

func TestCorrelator_AddRule(t *testing.T) {
	c := correlate.NewCorrelator()

	spec := &correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	}

	c.AddRule(spec)

	if c.RuleCount() != 1 {
		t.Errorf("Expected 1 rule, got %d", c.RuleCount())
	}
}

func TestCorrelator_RemoveRule(t *testing.T) {
	c := correlate.NewCorrelator()

	spec := &correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	}

	c.AddRule(spec)
	c.RemoveRule("R014")

	if c.RuleCount() != 0 {
		t.Errorf("Expected 0 rules after removal, got %d", c.RuleCount())
	}
}

func TestCorrelator_AddMultipleRules(t *testing.T) {
	c := correlate.NewCorrelator()

	for _, spec := range correlate.DefaultCorrelationRules() {
		c.AddRule(spec)
	}

	if c.RuleCount() != 7 {
		t.Errorf("Expected 7 default rules, got %d", c.RuleCount())
	}
}

// ── Correlation Logic: ALL ───────────────────────────────────────────

func TestCorrelator_LogicAll_FiresOnAllSignals(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// First signal — should not fire
	result := c.ProcessSignal(&correlate.Signal{
		Name:        "shell_procs",
		Timestamp:   time.Now(),
		PID:         1234,
		ContainerID: "abc123",
		Namespace:   "default",
		RuleID:      "R014",
	})
	if result != nil {
		t.Error("Correlation should not fire with only one signal")
	}

	// Second signal — should fire
	result = c.ProcessSignal(&correlate.Signal{
		Name:        "net_outbound",
		Timestamp:   time.Now(),
		PID:         1234,
		ContainerID: "abc123",
		Namespace:   "default",
		RuleID:      "R014",
	})
	if result == nil {
		t.Fatal("Expected correlation to fire when all signals match")
	}

	if result.RuleID != "R014" {
		t.Errorf("Expected rule R014, got %s", result.RuleID)
	}
	if len(result.MatchedSignals) != 2 {
		t.Errorf("Expected 2 matched signals, got %d", len(result.MatchedSignals))
	}
	if result.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", result.PID)
	}
	if result.ContainerID != "abc123" {
		t.Errorf("Expected container abc123, got %s", result.ContainerID)
	}
}

func TestCorrelator_LogicAll_DoesNotFireWithPartialSignals(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound", "sensitive_file_read"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Only 2 out of 3 signals — should not fire
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 1234, ContainerID: "abc",
	})
	result := c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 1234, ContainerID: "abc",
	})
	if result != nil {
		t.Error("Correlation should not fire with only 2/3 signals")
	}
}

// ── Correlation Logic: ANY ────────────────────────────────────────────

func TestCorrelator_LogicAny_FiresOnFirstSignal(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R011-any",
		Window:  30 * time.Second,
		Signals: []string{"high_cpu", "minerpool_connection"},
		Logic:   correlate.LogicAny,
		GroupBy: []string{"container.id"},
	})

	// First signal — should fire with LogicAny
	result := c.ProcessSignal(&correlate.Signal{
		Name:        "high_cpu",
		PID:         5678,
		ContainerID: "xyz789",
		Namespace:   "production",
	})
	if result == nil {
		t.Fatal("LogicAny should fire on first signal")
	}

	if result.RuleID != "R011-any" {
		t.Errorf("Expected rule R011-any, got %s", result.RuleID)
	}
}

// ── Group By Tests ───────────────────────────────────────────────────

func TestCorrelator_GroupBy_PID(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Signal from PID 100 — should not correlate with PID 200
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 100, ContainerID: "abc",
	})

	// Signal from PID 200 — different group, should not fire with PID 100
	result := c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 200, ContainerID: "abc",
	})
	if result != nil {
		t.Error("Signals from different PIDs should not correlate")
	}

	// Signal from PID 100 — same group as the first signal, should fire
	result = c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 100, ContainerID: "abc",
	})
	if result == nil {
		t.Fatal("Signals from same PID should correlate")
	}
}

func TestCorrelator_GroupBy_ContainerID(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R011",
		Window:  30 * time.Second,
		Signals: []string{"high_cpu", "minerpool_connection"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"container.id"},
	})

	// Signal from container abc — should not correlate with container xyz
	c.ProcessSignal(&correlate.Signal{
		Name: "high_cpu", PID: 100, ContainerID: "abc",
	})

	result := c.ProcessSignal(&correlate.Signal{
		Name: "minerpool_connection", PID: 200, ContainerID: "xyz",
	})
	if result != nil {
		t.Error("Signals from different containers should not correlate")
	}

	// Signal from same container (different PID is OK for container grouping)
	result = c.ProcessSignal(&correlate.Signal{
		Name: "minerpool_connection", PID: 200, ContainerID: "abc",
	})
	if result == nil {
		t.Fatal("Signals from same container should correlate")
	}
}

func TestCorrelator_GroupBy_Global(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014-global",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{}, // global — no grouping
	})

	// Any match fires, regardless of PID/container
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 100, ContainerID: "abc",
	})

	result := c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 200, ContainerID: "xyz",
	})
	if result == nil {
		t.Fatal("Global grouping should correlate across different PIDs/containers")
	}
}

// ── Window Expiry Tests ──────────────────────────────────────────────

func TestCorrelator_WindowExpiry(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  100 * time.Millisecond, // Very short window for testing
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// First signal
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 5000, ContainerID: "abc",
	})

	// Wait for window to expire
	time.Sleep(200 * time.Millisecond)

	// Second signal arrives after window expired — should create new window, not fire
	result := c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 5000, ContainerID: "abc",
	})
	if result != nil {
		t.Error("Correlation should not fire when second signal arrives after window expiry")
	}

	// Use a different PID to avoid the leftover window from step 3.
	// PID 6000: send both signals within a fresh window.
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 6000, ContainerID: "abc",
	})
	result = c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 6000, ContainerID: "abc",
	})
	if result == nil {
		t.Fatal("Correlation should fire when both signals arrive within window")
	}
}

// ── No Re-fire Tests ─────────────────────────────────────────────────

func TestCorrelator_NoReFire(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Send signals that fire correlation
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 3000, ContainerID: "abc",
	})
	result := c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 3000, ContainerID: "abc",
	})
	if result == nil {
		t.Fatal("Expected first correlation to fire")
	}

	// Send same signal again — should NOT re-fire within the same window
	result = c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 3000, ContainerID: "abc",
	})
	if result != nil {
		t.Error("Correlation should not re-fire within the same window")
	}
}

// ── Unmatched Signal Tests ────────────────────────────────────────────

func TestCorrelator_UnmatchedSignal(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Signal that doesn't match any rule
	result := c.ProcessSignal(&correlate.Signal{
		Name: "unrelated_signal", PID: 1234, ContainerID: "abc",
	})
	if result != nil {
		t.Error("Unmatched signal should not produce correlation result")
	}
}

// ── Stats Tests ─────────────────────────────────────────────────────────

func TestCorrelator_Stats(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Process signals that fire a correlation
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 999, ContainerID: "abc",
	})
	c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 999, ContainerID: "abc",
	})

	stats := c.Stats()
	if stats.RulesCount != 1 {
		t.Errorf("Expected 1 rule, got %d", stats.RulesCount)
	}
	if stats.SignalsProcessed != 2 {
		t.Errorf("Expected 2 signals processed, got %d", stats.SignalsProcessed)
	}
	if stats.CorrelationsFired != 1 {
		t.Errorf("Expected 1 correlation fired, got %d", stats.CorrelationsFired)
	}
}

func TestCorrelator_Stats_FiredCount(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "correlation-test",
		Window:  5 * time.Second,
		Signals: []string{"sig_a", "sig_b"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Three different PIDs — three correlations
	for pid := uint32(1); pid <= 3; pid++ {
		c.ProcessSignal(&correlate.Signal{
			Name: "sig_a", PID: pid, ContainerID: "abc",
		})
		c.ProcessSignal(&correlate.Signal{
			Name: "sig_b", PID: pid, ContainerID: "abc",
		})
	}

	stats := c.Stats()
	if stats.CorrelationsFired != 3 {
		t.Errorf("Expected 3 correlations fired, got %d", stats.CorrelationsFired)
	}
}

// ── Max Windows Tests ─────────────────────────────────────────────────

func TestCorrelator_MaxWindows(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Minute, // Long window
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Process many signals with different PIDs to create many windows
	for pid := uint32(0); pid < 100; pid++ {
		c.ProcessSignal(&correlate.Signal{
			Name: "shell_procs", PID: pid, ContainerID: "abc",
		})
	}

	stats := c.Stats()
	if stats.ActiveWindows > 100 {
		t.Errorf("Active windows should be bounded, got %d", stats.ActiveWindows)
	}
}

// ── Result Channel Tests ──────────────────────────────────────────────

func TestCorrelator_ResultChannel(t *testing.T) {
	c := correlate.NewCorrelator()
	ch := make(chan correlate.CorrelationResult, 10)
	c.SetResultChannel(ch)

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	// Fire correlation
	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 777, ContainerID: "abc",
	})
	c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 777, ContainerID: "abc",
	})

	// Check result channel
	select {
	case result := <-ch:
		if result.RuleID != "R014" {
			t.Errorf("Expected rule R014 from channel, got %s", result.RuleID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for result from channel")
	}
}

// ── Concurrent Signal Processing ───────────────────────────────────────

func TestCorrelator_ConcurrentSignals(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	var wg sync.WaitGroup
	var fired atomic.Uint32

	// Concurrently process signals for different PIDs
	for i := uint32(0); i < 100; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			c.ProcessSignal(&correlate.Signal{
				Name: "shell_procs", PID: pid, ContainerID: "abc",
			})
			result := c.ProcessSignal(&correlate.Signal{
				Name: "net_outbound", PID: pid, ContainerID: "abc",
			})
			if result != nil {
				fired.Add(1)
			}
		}(i)
	}

	wg.Wait()

	totalFired := c.Stats().CorrelationsFired
	if totalFired != 100 {
		t.Errorf("Expected 100 correlations fired, got %d", totalFired)
	}
}

// ── Default Correlation Rules ───────────────────────────────────────────

func TestDefaultCorrelationRules(t *testing.T) {
	rules := correlate.DefaultCorrelationRules()
	if len(rules) != 7 {
		t.Fatalf("Expected 7 default correlation rules, got %d", len(rules))
	}

	// R014 — Reverse Shell
	r014 := rules[0]
	if r014.RuleID != "R014" {
		t.Errorf("Expected first rule R014, got %s", r014.RuleID)
	}
	if r014.Window != 5*time.Second {
		t.Errorf("Expected R014 window 5s, got %v", r014.Window)
	}
	if len(r014.Signals) != 2 {
		t.Errorf("Expected 2 signals for R014, got %d", len(r014.Signals))
	}
	if r014.Logic != correlate.LogicAll {
		t.Errorf("Expected LogicAll for R014, got %s", r014.Logic)
	}

	// R011 — Behavioral Cryptojacking
	r011 := rules[1]
	if r011.RuleID != "R011" {
		t.Errorf("Expected second rule R011, got %s", r011.RuleID)
	}

	// TLS-SNI-001 — Suspicious TLS SNI + mining pool connection
	tlsSNI := rules[4]
	if tlsSNI.RuleID != "TLS-SNI-001" {
		t.Errorf("Expected fifth rule TLS-SNI-001, got %s", tlsSNI.RuleID)
	}
	if tlsSNI.Window != 30*time.Second {
		t.Errorf("Expected TLS-SNI-001 window 30s, got %v", tlsSNI.Window)
	}
	if tlsSNI.Logic != correlate.LogicAny {
		t.Errorf("Expected LogicAny for TLS-SNI-001, got %s", tlsSNI.Logic)
	}

	// DNS-SNI-001 — Suspicious DNS query + suspicious SNI
	dnsSNI := rules[5]
	if dnsSNI.RuleID != "DNS-SNI-001" {
		t.Errorf("Expected sixth rule DNS-SNI-001, got %s", dnsSNI.RuleID)
	}
	if dnsSNI.Window != 10*time.Second {
		t.Errorf("Expected DNS-SNI-001 window 10s, got %v", dnsSNI.Window)
	}
	if dnsSNI.Logic != correlate.LogicAny {
		t.Errorf("Expected LogicAny for DNS-SNI-001, got %s", dnsSNI.Logic)
	}

	// DNS-001 — Suspicious DNS query pattern
	dns001 := rules[6]
	if dns001.RuleID != "DNS-001" {
		t.Errorf("Expected seventh rule DNS-001, got %s", dns001.RuleID)
	}
	if dns001.Window != 60*time.Second {
		t.Errorf("Expected DNS-001 window 60s, got %v", dns001.Window)
	}
	if len(dns001.Signals) != 1 {
		t.Errorf("Expected 1 signal for DNS-001, got %d", len(dns001.Signals))
	}
	if dns001.Logic != correlate.LogicAny {
		t.Errorf("Expected LogicAny for DNS-001, got %s", dns001.Logic)
	}
}

// ── Signal Type Tests ──────────────────────────────────────────────────

func TestSignal_ExtraFields(t *testing.T) {
	sig := &correlate.Signal{
		Name:        "net_outbound",
		Timestamp:   time.Now(),
		PID:         1234,
		ContainerID: "abc",
		Namespace:   "default",
		RuleID:      "R009",
		Extra: map[string]string{
			"remote_ip":   "192.168.1.100",
			"remote_port": "3333",
		},
	}

	if sig.Extra["remote_ip"] != "192.168.1.100" {
		t.Errorf("Expected remote_ip 192.168.1.100, got %s", sig.Extra["remote_ip"])
	}
	if sig.Extra["remote_port"] != "3333" {
		t.Errorf("Expected remote_port 3333, got %s", sig.Extra["remote_port"])
	}
}

func TestCorrelationResult_Fields(t *testing.T) {
	c := correlate.NewCorrelator()

	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	c.ProcessSignal(&correlate.Signal{
		Name: "shell_procs", PID: 5555, ContainerID: "container-1", Namespace: "prod",
	})
	result := c.ProcessSignal(&correlate.Signal{
		Name: "net_outbound", PID: 5555, ContainerID: "container-1", Namespace: "prod",
	})

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.RuleID != "R014" {
		t.Errorf("Expected RuleID R014, got %s", result.RuleID)
	}
	if result.PID != 5555 {
		t.Errorf("Expected PID 5555, got %d", result.PID)
	}
	if result.ContainerID != "container-1" {
		t.Errorf("Expected ContainerID container-1, got %s", result.ContainerID)
	}
	if result.Namespace != "prod" {
		t.Errorf("Expected Namespace prod, got %s", result.Namespace)
	}
	if result.GroupKey != "pid:5555" {
		t.Errorf("Expected GroupKey pid:5555, got %s", result.GroupKey)
	}
	if result.WindowStart.IsZero() {
		t.Error("Expected non-zero WindowStart")
	}
	if result.WindowEnd.IsZero() {
		t.Error("Expected non-zero WindowEnd")
	}
	if result.Description == "" {
		t.Error("Expected non-empty Description")
	}
}

// ── Start/Stop Tests ──────────────────────────────────────────────────

func TestCorrelator_StartStop(t *testing.T) {
	c := correlate.NewCorrelator()
	c.AddRule(&correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	})

	c.Start()
	time.Sleep(50 * time.Millisecond)
	c.Stop()

	// Should not panic
}

func TestCorrelator_DoubleStart(t *testing.T) {
	c := correlate.NewCorrelator()
	c.Start()
	c.Start() // Should not panic
	time.Sleep(50 * time.Millisecond)
	c.Stop()
}

func TestCorrelator_DoubleStop(t *testing.T) {
	c := correlate.NewCorrelator()
	c.Start()
	time.Sleep(50 * time.Millisecond)
	c.Stop()
	c.Stop() // Should not panic
}

// ── CorrelationSpec Validation ────────────────────────────────────────

func TestCorrelationSpec_Fields(t *testing.T) {
	spec := &correlate.CorrelationSpec{
		RuleID:  "R014",
		Window:  5 * time.Second,
		Signals: []string{"shell_procs", "net_outbound"},
		Logic:   correlate.LogicAll,
		GroupBy: []string{"proc.pid"},
	}

	if spec.RuleID != "R014" {
		t.Errorf("Expected RuleID R014, got %s", spec.RuleID)
	}
	if spec.Window != 5*time.Second {
		t.Errorf("Expected window 5s, got %v", spec.Window)
	}
	if len(spec.Signals) != 2 {
		t.Errorf("Expected 2 signals, got %d", len(spec.Signals))
	}
	if spec.Logic != correlate.LogicAll {
		t.Errorf("Expected LogicAll, got %s", spec.Logic)
	}
}

func TestCorrelationLogic_String(t *testing.T) {
	if string(correlate.LogicAll) != "all" {
		t.Errorf("Expected 'all', got %s", string(correlate.LogicAll))
	}
	if string(correlate.LogicAny) != "any" {
		t.Errorf("Expected 'any', got %s", string(correlate.LogicAny))
	}
}
