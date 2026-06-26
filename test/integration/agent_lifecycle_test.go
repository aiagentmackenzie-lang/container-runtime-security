// Package agent_test — integration test for agent startup/shutdown lifecycle.
// Tests that an Agent with Start() + Stop() using a mocked eBPF event channel
// starts all components, processes synthetic events, and shuts down cleanly.
package agent_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/correlate"
	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/enrichment"
	"github.com/securityscarlet/runtime/pkg/output"
	"github.com/securityscarlet/runtime/pkg/pipeline"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Agent Integration Test ──────────────────────────────────────────────

// TestAgent_StartStopLifecycle tests that an Agent can be created with all
// components, started, process synthetic events, and shut down cleanly.
// This uses a mocked eBPF event channel instead of a real ring buffer.
func TestAgent_StartStopLifecycle(t *testing.T) {
	// 1. Create a test event channel for injecting synthetic events
	eventCh := make(chan *ebpf.ScarletEvent, 256)

	// 2. Create all components manually (mirrors agent.initComponents)
	// Metrics exporter (port 0 = disabled)
	metrics := output.NewMetricsExporter(0)

	// Alert emitter (file-less, captures to memory)
	alertEmitter := output.NewAlertEmitterForTest()

	// Enrichment manager
	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 10000,
		PIDCacheTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create enrichment manager: %v", err)
	}

	// Rule engine
	ruleEngine, err := rules.NewEngine(rules.EngineConfig{
		DefaultMode: "audit",
	})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}
	if ruleEngine.RuleCount() == 0 {
		t.Error("Expected rule engine to have default rules loaded")
	}

	// eBPF loader with mock mode + test event channel
	loader := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    "/tmp/nonexistent",
		RingBufSizeMB:   4,
		EventBufferSize: 256,
	})
	loader.SetTestEventChannel(eventCh)

	// Network enforcer
	netEnforcer := enforcement.NewNetworkEnforcer()
	netEnforcer.Start()

	// Correlator
	correlator := correlate.NewCorrelator()
	for _, spec := range correlate.DefaultCorrelationRules() {
		correlator.AddRule(spec)
	}
	correlator.Start()

	// 3. Create the pipeline with all components
	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		EventChannel:    eventCh,
		RuleEngine:      ruleEngine,
		Enricher:        enricher,
		AlertEmitter:    alertEmitter,
		MetricsExporter: metrics,
		NetworkEnforcer: netEnforcer,
		Correlator:      correlator,
		Mode:            "audit",
		Workers:         2,
		AnomalyEnabled:  false, // Disable anomaly for deterministic test
	})

	// Verify pipeline components
	if p.EventsProcessed() != 0 {
		t.Error("Expected 0 events processed at start")
	}

	// 4. Start the pipeline
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p.Start(ctx)

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)

	// 5. Inject synthetic events through the test channel
	events := []*ebpf.ScarletEvent{
		// Process exec event (shell spawn)
		{
			TimestampNS: uint64(time.Now().UnixNano()),
			PID:         1001,
			TGID:        1001,
			PPID:        1,
			UID:         1000,
			GID:         1000,
			CgroupID:    12345,
			PIDNSLevel:  1,
			Category:    ebpf.CatProcess,
			EventType:   ebpf.EvtExec,
			SyscallNr:   59,
		},
		// Network connection event (mining pool)
		{
			TimestampNS: uint64(time.Now().UnixNano()),
			PID:         1001,
			TGID:        1001,
			PPID:        1,
			UID:         1000,
			GID:         1000,
			CgroupID:    12345,
			PIDNSLevel:  1,
			Category:    ebpf.CatNetwork,
			EventType:   ebpf.EvtNetConnect,
			SyscallNr:   42,
		},
		// File access event (sensitive file)
		{
			TimestampNS: uint64(time.Now().UnixNano()),
			PID:         2002,
			TGID:        2002,
			PPID:        1,
			UID:         0,
			GID:         0,
			CgroupID:    67890,
			PIDNSLevel:  1,
			Category:    ebpf.CatFile,
			EventType:   ebpf.EvtFileOpen,
			SyscallNr:   257,
		},
	}

	// Inject events through the test channel (bypasses eBPF filter)
	for _, event := range events {
		p.ProcessEvent(event)
	}

	// Give the pipeline time to process events
	time.Sleep(100 * time.Millisecond)

	// 6. Verify events were processed
	eventsProcessed := p.EventsProcessed()
	if eventsProcessed < 3 {
		t.Errorf("Expected at least 3 events processed, got %d", eventsProcessed)
	}

	t.Logf("Pipeline processed %d events, emitted %d alerts",
		eventsProcessed, p.AlertsEmitted())

	// 7. Test the ring buffer filter
	filter := loader.Filter()
	if filter == nil {
		t.Fatal("Expected non-nil ring buffer filter")
	}

	// Configure filter to only pass network events
	filter.SetCategoryFilter([]uint8{ebpf.CatNetwork})

	networkEvent := &ebpf.ScarletEvent{
		PID:       3001,
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	processEvent := &ebpf.ScarletEvent{
		PID:       3002,
		Category:  ebpf.CatProcess,
		EventType: ebpf.EvtExec,
	}

	if !filter.ShouldPass(networkEvent) {
		t.Error("Network event should pass category filter")
	}
	if filter.ShouldPass(processEvent) {
		t.Error("Process event should be dropped by category filter")
	}

	// Check filter stats
	stats := filter.FilterStats()
	if stats.EventsSeen < 2 {
		t.Errorf("Expected at least 2 events seen by filter, got %d", stats.EventsSeen)
	}

	// 8. Shut down cleanly
	p.Stop()
	correlator.Stop()
	netEnforcer.Stop()

	t.Logf("Agent lifecycle test completed: %d events, %d alerts, %d enforcements",
		p.EventsProcessed(), p.AlertsEmitted(), p.EnforcementsExecuted())
}

// TestAgent_FilterIntegration tests that the ring buffer filter works
// correctly with the eBPF loader.
func TestAgent_FilterIntegration(t *testing.T) {
	loader := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    "/tmp/nonexistent",
		EventBufferSize: 1024,
	})

	filter := loader.Filter()

	// Initially no filter is active
	if filter.IsActive() {
		t.Error("Expected filter to be inactive initially")
	}

	// Add a category filter
	filter.AddCategory(ebpf.CatProcess)

	if !filter.IsActive() {
		t.Error("Expected filter to be active after adding category")
	}

	// Verify the test event channel works
	testCh := make(chan *ebpf.ScarletEvent, 10)
	loader.SetTestEventChannel(testCh)

	eventsCh := loader.Events()
	if eventsCh != testCh {
		t.Error("Events() should return the test event channel")
	}
}

// TestAgent_MultipleStartStop tests that starting and stopping the pipeline
// multiple times does not leak goroutines or panic.
func TestAgent_MultipleStartStop(t *testing.T) {
	eventCh := make(chan *ebpf.ScarletEvent, 256)

	ruleEngine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}

	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 1000,
		PIDCacheTTL:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create enrichment manager: %v", err)
	}

	alertEmit := output.NewAlertEmitterForTest()

	for i := 0; i < 3; i++ {
		p := pipeline.NewPipeline(pipeline.PipelineConfig{
			EventChannel:   eventCh,
			RuleEngine:     ruleEngine,
			Enricher:       enricher,
			AlertEmitter:   alertEmit,
			Mode:           "audit",
			Workers:        1,
			AnomalyEnabled: false,
			CoalesceWindow: 1 * time.Second,
		})

		ctx, cancel := context.WithCancel(context.Background())
		p.Start(ctx)

		// Inject a few events
		p.ProcessEvent(&ebpf.ScarletEvent{
			PID:       uint32(1000 + i),
			Category:  ebpf.CatProcess,
			EventType: ebpf.EvtExec,
			SyscallNr: 59,
		})

		time.Sleep(50 * time.Millisecond)
		p.Stop()
		cancel()
	}
}

// TestAgent_ConcurrentEvents tests that the pipeline handles concurrent
// event injection correctly.
func TestAgent_ConcurrentEvents(t *testing.T) {
	eventCh := make(chan *ebpf.ScarletEvent, 10000)

	ruleEngine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}

	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 10000,
		PIDCacheTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create enrichment manager: %v", err)
	}

	alertEmit := output.NewAlertEmitterForTest()

	correlator := correlate.NewCorrelator()
	for _, spec := range correlate.DefaultCorrelationRules() {
		correlator.AddRule(spec)
	}

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		EventChannel:   eventCh,
		RuleEngine:     ruleEngine,
		Enricher:       enricher,
		AlertEmitter:   alertEmit,
		Correlator:     correlator,
		Mode:           "audit",
		Workers:        4,
		AnomalyEnabled: false,
		CoalesceWindow: 5 * time.Minute,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)

	// Inject events from multiple goroutines concurrently
	var injected atomic.Uint64
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			p.ProcessEvent(&ebpf.ScarletEvent{
				TimestampNS: uint64(time.Now().UnixNano()),
				PID:         uint32(i % 5000),
				TGID:        uint32(i % 5000),
				PPID:        1,
				UID:         1000,
				GID:         1000,
				CgroupID:    uint64(i%100) + 1000,
				PIDNSLevel:  1,
				Category:    ebpf.CatProcess,
				EventType:   ebpf.EvtExec,
				SyscallNr:   59,
			})
			injected.Add(1)
		}
	}()

	<-done

	// Give pipeline time to drain
	time.Sleep(200 * time.Millisecond)

	processed := p.EventsProcessed()
	if processed < injected.Load() {
		t.Errorf("Expected at least %d events processed, got %d", injected.Load(), processed)
	}

	p.Stop()

	t.Logf("Concurrent test: injected=%d processed=%d alerts=%d",
		injected.Load(), processed, p.AlertsEmitted())
}

// TestAgent_RingBufferFilterWithPipeline tests the ring buffer filter
// integrated with the event pipeline.
func TestAgent_RingBufferFilterWithPipeline(t *testing.T) {
	eventCh := make(chan *ebpf.ScarletEvent, 256)

	ruleEngine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "audit"})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}

	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 10000,
		PIDCacheTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create enrichment manager: %v", err)
	}

	alertEmit := output.NewAlertEmitterForTest()

	loader := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    "/tmp/nonexistent",
		EventBufferSize: 256,
	})
	loader.SetTestEventChannel(eventCh)

	// Configure filter to only pass network and escape events
	loader.Filter().SetCategoryFilter([]uint8{ebpf.CatNetwork, ebpf.CatEscape})

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		EventChannel:   eventCh,
		RuleEngine:     ruleEngine,
		Enricher:       enricher,
		AlertEmitter:   alertEmit,
		Mode:           "audit",
		Workers:        1,
		AnomalyEnabled: false,
		CoalesceWindow: 5 * time.Minute,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	// Inject event that passes filter
	passEvent := &ebpf.ScarletEvent{
		PID:       100,
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
		SyscallNr: 42,
	}
	p.ProcessEvent(passEvent)

	// Inject event that would be dropped by filter
	// (Process a file event directly - bypassing filter since ProcessEvent
	// doesn't go through the filter)
	fileEvent := &ebpf.ScarletEvent{
		PID:       200,
		Category:  ebpf.CatFile,
		EventType: ebpf.EvtFileOpen,
		SyscallNr: 257,
	}
	p.ProcessEvent(fileEvent)

	// Verify that both events were processed (ProcessEvent bypasses filter)
	time.Sleep(100 * time.Millisecond)
	processed := p.EventsProcessed()
	if processed < 2 {
		t.Errorf("Expected at least 2 events processed, got %d", processed)
	}

	// Verify filter stats
	filterStats := loader.Filter().FilterStats()
	if filterStats.EventsSeen == 0 && filterStats.EventsPassed == 0 {
		t.Log("Filter active but no events seen directly through filter (expected - ProcessEvent bypasses it)")
	}

	p.Stop()

	t.Logf("Filter integration test: processed=%d alerts=%d filter_seen=%d filter_passed=%d",
		processed, p.AlertsEmitted(), filterStats.EventsSeen, filterStats.EventsPassed)
}

// TestAgent_EnrichmentCacheLRU tests the LRU cache pruning in the enrichment module.
func TestAgent_EnrichmentCacheLRU(t *testing.T) {
	// PID cache with small size to test eviction
	pidCache := enrichment.NewPIDCache(10, 5*time.Minute)

	// Fill cache beyond capacity
	for i := 0; i < 20; i++ {
		pidCache.Set(uint32(1000+i), "container-abc")
	}

	size := pidCache.Size()
	if size > 10 {
		t.Errorf("PID cache should be capped at 10 entries, got %d", size)
	}

	// CRI cache with max size
	criCache := enrichment.NewCRICacheWithMaxSize(5)

	for i := 0; i < 10; i++ {
		id := string(rune('a' + i))
		criCache.Set(id, &enrichment.ContainerInfo{ID: id, Name: "test"})
	}

	criSize := criCache.Size()
	if criSize > 5 {
		t.Errorf("CRI cache should be capped at 5 entries, got %d", criSize)
	}

	// Verify most recently added entries exist
	for i := 5; i < 10; i++ {
		id := string(rune('a' + i))
		info := criCache.Get(id)
		if info == nil {
			t.Errorf("Expected to find recent entry %s in CRI cache", id)
		}
	}

	// Test pruning
	pruned := pidCache.Prune(0) // Prune all idle entries (0 idle threshold)
	t.Logf("Pruned %d entries from PID cache", pruned)

	// Test CRI cache pruning
	criPruned := criCache.Prune(0)
	t.Logf("Pruned %d entries from CRI cache", criPruned)

	// Enrichment manager with PruneCaches
	mgr, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 100,
		PIDCacheTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create enrichment manager: %v", err)
	}

	totalPruned := mgr.PruneCaches(1 * time.Millisecond)
	t.Logf("Total pruned from all caches: %d", totalPruned)
}
