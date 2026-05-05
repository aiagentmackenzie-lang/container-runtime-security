// Package pipeline_test — benchmark tests for event processing pipeline throughput.
// Target: 100k events/sec on a single core.
package pipeline_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/correlate"
	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/enrichment"
	"github.com/securityscarlet/runtime/pkg/output"
	"github.com/securityscarlet/runtime/pkg/pipeline"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Benchmark Helpers ──────────────────────────────────────────────────

// createBenchPipeline creates a pipeline suitable for benchmarking.
// Uses a buffered alert emitter to avoid I/O bottlenecks.
func createBenchPipeline(b *testing.B, eventCh chan *ebpf.ScarletEvent) *pipeline.Pipeline {
	ruleEngine, err := rules.NewEngine(rules.EngineConfig{
		DefaultMode: "audit",
	})
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "bench-node",
		PIDCacheSize: 10000,
		PIDCacheTTL:  5 * time.Minute,
	})
	if err != nil {
		b.Fatalf("Failed to create enrichment manager: %v", err)
	}

	alertCh := make(chan *output.Alert, 10000)
	alertEmit := &benchAlertEmitter{ch: alertCh}

	correlator := correlate.NewCorrelator()
	for _, spec := range correlate.DefaultCorrelationRules() {
		correlator.AddRule(spec)
	}
	correlator.Start()

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		EventChannel:    eventCh,
		RuleEngine:      ruleEngine,
		Enricher:        enricher,
		AlertEmitter:    alertEmit,
		Mode:            "audit",
		Workers:         1,
		AnomalyEnabled:  false, // Disable anomaly for raw throughput measurement
		CoalesceWindow: 5 * time.Minute, // Long window to avoid coalescing in bench
	})

	p.SetCorrelator(correlator)

	return p
}

// benchAlertEmitter collects alerts for benchmark measurement.
type benchAlertEmitter struct {
	ch     chan *output.Alert
	count  uint64
}

func (e *benchAlertEmitter) Emit(alert *output.Alert) {
	e.count++
	select {
	case e.ch <- alert:
	default:
		// Drop if channel full — don't block the pipeline
	}
}

// createBenchEvent creates a synthetic security event for benchmarking.
func createBenchEvent(pid uint32, category uint8, eventType uint8) *ebpf.ScarletEvent {
	e := &ebpf.ScarletEvent{
		TimestampNS: uint64(time.Now().UnixNano()),
		PID:         pid,
		TGID:        pid,
		PPID:        1,
		UID:         1000,
		GID:         1000,
		CgroupID:    12345 + uint64(pid%100),
		PIDNSLevel:  1,
		Category:    category,
		EventType:   eventType,
		SyscallNr:   59,
	}
	copy(e.Comm[:], []byte("benchproc"))
	return e
}

// ── Benchmark: Single Event Processing ─────────────────────────────────

func BenchmarkProcessEvent_SingleWorker(b *testing.B) {
	eventCh := make(chan *ebpf.ScarletEvent, 100000)
	p := createBenchPipeline(b, eventCh)
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Start(ctx)
	time.Sleep(10 * time.Millisecond) // Let workers start

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		event := createBenchEvent(pid, ebpf.CatProcess, ebpf.EvtExec)
		p.ProcessEvent(event)
	}
}

func BenchmarkProcessEvent_NetworkEvent(b *testing.B) {
	eventCh := make(chan *ebpf.ScarletEvent, 100000)
	p := createBenchPipeline(b, eventCh)
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		e := createBenchEvent(pid, ebpf.CatNetwork, ebpf.EvtNetConnect)
		e.Payload.Network.RemoteAddr = [4]byte{10, 0, 0, 1}
		e.Payload.Network.RemotePort = 443
		p.ProcessEvent(e)
	}
}

func BenchmarkProcessEvent_FileEvent(b *testing.B) {
	eventCh := make(chan *ebpf.ScarletEvent, 100000)
	p := createBenchPipeline(b, eventCh)
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		e := createBenchEvent(pid, ebpf.CatFile, ebpf.EvtFileOpen)
		copy(e.Payload.File.Path[:], []byte("/etc/passwd"))
		p.ProcessEvent(e)
	}
}

func BenchmarkProcessEvent_EscapeEvent(b *testing.B) {
	eventCh := make(chan *ebpf.ScarletEvent, 100000)
	p := createBenchPipeline(b, eventCh)
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		e := createBenchEvent(pid, ebpf.CatEscape, ebpf.EvtSetns)
		p.ProcessEvent(e)
	}
}

// ── Benchmark: Parallel Event Processing ───────────────────────────────

func BenchmarkProcessEvent_Parallel(b *testing.B) {
	eventCh := make(chan *ebpf.ScarletEvent, 100000)
	p := createBenchPipeline(b, eventCh)
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pid := uint32(i % 10000)
			category := uint8(ebpf.CatProcess + uint8(i%6))
			eventType := uint8(ebpf.EvtExec + uint8(i%4))
			e := createBenchEvent(pid, category, eventType)
			p.ProcessEvent(e)
			i++
		}
	})
}

// ── Benchmark: Event Category Signal ───────────────────────────────────

func BenchmarkEventCategorySignal(b *testing.B) {
	events := make([]*ebpf.ScarletEvent, 0, b.N)

	for i := 0; i < b.N; i++ {
		switch i % 6 {
		case 0:
			e := &ebpf.ScarletEvent{
				PID:       uint32(i % 10000),
				Category:  ebpf.CatProcess,
				EventType: ebpf.EvtExec,
			}
			copy(e.Comm[:], []byte("bash"))
			events = append(events, e)
		case 1:
			e := &ebpf.ScarletEvent{
				PID:       uint32(i % 10000),
				Category:  ebpf.CatNetwork,
				EventType: ebpf.EvtNetConnect,
			}
			e.Payload.Network.RemotePort = 3333
			events = append(events, e)
		case 2:
			e := &ebpf.ScarletEvent{
				PID:       uint32(i % 10000),
				Category:  ebpf.CatNetwork,
				EventType: ebpf.EvtNetConnect,
			}
			e.Payload.Network.RemotePort = 4444
			events = append(events, e)
		case 3:
			e := &ebpf.ScarletEvent{
				PID:       uint32(i % 10000),
				Category:  ebpf.CatEscape,
				EventType: ebpf.EvtSetns,
			}
			events = append(events, e)
		case 4:
			e := &ebpf.ScarletEvent{
				PID:       uint32(i % 10000),
				Category:  ebpf.CatNetwork,
				EventType: ebpf.EvtNetConnect,
			}
			e.Payload.Network.RemotePort = 443
			events = append(events, e)
		case 5:
			e := &ebpf.ScarletEvent{
				PID:       uint32(i % 10000),
				Category:  ebpf.CatNetwork,
				EventType: ebpf.EvtNetConnect,
			}
			e.Payload.Network.RemotePort = 53
			events = append(events, e)
		}
	}

	b.ResetTimer()
	for _, e := range events {
		pipeline.EventCategorySignal(e)
	}
}

// ── Benchmark: Ring Buffer Filter ──────────────────────────────────────

func BenchmarkRingBufferFilter_NoFilter(b *testing.B) {
	filter := ebpf.NewRingBufferFilter()
	event := createBenchEvent(1000, ebpf.CatProcess, ebpf.EvtExec)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.ShouldPass(event)
	}
}

func BenchmarkRingBufferFilter_CategoryFilter(b *testing.B) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetCategoryFilter([]uint8{ebpf.CatProcess, ebpf.CatNetwork})
	event := createBenchEvent(1000, ebpf.CatProcess, ebpf.EvtExec)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.ShouldPass(event)
	}
}

func BenchmarkRingBufferFilter_PIDFilter(b *testing.B) {
	filter := ebpf.NewRingBufferFilter()
	pids := make([]uint32, 100)
	for i := range pids {
		pids[i] = uint32(i + 1)
	}
	filter.SetPIDFilter(pids)
	event := createBenchEvent(50, ebpf.CatProcess, ebpf.EvtExec)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.ShouldPass(event)
	}
}

func BenchmarkRingBufferFilter_CombinedFilter(b *testing.B) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetCategoryFilter([]uint8{ebpf.CatProcess, ebpf.CatNetwork})
	filter.SetPIDFilter([]uint32{100, 200, 300})
	event := createBenchEvent(200, ebpf.CatProcess, ebpf.EvtExec)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.ShouldPass(event)
	}
}

// ── Benchmark: Enrichment Cache ────────────────────────────────────────

func BenchmarkPIDCache_Set(b *testing.B) {
	cache := enrichment.NewPIDCache(10000, 5*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		cache.Set(pid, fmt.Sprintf("container-%d", pid))
	}
}

func BenchmarkPIDCache_Get(b *testing.B) {
	cache := enrichment.NewPIDCache(10000, 5*time.Minute)
	for i := 0; i < 10000; i++ {
		cache.Set(uint32(i), fmt.Sprintf("container-%d", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		cache.Get(pid)
	}
}

func BenchmarkPIDCache_GetSet(b *testing.B) {
	cache := enrichment.NewPIDCache(10000, 5*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		cache.Get(pid)
		cache.Set(pid, fmt.Sprintf("container-%d", pid))
	}
}

func BenchmarkPIDCache_EViction(b *testing.B) {
	cache := enrichment.NewPIDCache(1000, 5*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(i)
		cache.Set(pid, fmt.Sprintf("container-%d", pid%500))
	}
}

func BenchmarkCRICache_Set(b *testing.B) {
	cache := enrichment.NewCRICache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("container-%d", i%10000)
		cache.Set(id, &enrichment.ContainerInfo{ID: id, Name: "test"})
	}
}

func BenchmarkCRICache_Get(b *testing.B) {
	cache := enrichment.NewCRICache()
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("container-%d", i)
		cache.Set(id, &enrichment.ContainerInfo{ID: id, Name: "test"})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("container-%d", i%10000)
		cache.Get(id)
	}
}

func BenchmarkCRICache_LRU_Eviction(b *testing.B) {
	cache := enrichment.NewCRICacheWithMaxSize(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("container-%d", i)
		cache.Set(id, &enrichment.ContainerInfo{ID: id, Name: "test"})
	}
}

// ── Benchmark: Correlation Engine ───────────────────────────────────────

func BenchmarkCorrelator_ProcessSignal(b *testing.B) {
	correlator := correlate.NewCorrelator()
	for _, spec := range correlate.DefaultCorrelationRules() {
		correlator.AddRule(spec)
	}

	signals := []string{
		"shell_procs",
		"net_outbound",
		"minerpool_connection",
		"high_cpu",
		"dns_query",
		"tls_connection",
		"namespace_join",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sigName := signals[i%len(signals)]
		correlator.ProcessSignal(&correlate.Signal{
			Name:        sigName,
			Timestamp:   time.Now(),
			PID:         uint32(i % 1000),
			ContainerID: fmt.Sprintf("container-%d", i%100),
		})
	}
}

// ── Benchmark: Throughput Target ──────────────────────────────────────

// Benchmark_ThroughputTarget measures whether we meet 100k events/sec target.
// On a single core, each iteration processes one event. The benchmark
// framework reports ns/op — 100k events/sec = 10,000 ns/op budget.
func Benchmark_ThroughputTarget(b *testing.B) {
	ruleEngine, err := rules.NewEngine(rules.EngineConfig{
		DefaultMode: "audit",
	})
	if err != nil {
		b.Fatal(err)
	}

	alertEmit := &noopAlertEmitter{}

	correlator := correlate.NewCorrelator()
	for _, spec := range correlate.DefaultCorrelationRules() {
		correlator.AddRule(spec)
	}

	enricher, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/nonexistent/containerd.sock",
		K8sNodeName:  "bench-node",
		PIDCacheSize: 10000,
		PIDCacheTTL:  5 * time.Minute,
	})
	if err != nil {
		b.Fatal(err)
	}

	p := pipeline.NewPipeline(pipeline.PipelineConfig{
		EventChannel:   make(chan *ebpf.ScarletEvent, 100000),
		RuleEngine:     ruleEngine,
		Enricher:       enricher,
		AlertEmitter:   alertEmit,
		Mode:           "audit",
		Workers:        1,
		AnomalyEnabled: false,
		CoalesceWindow: 5 * time.Minute,
	})
	p.SetCorrelator(correlator)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pid := uint32(i % 10000)
		e := createBenchEvent(pid, ebpf.CatProcess, ebpf.EvtExec)
		p.ProcessEvent(e)
	}
}

type noopAlertEmitter struct{}

func (e *noopAlertEmitter) Emit(alert *output.Alert) {}