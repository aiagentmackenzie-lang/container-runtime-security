// Package ebpf_test — tests and benchmarks for eBPF ring buffer filter.
package ebpf_test

import (
	"testing"

	"github.com/securityscarlet/runtime/pkg/ebpf"
)

// ── Ring Buffer Filter Tests ────────────────────────────────────────────

func TestRingBufferFilter_NoFilter(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()

	event := &ebpf.ScarletEvent{
		PID:      1234,
		Category: ebpf.CatProcess,
	}

	if !filter.ShouldPass(event) {
		t.Error("Event should pass when no filter is configured")
	}
}

func TestRingBufferFilter_CategoryWhitelist(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetCategoryFilter([]uint8{ebpf.CatProcess, ebpf.CatNetwork})

	processEvent := &ebpf.ScarletEvent{Category: ebpf.CatProcess}
	fileEvent := &ebpf.ScarletEvent{Category: ebpf.CatFile}
	networkEvent := &ebpf.ScarletEvent{Category: ebpf.CatNetwork}

	if !filter.ShouldPass(processEvent) {
		t.Error("Process event should pass category filter")
	}
	if !filter.ShouldPass(networkEvent) {
		t.Error("Network event should pass category filter")
	}
	if filter.ShouldPass(fileEvent) {
		t.Error("File event should be dropped by category filter")
	}
}

func TestRingBufferFilter_PIDWhitelist(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetPIDFilter([]uint32{100, 200, 300})

	allowed := &ebpf.ScarletEvent{PID: 200}
	blocked := &ebpf.ScarletEvent{PID: 999}

	if !filter.ShouldPass(allowed) {
		t.Error("PID 200 should pass whitelist filter")
	}
	if filter.ShouldPass(blocked) {
		t.Error("PID 999 should be dropped by whitelist filter")
	}
}

func TestRingBufferFilter_PIDBlacklist(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.AddPIDBlacklist(1) // init

	blocked := &ebpf.ScarletEvent{PID: 1}
	allowed := &ebpf.ScarletEvent{PID: 1234}

	if filter.ShouldPass(blocked) {
		t.Error("PID 1 should be dropped by blacklist filter")
	}
	if !filter.ShouldPass(allowed) {
		t.Error("PID 1234 should pass when not in blacklist")
	}
}

func TestRingBufferFilter_CgroupWhitelist(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetCgroupFilter([]uint64{1000, 2000})

	inContainer := &ebpf.ScarletEvent{CgroupID: 1000}
	hostProcess := &ebpf.ScarletEvent{CgroupID: 42}

	if !filter.ShouldPass(inContainer) {
		t.Error("Container event should pass cgroup filter")
	}
	if filter.ShouldPass(hostProcess) {
		t.Error("Host process should be dropped by cgroup filter")
	}
}

func TestRingBufferFilter_SyscallWhitelist(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetSyscallFilter([]uint16{59, 42, 257}) // execve, connect, openat

	execEvent := &ebpf.ScarletEvent{SyscallNr: 59}
	unknownEvent := &ebpf.ScarletEvent{SyscallNr: 999}

	if !filter.ShouldPass(execEvent) {
		t.Error("execve event should pass syscall filter")
	}
	if filter.ShouldPass(unknownEvent) {
		t.Error("Unknown syscall should be dropped by syscall filter")
	}
}

func TestRingBufferFilter_DropProbability(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()

	// 0% drop probability — all events pass
	filter.SetDropProbability(0.0)
	event := &ebpf.ScarletEvent{PID: 100}
	for i := 0; i < 100; i++ {
		if !filter.ShouldPass(event) {
			t.Error("Event should pass with 0% drop probability")
			break
		}
	}

	// 100% drop probability — all events dropped
	filter.SetDropProbability(1.0)
	for i := 0; i < 100; i++ {
		if filter.ShouldPass(event) {
			t.Error("Event should be dropped with 100% drop probability")
			break
		}
	}
}

func TestRingBufferFilter_CombinedFilters(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetCategoryFilter([]uint8{ebpf.CatProcess, ebpf.CatNetwork})
	filter.SetPIDFilter([]uint32{100, 200})

	// Matches both category and PID — should pass
	matchBoth := &ebpf.ScarletEvent{PID: 100, Category: ebpf.CatProcess}
	if !filter.ShouldPass(matchBoth) {
		t.Error("Event matching both filters should pass")
	}

	// Wrong category — should be dropped
	wrongCategory := &ebpf.ScarletEvent{PID: 100, Category: ebpf.CatFile}
	if filter.ShouldPass(wrongCategory) {
		t.Error("Event with wrong category should be dropped")
	}

	// Wrong PID — should be dropped
	wrongPID := &ebpf.ScarletEvent{PID: 999, Category: ebpf.CatProcess}
	if filter.ShouldPass(wrongPID) {
		t.Error("Event with wrong PID should be dropped")
	}
}

func TestRingBufferFilter_BlacklistOverridesWhitelist(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetPIDFilter([]uint32{100})
	filter.AddPIDBlacklist(100)

	// PID is in both whitelist and blacklist — blacklist wins
	event := &ebpf.ScarletEvent{PID: 100}
	if filter.ShouldPass(event) {
		t.Error("Blacklist should override whitelist")
	}
}

func TestRingBufferFilter_FilterStats(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	filter.SetCategoryFilter([]uint8{ebpf.CatProcess})

	// Pass a process event
	processEvent := &ebpf.ScarletEvent{PID: 100, Category: ebpf.CatProcess}
	fileEvent := &ebpf.ScarletEvent{PID: 100, Category: ebpf.CatFile}

	filter.ShouldPass(processEvent)
	filter.ShouldPass(fileEvent)
	filter.ShouldPass(processEvent)

	stats := filter.FilterStats()
	if stats.EventsSeen != 3 {
		t.Errorf("Expected 3 events seen, got %d", stats.EventsSeen)
	}
	if stats.EventsPassed != 2 {
		t.Errorf("Expected 2 events passed, got %d", stats.EventsPassed)
	}
	if stats.EventsDropped != 1 {
		t.Errorf("Expected 1 event dropped, got %d", stats.EventsDropped)
	}
	if stats.CategoryFilterSize != 1 {
		t.Errorf("Expected 1 category filter, got %d", stats.CategoryFilterSize)
	}
}

func TestRingBufferFilter_ResetStats(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	event := &ebpf.ScarletEvent{PID: 100, Category: ebpf.CatProcess}

	filter.ShouldPass(event)
	filter.ResetStats()

	stats := filter.FilterStats()
	if stats.EventsSeen != 0 {
		t.Errorf("Expected 0 events seen after reset, got %d", stats.EventsSeen)
	}
}

func TestRingBufferFilter_IsActive(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()
	if filter.IsActive() {
		t.Error("Empty filter should not be active")
	}

	filter.SetCategoryFilter([]uint8{ebpf.CatProcess})
	if !filter.IsActive() {
		t.Error("Filter with categories should be active")
	}
}

func TestRingBufferFilter_AddRemoveCategory(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()

	filter.AddCategory(ebpf.CatProcess)
	stats := filter.FilterStats()
	if stats.CategoryFilterSize != 1 {
		t.Errorf("Expected 1 category filter, got %d", stats.CategoryFilterSize)
	}

	filter.RemoveCategory(ebpf.CatProcess)
	stats = filter.FilterStats()
	if stats.CategoryFilterSize != 0 {
		t.Errorf("Expected 0 category filters after removal, got %d", stats.CategoryFilterSize)
	}
}

func TestRingBufferFilter_AddRemoveCgroup(t *testing.T) {
	filter := ebpf.NewRingBufferFilter()

	// Set up filter with cgroup 1000
	filter.SetCgroupFilter([]uint64{1000})
	event := &ebpf.ScarletEvent{CgroupID: 1000}
	if !filter.ShouldPass(event) {
		t.Error("Cgroup 1000 should pass after SetCgroupFilter")
	}

	// Add another cgroup
	filter.AddCgroup(2000)
	event2000 := &ebpf.ScarletEvent{CgroupID: 2000}
	if !filter.ShouldPass(event2000) {
		t.Error("Cgroup 2000 should pass after AddCgroup")
	}

	// Remove cgroup 1000 — events with cgroup 1000 should now be dropped
	filter.RemoveCgroup(1000)
	if filter.ShouldPass(event) {
		t.Error("Cgroup 1000 should be dropped after RemoveCgroup")
	}
}

// ── Loader Filter Integration Test ──────────────────────────────────────

func TestLoader_FilterIntegration(t *testing.T) {
	loader := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    "/tmp/nonexistent",
		EventBufferSize: 1024,
	})

	filter := loader.Filter()
	if filter == nil {
		t.Fatal("Expected non-nil filter on loader")
	}

	// Configure filter to only pass network events
	filter.SetCategoryFilter([]uint8{ebpf.CatNetwork})

	networkEvent := &ebpf.ScarletEvent{
		PID:       100,
		Category:  ebpf.CatNetwork,
		EventType: ebpf.EvtNetConnect,
	}
	processEvent := &ebpf.ScarletEvent{
		PID:       100,
		Category:  ebpf.CatProcess,
		EventType: ebpf.EvtExec,
	}

	// Network event should pass the filter
	if !filter.ShouldPass(networkEvent) {
		t.Error("Network event should pass category filter")
	}

	// Process event should be dropped by the filter
	if filter.ShouldPass(processEvent) {
		t.Error("Process event should be dropped by category filter")
	}
}

func TestLoader_TestEventChannel(t *testing.T) {
	loader := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    "/tmp/nonexistent",
		EventBufferSize: 1024,
	})

	// Create a test event channel
	testCh := make(chan *ebpf.ScarletEvent, 10)
	loader.SetTestEventChannel(testCh)

	// Verify Events() returns the test channel
	eventsCh := loader.Events()
	if eventsCh != testCh {
		t.Error("Events() should return the test event channel")
	}
}
