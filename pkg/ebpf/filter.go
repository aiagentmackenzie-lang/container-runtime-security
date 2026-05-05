// Package ebpf - filter.go
// Kernel-side event filtering for the eBPF ring buffer.
//
// The RingBufferFilter allows configuring in-kernel event filters that
// reduce userspace processing overhead by dropping uninteresting events
// before they are submitted to the ring buffer. This dramatically reduces
// CPU usage and ring buffer contention on high-throughput systems.
//
// Filter configuration is pushed to eBPF maps that the kernel-side BPF
// program reads before submitting an event. In mock/development mode,
// the filter is applied in userspace by the Loader before an event
// reaches the pipeline channel.
//
// Filter categories:
//   - Category filter: which event categories (process, file, network, etc.)
//     to pass through (drop all others)
//   - PID filter: only pass events from these PIDs (whitelist mode)
//   - Container filter: only pass events from these cgroup IDs (whitelist mode)
//   - Syscall filter: only pass events with these syscall numbers
//   - Drop probability: sample a fraction of events (for load shedding)
package ebpf

import (
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
)

// ── Ring Buffer Filter ────────────────────────────────────────────────

// RingBufferFilter configures kernel-side event filtering to reduce
// userspace processing overhead. Events that do not match the filter
// criteria are dropped before being written to the ring buffer.
//
// In production (with real eBPF), the filter configuration is written to
// BPF maps that the kernel program checks before bpf_ringbuf_submit().
// In mock/development mode, the filter is applied in the Loader's
// InjectEvent method.
type RingBufferFilter struct {
	mu sync.RWMutex

	// Category whitelist: only these categories pass through.
	// Empty = all categories pass.
	categoryFilter map[uint8]bool

	// PID whitelist: only events from these PIDs pass.
	// Empty = all PIDs pass.
	pidFilter map[uint32]bool

	// PID blacklist: events from these PIDs are always dropped.
	// Takes precedence over whitelist.
	pidBlacklist map[uint32]bool

	// Container/cgroup whitelist: only events from these cgroup IDs pass.
	// Empty = all cgroups pass.
	cgroupFilter map[uint64]bool

	// Syscall whitelist: only events with these syscall numbers pass.
	// Empty = all syscalls pass.
	syscallFilter map[uint16]bool

	// Drop probability: fraction of events to drop for load shedding.
	// 0.0 = none dropped, 1.0 = all dropped, 0.5 = 50% dropped.
	dropProbability float64

	// Stats
	eventsSeen    atomic.Uint64
	eventsPassed  atomic.Uint64
	eventsDropped atomic.Uint64
	eventsByCategory map[uint8]*categoryStats
	catStatsMu    sync.RWMutex
}

// categoryStats tracks per-category filter statistics.
type categoryStats struct {
	seen    atomic.Uint64
	passed  atomic.Uint64
	dropped atomic.Uint64
}

// NewRingBufferFilter creates a new ring buffer filter with no filtering.
func NewRingBufferFilter() *RingBufferFilter {
	return &RingBufferFilter{
		categoryFilter: make(map[uint8]bool),
		pidFilter:      make(map[uint32]bool),
		pidBlacklist:   make(map[uint32]bool),
		cgroupFilter:   make(map[uint64]bool),
		syscallFilter:  make(map[uint16]bool),
		eventsByCategory: make(map[uint8]*categoryStats),
	}
}

// ── Filter Configuration ──────────────────────────────────────────────

// SetCategoryFilter sets which event categories are allowed through.
// Only events with a category in the set will pass; all others are dropped.
// An empty set means all categories pass (no filtering).
func (f *RingBufferFilter) SetCategoryFilter(categories []uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.categoryFilter = make(map[uint8]bool, len(categories))
	for _, cat := range categories {
		f.categoryFilter[cat] = true
	}

	log.Printf("[ebpf-filter] Category filter updated: %d categories whitelisted", len(f.categoryFilter))
}

// AddCategory adds an event category to the whitelist.
func (f *RingBufferFilter) AddCategory(cat uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.categoryFilter[cat] = true
	log.Printf("[ebpf-filter] Category %d (%s) added to whitelist", cat, CategoryName[cat])
}

// RemoveCategory removes an event category from the whitelist.
func (f *RingBufferFilter) RemoveCategory(cat uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.categoryFilter, cat)
	log.Printf("[ebpf-filter] Category %d (%s) removed from whitelist", cat, CategoryName[cat])
}

// SetPIDFilter sets which PIDs are allowed through.
// Only events from PIDs in the set will pass.
// An empty set means all PIDs pass.
func (f *RingBufferFilter) SetPIDFilter(pids []uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.pidFilter = make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		f.pidFilter[pid] = true
	}

	log.Printf("[ebpf-filter] PID filter updated: %d PIDs whitelisted", len(f.pidFilter))
}

// AddPID adds a PID to the whitelist.
func (f *RingBufferFilter) AddPID(pid uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pidFilter[pid] = true
}

// AddPIDBlacklist adds a PID to the blacklist (always drop).
func (f *RingBufferFilter) AddPIDBlacklist(pid uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pidBlacklist[pid] = true
	log.Printf("[ebpf-filter] PID %d added to blacklist", pid)
}

// SetCgroupFilter sets which cgroup IDs are allowed through.
// Only events from containers with these cgroup IDs will pass.
// An empty set means all cgroups pass.
func (f *RingBufferFilter) SetCgroupFilter(cgroupIDs []uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cgroupFilter = make(map[uint64]bool, len(cgroupIDs))
	for _, id := range cgroupIDs {
		f.cgroupFilter[id] = true
	}

	log.Printf("[ebpf-filter] Cgroup filter updated: %d cgroups whitelisted", len(f.cgroupFilter))
}

// AddCgroup adds a cgroup ID to the whitelist.
func (f *RingBufferFilter) AddCgroup(cgroupID uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cgroupFilter[cgroupID] = true
}

// RemoveCgroup removes a cgroup ID from the whitelist.
func (f *RingBufferFilter) RemoveCgroup(cgroupID uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.cgroupFilter, cgroupID)
}

// SetSyscallFilter sets which syscall numbers are allowed through.
// Only events with syscall numbers in the set will pass.
// An empty set means all syscalls pass.
func (f *RingBufferFilter) SetSyscallFilter(syscalls []uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.syscallFilter = make(map[uint16]bool, len(syscalls))
	for _, nr := range syscalls {
		f.syscallFilter[nr] = true
	}

	log.Printf("[ebpf-filter] Syscall filter updated: %d syscalls whitelisted", len(f.syscallFilter))
}

// SetDropProbability sets the probability of dropping events for load shedding.
// 0.0 = no events dropped, 1.0 = all events dropped.
func (f *RingBufferFilter) SetDropProbability(p float64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	f.dropProbability = p
	log.Printf("[ebpf-filter] Drop probability set to %.2f", p)
}

// ── Filter Application ──────────────────────────────────────────────

// ShouldPass checks whether an event should pass the ring buffer filter.
// Returns true if the event should be delivered to userspace, false if
// it should be dropped at the kernel level (or in mock mode, before
// injection into the event channel).
//
// Filter precedence:
//  1. PID blacklist (always drop)
//  2. PID whitelist (empty = pass all)
//  3. Category whitelist (empty = pass all)
//  4. Cgroup whitelist (empty = pass all)
//  5. Syscall whitelist (empty = pass all)
//  6. Drop probability (load shedding)
func (f *RingBufferFilter) ShouldPass(event *ScarletEvent) bool {
	f.eventsSeen.Add(1)

	// Get or create category stats
	cat := event.Category
	f.catStatsMu.RLock()
	stats, ok := f.eventsByCategory[cat]
	f.catStatsMu.RUnlock()
	if !ok {
		f.catStatsMu.Lock()
		stats, ok = f.eventsByCategory[cat]
		if !ok {
			stats = &categoryStats{}
			f.eventsByCategory[cat] = stats
		}
		f.catStatsMu.Unlock()
	}
	stats.seen.Add(1)

	f.mu.RLock()
	defer f.mu.RUnlock()

	// 1. PID blacklist
	if len(f.pidBlacklist) > 0 {
		if f.pidBlacklist[event.PID] {
			f.eventsDropped.Add(1)
			stats.dropped.Add(1)
			return false
		}
	}

	// 2. PID whitelist
	if len(f.pidFilter) > 0 {
		if !f.pidFilter[event.PID] {
			f.eventsDropped.Add(1)
			stats.dropped.Add(1)
			return false
		}
	}

	// 3. Category whitelist
	if len(f.categoryFilter) > 0 {
		if !f.categoryFilter[event.Category] {
			f.eventsDropped.Add(1)
			stats.dropped.Add(1)
			return false
		}
	}

	// 4. Cgroup whitelist
	if len(f.cgroupFilter) > 0 {
		if !f.cgroupFilter[event.CgroupID] {
			f.eventsDropped.Add(1)
			stats.dropped.Add(1)
			return false
		}
	}

	// 5. Syscall whitelist
	if len(f.syscallFilter) > 0 {
		if !f.syscallFilter[event.SyscallNr] {
			f.eventsDropped.Add(1)
			stats.dropped.Add(1)
			return false
		}
	}

	// 6. Drop probability (load shedding)
	if f.dropProbability > 0 && rand.Float64() < f.dropProbability {
		f.eventsDropped.Add(1)
		stats.dropped.Add(1)
		return false
	}

	f.eventsPassed.Add(1)
	stats.passed.Add(1)
	return true
}

// ── Filter Stats ────────────────────────────────────────────────────

// FilterStats returns statistics about the ring buffer filter.
func (f *RingBufferFilter) FilterStats() RingBufferFilterStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := RingBufferFilterStats{
		EventsSeen:       f.eventsSeen.Load(),
		EventsPassed:     f.eventsPassed.Load(),
		EventsDropped:    f.eventsDropped.Load(),
		DropProbability:  f.dropProbability,
		CategoryFilterSize: len(f.categoryFilter),
		PIDFilterSize:     len(f.pidFilter),
		PIDBlacklistSize:   len(f.pidBlacklist),
		CgroupFilterSize:  len(f.cgroupFilter),
		SyscallFilterSize:  len(f.syscallFilter),
	}

	// Per-category stats
	f.catStatsMu.RLock()
	for cat, catStats := range f.eventsByCategory {
		name := CategoryName[cat]
		stats.ByCategory = append(stats.ByCategory, CategoryFilterStats{
			Category:    name,
			CategoryID:  cat,
			Seen:       catStats.seen.Load(),
			Passed:     catStats.passed.Load(),
			Dropped:    catStats.dropped.Load(),
		})
	}
	f.catStatsMu.RUnlock()

	return stats
}

// RingBufferFilterStats holds statistics about the ring buffer filter.
type RingBufferFilterStats struct {
	EventsSeen       uint64  `json:"events_seen"`
	EventsPassed     uint64  `json:"events_passed"`
	EventsDropped    uint64  `json:"events_dropped"`
	DropProbability  float64 `json:"drop_probability"`
	CategoryFilterSize int   `json:"category_filter_size"`
	PIDFilterSize     int   `json:"pid_filter_size"`
	PIDBlacklistSize  int   `json:"pid_blacklist_size"`
	CgroupFilterSize  int   `json:"cgroup_filter_size"`
	SyscallFilterSize  int   `json:"syscall_filter_size"`
	ByCategory []CategoryFilterStats `json:"by_category"`
}

// CategoryFilterStats holds per-category filter statistics.
type CategoryFilterStats struct {
	Category    string `json:"category"`
	CategoryID  uint8  `json:"category_id"`
	Seen       uint64 `json:"seen"`
	Passed     uint64 `json:"passed"`
	Dropped    uint64 `json:"dropped"`
}

// ResetStats resets the filter statistics counters.
func (f *RingBufferFilter) ResetStats() {
	f.eventsSeen.Store(0)
	f.eventsPassed.Store(0)
	f.eventsDropped.Store(0)

	f.catStatsMu.RLock()
	for _, stats := range f.eventsByCategory {
		stats.seen.Store(0)
		stats.passed.Store(0)
		stats.dropped.Store(0)
	}
	f.catStatsMu.RUnlock()
}

// IsActive returns true if any filter is configured.
func (f *RingBufferFilter) IsActive() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return len(f.categoryFilter) > 0 ||
		len(f.pidFilter) > 0 ||
		len(f.pidBlacklist) > 0 ||
		len(f.cgroupFilter) > 0 ||
		len(f.syscallFilter) > 0 ||
		f.dropProbability > 0
}