// Package pipeline - coalescer.go
// Event coalescing reduces output volume by merging duplicate alerts.
// Same process in same container hitting same rule within 5s → 1 record with event_count.

package pipeline

import (
	"sync"
	"time"

	"github.com/securityscarlet/runtime/pkg/output"
)

// CoalesceKey uniquely identifies a group of events that can be coalesced.
type CoalesceKey struct {
	RuleID      string
	ContainerID string
	ProcessName string
}

// CoalesceEntry tracks a group of coalesced events.
type CoalesceEntry struct {
	Key      CoalesceKey
	First    *output.Alert
	Count    uint64
	LastSeen time.Time
}

// Coalescer merges duplicate alerts within a time window.
type Coalescer struct {
	window  time.Duration
	mu      sync.RWMutex
	entries map[CoalesceKey]*CoalesceEntry
}

// NewCoalescer creates a new event coalescer with the given window.
func NewCoalescer(window time.Duration) *Coalescer {
	return &Coalescer{
		window:  window,
		entries: make(map[CoalesceKey]*CoalesceEntry),
	}
}

// Add attempts to coalesce an alert. Returns true if the alert was coalesced
// (caller should NOT emit it individually), false if it should be emitted.
func (c *Coalescer) Add(alert *output.Alert) bool {
	key := CoalesceKey{
		RuleID:      alert.RuleID,
		ContainerID: alert.ContainerID,
		ProcessName: alert.ProcessName,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[key]; exists {
		// Coalesce: increment count, don't emit individually
		entry.Count++
		entry.LastSeen = time.Now()
		return true
	}

	// First event of this group — create entry
	c.entries[key] = &CoalesceEntry{
		Key:      key,
		First:    alert,
		Count:    1,
		LastSeen: time.Now(),
	}
	return false
}

// Flush emits coalesced alerts and resets the coalescer.
// This is called periodically (every CoalesceWindow).
func (c *Coalescer) Flush(emitter AlertEmitter) {
	c.mu.Lock()
	entries := c.entries
	c.entries = make(map[CoalesceKey]*CoalesceEntry)
	c.mu.Unlock()

	if emitter == nil {
		return
	}

	for _, entry := range entries {
		if entry.Count > 1 {
			// Emit a single coalesced alert with count
			alert := *entry.First // shallow copy
			alert.EventCount = entry.Count
			alert.Coalesced = true
			emitter.Emit(&alert)
		} else {
			// Single event — emit as-is
			emitter.Emit(entry.First)
		}
	}
}

// Count returns the number of active coalesce groups.
func (c *Coalescer) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
