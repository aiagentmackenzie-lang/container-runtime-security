// Package pipeline - enforcement_log.go
// Enforcement audit log records every enforcement decision for forensics
// and compliance. Every call to Enforce() — whether it results in an actual
// kill or is skipped by a safety rule — is recorded here.

package pipeline

import (
	"encoding/json"
	"sync"
	"time"
)

// ── Enforcement Audit Log ──────────────────────────────────────────────

// EnforcementAuditLog records all enforcement actions and their outcomes.
type EnforcementAuditLog struct {
	mu      sync.RWMutex
	entries []EnforcementResult
	maxSize int
}

// NewEnforcementAuditLog creates a new enforcement audit log.
func NewEnforcementAuditLog() *EnforcementAuditLog {
	return &EnforcementAuditLog{
		entries: make([]EnforcementResult, 0, 1000),
		maxSize: 10000, // keep last 10K entries in memory
	}
}

// Record appends an enforcement result to the audit log.
func (l *EnforcementAuditLog) Record(result EnforcementResult) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Evict oldest if at capacity
	if len(l.entries) >= l.maxSize {
		l.entries = l.entries[1:]
	}

	l.entries = append(l.entries, result)
}

// Entries returns all audit log entries (snapshot copy).
func (l *EnforcementAuditLog) Entries() []EnforcementResult {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]EnforcementResult, len(l.entries))
	copy(result, l.entries)
	return result
}

// Recent returns the last N audit log entries.
func (l *EnforcementAuditLog) Recent(n int) []EnforcementResult {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if n > len(l.entries) {
		n = len(l.entries)
	}
	if n <= 0 {
		return nil
	}

	result := make([]EnforcementResult, n)
	start := len(l.entries) - n
	copy(result, l.entries[start:])
	return result
}

// Count returns the total number of recorded entries.
func (l *EnforcementAuditLog) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// CountByReason returns counts grouped by reason.
func (l *EnforcementAuditLog) CountByReason() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	counts := make(map[string]int)
	for _, entry := range l.entries {
		counts[entry.Reason]++
	}
	return counts
}

// CountByRule returns counts grouped by rule ID.
func (l *EnforcementAuditLog) CountByRule() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	counts := make(map[string]int)
	for _, entry := range l.entries {
		if entry.RuleID != "" {
			counts[entry.RuleID]++
		}
	}
	return counts
}

// SuccessfulKills returns the number of successful kill enforcement actions.
func (l *EnforcementAuditLog) SuccessfulKills() int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	count := 0
	for _, entry := range l.entries {
		if entry.Success && (entry.Action == EnforceSIGKILL || entry.Action == EnforceSIGTERM) {
			count++
		}
	}
	return count
}

// SkippedEnforcements returns the number of enforcement actions that were
// skipped due to safety rules.
func (l *EnforcementAuditLog) SkippedEnforcements() int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	count := 0
	for _, entry := range l.entries {
		if !entry.Success {
			count++
		}
	}
	return count
}

// ── Enforcement Summary ────────────────────────────────────────────────

// EnforcementSummary provides a point-in-time summary of enforcement activity.
type EnforcementSummary struct {
	Timestamp           time.Time      `json:"timestamp"`
	TotalDecisions      int            `json:"total_decisions"`
	SuccessfulKills     int            `json:"successful_kills"`
	SkippedEnforcements int            `json:"skipped_enforcements"`
	ByReason            map[string]int `json:"by_reason"`
	ByRule              map[string]int `json:"by_rule"`
}

// Summary returns a summary of all enforcement activity.
func (l *EnforcementAuditLog) Summary() EnforcementSummary {
	l.mu.RLock()
	defer l.mu.RUnlock()

	summary := EnforcementSummary{
		Timestamp:           time.Now(),
		TotalDecisions:      len(l.entries),
		SuccessfulKills:     0,
		SkippedEnforcements: 0,
		ByReason:            make(map[string]int),
		ByRule:              make(map[string]int),
	}

	for _, entry := range l.entries {
		if entry.Success && (entry.Action == EnforceSIGKILL || entry.Action == EnforceSIGTERM) {
			summary.SuccessfulKills++
		}
		if !entry.Success {
			summary.SkippedEnforcements++
		}
		summary.ByReason[entry.Reason]++
		if entry.RuleID != "" {
			summary.ByRule[entry.RuleID]++
		}
	}

	return summary
}

// MarshalJSON implements json.Marshaler for the audit log summary.
func (s EnforcementSummary) MarshalJSON() ([]byte, error) {
	type Alias EnforcementSummary
	return json.Marshal(&struct {
		Alias
	}{
		Alias: Alias(s),
	})
}
