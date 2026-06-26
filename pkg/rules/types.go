// Package rules implements the SecurityScarlet Runtime rule engine.
// It parses YAML rule definitions (Falco-compatible), compiles them into
// a fast-path matching structure bucketed by event type, and evaluates
// enriched events against the rule set.
package rules

// ── Action Constants ─────────────────────────────────────────────────

const (
	ActionAlert     = "alert"
	ActionEnforce   = "enforce"
	ActionSimulated = "simulate"
	ActionSuppress  = "suppress"
)

// ── Priority Constants ────────────────────────────────────────────────

const (
	PriorityEmergency = "EMERGENCY"
	PriorityAlert     = "ALERT"
	PriorityCritical  = "CRITICAL"
	PriorityError     = "ERROR"
	PriorityWarning   = "WARNING"
	PriorityNotice    = "NOTICE"
	PriorityInfo      = "INFO"
	PriorityDebug     = "DEBUG"
)

// PriorityOrder defines severity ordering (higher index = more severe).
var PriorityOrder = map[string]int{
	PriorityDebug:     0,
	PriorityInfo:      1,
	PriorityNotice:    2,
	PriorityWarning:   3,
	PriorityError:     4,
	PriorityCritical:  5,
	PriorityAlert:     6,
	PriorityEmergency: 7,
}

// ── Rule Match Result ────────────────────────────────────────────────

// RuleMatch is returned when a rule matches an event.
type RuleMatch struct {
	RuleID   string
	RuleName string
	Priority string
	Action   string
	Output   string
	Tags     []string
}

// IsMoreSevere returns true if this match has higher severity than another.
func (m *RuleMatch) IsMoreSevere(other *RuleMatch) bool {
	myRank := PriorityOrder[m.Priority]
	otherRank := PriorityOrder[other.Priority]
	if myRank != otherRank {
		return myRank > otherRank
	}
	// Same priority: enforce > alert
	if m.Action == ActionEnforce && other.Action != ActionEnforce {
		return true
	}
	return false
}
