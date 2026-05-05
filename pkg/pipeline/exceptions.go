// Package pipeline - exceptions.go
// Exception framework for suppressing rule matches on legitimate workloads.
//
// Two evaluation paths:
//   1. Built-in field matching — exact/list/prefix comparisons on enriched event fields.
//      This is always available and handles the majority of exception cases.
//   2. OPA Rego policy evaluation — for complex conditional exceptions that
//      cannot be expressed as simple field comparisons. Optional, requires
//      the opa engine to be configured.
//
// Exception model follows Falco's proven approach (SRD Section 8.3):
//
//   exceptions:
//     - name: trusted_debug_images
//       fields: [container.image.repository]
//       comps: [=]
//       values:
//         - [admin-toolkit/admin-cli]
//     - name: admin_shells
//       fields: [container.image.repository, proc.name]
//       comps: [=, =]
//       values:
//         - [admin-toolkit/admin-cli, /usr/bin/bash]
//         - [debug-pod/tools, /bin/sh]
//
// A rule match is suppressed if ANY exception's ALL fields match against
// ANY of the value rows. This is Falco's "AND across fields, OR across values" model.

package pipeline

import (
	"fmt"
	"log"
	"sync"

	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Exception Evaluator ───────────────────────────────────────────────

// ExceptionEvaluator evaluates rule exceptions against enriched events.
// It implements the Falco-compatible field matching model and optionally
// integrates with OPA Rego for complex policy decisions.
type ExceptionEvaluator struct {
	// OPA integration (optional, nil if not configured)
	opa *OPAEvaluator

	mu sync.RWMutex
}

// NewExceptionEvaluator creates a new exception evaluator.
func NewExceptionEvaluator() *ExceptionEvaluator {
	return &ExceptionEvaluator{}
}

// SetOPAEvaluator configures an OPA Rego policy evaluator for complex exceptions.
func (e *ExceptionEvaluator) SetOPAEvaluator(opa *OPAEvaluator) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opa = opa
}

// EvaluateException checks whether any exception in the rule applies to the event.
// Returns true if the event should be suppressed (exception matches).
func (e *ExceptionEvaluator) EvaluateException(rule *rules.CompiledRule, event *rules.EnrichedEventForRule) bool {
	for _, exc := range rule.Exceptions {
		if e.matchException(exc, event) {
			log.Printf("[exception] Rule %s suppressed by exception %s", rule.ID, exc.Name)
			return true
		}
	}

	// Fall through to OPA evaluation for policy-driven exceptions
	e.mu.RLock()
	opa := e.opa
	e.mu.RUnlock()

	if opa != nil {
		if opa.Evaluate(rule.ID, event) {
			log.Printf("[exception] Rule %s suppressed by OPA policy", rule.ID)
			return true
		}
	}

	return false
}

// matchException implements the Falco-compatible field matching model:
//   - For each value row: ALL fields must match their comparator
//   - If ANY value row matches ALL fields, the exception applies
//   - Comparators: = (exact), in (list membership), != (not equal)
func (e *ExceptionEvaluator) matchException(exc rules.Exception, event *rules.EnrichedEventForRule) bool {
	// Each value row is checked independently (OR across rows)
	for _, valueRow := range exc.Values {
		if e.matchValueRow(exc.Fields, exc.Comps, valueRow, event) {
			return true
		}
	}
	return false
}

// matchValueRow checks if ALL fields in a single value row match.
// Returns true only if every (field, comp, value) tuple matches.
func (e *ExceptionEvaluator) matchValueRow(fields []string, comps []string, values []string, event *rules.EnrichedEventForRule) bool {
	// Pad comps and values with defaults if shorter than fields
	for i, field := range fields {
		if i >= len(values) {
			// Not enough values for this field — no match
			return false
		}

		comp := "=" // default comparator
		if i < len(comps) && comps[i] != "" {
			comp = comps[i]
		}

		expectedValue := values[i]
		eventValue := resolveEventField(field, event)

		if !matchField(comp, eventValue, expectedValue) {
			return false // AND across fields: one miss means whole row fails
		}
	}
	return true
}

// resolveEventField maps a field name to the corresponding value in the enriched event.
func resolveEventField(field string, event *rules.EnrichedEventForRule) string {
	switch field {
	case "container.image.repository", "container.image":
		return event.ContainerImage
	case "container.name":
		return event.ContainerName
	case "container.id":
		return event.ContainerID
	case "proc.name":
		return event.Event.CommString()
	case "proc.cmdline":
		return event.Event.Args()
	case "proc.exe":
		return event.Event.Filename()
	case "namespace":
		return event.Namespace
	case "pod.name":
		return event.PodName
	case "serviceaccount", "sa":
		return event.ServiceAccount
	case "fd.name":
		return event.Event.FilePath()
	case "fd.rip":
		return event.Event.RemoteIP()
	case "fd.rport":
		return fmt.Sprintf("%d", event.Event.RemotePort())
	default:
		return "" // unknown fields never match
	}
}

// matchField compares an event value against an expected value using the given comparator.
func matchField(comp, eventValue, expectedValue string) bool {
	switch comp {
	case "=", "equals":
		return eventValue == expectedValue
	case "!=", "not_equals":
		return eventValue != expectedValue
	case "in":
		// expectedValue is a comma-separated list
		return listContains(expectedValue, eventValue)
	case "contains":
		return containsSubstring(eventValue, expectedValue)
	case "startswith":
		return len(eventValue) >= len(expectedValue) && eventValue[:len(expectedValue)] == expectedValue
	case "endswith":
		return len(eventValue) >= len(expectedValue) && eventValue[len(eventValue)-len(expectedValue):] == expectedValue
	default:
		return eventValue == expectedValue // default: exact match
	}
}

// listContains checks if a value is in a comma-separated list.
func listContains(list, value string) bool {
	// Simple comma-separated parsing
	start := 0
	for i := 0; i <= len(list); i++ {
		if i == len(list) || list[i] == ',' {
			item := list[start:i]
			if item == value {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// containsSubstring checks if value contains the substring.
func containsSubstring(value, substr string) bool {
	for i := 0; i <= len(value)-len(substr); i++ {
		if value[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ── OPA Rego Evaluator ────────────────────────────────────────────────

// OPAEvaluator wraps an embedded OPA Rego engine for policy-driven
// exception evaluation. This enables complex conditional expressions
// that cannot be expressed as simple field comparisons.
//
// Example Rego policy that suppresses shell processes in debug namespaces:
//
//   package scarlet.exceptions
//
//   suppress[rules.ID] {
//     input.rule_id == rules.ID
//     input.namespace == rules.namespace
//     startswith(input.namespace, "debug-")
//     input.proc_name in {"bash", "sh"}
//   }
//
// OPA evaluation is optional. If not configured, only built-in field
// matching is used.

// OPAEvaluator evaluates Rego policies against enriched events.
type OPAEvaluator struct {
	policies map[string]string // rule_id → Rego query
	enabled  bool
	mu       sync.RWMutex
}

// NewOPAEvaluator creates a new OPA policy evaluator.
func NewOPAEvaluator() *OPAEvaluator {
	return &OPAEvaluator{
		policies: make(map[string]string),
		enabled:  true,
	}
}

// AddPolicy adds a Rego policy for a specific rule.
func (o *OPAEvaluator) AddPolicy(ruleID, regoQuery string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.policies[ruleID] = regoQuery
}

// RemovePolicy removes the Rego policy for a rule.
func (o *OPAEvaluator) RemovePolicy(ruleID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.policies, ruleID)
}

// Evaluate checks if an OPA policy suppresses the given rule match.
// Currently implements a simplified policy evaluation. Full OPA Rego
// evaluation requires the open-policy-agent/opa dependency and will
// be enabled when that dependency is added.
func (o *OPAEvaluator) Evaluate(ruleID string, event *rules.EnrichedEventForRule) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.enabled {
		return false
	}

	_, hasPolicy := o.policies[ruleID]
	if !hasPolicy {
		return false // no OPA policy for this rule
	}

	// Simplified evaluation placeholder:
	// In production, this would compile and evaluate the Rego query against
	// the event as input data, returning the boolean result.
	// For now, OPA policies are registered but evaluation returns false
	// until the full OPA engine dependency is integrated.
	//
	// The integration point is here — when OPA is fully integrated,
	// this method will:
	//   1. Prepare input JSON from the event
	//   2. Compile the Rego query
	//   3. Evaluate query against input
	//   4. Return boolean result

	log.Printf("[exception] OPA policy exists for rule %s but full Rego evaluation not yet integrated", ruleID)
	return false
}

// PolicyCount returns the number of registered OPA policies.
func (o *OPAEvaluator) PolicyCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.policies)
}

// HasPolicy returns whether a policy exists for the given rule.
func (o *OPAEvaluator) HasPolicy(ruleID string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.policies[ruleID]
	return ok
}