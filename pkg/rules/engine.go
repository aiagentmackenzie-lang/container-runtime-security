// Package rules - engine.go
// The rule engine evaluates enriched events against compiled rules.

package rules

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/securityscarlet/runtime/pkg/ebpf"
)

// ── Engine ────────────────────────────────────────────────────────────

// Engine is the fast-path rule evaluation engine. Rules are compiled into
// lookup structures bucketed by event type for O(1) candidate lookup.
type Engine struct {
	mu sync.RWMutex

	// Compiled rule buckets: event_type → slice of compiled rules
	buckets map[uint8][]*CompiledRule

	// All rules by ID (for listing, validation, etc.)
	rules map[string]*CompiledRule

	// Global lists (miners, shells, C2 ports, etc.)
	lists map[string]ListValues

	// Correlation rules (Phase 3 — placeholder for now)
	correlators []*CorrelationRule

	// Stats
	ruleCount    atomic.Int32
	enforceCount atomic.Int32
	alertCount   atomic.Int32
	evalCount    atomic.Int64

	// Config
	config EngineConfig
}

// EngineConfig holds engine configuration.
type EngineConfig struct {
	RulePaths     []string
	DefaultMode   string // audit, enforce, simulate
	ReloadOnWatch bool
}

// CompiledRule is a rule that has been parsed and optimized for fast evaluation.
type CompiledRule struct {
	ID          string
	Name        string
	Description string
	Priority    string
	Action      string
	Output      string
	Tags        []string
	Category    uint8
	EventTypes  []uint8
	Condition   RuleCondition
	Correlate   *CorrelationSpec
	Exceptions  []Exception
}

// RuleCondition is a compiled condition function that evaluates an event.
type RuleCondition func(event *EnrichedEventForRule) bool

// EnrichedEventForRule is the view of an event exposed to rule conditions.
// It carries the raw eBPF event plus enriched container/K8s metadata.
type EnrichedEventForRule struct {
	Event *ebpf.ScarletEvent

	// Enrichment fields (populated by pipeline before evaluation)
	ContainerID         string
	ContainerName       string
	ContainerImage      string
	ContainerAttributed bool
	PodName             string
	Namespace           string
	ServiceAccount      string
	PodLabels           map[string]string
	Privileged          bool
	NodeName            string
}

// CorrelationSpec defines multi-signal correlation for a rule.
type CorrelationSpec struct {
	Window  time.Duration
	Signals []string
	Logic   string // "all" or "any"
	GroupBy []string
}

// CorrelationRule is a runtime correlation tracker.
type CorrelationRule struct {
	Spec    *CorrelationSpec
	RuleID  string
	Windows map[string]*SignalWindow // keyed by group_by values
}

// SignalWindow tracks signal matches within a time window.
type SignalWindow struct {
	Matches map[string]time.Time // signal_name → timestamp
	Started time.Time
}

// Exception defines an exception that suppresses a rule match.
type Exception struct {
	Name   string
	Fields []string
	Comps  []string
	Values [][]string
}

// NewEngine creates a new rule engine and loads rules from the configured paths.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	e := &Engine{
		buckets: make(map[uint8][]*CompiledRule),
		rules:   make(map[string]*CompiledRule),
		lists:   make(map[string]ListValues),
		config:  cfg,
	}

	// Load default lists
	e.loadDefaultLists()

	// Load rule files
	if err := e.loadRules(); err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	return e, nil
}

// loadDefaultLists initializes the built-in lists for rule conditions.
func (e *Engine) loadDefaultLists() {
	e.lists["shell_binaries"] = ListValues{
		Items: []string{"bash", "sh", "zsh", "dash", "ksh", "tcsh", "fish", "csh"},
	}

	e.lists["miner_binaries"] = ListValues{
		Items: []string{"xmrig", "ccminer", "t-rex", "nanominer", "pwnrig",
			"minerd", "xmr-stak", "cpuminer", "cgminer", "bfgminer"},
	}

	e.lists["miner_pool_ports"] = ListValues{
		Items: []string{"25", "3333", "3334", "3335", "3336", "3357",
			"4444", "5555", "5556", "5588", "5730", "6099",
			"6666", "7777", "7778", "8333", "8888", "8899",
			"9332", "9999", "14433", "14444", "45560", "45700"},
	}

	e.lists["miner_domains"] = ListValues{
		Items: []string{"asia1.ethpool.org", "ca.minexmr.com",
			"cn.stratum.slushpool.com", "de.minexmr.com",
			"eth-ar.dwarfpool.com", "fr.minexmr.com",
			"mine.moneropool.com", "pool.minexmr.com",
			"xmr.crypto-pool.fr"},
	}

	e.lists["sensitive_paths"] = ListValues{
		Items: ebpf.SensitivePaths,
	}

	e.lists["c2_ports"] = ListValues{
		Items: []string{"4444", "1337", "31337", "6666", "8080", "9001", "1234", "4443"},
	}

	e.lists["cloud_metadata_ips"] = ListValues{
		Items: []string{"169.254.169.254", "168.63.129.16"},
	}

	log.Printf("[rules] Loaded %d default lists", len(e.lists))
}

// loadRules loads and compiles rules from all configured paths.
// The built-in default catalog is always loaded first as a baseline.
// Configured RulePaths (files or directories of *.yaml/*.yml) are then
// loaded and may override or augment the defaults (same rule ID replaces).
func (e *Engine) loadRules() error {
	parser := NewParser(e.lists)
	macros := make(map[string]MacroDef)

	// 1. Always load the built-in default catalog as the baseline.
	if err := e.loadYAML(DefaultRuleCatalog(), parser, macros); err != nil {
		return fmt.Errorf("failed to load default rules: %w", err)
	}

	// 2. Load user-configured rule paths (override/augment defaults).
	for _, p := range e.config.RulePaths {
		if err := e.loadRulePath(p, parser, macros); err != nil {
			log.Printf("[rules] Warning: failed to load rule path %s: %v", p, err)
		}
	}

	log.Printf("[rules] Rules loaded: %d total (%d enforce, %d alert)",
		e.ruleCount.Load(), e.enforceCount.Load(), e.alertCount.Load())

	return nil
}

// loadYAML parses a single YAML document and merges its lists, macros, and
// rules into the engine. Lists and macros accumulate across documents;
// a rule with an existing ID replaces the prior compiled rule.
func (e *Engine) loadYAML(src string, parser *Parser, macros map[string]MacroDef) error {
	ruleDefs, macroDefs, listDefs, err := parser.ParseYAML([]byte(src))
	if err != nil {
		return err
	}

	// Merge lists from this document
	for _, l := range listDefs {
		e.lists[l.Name] = l
	}

	// Accumulate macros
	for _, m := range macroDefs {
		macros[m.Name] = m
	}

	// Compile rules
	for _, rd := range ruleDefs {
		compiled, err := e.compileRule(rd, macros)
		if err != nil {
			log.Printf("[rules] Warning: failed to compile rule %s: %v", rd.Name, err)
			continue
		}
		e.addCompiledRule(compiled)
	}
	return nil
}

// loadRulePath loads rules from a file or directory. Directories are walked
// for *.yaml / *.yml files (non-recursive).
func (e *Engine) loadRulePath(p string, parser *Parser, macros map[string]MacroDef) error {
	info, err := os.Stat(p)
	if err != nil {
		return err
	}
	if info.IsDir() {
		entries, err := os.ReadDir(p)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			name := ent.Name()
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(p, name))
			if err != nil {
				return err
			}
			if err := e.loadYAML(string(data), parser, macros); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return e.loadYAML(string(data), parser, macros)
}

// AllRules returns a snapshot of all compiled rules (read-only). The slice
// is a copy; callers must not mutate the compiled rules. Exported for
// tooling (e.g. scarletctl rules list).
func (e *Engine) AllRules() []*CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*CompiledRule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r)
	}
	return out
}

// ValidationResult summarizes a standalone rule-file validation.
type ValidationResult struct {
	Rules  int
	Macros int
	Lists  int
	Errors []string
}

// ValidateFile parses and compiles a rule file against the built-in default
// lists/macros, returning any parse or compile errors. It does not mutate
// any engine state. Used by `scarletctl rules validate`.
func ValidateFile(path string) (*ValidationResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ValidateYAML(data)
}

// ValidateYAML parses and compiles rule YAML against the built-in default
// lists/macros, returning any parse or compile errors.
func ValidateYAML(data []byte) (*ValidationResult, error) {
	e := &Engine{
		buckets: make(map[uint8][]*CompiledRule),
		rules:   make(map[string]*CompiledRule),
		lists:   make(map[string]ListValues),
	}
	e.loadDefaultLists()

	parser := NewParser(e.lists)
	ruleDefs, macroDefs, listDefs, err := parser.ParseYAML(data)
	res := &ValidationResult{}
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res, nil
	}
	res.Lists = len(listDefs)
	res.Macros = len(macroDefs)

	macros := make(map[string]MacroDef)
	for _, m := range macroDefs {
		macros[m.Name] = m
	}
	for _, l := range listDefs {
		e.lists[l.Name] = l
	}
	for _, rd := range ruleDefs {
		res.Rules++
		if _, err := e.compileRule(rd, macros); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("rule %q: %v", rd.Name, err))
		}
	}
	return res, nil
}

// addCompiledRule inserts a compiled rule into the engine's lookup structures.
func (e *Engine) addCompiledRule(rule *CompiledRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules[rule.ID] = rule

	// Bucket by each event type the rule cares about
	// Rules with EventTypes=[0] (wildcard) go into bucket 0 for
	// inclusion in every evaluation via Evaluate()'s wildcard merge.
	for _, evtType := range rule.EventTypes {
		e.buckets[evtType] = append(e.buckets[evtType], rule)
	}

	e.ruleCount.Add(1)
	if rule.Action == ActionEnforce {
		e.enforceCount.Add(1)
	} else if rule.Action == ActionAlert {
		e.alertCount.Add(1)
	}
}

// Reload re-reads rule files and rebuilds the engine.
func (e *Engine) Reload() error {
	e.mu.Lock()
	// Clear existing state
	e.buckets = make(map[uint8][]*CompiledRule)
	e.rules = make(map[string]*CompiledRule)
	e.ruleCount.Store(0)
	e.enforceCount.Store(0)
	e.alertCount.Store(0)
	e.mu.Unlock()

	return e.loadRules()
}

// RuleCount returns the number of loaded rules.
func (e *Engine) RuleCount() int {
	return int(e.ruleCount.Load())
}

// EnforceCount returns the number of enforce rules.
func (e *Engine) EnforceCount() int {
	return int(e.enforceCount.Load())
}

// AlertCount returns the number of alert rules.
func (e *Engine) AlertCount() int {
	return int(e.alertCount.Load())
}

// CompileRule compiles a rule definition into a CompiledRule. Exported for
// testing and dynamic rule loading.
func (e *Engine) CompileRule(def RuleDef, macros map[string]MacroDef) (*CompiledRule, error) {
	return e.compileRule(def, macros)
}

// AddCompiledRule adds a pre-compiled rule to the engine. Exported for testing
// and dynamic rule loading.
func (e *Engine) AddCompiledRule(rule *CompiledRule) {
	e.addCompiledRule(rule)
}

// CorrelationRules returns all rules that have correlation specifications.
// Used by the pipeline to register correlation rules with the correlator.
func (e *Engine) CorrelationRules() []*CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*CompiledRule
	for _, rule := range e.rules {
		if rule.Correlate != nil {
			result = append(result, rule)
		}
	}
	return result
}

// Lists returns the engine's loaded lists. Exported for testing.
func (e *Engine) Lists() map[string]ListValues {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]ListValues, len(e.lists))
	for k, v := range e.lists {
		result[k] = v
	}
	return result
}

// ── OPA Evaluator (in rules package) ───────────────────────────────────

// OPAEvaluator in the rules package provides policy-based exception evaluation.
// The full OPA Rego engine is a dependency that can be added when complex
// policy expressions are needed. The struct and API are available now.
type OPAEvaluator struct {
	policies map[string]string // rule_id → Rego query
	enabled  bool
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
	o.policies[ruleID] = regoQuery
}

// RemovePolicy removes the Rego policy for a rule.
func (o *OPAEvaluator) RemovePolicy(ruleID string) {
	delete(o.policies, ruleID)
}

// Evaluate checks if an OPA policy suppresses the given rule match.
// Full Rego evaluation requires the open-policy-agent/opa dependency.
func (o *OPAEvaluator) Evaluate(ruleID string, event *EnrichedEventForRule) bool {
	if !o.enabled {
		return false
	}
	_, hasPolicy := o.policies[ruleID]
	if !hasPolicy {
		return false
	}
	// Placeholder: returns false until OPA Rego engine is integrated
	return false
}

// PolicyCount returns the number of registered OPA policies.
func (o *OPAEvaluator) PolicyCount() int {
	return len(o.policies)
}

// HasPolicy returns whether a policy exists for the given rule.
func (o *OPAEvaluator) HasPolicy(ruleID string) bool {
	_, ok := o.policies[ruleID]
	return ok
}

// ── Rule Evaluation ───────────────────────────────────────────────────

// EvaluateRule checks an enriched event against all applicable rules.
// This is the primary public API for the rule engine.
// Returns the highest-severity match, or nil if no rule matched.
func (e *Engine) EvaluateRule(event *EnrichedEventForRule) *RuleMatch {
	return e.Evaluate(event)
}

// Evaluate checks an enriched event against all applicable rules.
// Returns the highest-severity match, or nil if no rule matched.
func (e *Engine) Evaluate(event *EnrichedEventForRule) *RuleMatch {
	e.evalCount.Add(1)

	e.mu.RLock()
	defer e.mu.RUnlock()

	raw := event.Event

	// Fast path: look up candidate rules by event type
	candidates := e.buckets[raw.EventType]
	seen := make(map[string]bool)
	for _, r := range candidates {
		seen[r.ID] = true
	}

	// Also check category-level rules
	categoryCandidates := e.buckets[raw.Category]
	for _, r := range categoryCandidates {
		if !seen[r.ID] {
			candidates = append(candidates, r)
			seen[r.ID] = true
		}
	}

	// Also check wildcard bucket (rules with EventTypes=[0] that have
	// no specific event type keyword in their original condition).
	// These rules must be evaluated against ALL events.
	wildcardCandidates := e.buckets[0]
	for _, r := range wildcardCandidates {
		if !seen[r.ID] {
			candidates = append(candidates, r)
			seen[r.ID] = true
		}
	}

	var bestMatch *RuleMatch

	for _, rule := range candidates {
		// Skip rules that don't match the event category
		if rule.Category != 0 && rule.Category != raw.Category {
			continue
		}

		// Evaluate condition
		if !rule.Condition(event) {
			continue
		}

		// Check exceptions
		if e.matchException(rule, event) {
			continue
		}

		// Rule matched — create match result
		match := &RuleMatch{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Priority: rule.Priority,
			Action:   rule.Action,
			Output:   e.formatOutput(rule.Output, event),
			Tags:     rule.Tags,
		}

		// Keep highest-severity match
		if bestMatch == nil || match.IsMoreSevere(bestMatch) {
			bestMatch = match
		}
	}

	return bestMatch
}

// matchException checks if any exception applies to this rule/event.
func (e *Engine) matchException(rule *CompiledRule, event *EnrichedEventForRule) bool {
	// Use the built-in field matching model (Falco-compatible)
	// The pipeline-level ExceptionEvaluator extends this with OPA when configured.
	for _, exc := range rule.Exceptions {
		if e.evaluateException(exc, event) {
			log.Printf("[rules] Rule %s suppressed by exception %s", rule.ID, exc.Name)
			return true
		}
	}
	return false
}

// evaluateException checks a single exception against an event.
// Implements Falco's model: AND across fields, OR across value rows.
func (e *Engine) evaluateException(exc Exception, event *EnrichedEventForRule) bool {
	// Each value row is checked independently (OR across rows)
	for _, valueRow := range exc.Values {
		if e.matchValueRow(exc.Fields, exc.Comps, valueRow, event) {
			return true
		}
	}
	return false
}

// matchValueRow checks if ALL fields in a single value row match.
func (e *Engine) matchValueRow(fields []string, comps []string, values []string, event *EnrichedEventForRule) bool {
	for i, field := range fields {
		if i >= len(values) {
			return false // not enough values
		}

		comp := "=" // default comparator
		if i < len(comps) && comps[i] != "" {
			comp = comps[i]
		}

		expectedValue := values[i]
		eventValue := e.resolveEventField(field, event)

		if !e.matchField(comp, eventValue, expectedValue) {
			return false // AND across fields
		}
	}
	return true
}

// resolveEventField maps field names to event values.
func (e *Engine) resolveEventField(field string, event *EnrichedEventForRule) string {
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
		return ""
	}
}

// matchField compares values using the given comparator.
func (e *Engine) matchField(comp, eventValue, expectedValue string) bool {
	switch comp {
	case "=", "equals":
		return eventValue == expectedValue
	case "!=", "not_equals":
		return eventValue != expectedValue
	case "in":
		// expectedValue is comma-separated list
		return engineListContains(expectedValue, eventValue)
	case "contains":
		return strings.Contains(eventValue, expectedValue)
	case "startswith":
		return strings.HasPrefix(eventValue, expectedValue)
	default:
		return eventValue == expectedValue
	}
}

// engineListContains checks if a value is in a comma-separated list.
func engineListContains(list, value string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == value {
			return true
		}
	}
	return false
}

// formatOutput interpolates event fields into the rule output template.
func (e *Engine) formatOutput(template string, event *EnrichedEventForRule) string {
	out := template

	// Simple field interpolation
	replacements := map[string]string{
		"%proc.name":                  event.Event.CommString(),
		"%proc.pid":                   fmt.Sprintf("%d", event.Event.PID),
		"%proc.cmdline":               event.Event.Args(),
		"%proc.exe":                   event.Event.Filename(),
		"%user.name":                  fmt.Sprintf("uid=%d", event.Event.UID),
		"%container.id":               event.ContainerID,
		"%container.name":             event.ContainerName,
		"%container.image.repository": event.ContainerImage,
		"%fd.name":                    event.Event.FilePath(),
		"%fd.rip":                     event.Event.RemoteIP(),
		"%fd.rport":                   fmt.Sprintf("%d", event.Event.RemotePort()),
		"%evt.type":                   event.Event.EventTypeString(),
		"%evt.arg.nstype":             fmt.Sprintf("%d", event.Event.Payload.Escape.NSType),
	}

	for key, val := range replacements {
		out = strings.ReplaceAll(out, key, val)
	}

	return out
}

// ── Rule Compilation ──────────────────────────────────────────────────

// compileRule converts a parsed RuleDef into a CompiledRule with a condition function.
func (e *Engine) compileRule(def RuleDef, macros map[string]MacroDef) (*CompiledRule, error) {
	rule := &CompiledRule{
		ID:          def.ID,
		Name:        def.Name,
		Description: def.Desc,
		Priority:    def.Priority,
		Action:      def.Action,
		Output:      def.Output,
		Tags:        def.Tags,
	}

	// Determine event types this rule cares about (for bucketing)
	rule.EventTypes = e.inferEventTypes(def.Condition)
	rule.Category = e.inferCategory(def.Condition)

	// Wildcard rules (EventTypes contains 0) must not be filtered by
	// category — their conditions already contain the necessary type
	// checks (e.g., "evt.type = connect"), so inferring a static
	// category from the un-expanded macro name is unreliable.
	for _, et := range rule.EventTypes {
		if et == 0 {
			rule.Category = 0 // wildcard category
			break
		}
	}

	// Compile condition into a function
	cond, err := e.compileCondition(def.Condition, macros)
	if err != nil {
		return nil, fmt.Errorf("rule %s: condition compilation failed: %w", def.Name, err)
	}
	rule.Condition = cond

	// Compile correlation spec if present
	if def.Correlate != nil {
		dur, _ := time.ParseDuration(def.Correlate.Window)
		rule.Correlate = &CorrelationSpec{
			Window:  dur,
			Signals: def.Correlate.Signals,
			Logic:   def.Correlate.Logic,
			GroupBy: def.Correlate.GroupBy,
		}
	}

	// Store exceptions
	if len(def.Exceptions) > 0 {
		rule.Exceptions = make([]Exception, len(def.Exceptions))
		for i, excDef := range def.Exceptions {
			rule.Exceptions[i] = Exception{
				Name:   excDef.Name,
				Fields: excDef.Fields,
				Comps:  excDef.Comps,
				Values: excDef.Values,
			}
		}
	}

	return rule, nil
}

// inferEventTypes determines which event types a condition expression cares about.
func (e *Engine) inferEventTypes(condition string) []uint8 {
	var types []uint8
	cond := strings.ToLower(condition)

	if strings.Contains(cond, "execve") || strings.Contains(cond, "spawned_process") {
		types = append(types, ebpf.EvtExec)
	}
	if strings.Contains(cond, "fork") || strings.Contains(cond, "clone") {
		types = append(types, ebpf.EvtFork)
	}
	if strings.Contains(cond, "open") || strings.Contains(cond, "file_open") {
		types = append(types, ebpf.EvtFileOpen)
	}
	if strings.Contains(cond, "unlink") {
		types = append(types, ebpf.EvtFileUnlink)
	}
	if strings.Contains(cond, "memfd") {
		types = append(types, ebpf.EvtFileMemfd)
	}
	if strings.Contains(cond, "connect") || strings.Contains(cond, "net_outbound") {
		types = append(types, ebpf.EvtNetConnect, ebpf.EvtNetUDP)
	}
	if strings.Contains(cond, "listen") {
		types = append(types, ebpf.EvtNetListen)
	}
	if strings.Contains(cond, "setns") {
		types = append(types, ebpf.EvtSetns)
	}
	if strings.Contains(cond, "unshare") {
		types = append(types, ebpf.EvtUnshare)
	}
	if strings.Contains(cond, "mount") {
		types = append(types, ebpf.EvtMount)
	}
	if strings.Contains(cond, "ptrace") {
		types = append(types, ebpf.EvtPtrace)
	}
	if strings.Contains(cond, "bpf") && !strings.Contains(cond, "ebpf") {
		types = append(types, ebpf.EvtBpfLoad)
	}
	if strings.Contains(cond, "setuid") {
		types = append(types, ebpf.EvtSetuid)
	}
	if strings.Contains(cond, "capset") {
		types = append(types, ebpf.EvtCapset)
	}
	if strings.Contains(cond, "chmod") || strings.Contains(cond, "suid") || strings.Contains(cond, "sgid") {
		types = append(types, ebpf.EvtChmod)
	}
	if strings.Contains(cond, "dup") {
		// dup2/dup3 for reverse shell detection — mapped to fork/exec events
		types = append(types, ebpf.EvtExec, ebpf.EvtNetConnect)
	}

	// If no specific types found, match all
	if len(types) == 0 {
		types = append(types, 0) // 0 = wildcard
	}

	return types
}

// inferCategory determines the dominant event category for a condition.
func (e *Engine) inferCategory(condition string) uint8 {
	cond := strings.ToLower(condition)

	if strings.Contains(cond, "escape") || strings.Contains(cond, "setns") ||
		strings.Contains(cond, "unshare") || strings.Contains(cond, "mount") ||
		strings.Contains(cond, "docker.sock") {
		return ebpf.CatEscape
	}
	if strings.Contains(cond, "network") || strings.Contains(cond, "connect") ||
		strings.Contains(cond, "outbound") || strings.Contains(cond, "listen") {
		return ebpf.CatNetwork
	}
	if strings.Contains(cond, "file") || strings.Contains(cond, "open") ||
		strings.Contains(cond, "sensitive") || strings.Contains(cond, "drift") {
		return ebpf.CatFile
	}
	if strings.Contains(cond, "privilege") || strings.Contains(cond, "setuid") ||
		strings.Contains(cond, "chmod") || strings.Contains(cond, "capset") {
		return ebpf.CatPrivilege
	}
	if strings.Contains(cond, "credential") || strings.Contains(cond, "shadow") ||
		strings.Contains(cond, "metadata") {
		return ebpf.CatCredential
	}

	return 0 // wildcard
}
