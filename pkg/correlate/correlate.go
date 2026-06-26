// Package correlate implements the multi-signal correlation engine for
// SecurityScarlet Runtime. It detects composite attack patterns by matching
// multiple signals (events) within configurable time windows.
//
// Per SRD Section 8.2, rules can specify a `correlate` section:
//
//	rule: Reverse Shell — Shell with Outbound Network
//	  condition: net_outbound and container and shell_procs and fd.rport not in (80, 443)
//	  correlate:
//	    window: 5s
//	    signals: [shell_procs, net_outbound]
//	    logic: all         # all signals must match within window
//	    group_by: [proc.pid] # group events by PID
//
// The correlation engine maintains time-windowed state per (rule, group_by key)
// and fires when all required signals appear within the window. This enables
// detection of:
//   - Reverse shells (shell spawn + network connect within 5s)
//   - Cryptojacking behavioral patterns (CPU spike + pool connection)
//   - Privilege escalation chains (setuid + sensitive file access)
//
// Architecture:
//   - Correlator: manages correlation windows, signal tracking, and firing
//   - CorrelationRule: configured correlation specification
//   - SignalWindow: tracks which signals have been seen within a window
//   - CorrelationResult: result of a successful correlation match
package correlate

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ── Signal Types ────────────────────────────────────────────────────────

// Signal represents a named event signal that can participate in correlation.
// Signals are derived from rule conditions (e.g., "shell_procs", "net_outbound").
type Signal struct {
	Name        string            // Signal name (e.g., "shell_procs", "net_outbound")
	Timestamp   time.Time         // When the signal was observed
	PID         uint32            // Process ID that produced the signal
	ContainerID string            // Container where the signal was observed
	Namespace   string            // Kubernetes namespace
	RuleID      string            // Rule that produced this signal
	Extra       map[string]string // Additional context (IP, port, path, etc.)
}

// ── Correlation Logic ──────────────────────────────────────────────────

// CorrelationLogic determines how signals must combine to fire.
type CorrelationLogic string

const (
	// LogicAll fires when ALL specified signals match within the window.
	LogicAll CorrelationLogic = "all"

	// LogicAny fires when ANY of the specified signals match.
	// (Less useful for correlation, but supported for completeness.)
	LogicAny CorrelationLogic = "any"
)

// ── Correlation Spec ────────────────────────────────────────────────────

// CorrelationSpec defines a time-windowed correlation pattern.
// This is the configuration that correlates with the rule's `correlate` section.
type CorrelationSpec struct {
	// RuleID is the ID of the rule this correlation belongs to (e.g., "R014").
	RuleID string

	// Window is the time window in which all signals must appear.
	Window time.Duration

	// Signals is the list of signal names that must match for correlation.
	// A correlation fires when all (or any, depending on Logic) signals
	// have been observed within the Window.
	Signals []string

	// Logic determines how signals combine: "all" (AND) or "any" (OR).
	Logic CorrelationLogic

	// GroupBy is the list of event fields used to group signals.
	// For example, ["proc.pid"] groups by process ID so that
	// signals from different processes don't correlate.
	GroupBy []string
}

// ── Correlation Result ──────────────────────────────────────────────────

// CorrelationResult is emitted when a correlation fires.
type CorrelationResult struct {
	// RuleID is the rule that triggered the correlation.
	RuleID string

	// MatchedSignals are the signals that contributed to the match.
	MatchedSignals []Signal

	// WindowStart is when the correlation window opened (first signal).
	WindowStart time.Time

	// WindowEnd is when the correlation fired (last signal).
	WindowEnd time.Time

	// GroupKey is the group_by key that identified this correlation.
	GroupKey string

	// PID is the primary process ID involved.
	PID uint32

	// ContainerID is the container where the correlation was detected.
	ContainerID string

	// Namespace is the Kubernetes namespace.
	Namespace string

	// Description is a human-readable summary of the correlation.
	Description string
}

// ── Signal Window ──────────────────────────────────────────────────────

// SignalWindow tracks which signals have been observed within a time window.
// One window per (rule_id, group_by_key) pair.
type SignalWindow struct {
	// RuleID is the correlation rule this window belongs to.
	RuleID string

	// GroupKey is the composite key from group_by fields (e.g., PID).
	GroupKey string

	// Spec is the correlation spec for this window.
	Spec *CorrelationSpec

	// Matched signals: signal_name → last observed Signal
	signals map[string]*Signal

	// When the window was first opened (first signal timestamp).
	started time.Time

	// Whether this window has already fired (prevents re-firing within window).
	fired bool
}

// Matches checks if the window has satisfied its correlation logic.
func (sw *SignalWindow) Matches() bool {
	switch sw.Spec.Logic {
	case LogicAll:
		// All signals must be present
		for _, sigName := range sw.Spec.Signals {
			if _, ok := sw.signals[sigName]; !ok {
				return false
			}
		}
		return true

	case LogicAny:
		// At least one signal must be present
		return len(sw.signals) > 0

	default:
		return len(sw.signals) == len(sw.Spec.Signals)
	}
}

// IsExpired checks if the window has exceeded its time duration.
func (sw *SignalWindow) IsExpired(now time.Time) bool {
	return now.Sub(sw.started) > sw.Spec.Window
}

// ── Correlator ──────────────────────────────────────────────────────────

// Correlator manages time-windowed correlation of security signals.
// It receives signals from the rule engine and fires correlation results
// when all (or any) specified signals appear within the time window,
// grouped by the specified fields.
type Correlator struct {
	mu sync.RWMutex

	// Active correlation rules
	rules map[string]*CorrelationSpec // rule_id → spec

	// Active windows: (rule_id, group_key) → SignalWindow
	windows map[windowKey]*SignalWindow

	// Configuration
	maxWindows    int           // Maximum number of active windows (prevent memory leak)
	purgeInterval time.Duration // How often to purge expired windows

	// Output channel for correlation results
	resultCh chan<- CorrelationResult

	// Lifecycle
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Stats
	correlationsFired uint64
	signalsProcessed  uint64
	windowsCreated    uint64
	windowsExpired    uint64
}

// windowKey uniquely identifies a correlation window.
type windowKey struct {
	ruleID   string
	groupKey string
}

// NewCorrelator creates a new correlation engine.
func NewCorrelator() *Correlator {
	return &Correlator{
		rules:         make(map[string]*CorrelationSpec),
		windows:       make(map[windowKey]*SignalWindow),
		maxWindows:    10000, // prevent unbounded memory growth
		purgeInterval: 30 * time.Second,
		stopCh:        make(chan struct{}),
	}
}

// SetResultChannel sets the output channel for correlation results.
func (c *Correlator) SetResultChannel(ch chan<- CorrelationResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resultCh = ch
}

// AddRule adds a correlation rule to the engine.
func (c *Correlator) AddRule(spec *CorrelationSpec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[spec.RuleID] = spec
	log.Printf("[correlate] Added correlation rule %s: signals=%v window=%v logic=%s group_by=%v",
		spec.RuleID, spec.Signals, spec.Window, spec.Logic, spec.GroupBy)
}

// RemoveRule removes a correlation rule from the engine.
func (c *Correlator) RemoveRule(ruleID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.rules, ruleID)
	// Also remove all windows for this rule
	for key := range c.windows {
		if key.ruleID == ruleID {
			delete(c.windows, key)
		}
	}
	log.Printf("[correlate] Removed correlation rule %s", ruleID)
}

// RuleCount returns the number of active correlation rules.
func (c *Correlator) RuleCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

// ── Signal Processing ──────────────────────────────────────────────────

// ProcessSignal processes an incoming signal against all correlation rules.
// This is the primary entry point for the correlation engine.
// Returns a correlation result if a correlation fires, or nil otherwise.
func (c *Correlator) ProcessSignal(signal *Signal) *CorrelationResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.signalsProcessed++

	// Check each correlation rule
	for ruleID, spec := range c.rules {
		// Check if this signal matches any of the rule's expected signals
		if !c.signalMatchesRule(signal, spec) {
			continue
		}

		// Build the group_by key
		groupKey := c.buildGroupKey(signal, spec)

		// Get or create the correlation window
		key := windowKey{ruleID: ruleID, groupKey: groupKey}
		window, exists := c.windows[key]

		if !exists || window.IsExpired(time.Now()) {
			// Create new window or reset expired one
			if exists && window.IsExpired(time.Now()) {
				c.windowsExpired++
			}
			if len(c.windows) >= c.maxWindows {
				// Evict eldest window to prevent memory leak
				c.evictEldestWindow()
			}
			window = &SignalWindow{
				RuleID:   ruleID,
				GroupKey: groupKey,
				Spec:     spec,
				signals:  make(map[string]*Signal),
				started:  time.Now(),
				fired:    false,
			}
			c.windows[key] = window
			c.windowsCreated++
		}

		// Add signal to window
		window.signals[signal.Name] = signal

		// Check if window has already fired (don't re-fire within same window)
		if window.fired {
			continue
		}

		// Check if correlation fires
		if window.Matches() {
			window.fired = true
			result := c.buildResult(window)
			c.correlationsFired++

			// Send result if channel is available
			if c.resultCh != nil {
				select {
				case c.resultCh <- result:
				default:
					log.Printf("[correlate] Warning: result channel full, dropping correlation result for %s", ruleID)
				}
			}

			return &result
		}
	}

	return nil
}

// signalMatchesRule checks if a signal name is in the rule's signal list.
func (c *Correlator) signalMatchesRule(signal *Signal, spec *CorrelationSpec) bool {
	for _, sigName := range spec.Signals {
		if signal.Name == sigName {
			return true
		}
	}
	return false
}

// buildGroupKey constructs the group_by key for a signal.
func (c *Correlator) buildGroupKey(signal *Signal, spec *CorrelationSpec) string {
	if len(spec.GroupBy) == 0 {
		return "global"
	}

	// Build composite key from group_by fields
	key := ""
	for _, field := range spec.GroupBy {
		switch field {
		case "proc.pid", "pid":
			key += fmt.Sprintf("pid:%d", signal.PID)
		case "container.id", "container_id":
			key += fmt.Sprintf("cid:%s", signal.ContainerID)
		case "namespace":
			key += fmt.Sprintf("ns:%s", signal.Namespace)
		default:
			// Check extra fields
			if v, ok := signal.Extra[field]; ok {
				key += fmt.Sprintf("%s:%s", field, v)
			}
		}
	}

	if key == "" {
		return "global"
	}
	return key
}

// buildResult creates a CorrelationResult from a matched SignalWindow.
func (c *Correlator) buildResult(window *SignalWindow) CorrelationResult {
	var matchedSignals []Signal
	for _, sig := range window.signals {
		matchedSignals = append(matchedSignals, *sig)
	}

	// Build description
	description := fmt.Sprintf("Correlation fired for rule %s: %d signals matched in %v window",
		window.RuleID, len(matchedSignals), window.Spec.Window)

	return CorrelationResult{
		RuleID:         window.RuleID,
		MatchedSignals: matchedSignals,
		WindowStart:    window.started,
		WindowEnd:      time.Now(),
		GroupKey:       window.GroupKey,
		PID:            matchedSignals[0].PID,
		ContainerID:    matchedSignals[0].ContainerID,
		Namespace:      matchedSignals[0].Namespace,
		Description:    description,
	}
}

// evictEldestWindow removes the oldest correlation window to limit memory usage.
func (c *Correlator) evictEldestWindow() {
	var oldestKey windowKey
	var oldestTime time.Time
	first := true

	for key, window := range c.windows {
		if first || window.started.Before(oldestTime) {
			oldestKey = key
			oldestTime = window.started
			first = false
		}
	}

	if oldestKey.ruleID != "" {
		delete(c.windows, oldestKey)
	}
}

// ── Lifecycle ────────────────────────────────────────────────────────

// Start begins the correlation engine's background goroutines.
func (c *Correlator) Start() {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.mu.Unlock()

	c.wg.Add(1)
	go c.purgeLoop()
	log.Printf("[correlate] Started correlation engine with %d rules, max windows=%d",
		len(c.rules), c.maxWindows)
}

// Stop gracefully stops the correlation engine.
func (c *Correlator) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	c.mu.Unlock()

	close(c.stopCh)
	c.wg.Wait()

	log.Printf("[correlate] Correlation engine stopped. Fired=%d Processed=%d Created=%d Expired=%d",
		c.correlationsFired, c.signalsProcessed, c.windowsCreated, c.windowsExpired)
}

// purgeLoop periodically removes expired correlation windows.
func (c *Correlator) purgeLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.purgeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.purgeExpiredWindows()
		}
	}
}

// purgeExpiredWindows removes all windows that have exceeded their time duration.
func (c *Correlator) purgeExpiredWindows() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var purged int

	for key, window := range c.windows {
		if window.IsExpired(now) {
			delete(c.windows, key)
			c.windowsExpired++
			purged++
		}
	}

	if purged > 0 {
		log.Printf("[correlate] Purged %d expired windows (total expired: %d)",
			purged, c.windowsExpired)
	}
}

// ── Stats ──────────────────────────────────────────────────────────────

// CorrelatorStats holds statistics about the correlation engine.
type CorrelatorStats struct {
	RulesCount        int    `json:"rules_count"`
	ActiveWindows     int    `json:"active_windows"`
	CorrelationsFired uint64 `json:"correlations_fired"`
	SignalsProcessed  uint64 `json:"signals_processed"`
	WindowsCreated    uint64 `json:"windows_created"`
	WindowsExpired    uint64 `json:"windows_expired"`
}

// Stats returns current correlation engine statistics.
func (c *Correlator) Stats() CorrelatorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CorrelatorStats{
		RulesCount:        len(c.rules),
		ActiveWindows:     len(c.windows),
		CorrelationsFired: c.correlationsFired,
		SignalsProcessed:  c.signalsProcessed,
		WindowsCreated:    c.windowsCreated,
		WindowsExpired:    c.windowsExpired,
	}
}

// ── Built-in Correlation Rules ─────────────────────────────────────────

// DefaultCorrelationRules returns the built-in correlation rules from the SRD.
// These correlate with rules R014 (shell+network = reverse shell) and
// other multi-signal patterns.
func DefaultCorrelationRules() []*CorrelationSpec {
	return []*CorrelationSpec{
		// R014: Reverse Shell — Shell process with outbound network connection
		{
			RuleID:  "R014",
			Window:  5 * time.Second,
			Signals: []string{"shell_procs", "net_outbound"},
			Logic:   LogicAll,
			GroupBy: []string{"proc.pid"},
		},
		// R011: Behavioral Cryptojacking — high CPU activity + mining pool connection
		{
			RuleID:  "R011",
			Window:  30 * time.Second,
			Signals: []string{"high_cpu", "minerpool_connection"},
			Logic:   LogicAll,
			GroupBy: []string{"container.id"},
		},
		// Privilege Escalation Chain — setuid + sensitive file access
		{
			RuleID:  "R021-R018",
			Window:  10 * time.Second,
			Signals: []string{"setuid_transition", "sensitive_file_read"},
			Logic:   LogicAll,
			GroupBy: []string{"proc.pid"},
		},
		// Container Escape Chain — cgroup mount + namespace join
		{
			RuleID:  "R003-R001",
			Window:  5 * time.Second,
			Signals: []string{"cgroup_mount", "namespace_join"},
			Logic:   LogicAll,
			GroupBy: []string{"container.id"},
		},
		// Suspicious TLS SNI + mining pool connection — cryptojacking via TLS
		{
			RuleID:  "TLS-SNI-001",
			Window:  30 * time.Second,
			Signals: []string{"tls_suspicious_sni", "minerpool_connection"},
			Logic:   LogicAny,
			GroupBy: []string{"container.id"},
		},
		// Suspicious DNS query + suspicious SNI — malware C2 detection
		{
			RuleID:  "DNS-SNI-001",
			Window:  10 * time.Second,
			Signals: []string{"dns_suspicious_query", "tls_suspicious_sni"},
			Logic:   LogicAny,
			GroupBy: []string{"container.id"},
		},
		// Suspicious DNS query pattern — DGA or tunnel detection
		{
			RuleID:  "DNS-001",
			Window:  60 * time.Second,
			Signals: []string{"dns_suspicious_query"},
			Logic:   LogicAny,
			GroupBy: []string{"container.id"},
		},
	}
}
