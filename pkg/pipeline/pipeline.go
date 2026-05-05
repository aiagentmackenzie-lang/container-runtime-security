// Package pipeline implements the event processing pipeline for
// SecurityScarlet Runtime. Events flow from the eBPF ring buffer through
// decoding, enrichment, rule matching, and alert emission.
package pipeline

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/securityscarlet/runtime/pkg/ai"
	"github.com/securityscarlet/runtime/pkg/correlate"
	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/enrichment"
	"github.com/securityscarlet/runtime/pkg/output"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── AI Alert Triage Interface ──────────────────────────────────────────

// AIAlertTrier is an interface for AI-powered alert triage.
// This decouples the pipeline from the AI package (avoids import cycles).
// The AIConnector in pkg/ai implements this interface.
//
// When a trier is set, alerts are submitted for false-positive assessment
// before emission. If the AI recommends suppression, the alert is suppressed.
// If the AI recommends downgrading, the alert priority is adjusted.
type AIAlertTrier interface {
	// TriageAlert assesses whether an alert is a false positive.
	// Returns a false-positive score (0=definitely real, 1=definitely FP)
	// and a recommended priority.
	TriageAlert(ruleID string, priority string, namespace string, container string) (fpScore float64, recommendedPriority string, reasoning string)
}

// ── Alert Emitter Interface ────────────────────────────────────────────

// AlertEmitter is an interface for emitting security alerts.
// The output.AlertEmitter type and output.TestAlertEmitter implement this interface.
// Using an interface enables testing with mock emitters without
// requiring file-based emission.
type AlertEmitter interface {
	Emit(alert *output.Alert)
}

// ── AI Rule Suggester Interface ──────────────────────────────────────────

// AIRuleSuggester is an interface for AI-driven rule suggestions.
// When a correlation fires or an anomaly is detected, the pipeline collects
// incident context and calls SuggestRule() to generate a draft YAML rule.
// High-confidence suggestions are logged for human review.
// The AIConnector in pkg/ai implements this interface.
type AIRuleSuggester interface {
	// SuggestRule requests an AI-generated rule suggestion from incident context.
	// Returns a RuleSuggestion that requires human approval.
	SuggestRule(ctx context.Context, incident *ai.IncidentContext) (*ai.RuleSuggestion, error)
}

// ── Pipeline Configuration ────────────────────────────────────────────

// PipelineConfig holds configuration for the event processing pipeline.
type PipelineConfig struct {
	EventChannel    <-chan *ebpf.ScarletEvent
	RuleEngine      *rules.Engine
	Enricher        *enrichment.Manager
	AlertEmitter    AlertEmitter
	MetricsExporter *output.MetricsExporter
	NetworkEnforcer *enforcement.NetworkEnforcer // TC-based network blocker
	Correlator      *correlate.Correlator        // Multi-signal correlation engine
	AIConnector     AIAlertTrier                // AI-powered alert triage
	Mode            string // audit, enforce, simulate

	// Anomaly detection
	AnomalyThreshold float64 // Minimum score to emit anomaly-only alert (default: 0.8)
	AnomalyEnabled   bool    // Enable per-container anomaly scoring (default: true)

	// AI-driven rule suggestions
	AIRuleSuggester AIRuleSuggester // AI connector for rule suggestions (optional)

	// Suggestion confidence threshold — suggestions with confidence below this
	// value are discarded. Default: 0.5.
	SuggestionMinConfidence float64

	// AI triage thresholds (default: 0.5/0.7/0.9)
	// fpScore >= SuppressThreshold → suppress the alert entirely
	// fpScore >= DowngradeThreshold (non-enforce) → downgrade priority
	// fpScore >= AdjustThreshold → adjust priority but don't suppress
	TriageSuppressThreshold   float64 // Default: 0.9
	TriageDowngradeThreshold  float64 // Default: 0.7
	TriageAdjustThreshold     float64 // Default: 0.5

	// Baseline learning mode
	LearningMode        bool // Enable automatic baseline learning (default: true)
	MinEventsForBaseline int  // Minimum events before auto-building baseline (default: 100)

	// Tuning
	Workers        int // Number of parallel event processors (default: 4)
	BatchSize      int // Events per enforcement batch (default: 1)
	CoalesceWindow time.Duration
}

// ── Pipeline ──────────────────────────────────────────────────────────

// Pipeline is the core event processing pipeline. It reads events from
// the eBPF ring buffer channel, enriches them with container/K8s metadata,
// evaluates them against the rule engine, and routes decisions through
// the response actor.
type Pipeline struct {
	config    PipelineConfig
	mode      string
	eventCh   <-chan *ebpf.ScarletEvent

	// Components
	ruleEngine     *rules.Engine
	enricher       *enrichment.Manager
	alertEmit      AlertEmitter
	metrics        *output.MetricsExporter
	coalescer      *Coalescer
	response       *ResponseActor
	netEnforcer    *enforcement.NetworkEnforcer // TC-based network enforcer
	correlator     *correlate.Correlator         // Multi-signal correlation engine
	aiTrier       AIAlertTrier                  // AI-powered alert triage
	aiSuggester   AIRuleSuggester               // AI-powered rule suggestions
	suggestionMinConfidence float64             // Minimum confidence to log a suggestion

	// AI triage thresholds
	triageSuppressThreshold  float64 // fpScore >= this → suppress (default: 0.9)
	triageDowngradeThreshold float64 // fpScore >= this → downgrade (default: 0.7)
	triageAdjustThreshold    float64 // fpScore >= this → adjust (default: 0.5)

	// Baseline learning mode
	learningMode         bool // Auto-build baselines after enough events (default: true)
	minEventsForBaseline int  // Minimum events before auto-building (default: 100)
	eventCounts          map[string]int // container_id → processed event count for learning
	learningMu           sync.Mutex      // protects eventCounts and baseline learning

	// Per-container anomaly scoring
	extractors       map[string]*ai.FeatureExtractor // container_id → feature extractor
	baselines        map[string]*ai.NgramBaseline     // container_image → baseline
	anomalyMu        sync.RWMutex
	anomalyThreshold float64
	anomalyEnabled   bool

	// Counters
	eventsProcessed  atomic.Uint64
	alertsEmitted    atomic.Uint64
	enforcementsExec atomic.Uint64

	// State
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// NewPipeline creates a new event processing pipeline.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.CoalesceWindow <= 0 {
		cfg.CoalesceWindow = 5 * time.Second
	}

	// Anomaly defaults
	anomalyThreshold := cfg.AnomalyThreshold
	if anomalyThreshold <= 0 {
		anomalyThreshold = 0.8
	}
	anomalyEnabled := true
	// AnomalyEnabled defaults to true; only disable if explicitly set to false
	// (we can't distinguish "not set" from "set to false" on a bool, so use
	// a positive default unless the field is explicitly managed via config)

	// Suggestion confidence default
	suggestionMinConfidence := cfg.SuggestionMinConfidence
	if suggestionMinConfidence <= 0 {
		suggestionMinConfidence = 0.5
	}

	// AI triage threshold defaults
	triageSuppressThreshold := cfg.TriageSuppressThreshold
	if triageSuppressThreshold <= 0 {
		triageSuppressThreshold = 0.9
	}
	triageDowngradeThreshold := cfg.TriageDowngradeThreshold
	if triageDowngradeThreshold <= 0 {
		triageDowngradeThreshold = 0.7
	}
	triageAdjustThreshold := cfg.TriageAdjustThreshold
	if triageAdjustThreshold <= 0 {
		triageAdjustThreshold = 0.5
	}

	// Baseline learning defaults
	learningMode := true // default to true; use SetLearningMode to disable at runtime
	minEventsForBaseline := cfg.MinEventsForBaseline
	if minEventsForBaseline <= 0 {
		minEventsForBaseline = 100
	}

	return &Pipeline{
		config:           cfg,
		mode:             cfg.Mode,
		eventCh:          cfg.EventChannel,
		ruleEngine:       cfg.RuleEngine,
		enricher:         cfg.Enricher,
		alertEmit:        cfg.AlertEmitter,
		metrics:          cfg.MetricsExporter,
		coalescer:        NewCoalescer(cfg.CoalesceWindow),
		response:         NewResponseActor(cfg.Mode),
		netEnforcer:      cfg.NetworkEnforcer,
		correlator:       cfg.Correlator,
		extractors:        make(map[string]*ai.FeatureExtractor),
		baselines:         make(map[string]*ai.NgramBaseline),
		anomalyThreshold:  anomalyThreshold,
		anomalyEnabled:    anomalyEnabled,
		suggestionMinConfidence: suggestionMinConfidence,
		aiSuggester:       cfg.AIRuleSuggester,
		triageSuppressThreshold:  triageSuppressThreshold,
		triageDowngradeThreshold: triageDowngradeThreshold,
		triageAdjustThreshold:    triageAdjustThreshold,
		learningMode:         learningMode,
		minEventsForBaseline: minEventsForBaseline,
		eventCounts:          make(map[string]int),
		stopCh:           make(chan struct{}),
	}
}

// Start begins the event processing pipeline. Blocks until Stop is called.
func (p *Pipeline) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.mu.Unlock()

	log.Printf("[pipeline] Starting event processing pipeline (%d workers)", p.config.Workers)

	// Start coalescer flush loop
	p.wg.Add(1)
	go p.coalescerLoop(ctx)

	// Start event processing workers
	for i := 0; i < p.config.Workers; i++ {
		p.wg.Add(1)
		go p.processEvents(ctx, i)
	}

	log.Printf("[pipeline] Pipeline running in %s mode", p.mode)
}

// Stop gracefully stops the pipeline.
func (p *Pipeline) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return
	}

	log.Printf("[pipeline] Stopping event processing pipeline...")
	close(p.stopCh)
	p.wg.Wait()

	// Flush coalescer
	p.coalescer.Flush(p.alertEmit)

	p.running = false
	log.Printf("[pipeline] Pipeline stopped. Events processed: %d, Alerts: %d, Enforcements: %d",
		p.eventsProcessed.Load(), p.alertsEmitted.Load(), p.enforcementsExec.Load())
}

// SetMode changes the pipeline operating mode at runtime.
func (p *Pipeline) SetMode(mode string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = mode
	p.response.SetMode(mode)
	log.Printf("[pipeline] Mode changed to: %s", mode)
}

// SetNetworkEnforcer sets the network enforcer for TC-based network blocking.
// This can be called after pipeline creation to inject the network enforcer.
func (p *Pipeline) SetNetworkEnforcer(ne *enforcement.NetworkEnforcer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.netEnforcer = ne
}

// SetCorrelator sets the multi-signal correlation engine.
// This can be called after pipeline creation to inject the correlator.
// When set, rule matches are forwarded as signals to the correlator,
// which can fire composite attack pattern detections.
func (p *Pipeline) SetCorrelator(c *correlate.Correlator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.correlator = c
}

// SetAIAlertTrier sets the AI-powered alert triage service.
// When set, alerts are submitted for false-positive assessment before emission.
// Alerts that the AI identifies as likely false positives can be suppressed
// or downgraded.
func (p *Pipeline) SetAIAlertTrier(trier AIAlertTrier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.aiTrier = trier
}

// SetAIRuleSuggester sets the AI-powered rule suggestion service.
// When set, correlation alerts and anomaly alerts will trigger async rule
// suggestions. High-confidence suggestions are logged for human review.
func (p *Pipeline) SetAIRuleSuggester(suggester AIRuleSuggester) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.aiSuggester = suggester
}

// InitCorrelationRules registers correlation rules from the rule engine
// with the correlator. This should be called after both the rule engine
// and correlator are set on the pipeline.
func (p *Pipeline) InitCorrelationRules() {
	p.mu.Lock()
	correl := p.correlator
	p.mu.Unlock()

	if correl == nil || p.ruleEngine == nil {
		return
	}

	// Register correlation specs from the rule engine's compiled rules
	for _, rule := range p.ruleEngine.CorrelationRules() {
		if rule.Correlate == nil {
			continue
		}

		logic := correlate.LogicAll
		if rule.Correlate.Logic == "any" {
			logic = correlate.LogicAny
		}

		spec := &correlate.CorrelationSpec{
			RuleID:  rule.ID,
			Window:  rule.Correlate.Window,
			Signals: rule.Correlate.Signals,
			Logic:   logic,
			GroupBy: rule.Correlate.GroupBy,
		}
		correl.AddRule(spec)
	}

	// Also register the default built-in correlation rules
	for _, spec := range correlate.DefaultCorrelationRules() {
		correl.AddRule(spec)
	}
}

// ── Per-Container Anomaly Scoring ──────────────────────────────────────

// feedSyscallForAnomaly feeds a syscall from the enriched event to the
// per-container FeatureExtractor and computes the anomaly score.
// Returns 0 if there is not enough data to score.
func (p *Pipeline) feedSyscallForAnomaly(event *EnrichedEvent) float64 {
	if event.ContainerID == "" {
		return 0
	}

	extractor := p.getOrCreateExtractor(event.ContainerID)
	extractor.AddSyscall(uint32(event.RawEvent.SyscallNr))

	// Look up baseline for this container's image
	var baseline *ai.NgramBaseline
	p.anomalyMu.RLock()
	if event.ContainerImage != "" {
		baseline = p.baselines[event.ContainerImage]
	}
	p.anomalyMu.RUnlock()

	return extractor.ScoreAnomaly(baseline)
}

// FeedSyscallForAnomalyCgroupFallback provides anomaly scoring for
// unattributed events by using CgroupID as a fallback key. This is the
// exported version for testing; callers should normally let processOneEvent
// call it via the CgroupID fallback path.
func (p *Pipeline) FeedSyscallForAnomalyCgroupFallback(event *EnrichedEvent) float64 {
	return p.feedSyscallForAnomalyCgroupFallback(event)
}

// feedSyscallForAnomalyCgroupFallback provides anomaly scoring for
// unattributed events by using CgroupID as a fallback key. This allows
// anomaly detection to work even when CRI resolution fails and container
// metadata is not available.
func (p *Pipeline) feedSyscallForAnomalyCgroupFallback(event *EnrichedEvent) float64 {
	cgroupKey := fmt.Sprintf("cgroup:%d", event.RawEvent.CgroupID)

	extractor := p.getOrCreateExtractor(cgroupKey)
	extractor.AddSyscall(uint32(event.RawEvent.SyscallNr))

	// No baseline available for cgroup-keyed extractors (no container image)
	return extractor.ScoreAnomaly(nil)
}

// getOrCreateExtractor returns the FeatureExtractor for a container,
// creating it if it does not yet exist. Thread-safe.
func (p *Pipeline) getOrCreateExtractor(containerID string) *ai.FeatureExtractor {
	p.anomalyMu.RLock()
	extractor, ok := p.extractors[containerID]
	p.anomalyMu.RUnlock()
	if ok {
		return extractor
	}

	p.anomalyMu.Lock()
	defer p.anomalyMu.Unlock()

	// Double-check after acquiring write lock
	if extractor, ok = p.extractors[containerID]; ok {
		return extractor
	}

	extractor = ai.NewFeatureExtractor()
	p.extractors[containerID] = extractor
	return extractor
}

// emitAnomalyAlert emits an anomaly-only alert when no rule matched but
// the per-container anomaly score exceeded the threshold.
func (p *Pipeline) emitAnomalyAlert(event *EnrichedEvent) {
	// Only emit if score meets threshold
	p.anomalyMu.RLock()
	score := event.AnomalyScore
	threshold := p.anomalyThreshold
	p.anomalyMu.RUnlock()

	if score < threshold {
		return
	}

	raw := event.RawEvent

	// Determine priority based on anomaly score
	priority := rules.PriorityWarning
	if event.AnomalyScore >= 0.9 {
		priority = rules.PriorityCritical
	} else if event.AnomalyScore >= 0.8 {
		priority = rules.PriorityError
	}

	alert := &output.Alert{
		Timestamp:      time.Now(),
		RuleID:         "ANOMALY",
		RuleName:       "Anomaly Detection — N-gram Score Exceeded Threshold",
		Priority:       priority,
		Action:         output.ActionAlert,
		Output:         fmt.Sprintf("Anomaly score %.2f exceeded threshold %.2f for container %s (image=%s comm=%s pid=%d)",
			event.AnomalyScore, p.anomalyThreshold, event.ContainerID,
			event.ContainerImage, raw.CommString(), raw.PID),
		AnomalyScore:   event.AnomalyScore,
		ProcessName:    raw.CommString(),
		PID:            raw.PID,
		PPID:           raw.PPID,
		UID:            raw.UID,
		GID:            raw.GID,
		Category:       raw.CategoryString(),
		EventType:      raw.EventTypeString(),
		ContainerID:    event.ContainerID,
		ContainerName:  event.ContainerName,
		ContainerImage: event.ContainerImage,
		Namespace:      event.Namespace,
		PodName:        event.PodName,
		Tags:           []string{"anomaly", "ngram"},
	}

	if p.alertEmit != nil {
		p.alertEmit.Emit(alert)
	}
	p.alertsEmitted.Add(1)

	log.Printf("[pipeline] ANOMALY: score=%.2f container=%s image=%s comm=%s pid=%d",
		event.AnomalyScore, event.ContainerID, event.ContainerImage,
		raw.CommString(), raw.PID)

	// AI-driven rule suggestion: request draft rule from anomaly context
	p.mu.RLock()
	suggester := p.aiSuggester
	minConf := p.suggestionMinConfidence
	p.mu.RUnlock()
	if suggester != nil {
		incident := &ai.IncidentContext{
			RuleID:         "ANOMALY",
			ContainerImage: event.ContainerImage,
			Namespace:      event.Namespace,
			Timestamp:      time.Now(),
			Events: []ai.AIEvent{{
				EventType:   "anomaly_detection",
				ProcessName: raw.CommString(),
				PID:         raw.PID,
				Category:    raw.CategoryString(),
				Timestamp:   time.Now(),
				Details: map[string]string{
					"anomaly_score": fmt.Sprintf("%.2f", event.AnomalyScore),
					"container_id":  event.ContainerID,
				},
			}},
		}
		// Fire SuggestRule async — must not block the pipeline
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			suggestion, err := suggester.SuggestRule(ctx, incident)
			if err != nil {
				log.Printf("[pipeline] AI SuggestRule failed for anomaly: %v", err)
				return
			}
			if suggestion.Confidence >= minConf {
				log.Printf("[pipeline] AI RULE SUGGESTION: anomaly_score=%.2f confidence=%.2f status=%s yaml=%q reasoning=%q",
					event.AnomalyScore, suggestion.Confidence, suggestion.Status,
					suggestion.RuleYAML, suggestion.Reasoning)
			}
		}()
	}
}

// SetBaseline sets the n-gram baseline for a container image. Baselines
// are used by ScoreAnomaly to compare observed syscall patterns against
// known-good behavior. This method is thread-safe.
func (p *Pipeline) SetBaseline(image string, baseline *ai.NgramBaseline) {
	p.anomalyMu.Lock()
	defer p.anomalyMu.Unlock()
	p.baselines[image] = baseline
}

// tryBuildBaseline checks if we have enough events to auto-build a baseline.
// When learning mode is enabled and a container has accumulated enough events,
// this method builds a baseline from the FeatureExtractor and stores it.
// Only builds if no baseline already exists for the container's image.
func (p *Pipeline) tryBuildBaseline(event *EnrichedEvent) {
	p.learningMu.Lock()
	defer p.learningMu.Unlock()

	containerID := event.ContainerID
	p.eventCounts[containerID]++

	if p.eventCounts[containerID] < p.minEventsForBaseline {
		return
	}

	// Check if baseline already exists for this image
	image := event.ContainerImage
	if image == "" {
		return
	}

	p.anomalyMu.RLock()
	_, exists := p.baselines[image]
	p.anomalyMu.RUnlock()
	if exists {
		return // Baseline already built
	}

	// Build baseline from the feature extractor
	extractor := p.getOrCreateExtractor(containerID)
	baseline := extractor.BuildBaseline(image)
	if baseline == nil || baseline.Confidence <= 0 {
		return // Not enough data in extractor yet
	}

	// Store the baseline
	p.SetBaseline(image, baseline)

	// Reset the event count for this container
	p.eventCounts[containerID] = 0

	log.Printf("[pipeline] BASELINE BUILT: image=%s confidence=%.2f ngrams=%d unique=%d",
		image, baseline.Confidence, baseline.TotalNgrams, baseline.UniqueNgrams)
}

// SetAnomalyEnabled enables or disables per-container anomaly scoring at runtime.
func (p *Pipeline) SetAnomalyEnabled(enabled bool) {
	p.anomalyMu.Lock()
	defer p.anomalyMu.Unlock()
	p.anomalyEnabled = enabled
	log.Printf("[pipeline] Anomaly scoring %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// AnomalyThreshold returns the current anomaly score threshold.
func (p *Pipeline) AnomalyThreshold() float64 {
	p.anomalyMu.RLock()
	defer p.anomalyMu.RUnlock()
	return p.anomalyThreshold
}

// IsAnomalyEnabled returns whether per-container anomaly scoring is enabled.
func (p *Pipeline) IsAnomalyEnabled() bool {
	p.anomalyMu.RLock()
	defer p.anomalyMu.RUnlock()
	return p.anomalyEnabled
}

// GetAIRuleSuggester returns the AI rule suggester (for testing/inspection).
func (p *Pipeline) GetAIRuleSuggester() AIRuleSuggester {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aiSuggester
}

// SuggestionMinConfidence returns the minimum confidence to log a suggestion.
func (p *Pipeline) SuggestionMinConfidence() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.suggestionMinConfidence
}

// SetTriageThresholds allows changing AI triage thresholds at runtime.
// Supply 0 or negative values to keep the current setting unchanged.
func (p *Pipeline) SetTriageThresholds(suppress, downgrade, adjust float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if suppress > 0 {
		p.triageSuppressThreshold = suppress
	}
	if downgrade > 0 {
		p.triageDowngradeThreshold = downgrade
	}
	if adjust > 0 {
		p.triageAdjustThreshold = adjust
	}
}

// TriageThresholds returns the current AI triage thresholds.
func (p *Pipeline) TriageThresholds() (suppress, downgrade, adjust float64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.triageSuppressThreshold, p.triageDowngradeThreshold, p.triageAdjustThreshold
}

// SetLearningMode enables or disables baseline learning mode at runtime.
func (p *Pipeline) SetLearningMode(enabled bool) {
	p.learningMu.Lock()
	defer p.learningMu.Unlock()
	p.learningMode = enabled
	log.Printf("[pipeline] Baseline learning mode %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// IsLearningMode returns whether baseline learning mode is enabled.
func (p *Pipeline) IsLearningMode() bool {
	p.learningMu.Lock()
	defer p.learningMu.Unlock()
	return p.learningMode
}

// MinEventsForBaseline returns the minimum events before auto-building a baseline.
func (p *Pipeline) MinEventsForBaseline() int {
	p.learningMu.Lock()
	defer p.learningMu.Unlock()
	return p.minEventsForBaseline
}

// GetBaseline returns the n-gram baseline for a container image, or nil if none.
func (p *Pipeline) GetBaseline(image string) *ai.NgramBaseline {
	p.anomalyMu.RLock()
	defer p.anomalyMu.RUnlock()
	return p.baselines[image]
}

// GetOrCreateExtractor returns the FeatureExtractor for a given container ID,
// creating one if it does not exist. This is the exported version for testing.
func (p *Pipeline) GetOrCreateExtractor(containerID string) *ai.FeatureExtractor {
	return p.getOrCreateExtractor(containerID)
}

// FeedSyscallForAnomaly tests a single enriched event and returns the anomaly
// score. This is the exported version for testing.
func (p *Pipeline) FeedSyscallForAnomaly(event *EnrichedEvent) float64 {
	return p.feedSyscallForAnomaly(event)
}

// EmitAnomalyAlert emits an anomaly-only alert. This is the exported version
// for testing; callers should normally let processOneEvent call it.
func (p *Pipeline) EmitAnomalyAlert(event *EnrichedEvent) {
	p.emitAnomalyAlert(event)
}

// CorrelationSignalNames maps rule IDs and event characteristics to the
// signal names used by the correlation engine. When a rule matches,
// the matched rule's ID and the event's properties determine which
// correlation signal name to emit.
var CorrelationSignalNames = map[string]string{
	// Shell processes → "shell_procs" signal
	"R014": "shell_procs",
	"R015": "shell_procs", // dup2 reverse shell
	"R016": "shell_procs", // shell on non-std port
	"R017": "shell_procs", // pipe-based shell

	// Network outbound → "net_outbound" signal
	"R009": "minerpool_connection", // mining pool
	"R027": "net_outbound",          // C2 port
	"R019": "net_outbound",          // cloud metadata
	"R026": "net_outbound",          // rogue listener

	// Behavioral cryptojacking signals
	"R008": "miner_procs",         // known miner binary
	"R010": "miner_procs",         // stratum protocol
	"R011": "high_cpu",            // behavioral CPU+net

	// Privilege / credential signals
	"R021": "setuid_transition",   // SetUID
	"R022": "suid_set",            // SUID/SGID bit
	"R018": "sensitive_file_read",  // sensitive file
	"R020": "sensitive_file_read",  // K8s SA token

	// Escape signals
	"R001": "namespace_join",       // setns
	"R002": "unshare",             // unshare
	"R003": "cgroup_mount",        // cgroup mount
	}

// NetworkBlockingRuleIDs maps rule IDs that trigger TC network enforcement
// to their reason strings. These rules block network traffic in addition
// to their normal alert/enforce action.
var NetworkBlockingRuleIDs = map[string]string{
	"R009": "mining_pool_connection",  // Mining pool connection → block destination
	"R027": "c2_port_connection",      // C2 port connection → block destination
	"R019": "cloud_metadata_ssrf",     // Cloud metadata SSRF → block 169.254.169.254
}

// EventsProcessed returns the total number of events processed.
func (p *Pipeline) EventsProcessed() uint64 {
	return p.eventsProcessed.Load()
}

// AlertsEmitted returns the total number of alerts emitted.
func (p *Pipeline) AlertsEmitted() uint64 {
	return p.alertsEmitted.Load()
}

// EnforcementsExecuted returns the total number of enforcement actions taken.
func (p *Pipeline) EnforcementsExecuted() uint64 {
	return p.enforcementsExec.Load()
}

// ProcessEvent processes a single eBPF event through the full pipeline.
// This method is intended for integration testing — normally, events come
// from the eBPF ring buffer channel. It calls the internal processOneEvent
// method directly, bypassing the channel.
func (p *Pipeline) ProcessEvent(event *ebpf.ScarletEvent) {
	p.processOneEvent(event)
}

// ── Event Processing ──────────────────────────────────────────────────

// processEvents is the main event processing goroutine.
func (p *Pipeline) processEvents(ctx context.Context, workerID int) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case event, ok := <-p.eventCh:
			if !ok {
				log.Printf("[pipeline] Worker %d: event channel closed", workerID)
				return
			}
			p.processOneEvent(event)
		}
	}
}

// processOneEvent handles a single event through the full pipeline.
func (p *Pipeline) processOneEvent(event *ebpf.ScarletEvent) {
	// 1. Increment processed counter
	p.eventsProcessed.Add(1)

	// 2. Enrich event with container metadata
	enriched := p.enrichEvent(event)

	// 3. Per-container anomaly scoring (before rule matching)
	if p.anomalyEnabled {
		// For container-attributed events, use container_id as the key.
		// For unattributed events (no CRI resolution), use cgroup_id as a
		// fallback key so these events still contribute to anomaly detection.
		if enriched.ContainerAttributed {
			if score := p.feedSyscallForAnomaly(enriched); score > 0 {
				enriched.AnomalyScore = score
			}
			// 3b. Baseline learning: auto-build baseline after enough events
			if p.learningMode && enriched.ContainerImage != "" {
				p.tryBuildBaseline(enriched)
			}
		} else if enriched.RawEvent.CgroupID != 0 {
			// Fallback: use CgroupID as key for unattributed events
			if score := p.feedSyscallForAnomalyCgroupFallback(enriched); score > 0 {
				enriched.AnomalyScore = score
			}
		}
	}

	// 4. Convert to rule engine view and evaluate
	var match *rules.RuleMatch
	ruleView := p.toRuleView(enriched)
	if p.ruleEngine != nil {
		match = p.ruleEngine.EvaluateRule(ruleView)
	}
	if match == nil {
		// No rule matched — emit anomaly-only alert if score exceeds threshold
		if enriched.AnomalyScore >= p.anomalyThreshold {
			p.emitAnomalyAlert(enriched)
		}
		// Still send to correlator as a raw signal for behavioral analysis.
		p.processCorrelationSignal(enriched, nil)
		return
	}

	// 5. Route decision (anomaly_score is attached to enriched event for buildAlert)
	p.routeDecision(enriched, match)

	// 6. Send matched rule signal to correlation engine
	p.processCorrelationSignal(enriched, match)
}

// enrichEvent adds container and Kubernetes metadata to the event.
func (p *Pipeline) enrichEvent(event *ebpf.ScarletEvent) *EnrichedEvent {
	enriched := &EnrichedEvent{
		RawEvent: event,
	}

	if p.enricher == nil {
		return enriched
	}

	// Resolve cgroup_id → container_id
	containerID := p.enricher.ResolveContainerID(event.CgroupID, event.PID)
	if containerID == "" {
		// Could not resolve — mark as unattributed
		enriched.ContainerAttributed = false
		return enriched
	}
	enriched.ContainerID = containerID
	enriched.ContainerAttributed = true

	// Get container info from CRI cache
	info := p.enricher.GetContainerInfo(containerID)
	if info != nil {
		enriched.ContainerName = info.Name
		enriched.ContainerImage = info.Image
		enriched.PodName = info.PodName
		enriched.Namespace = info.Namespace
		enriched.ServiceAccount = info.ServiceAccount
		enriched.PodLabels = info.Labels
		enriched.Privileged = info.Privileged
	}

	return enriched
}

// toRuleView converts an EnrichedEvent to the view expected by the rule engine.
func (p *Pipeline) toRuleView(event *EnrichedEvent) *rules.EnrichedEventForRule {
	return &rules.EnrichedEventForRule{
		Event:              event.RawEvent,
		ContainerID:         event.ContainerID,
		ContainerName:       event.ContainerName,
		ContainerImage:      event.ContainerImage,
		ContainerAttributed: event.ContainerAttributed,
		PodName:             event.PodName,
		Namespace:           event.Namespace,
		ServiceAccount:      event.ServiceAccount,
		PodLabels:           event.PodLabels,
		Privileged:          event.Privileged,
		NodeName:            event.NodeName,
	}
}

// processCorrelationSignal sends the event as a correlation signal to the correlator.
// When a correlation fires, an enriched alert is emitted with the correlation result.
// If match is nil (no rule matched), only event-category-derived signals are sent
// for behavioral pattern tracking.
func (p *Pipeline) processCorrelationSignal(event *EnrichedEvent, match *rules.RuleMatch) {
	p.mu.RLock()
	correl := p.correlator
	p.mu.RUnlock()

	if correl == nil {
		if p.metrics != nil && match != nil {
			p.metrics.RecordEventProcessed(string(match.Action), event.RawEvent.CategoryString())
		}
		return
	}

	// Determine the signal name
	signalName := ""
	if match != nil {
		if name, ok := CorrelationSignalNames[match.RuleID]; ok {
			signalName = name
		}
	} else {
		// For unmatched events, derive a signal name from event category+type
		signalName = EventCategorySignal(event.RawEvent)
	}

	if signalName == "" {
		return // Not a correlatable signal
	}

	// Build the signal with event context
	signal := &correlate.Signal{
		Name:        signalName,
		Timestamp:   time.Now(),
		PID:         event.RawEvent.PID,
		ContainerID: event.ContainerID,
		Namespace:   event.Namespace,
		RuleID:      "",
		Extra:       make(map[string]string),
	}

	if match != nil {
		signal.RuleID = match.RuleID
	}

	// Add event-specific context
	raw := event.RawEvent
	switch raw.Category {
	case ebpf.CatNetwork:
		signal.Extra["remote_ip"] = raw.RemoteIP()
		signal.Extra["remote_port"] = fmt.Sprintf("%d", raw.RemotePort())

		// Check for suspicious TLS SNI if this is a TLS connection
		if signalName == "tls_connection" {
			// In production, the payload would be parsed from the eBPF event's
			// network payload buffer. For now, the SNI detection is wired into
			// the signal path so that when eBPF provides TLS payload data,
			// the SNI will be extracted and checked.
			// The SNI extraction function (ebpf.ExtractTLSClientHelloSNI) can be
			// called on network payload bytes when available.
			signal.Extra["has_tls"] = "true"
		}

		// Check for DNS queries
		if signalName == "dns_query" {
			signal.Extra["is_dns"] = "true"
		}

	case ebpf.CatFile:
		signal.Extra["file_path"] = raw.FilePath()
	case ebpf.CatProcess:
		signal.Extra["filename"] = raw.Filename()
	case ebpf.CatEscape:
		signal.Extra["ns_type"] = fmt.Sprintf("%d", raw.Payload.Escape.NSType)
	}

	// Process the signal
	result := correl.ProcessSignal(signal)
	if result != nil {
		// Correlation fired — emit an enriched alert
		p.emitCorrelationAlert(event, result)
	}
}

// eventCategorySignal maps event categories and types to correlation signal names
// for unmatched events. This enables the correlator to receive behavioral context
// even when no rule has specifically matched.
func EventCategorySignal(event *ebpf.ScarletEvent) string {
	switch event.Category {
	case ebpf.CatProcess:
		if event.EventType == ebpf.EvtExec {
			if ebpf.IsShellProcess(event.CommString()) {
				return "shell_procs"
			}
			if ebpf.IsMinerProcess(event.CommString()) {
				return "miner_procs"
			}
		}
	case ebpf.CatNetwork:
		if event.EventType == ebpf.EvtNetConnect {
			if ebpf.IsMinerPoolPort(event.RemotePort()) {
				return "minerpool_connection"
			}
			if ebpf.IsC2Port(event.RemotePort()) {
				return "net_outbound"
			}
			if ebpf.IsCloudMetadataIP(event.RemoteIP()) {
				return "net_outbound"
			}
			// Check for DNS suspicious queries (port 53)
			if ebpf.IsDNSPort(event.RemotePort()) || ebpf.IsDNSPort(event.LocalPort()) {
				return "dns_query"
			}
			// Check for TLS connections that might contain suspicious SNI
			// (port 443 is common for HTTPS)
			if event.RemotePort() == 443 || event.LocalPort() == 443 {
				return "tls_connection"
			}
			return "net_outbound"
		}
	case ebpf.CatEscape:
		switch event.EventType {
		case ebpf.EvtSetns:
			return "namespace_join"
		case ebpf.EvtMount:
			return "cgroup_mount"
		case ebpf.EvtUnshare:
			return "unshare"
		}
	case ebpf.CatPrivilege:
		if event.EventType == ebpf.EvtSetuid {
			return "setuid_transition"
		}
	case ebpf.CatFile:
		if ebpf.IsSensitivePath(event.FilePath()) {
			return "sensitive_file_read"
		}
	}
	return "" // Not a correlatable signal
}

// emitCorrelationAlert emits an alert enriched with correlation context when
// a multi-signal correlation fires.
func (p *Pipeline) emitCorrelationAlert(event *EnrichedEvent, result *correlate.CorrelationResult) {
	raw := event.RawEvent

	alert := &output.Alert{
		Timestamp:      time.Now(),
		RuleID:         result.RuleID,
		RuleName:       "correlation:" + result.RuleID,
		Priority:       rules.PriorityCritical,
		Action:         output.ActionAlert,
		Output:         result.Description,
		ProcessName:    raw.CommString(),
		PID:            raw.PID,
		PPID:           raw.PPID,
		UID:            raw.UID,
		GID:            raw.GID,
		Category:       raw.CategoryString(),
		EventType:      raw.EventTypeString(),
		ContainerID:    event.ContainerID,
		ContainerName:  event.ContainerName,
		ContainerImage: event.ContainerImage,
		PodName:        event.PodName,
		Namespace:      event.Namespace,
		ServiceAccount: event.ServiceAccount,
		Tags:           []string{"correlation", "multi_signal"},
	}

	// Add correlation-specific enrichment
	if alert.Tags == nil {
		alert.Tags = []string{}
	}
	alert.CorrelationResult = &output.CorrelationResultAlert{
		RuleID:         result.RuleID,
		GroupKey:       result.GroupKey,
		MatchedSignals: len(result.MatchedSignals),
		WindowStart:    result.WindowStart,
		WindowEnd:      result.WindowEnd,
		Description:    result.Description,
	}

	if p.alertEmit != nil {
		p.alertEmit.Emit(alert)
	}
	p.alertsEmitted.Add(1)

	log.Printf("[pipeline] CORRELATION: rule=%s signals=%d window=%v group=%s pid=%d container=%s",
		result.RuleID, len(result.MatchedSignals),
		result.WindowEnd.Sub(result.WindowStart),
		result.GroupKey, result.PID, event.ContainerName)

	// AI-driven rule suggestion: collect incident context and request
	// a draft rule from the AI service. This is advisory and does not
	// block the pipeline — suggestions are logged for human review.
	p.mu.RLock()
	suggester := p.aiSuggester
	minConf := p.suggestionMinConfidence
	p.mu.RUnlock()
	if suggester != nil {
		incident := &ai.IncidentContext{
			RuleID:         result.RuleID,
			ContainerImage: event.ContainerImage,
			Namespace:      event.Namespace,
			Timestamp:      time.Now(),
		}
		// Collect contributing signals as AI events
		for _, sig := range result.MatchedSignals {
			aievt := ai.AIEvent{
				EventType: sig.Name,
				PID:       sig.PID,
				Category:  "correlation_signal",
				Timestamp: sig.Timestamp,
			}
			if sig.RuleID != "" {
				aievt.Details = map[string]string{"rule_id": sig.RuleID}
			}
			incident.Events = append(incident.Events, aievt)
		}
		// Fire SuggestRule async — must not block the pipeline
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			suggestion, err := suggester.SuggestRule(ctx, incident)
			if err != nil {
				log.Printf("[pipeline] AI SuggestRule failed for correlation %s: %v", result.RuleID, err)
				return
			}
			if suggestion.Confidence >= minConf {
				log.Printf("[pipeline] AI RULE SUGGESTION: rule_id=%s confidence=%.2f status=%s yaml=%q reasoning=%q",
					result.RuleID, suggestion.Confidence, suggestion.Status,
					suggestion.RuleYAML, suggestion.Reasoning)
			}
		}()
	}
}

// routeDecision handles the result of rule evaluation.
func (p *Pipeline) routeDecision(event *EnrichedEvent, match *rules.RuleMatch) {
	p.mu.RLock()
	currentMode := p.mode
	netEnf := p.netEnforcer
	p.mu.RUnlock()

	// Determine action based on rule and current mode
	action := match.Action

	// Enforcement safety: if event cannot be attributed to a container,
	// downgrade enforce to alert (7-rule safety protocol #1)
	if !event.ContainerAttributed && action == rules.ActionEnforce {
		action = rules.ActionAlert
		log.Printf("[pipeline] Enforcement downgraded to alert: cannot attribute event to container (rule=%s)",
			match.RuleID)
	}

	// If mode is audit or simulate, never actually enforce
	if currentMode == "audit" {
		if action == rules.ActionEnforce {
			action = rules.ActionAlert
		}
	} else if currentMode == "simulate" {
		if action == rules.ActionEnforce {
			action = rules.ActionSimulated
		}
	}

	// Network blocking: for rules that trigger TC enforcement (R009, R027, R019),
	// add the destination to the network blocklist. This is independent of
	// process kill enforcement — even alert-only rules can trigger network blocks.
	// Network blocking respects audit mode (no blocks in audit mode).
	if netEnf != nil && currentMode != "audit" {
		p.handleNetworkBlock(event, match, currentMode)
	}

	// AI alert triage: submit the alert for false-positive assessment.
	// If the AI recommends suppression, downgrade the action.
	// If the AI recommends priority adjustment, update the match priority.
	// AI triage is advisory — it cannot upgrade alerts to enforce, only
	// downgrade or suppress. This preserves safety properties.
	p.mu.RLock()
	trier := p.aiTrier
	suppressThr := p.triageSuppressThreshold
	downgradeThr := p.triageDowngradeThreshold
	adjustThr := p.triageAdjustThreshold
	p.mu.RUnlock()
	if trier != nil {
		fpScore, recommendedPriority, reasoning := trier.TriageAlert(
			match.RuleID, match.Priority, event.Namespace, event.ContainerName)

		if fpScore >= suppressThr {
			// Very high false-positive score → suppress the alert
			log.Printf("[pipeline] AI triage suppressed alert: rule=%s fp_score=%.2f reason=%s",
				match.RuleID, fpScore, reasoning)
			action = rules.ActionSuppress
		} else if fpScore >= downgradeThr && action != rules.ActionEnforce {
			// High false-positive score (non-enforce) → downgrade to info/suppress
			log.Printf("[pipeline] AI triage downgraded alert: rule=%s fp_score=%.2f old_priority=%s new_priority=%s reason=%s",
				match.RuleID, fpScore, match.Priority, recommendedPriority, reasoning)
			match.Priority = recommendedPriority
		} else if fpScore >= adjustThr {
			// Moderate FP score: adjust priority but don't suppress
			if recommendedPriority != "" && recommendedPriority != match.Priority {
				log.Printf("[pipeline] AI triage adjusted priority: rule=%s %s → %s (fp_score=%.2f)",
					match.RuleID, match.Priority, recommendedPriority, fpScore)
				match.Priority = recommendedPriority
			}
		}
	}

	// Execute action
	switch action {
	case rules.ActionAlert:
		p.emitAlert(event, match)
	case rules.ActionEnforce:
		p.executeEnforcement(event, match)
	case rules.ActionSimulated:
		p.emitSimulated(event, match)
	case rules.ActionSuppress:
		// Suppressed — do nothing
		if p.metrics != nil {
			p.metrics.RecordEventProcessed("suppressed", event.RawEvent.CategoryString())
		}
		return
	}

	// Record metrics
	if p.metrics != nil {
		p.metrics.RecordRuleMatch(match.RuleID, string(action))
		p.metrics.RecordEventProcessed(string(action), event.RawEvent.CategoryString())
	}
}

// emitAlert emits an alert through the alert emitter and coalescer.
func (p *Pipeline) emitAlert(event *EnrichedEvent, match *rules.RuleMatch) {
	alert := p.buildAlert(event, match, output.ActionAlert)

	// Try coalescing first
	if p.coalescer.Add(alert) {
		// Coalesced — don't emit individually
		return
	}

	// Not coalesced, emit directly
	if p.alertEmit != nil {
		p.alertEmit.Emit(alert)
	}
	p.alertsEmitted.Add(1)
}

// emitSimulated emits a simulated enforcement alert.
func (p *Pipeline) emitSimulated(event *EnrichedEvent, match *rules.RuleMatch) {
	alert := p.buildAlert(event, match, output.ActionSimulated)
	alert.Simulated = true

	if p.alertEmit != nil {
		p.alertEmit.Emit(alert)
	}
	p.alertsEmitted.Add(1)

	log.Printf("[pipeline] SIMULATED ENFORCE: rule=%s pid=%d process=%s container=%s",
		match.RuleID, event.RawEvent.PID, event.RawEvent.CommString(),
		event.ContainerName)
}

// executeEnforcement takes enforcement action on the matched event.
func (p *Pipeline) executeEnforcement(event *EnrichedEvent, match *rules.RuleMatch) {
	// Execute enforcement through the response actor
	result := p.response.Enforce(event, match)
	p.enforcementsExec.Add(1)

	// Record enforcement metrics
	if p.metrics != nil {
		if result.Success {
			p.metrics.RecordEnforcement(result.Action, result.Reason)
		} else {
			p.metrics.RecordEnforcement(result.Action, "skipped_"+result.Reason)
		}
	}

	// Also emit an alert about the enforcement
	alert := p.buildAlert(event, match, output.ActionEnforce)
	alert.EnforcementResult = &output.EnforcementResultAlert{
		Action:    result.Action,
		Signal:    result.Signal,
		TargetPID: result.TargetPID,
		Success:   result.Success,
		Reason:    result.Reason,
		LatencyUS: result.LatencyUS,
		RuleID:    result.RuleID,
	}

	if p.alertEmit != nil {
		p.alertEmit.Emit(alert)
	}
	p.alertsEmitted.Add(1)
}

// buildAlert constructs an output alert from an enriched event and rule match.
func (p *Pipeline) buildAlert(event *EnrichedEvent, match *rules.RuleMatch, action string) *output.Alert {
	raw := event.RawEvent

	alert := &output.Alert{
		Timestamp:      time.Now(),
		RuleID:         match.RuleID,
		RuleName:       match.RuleName,
		Priority:       match.Priority,
		Action:         action,
		Output:         match.Output,
		ProcessName:    raw.CommString(),
		PID:            raw.PID,
		PPID:           raw.PPID,
		UID:            raw.UID,
		GID:            raw.GID,
		Category:       raw.CategoryString(),
		EventType:      raw.EventTypeString(),
		ContainerID:    event.ContainerID,
		ContainerName:  event.ContainerName,
		ContainerImage: event.ContainerImage,
		PodName:        event.PodName,
		Namespace:      event.Namespace,
		ServiceAccount: event.ServiceAccount,
		Tags:           match.Tags,
		NodeName:       event.NodeName,
	}

	// Add event-specific details
	switch raw.Category {
	case ebpf.CatProcess:
		alert.Filename = raw.Filename()
		alert.CmdLine = raw.Args()
	case ebpf.CatFile:
		alert.FilePath = raw.FilePath()
		alert.FileFlags = raw.Payload.File.Flags
		alert.FileMode = raw.Payload.File.Mode
	case ebpf.CatNetwork:
		alert.RemoteIP = raw.RemoteIP()
		alert.RemotePort = raw.RemotePort()
		alert.LocalIP = raw.LocalIP()
		alert.LocalPort = raw.LocalPort()
	case ebpf.CatEscape:
		alert.NSType = raw.Payload.Escape.NSType
	case ebpf.CatPrivilege:
		alert.OldUID = raw.Payload.Privilege.OldUID
		alert.NewUID = raw.Payload.Privilege.NewUID
		alert.Capability = raw.Payload.Privilege.Capability
		alert.ModeFlags = raw.Payload.Privilege.ModeFlags
	}

	// Attach anomaly score if available
	if event.AnomalyScore > 0 {
		alert.AnomalyScore = event.AnomalyScore
	}

	return alert
}

// handleNetworkBlock applies TC-based network blocking when a network-related
// rule (R009, R027, R019) matches. This is independent of process kill enforcement
// and works in both alert and enforce modes (but not audit mode).
//
// Rule mapping:
//   - R009 (Mining Pool Connection): blocks the destination IP:port
//   - R027 (C2 Port Connection): blocks the destination IP:port
//   - R019 (Cloud Metadata SSRF): blocks 169.254.169.254 on all ports
func (p *Pipeline) handleNetworkBlock(event *EnrichedEvent, match *rules.RuleMatch, mode string) {
	reason, isNetworkRule := NetworkBlockingRuleIDs[match.RuleID]
	if !isNetworkRule {
		return
	}

	netEnf := p.netEnforcer
	if netEnf == nil {
		return
	}

	raw := event.RawEvent

	switch match.RuleID {
	case "R009": // Mining pool connection
		destIP := net.ParseIP(raw.RemoteIP())
		if destIP != nil && raw.RemotePort() > 0 {
			if mode == "simulate" {
				log.Printf("[pipeline] SIMULATE NET_BLOCK: rule=%s ip=%s port=%d reason=%s",
					match.RuleID, destIP, raw.RemotePort(), reason)
			} else {
				err := netEnf.BlockMiningPool(destIP, raw.RemotePort())
				if err != nil {
					log.Printf("[pipeline] Warning: failed to block mining pool %s:%d: %v",
						destIP, raw.RemotePort(), err)
				} else {
					log.Printf("[pipeline] Blocked mining pool: %s:%d (rule=%s)",
						destIP, raw.RemotePort(), match.RuleID)
				}
			}
		}

	case "R027": // C2 port connection
		destIP := net.ParseIP(raw.RemoteIP())
		if destIP != nil && raw.RemotePort() > 0 {
			if mode == "simulate" {
				log.Printf("[pipeline] SIMULATE NET_BLOCK: rule=%s ip=%s port=%d reason=%s",
					match.RuleID, destIP, raw.RemotePort(), reason)
			} else {
				err := netEnf.BlockC2Port(destIP, raw.RemotePort())
				if err != nil {
					log.Printf("[pipeline] Warning: failed to block C2 port %s:%d: %v",
						destIP, raw.RemotePort(), err)
				} else {
					log.Printf("[pipeline] Blocked C2 port: %s:%d (rule=%s)",
						destIP, raw.RemotePort(), match.RuleID)
				}
			}
		}

	case "R019": // Cloud metadata SSRF
		if mode == "simulate" {
			log.Printf("[pipeline] SIMULATE NET_BLOCK: rule=%s reason=%s dest=169.254.169.254",
				match.RuleID, reason)
		} else {
			err := netEnf.BlockCloudMetadata()
			if err != nil {
				log.Printf("[pipeline] Warning: failed to block cloud metadata: %v", err)
			} else {
				log.Printf("[pipeline] Blocked cloud metadata access (rule=%s)", match.RuleID)
			}
		}
	}
}

// coalescerLoop periodically flushes the coalescer.
func (p *Pipeline) coalescerLoop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.CoalesceWindow)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.coalescer.Flush(p.alertEmit)
		}
	}
}

// ── Enriched Event ────────────────────────────────────────────────────

// EnrichedEvent wraps a raw eBPF event with container and K8s metadata.
type EnrichedEvent struct {
	RawEvent *ebpf.ScarletEvent

	// Container metadata
	ContainerID        string
	ContainerName      string
	ContainerImage     string
	ContainerAttributed bool // true if container_id was successfully resolved

	// Kubernetes metadata
	PodName        string
	Namespace      string
	ServiceAccount string
	PodLabels      map[string]string
	Privileged     bool
	NodeName       string

	// Anomaly scoring state
	AnomalyScore  float64 // 0.0 = normal, 1.0 = highly anomalous
}