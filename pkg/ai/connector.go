// Package ai provides the SecurityScarletAI gRPC connector for the
// SecurityScarlet Runtime intelligent analysis layer.
//
// Per SRD Section 11, the AI integration provides:
//   - Anomaly detection (syscall n-gram analysis, anomaly scoring)
//   - Behavioral profiling (per-image auto-baseline generation)
//   - AI rule suggestions (draft YAML rule generation from incidents)
//   - Threat intel correlation (enriched threat classification)
//   - Alert triage (AI-based false-positive reduction)
//
// Architecture:
//   - AIConnector manages the gRPC connection to SecurityScarletAI
//   - FeatureExtractor prepares event data for AI analysis
//   - InferenceClient wraps specific AI service RPCs
//
// The gRPC service definition (from SRD Section 11.5):
//
//	service SecurityScarletAI {
//	  rpc AnalyzeEvents(stream SecurityEvent) returns (stream AnalysisResult);
//	  rpc GetProfile(ProfileRequest) returns (BehavioralProfile);
//	  rpc TriageAlert(Alert) returns (TriageResult);
//	  rpc SuggestRule(IncidentContext) returns (RuleSuggestion);
//	}
//
// The connector is a stub for Phase 3 — the gRPC dependency
// (google.golang.org/grpc) will be added when full integration is ready.
// Until then, all methods return gracefully degraded results.
package ai

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// ── AI Service Types ────────────────────────────────────────────────────

// AnalysisResult is the result of AI event analysis.
type AnalysisResult struct {
	// AnomalyScore ranges from 0.0 (normal) to 1.0 (confirmed malicious).
	AnomalyScore float64 `json:"anomaly_score"`

	// Classification is the detected threat category (e.g., "cryptojacking",
	// "reverse_shell", "container_escape", "unknown").
	Classification string `json:"classification"`

	// Description is a human-readable explanation of the analysis.
	Description string `json:"description"`

	// EnforceRecommended indicates the AI recommends enforcement.
	EnforceRecommended bool `json:"enforce_recommended"`

	// Confidence ranges from 0.0 to 1.0.
	Confidence float64 `json:"confidence"`

	// ModelVersion is the version of the AI model that produced this result.
	ModelVersion string `json:"model_version"`

	// LatencyMS is the inference latency in milliseconds.
	LatencyMS int64 `json:"latency_ms"`
}

// BehavioralProfile contains a per-image behavioral baseline.
type BehavioralProfile struct {
	// Image is the container image this profile describes.
	Image string `json:"image"`

	// SyscallProfile describes the expected syscall distribution.
	SyscallProfile *SyscallProfile `json:"syscall_profile,omitempty"`

	// NetworkProfile describes expected network behavior.
	NetworkProfile *NetworkProfile `json:"network_profile,omitempty"`

	// FileProfile describes expected file access patterns.
	FileProfile *FileProfile `json:"file_profile,omitempty"`

	// BaselineEvents is the number of events used to build this profile.
	BaselineEvents uint64 `json:"baseline_events"`

	// LastUpdated is when the profile was last updated.
	LastUpdated time.Time `json:"last_updated"`

	// Confidence is the profile confidence level (0-1).
	Confidence float64 `json:"confidence"`
}

// SyscallProfile describes expected syscall patterns for a container image.
type SyscallProfile struct {
	// TopSyscalls is the most frequent syscalls and their rates.
	TopSyscalls map[string]float64 `json:"top_syscalls"`

	// UniqueSyscallCount is the number of distinct syscalls observed.
	UniqueSyscallCount int `json:"unique_syscall_count"`

	// NgramHashes is a set of n-gram pattern hashes for anomaly comparison.
	NgramHashes []uint64 `json:"ngram_hashes"`
}

// NetworkProfile describes expected network behavior for a container image.
type NetworkProfile struct {
	// ExpectedPorts is the set of expected destination ports.
	ExpectedPorts map[uint16]float64 `json:"expected_ports"`

	// ExpectedProtocols is the set of expected protocols.
	ExpectedProtocols map[string]float64 `json:"expected_protocols"`

	// ConnectionRate is the expected connections per second.
	ConnectionRate float64 `json:"connection_rate"`
}

// FileProfile describes expected file access patterns for a container image.
type FileProfile struct {
	// ReadPaths is the set of commonly read file paths.
	ReadPaths []string `json:"read_paths"`

	// WritePaths is the set of commonly written file paths.
	WritePaths []string `json:"write_paths"`

	// DriftBaseline is the set of expected executables.
	DriftBaseline []string `json:"drift_baseline"`
}

// ProfileRequest asks the AI service for a behavioral profile.
type ProfileRequest struct {
	// Image is the container image to profile.
	Image string `json:"image"`

	// ForceRebuild forces a profile rebuild even if one exists.
	ForceRebuild bool `json:"force_rebuild"`
}

// TriageResult is the AI assessment of an alert's validity.
type TriageResult struct {
	// FalsePositiveScore ranges from 0.0 (definitely real) to 1.0 (definitely FP).
	FalsePositiveScore float64 `json:"false_positive_score"`

	// Priority is the AI-recommended priority ("CRITICAL", "WARNING", etc.).
	Priority string `json:"priority"`

	// Reasoning is the AI's explanation for the triage decision.
	Reasoning string `json:"reasoning"`

	// SuppressRecommended indicates the AI recommends suppressing this alert.
	SuppressRecommended bool `json:"suppress_recommended"`

	// Confidence is the triage confidence (0-1).
	Confidence float64 `json:"confidence"`
}

// RuleSuggestion is a draft YAML rule generated by the AI.
type RuleSuggestion struct {
	// RuleYAML is the suggested rule in YAML format.
	RuleYAML string `json:"rule_yaml"`

	// Reasoning explains why the AI suggests this rule.
	Reasoning string `json:"reasoning"`

	// BasedOnIncidents is the number of incidents that triggered this suggestion.
	BasedOnIncidents int `json:"based_on_incidents"`

	// Confidence is the suggestion confidence (0-1).
	Confidence float64 `json:"confidence"`

	// Status is the review status: "draft", "pending_approval", "approved", "rejected".
	Status string `json:"status"`
}

// IncidentContext provides context for AI rule suggestion.
type IncidentContext struct {
	// RuleID that triggered the incident.
	RuleID string `json:"rule_id"`

	// Events that contributed to the incident.
	Events []AIEvent `json:"events"`

	// ContainerImage is the affected container image.
	ContainerImage string `json:"container_image"`

	// Namespace is the Kubernetes namespace.
	Namespace string `json:"namespace"`

	// Timestamp is when the incident occurred.
	Timestamp time.Time `json:"timestamp"`
}

// AIEvent is a simplified event representation for the AI service.
type AIEvent struct {
	// EventType is the system call or event type.
	EventType string `json:"event_type"`

	// ProcessName is the name of the process.
	ProcessName string `json:"process_name"`

	// PID is the process ID.
	PID uint32 `json:"pid"`

	// Category is the event category.
	Category string `json:"category"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Details is additional event context.
	Details map[string]string `json:"details,omitempty"`
}

// ── AI Connector ────────────────────────────────────────────────────────

// AIConnector manages the gRPC connection to the SecurityScarletAI service.
// It is the main entry point for all AI-powered features.
//
// When the gRPC endpoint is unavailable, all analysis methods return
// gracefully degraded results (e.g., neutral anomaly scores, no suggestions).
// This ensures the runtime agent can function without the AI service.
type AIConnector struct {
	mu sync.RWMutex

	// Configuration
	endpoint string        // gRPC endpoint (e.g., "scarlet-ai:9443")
	timeout  time.Duration // Request timeout (default: 5s)

	// Connection state
	connected   bool
	lastConnect time.Time
	lastError   error
	retryCount  int

	// Feature flag
	enabled bool // AI features enabled/disabled

	// Stats
	analysesRequested uint64
	analysesCompleted uint64
	analysesFailed    uint64
	profilesRequested uint64
	triagesRequested  uint64
	suggestionsMade   uint64
	lastInferenceMS   int64

	// Lifecycle
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// AIConnectorConfig holds configuration for the AI connector.
type AIConnectorConfig struct {
	// Endpoint is the SecurityScarletAI gRPC service address.
	Endpoint string

	// Timeout is the per-request timeout (default: 5s).
	Timeout time.Duration

	// Enabled controls whether AI features are active.
	Enabled bool
}

// NewAIConnector creates a new AI service connector.
func NewAIConnector(cfg AIConnectorConfig) *AIConnector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &AIConnector{
		endpoint: cfg.Endpoint,
		timeout:  cfg.Timeout,
		enabled:  cfg.Enabled,
		stopCh:   make(chan struct{}),
	}
}

// SetEnabled enables or disables AI features at runtime.
func (a *AIConnector) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
	log.Printf("[ai] AI features %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// IsEnabled returns whether AI features are active.
func (a *AIConnector) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

// ── Connection Management ──────────────────────────────────────────────

// Connect establishes a gRPC connection to the SecurityScarletAI service.
// In the stub implementation, this just checks reachability.
func (a *AIConnector) Connect(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.connected {
		return nil
	}

	log.Printf("[ai] Connecting to SecurityScarletAI at %s (timeout=%v)", a.endpoint, a.timeout)

	// TODO: When google.golang.org/grpc is added:
	//   conn, err := grpc.DialContext(ctx, a.endpoint,
	//     grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	//     grpc.WithBlock(),
	//     grpc.WithTimeout(a.timeout))
	//   if err != nil { return fmt.Errorf("gRPC connection failed: %w", err) }
	//   a.grpcConn = conn
	//   a.aiClient = pb.NewSecurityScarletAIClient(conn)

	// Stub: mark as connected (will fail on first actual RPC)
	a.connected = true
	a.lastConnect = time.Now()
	a.lastError = nil
	a.retryCount = 0

	log.Printf("[ai] SecurityScarletAI connector initialized (stub mode — gRPC not yet integrated)")
	return nil
}

// Disconnect closes the gRPC connection.
func (a *AIConnector) Disconnect() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.connected {
		return
	}

	// TODO: When gRPC is integrated:
	//   if a.grpcConn != nil { a.grpcConn.Close() }

	a.connected = false
	log.Printf("[ai] Disconnected from SecurityScarletAI")
}

// IsConnected returns whether the AI service is reachable.
func (a *AIConnector) IsConnected() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.connected
}

// ── AI Service RPCs ────────────────────────────────────────────────────

// AnalyzeEvent sends an event to the AI service for analysis.
// Returns an AnalysisResult with anomaly score and classification.
// When the AI service is unavailable, returns a neutral result.
func (a *AIConnector) AnalyzeEvent(ctx context.Context, event *AIEvent) (*AnalysisResult, error) {
	a.mu.Lock()
	a.analysesRequested++
	a.mu.Unlock()

	if !a.IsEnabled() || !a.IsConnected() {
		// Graceful degradation: return neutral result
		return a.neutralResult("ai_disabled"), nil
	}

	start := time.Now()

	// TODO: When gRPC is integrated:
	//   result, err := a.aiClient.AnalyzeEvents(ctx, eventProto)
	//   if err != nil { return nil, fmt.Errorf("AI analysis failed: %w", err) }
	//   return convertResult(result), nil

	// Stub: simulate inference with a small delay
	result := &AnalysisResult{
		AnomalyScore:       0.0,
		Classification:     "unknown",
		Description:        "AI analysis stub invoked (gRPC not yet integrated)",
		EnforceRecommended: false,
		Confidence:         0.0,
		ModelVersion:       "stub-v0",
		LatencyMS:          time.Since(start).Milliseconds(),
	}

	a.mu.Lock()
	a.analysesCompleted++
	a.lastInferenceMS = result.LatencyMS
	a.mu.Unlock()

	return result, nil
}

// GetProfile requests a behavioral profile for a container image.
// When unavailable, returns a minimal placeholder profile.
func (a *AIConnector) GetProfile(ctx context.Context, req *ProfileRequest) (*BehavioralProfile, error) {
	a.mu.Lock()
	a.profilesRequested++
	a.mu.Unlock()

	if !a.IsEnabled() || !a.IsConnected() {
		return &BehavioralProfile{
			Image:          req.Image,
			BaselineEvents: 0,
			Confidence:     0.0,
		}, nil
	}

	// TODO: When gRPC is integrated:
	//   profile, err := a.aiClient.GetProfile(ctx, profileReq)
	//   if err != nil { return nil, fmt.Errorf("GetProfile failed: %w", err) }

	return &BehavioralProfile{
		Image:          req.Image,
		BaselineEvents: 0,
		Confidence:     0.0,
		LastUpdated:    time.Now(),
	}, nil
}

// TriageAlertGRPC submits an alert for AI-based false-positive assessment via
// the gRPC service interface. Returns a TriageResult with the AI's recommendation.
func (a *AIConnector) TriageAlertGRPC(ctx context.Context, alert RuleIDAlert) (*TriageResult, error) {
	a.mu.Lock()
	a.triagesRequested++
	a.mu.Unlock()

	if !a.IsEnabled() || !a.IsConnected() {
		return &TriageResult{
			FalsePositiveScore: 0.5, // neutral
			Priority:           alert.Priority,
			Confidence:         0.0,
			Reasoning:          "ai_disabled_or_disconnected",
		}, nil
	}

	// TODO: When gRPC is integrated:
	//   result, err := a.aiClient.TriageAlert(ctx, alertProto)
	//   if err != nil { return nil, fmt.Errorf("TriageAlert failed: %w", err) }

	return &TriageResult{
		FalsePositiveScore: 0.5,
		Priority:           alert.Priority,
		Confidence:         0.0,
		Reasoning:          "AI triage stub (gRPC not yet integrated)",
	}, nil
}

// TriageAlert implements the pipeline's AIAlertTrier interface.
// It provides simplified alert triage with a false-positive score and
// recommended priority. Internally calls TriageAlertGRPC for the full
// assessment when the gRPC service is available.
func (a *AIConnector) TriageAlert(ruleID string, priority string, namespace string, container string) (float64, string, string) {
	ctx := context.Background()
	result, err := a.TriageAlertGRPC(ctx, RuleIDAlert{
		RuleID:    ruleID,
		Priority:  priority,
		Namespace: namespace,
		Container: container,
	})
	if err != nil || result == nil {
		// Graceful degradation: return neutral FP score
		return 0.5, priority, fmt.Sprintf("triage_error: %v", err)
	}
	return result.FalsePositiveScore, result.Priority, result.Reasoning
}

// SuggestRule requests an AI-generated rule suggestion from incident context.
// Returns a draft rule suggestion that requires human approval.
func (a *AIConnector) SuggestRule(ctx context.Context, incident *IncidentContext) (*RuleSuggestion, error) {
	a.mu.Lock()
	a.suggestionsMade++
	a.mu.Unlock()

	if !a.IsEnabled() || !a.IsConnected() {
		return nil, fmt.Errorf("AI service not available for rule suggestion")
	}

	// TODO: When gRPC is integrated:
	//   suggestion, err := a.aiClient.SuggestRule(ctx, incidentProto)
	//   if err != nil { return nil, fmt.Errorf("SuggestRule failed: %w", err) }

	return &RuleSuggestion{
		RuleYAML:         "# AI-suggested rule placeholder (gRPC not yet integrated)",
		Reasoning:        fmt.Sprintf("Based on %d incidents related to %s", len(incident.Events), incident.RuleID),
		BasedOnIncidents: len(incident.Events),
		Confidence:       0.0,
		Status:           "draft",
	}, nil
}

// ── Feature Extraction ─────────────────────────────────────────────────

// FeatureExtractor prepares event data for AI analysis.
type FeatureExtractor struct {
	// Syscall trace buffer for n-gram analysis
	syscallTrace []uint32
	traceMu      sync.Mutex

	// Configuration
	ngramSize int // n-gram window size (default: 5)
	traceSize int // max syscall trace length (default: 1000)
}

// NewFeatureExtractor creates a new feature extractor.
func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		syscallTrace: make([]uint32, 0, 1000),
		ngramSize:    5,
		traceSize:    1000,
	}
}

// AddSyscall adds a syscall number to the trace buffer.
func (fe *FeatureExtractor) AddSyscall(syscallNr uint32) {
	fe.traceMu.Lock()
	defer fe.traceMu.Unlock()

	fe.syscallTrace = append(fe.syscallTrace, syscallNr)

	// Trim if exceeds max trace size
	if len(fe.syscallTrace) > fe.traceSize {
		// Keep the most recent entries
		fe.syscallTrace = fe.syscallTrace[len(fe.syscallTrace)-fe.traceSize:]
	}
}

// ExtractNgrams returns n-gram frequency histogram from the syscall trace.
// Each n-gram is a sequence of N consecutive syscall numbers.
func (fe *FeatureExtractor) ExtractNgrams() map[[5]uint32]int {
	fe.traceMu.Lock()
	defer fe.traceMu.Unlock()

	ngrams := make(map[[5]uint32]int)
	if len(fe.syscallTrace) < fe.ngramSize {
		return ngrams
	}

	for i := 0; i <= len(fe.syscallTrace)-fe.ngramSize; i++ {
		var ngram [5]uint32
		copy(ngram[:], fe.syscallTrace[i:i+fe.ngramSize])
		ngrams[ngram]++
	}

	return ngrams
}

// Reset clears the syscall trace buffer.
func (fe *FeatureExtractor) Reset() {
	fe.traceMu.Lock()
	defer fe.traceMu.Unlock()
	fe.syscallTrace = fe.syscallTrace[:0]
}

// TraceLength returns the current number of syscalls in the trace.
func (fe *FeatureExtractor) TraceLength() int {
	fe.traceMu.Lock()
	defer fe.traceMu.Unlock()
	return len(fe.syscallTrace)
}

// ── Anomaly Scoring ──────────────────────────────────────────────────────

// NgramBaseline represents the "known good" n-gram distribution for a
// container image or workload. It is used by ScoreAnomaly to compare
// observed n-gram patterns against a baseline.
type NgramBaseline struct {
	// Hist is the baseline n-gram frequency histogram, normalized to [0,1].
	Hist map[[5]uint32]float64

	// TotalNgrams is the total number of n-grams in the baseline sample.
	TotalNgrams int

	// UniqueNgrams is the number of distinct n-gram patterns in the baseline.
	UniqueNgrams int

	// Image is the container image this baseline was built from.
	Image string

	// Confidence in the baseline (0-1), based on sample size.
	Confidence float64
}

// ScoreAnomaly compares the current n-gram distribution against a baseline
// and returns an anomaly score from 0.0 (normal) to 1.0 (highly anomalous).
//
// The algorithm uses a simplified Jensen-Shannon-like divergence:
//  1. Normalize both distributions to probability distributions
//  2. Compute per-n-gram absolute divergence from baseline
//  3. Weight novel n-grams (not in baseline) more heavily
//  4. Return the average divergence as the anomaly score
//
// If no baseline is provided (nil), ScoreAnomaly uses simple heuristics:
//   - Very low unique n-gram count → suspicious (repetitive behavior like mining)
//   - Very high unique n-gram count → slightly suspicious (exploration)
func (fe *FeatureExtractor) ScoreAnomaly(baseline *NgramBaseline) float64 {
	fe.traceMu.Lock()
	defer fe.traceMu.Unlock()

	if len(fe.syscallTrace) < fe.ngramSize {
		return 0.0 // Not enough data to score
	}

	// Extract current n-grams
	currentNgrams := make(map[[5]uint32]int)
	for i := 0; i <= len(fe.syscallTrace)-fe.ngramSize; i++ {
		var ngram [5]uint32
		copy(ngram[:], fe.syscallTrace[i:i+fe.ngramSize])
		currentNgrams[ngram]++
	}

	totalCurrent := len(fe.syscallTrace) - fe.ngramSize + 1
	if totalCurrent <= 0 {
		return 0.0
	}

	if baseline == nil || len(baseline.Hist) == 0 {
		// No baseline: use heuristic scoring
		return fe.heuristicScore(currentNgrams, totalCurrent)
	}

	// Compute divergence between current and baseline
	totalDivergence := 0.0
	novelNgrams := 0
	overlapNgrams := 0

	// Check current n-grams against baseline
	for ngram, count := range currentNgrams {
		observed := float64(count) / float64(totalCurrent)
		if baseFreq, ok := baseline.Hist[ngram]; ok {
			// Known n-gram: measure divergence
			div := observed - baseFreq
			if div < 0 {
				div = -div
			}
			totalDivergence += div
			overlapNgrams++
		} else {
			// Novel n-gram not in baseline: weight heavily
			totalDivergence += observed * 2.0 // 2x weight for novel patterns
			novelNgrams++
		}
	}

	// Check baseline n-grams missing from current
	currentHist := make(map[[5]uint32]float64)
	for ngram, count := range currentNgrams {
		currentHist[ngram] = float64(count) / float64(totalCurrent)
	}
	for ngram, baseFreq := range baseline.Hist {
		if _, ok := currentHist[ngram]; !ok {
			// Baseline n-gram missing from current observation
			totalDivergence += baseFreq * 0.5
		}
	}

	// Normalize score to [0, 1]
	totalNgrams := len(currentNgrams)
	if totalNgrams == 0 {
		return 0.0
	}

	score := totalDivergence / float64(totalNgrams)

	// Boost score if many novel n-grams
	if totalNgrams > 0 {
		novelRatio := float64(novelNgrams) / float64(totalNgrams)
		if novelRatio > 0.3 {
			score += novelRatio * 0.2
		}
	}

	// Clamp to [0, 1]
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}

// heuristicScore provides anomaly scoring when no baseline is available.
// It uses simple statistical properties of the n-gram distribution.
func (fe *FeatureExtractor) heuristicScore(currentNgrams map[[5]uint32]int, totalCurrent int) float64 {
	uniqueNgrams := len(currentNgrams)

	// Very few unique n-grams: could indicate repetitive behavior (mining)
	if uniqueNgrams <= 3 && totalCurrent > 50 {
		return 0.6 // Suspicious: highly repetitive syscall pattern
	}
	if uniqueNgrams <= 10 && totalCurrent > 100 {
		return 0.3 // Slightly suspicious
	}

	// Many unique n-grams: normal for most workloads
	if uniqueNgrams > 100 {
		return 0.05 // Normal: diverse syscall patterns
	}

	// Moderate: calculate entropy as proxy for normality
	entropy := fe.calculateEntropy(currentNgrams, totalCurrent)

	// Low entropy (very skewed distribution) is slightly suspicious
	if entropy < 1.0 {
		return 0.4
	}
	if entropy < 2.0 {
		return 0.2
	}

	return 0.1 // Default low anomaly score for moderate-entropy traces
}

// calculateEntropy computes the Shannon entropy of the n-gram distribution.
func (fe *FeatureExtractor) calculateEntropy(ngrams map[[5]uint32]int, total int) float64 {
	if total == 0 {
		return 0.0
	}

	var entropy float64
	for _, count := range ngrams {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * logBase2(p)
		}
	}
	return entropy
}

// logBase2 computes log2(x).
func logBase2(x float64) float64 {
	if x <= 0 {
		return 0.0
	}
	return math.Log2(x)
}

// BuildBaseline creates an NgramBaseline from the current n-gram distribution.
// This is used to establish the "known good" pattern for a container image
// during a learning phase.
func (fe *FeatureExtractor) BuildBaseline(image string) *NgramBaseline {
	fe.traceMu.Lock()
	defer fe.traceMu.Unlock()

	if len(fe.syscallTrace) < fe.ngramSize {
		return &NgramBaseline{
			Image:      image,
			Confidence: 0.0,
		}
	}

	// Extract n-grams
	ngrams := make(map[[5]uint32]int)
	for i := 0; i <= len(fe.syscallTrace)-fe.ngramSize; i++ {
		var ngram [5]uint32
		copy(ngram[:], fe.syscallTrace[i:i+fe.ngramSize])
		ngrams[ngram]++
	}

	totalNgrams := len(fe.syscallTrace) - fe.ngramSize + 1

	// Normalize to probability distribution
	hist := make(map[[5]uint32]float64, len(ngrams))
	for ngram, count := range ngrams {
		hist[ngram] = float64(count) / float64(totalNgrams)
	}

	// Calculate confidence based on sample size
	confidence := 0.0
	if totalNgrams >= 1000 {
		confidence = 1.0
	} else if totalNgrams >= 100 {
		confidence = float64(totalNgrams) / 1000.0
	}

	return &NgramBaseline{
		Hist:         hist,
		TotalNgrams:  totalNgrams,
		UniqueNgrams: len(ngrams),
		Image:        image,
		Confidence:   confidence,
	}
}

// ── Lifecycle ────────────────────────────────────────────────────────

// Start begins the AI connector's background goroutines.
func (a *AIConnector) Start(ctx context.Context) {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return
	}
	a.running = true
	a.mu.Unlock()

	// Attempt initial connection
	if a.enabled {
		if err := a.Connect(ctx); err != nil {
			log.Printf("[ai] Warning: initial connection failed: %v", err)
		}
	}

	log.Printf("[ai] AI connector started (endpoint=%s enabled=%v)", a.endpoint, a.enabled)
}

// Stop gracefully stops the AI connector.
func (a *AIConnector) Stop() {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return
	}
	a.running = false
	a.mu.Unlock()

	a.Disconnect()
	close(a.stopCh)
	a.wg.Wait()

	log.Printf("[ai] AI connector stopped. Analyses=%d Completed=%d Failed=%d Profiles=%d Triages=%d Suggestions=%d",
		a.analysesRequested, a.analysesCompleted, a.analysesFailed,
		a.profilesRequested, a.triagesRequested, a.suggestionsMade)
}

// ── Helper Methods ────────────────────────────────────────────────────

// RuleIDAlert is a simplified alert for triage (avoids import cycle).
type RuleIDAlert struct {
	RuleID    string
	Priority  string
	Namespace string
	Container string
}

// neutralResult returns a neutral analysis result for degraded mode.
func (a *AIConnector) neutralResult(reason string) *AnalysisResult {
	return &AnalysisResult{
		AnomalyScore:       0.0,
		Classification:     "unknown",
		Description:        fmt.Sprintf("AI analysis unavailable: %s", reason),
		EnforceRecommended: false,
		Confidence:         0.0,
		ModelVersion:       "neutral",
		LatencyMS:          0,
	}
}

// ── Stats ──────────────────────────────────────────────────────────────

// AIStats holds statistics about the AI connector.
type AIStats struct {
	Connected         bool      `json:"connected"`
	Enabled           bool      `json:"enabled"`
	Endpoint          string    `json:"endpoint"`
	AnalysesRequested uint64    `json:"analyses_requested"`
	AnalysesCompleted uint64    `json:"analyses_completed"`
	AnalysesFailed    uint64    `json:"analyses_failed"`
	ProfilesRequested uint64    `json:"profiles_requested"`
	TriagesRequested  uint64    `json:"triages_requested"`
	SuggestionsMade   uint64    `json:"suggestions_made"`
	LastInferenceMS   int64     `json:"last_inference_ms"`
	LastConnectTime   time.Time `json:"last_connect_time,omitempty"`
}

// Stats returns current AI connector statistics.
func (a *AIConnector) Stats() AIStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return AIStats{
		Connected:         a.connected,
		Enabled:           a.enabled,
		Endpoint:          a.endpoint,
		AnalysesRequested: a.analysesRequested,
		AnalysesCompleted: a.analysesCompleted,
		AnalysesFailed:    a.analysesFailed,
		ProfilesRequested: a.profilesRequested,
		TriagesRequested:  a.triagesRequested,
		SuggestionsMade:   a.suggestionsMade,
		LastInferenceMS:   a.lastInferenceMS,
		LastConnectTime:   a.lastConnect,
	}
}
