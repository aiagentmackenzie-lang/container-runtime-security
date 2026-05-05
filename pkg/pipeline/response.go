// Package pipeline - response.go
// Response actor executes enforcement actions (SIGTERM→SIGKILL chain, LSM deny, etc.)
// with the 7-rule enforcement safety protocol.
//
// Enforcement escalation order:
//   1. SIGTERM (graceful) → wait grace period → SIGKILL if still alive
//   2. SIGKILL (immediate) — for CRITICAL/enforce rules or when grace period is 0
//   3. LSM deny (inline kernel block) — stub for kernel 5.7+ with BPF_LSM

package pipeline

import (
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Enforcement Action Types ──────────────────────────────────────────

const (
	EnforceSIGTERM  = "sigterm"  // Graceful termination
	EnforceSIGKILL  = "sigkill"  // Immediate kill
	EnforceLSMDeny  = "lsm_deny" // BPF LSM inline deny (kernel 5.7+)
	EnforceNetBlock = "net_block" // TC-based network block
)

// EnforcementMode controls the kill escalation strategy.
type EnforcementMode string

const (
	EnforceModeGraceful  EnforcementMode = "graceful"  // SIGTERM → grace → SIGKILL
	EnforceModeImmediate EnforcementMode = "immediate" // SIGKILL immediately
)

// ── Enforcement Result ────────────────────────────────────────────────

// EnforcementResult records the outcome of an enforcement action.
type EnforcementResult struct {
	Action    string    `json:"action"`      // sigterm, sigkill, lsm_deny, net_block
	Signal    string    `json:"signal"`      // SIGTERM or SIGKILL (for kill actions)
	TargetPID uint32    `json:"target_pid"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason"`      // killed, graceful_killed, killed_after_grace, etc.
	RuleID    string    `json:"rule_id"`
	Container string    `json:"container,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	LatencyUS int64     `json:"latency_us"`  // microseconds
}

// ── Response Actor Configuration ──────────────────────────────────────

// ResponseActorConfig holds configuration for the response actor.
type ResponseActorConfig struct {
	Mode               EnforcementMode // graceful or immediate
	GracePeriodSeconds int             // seconds to wait after SIGTERM before SIGKILL (0 = immediate)
	MaxKillsPerPod     int             // rate limit: max kills per pod per window
	WindowSeconds      int             // rate limit: window in seconds
	ProtectedNamespaces []string       // namespaces exempt from enforcement
}

// DefaultResponseActorConfig returns sensible defaults.
func DefaultResponseActorConfig() ResponseActorConfig {
	return ResponseActorConfig{
		Mode:               EnforceModeImmediate,
		GracePeriodSeconds: 5,
		MaxKillsPerPod:     10,
		WindowSeconds:      60,
		ProtectedNamespaces: []string{"kube-system", "kube-public"},
	}
}

// ── Response Actor ────────────────────────────────────────────────────

// ResponseActor executes enforcement responses based on rule matches.
type ResponseActor struct {
	config ResponseActorConfig
	mode   string // audit, enforce, simulate

	// Rate limiting: tracks kills per pod
	rateLimiter *RateLimiter

	// Agent's own PID (self-preservation)
	agentPID int

	// Enforcement audit log
	auditLog *EnforcementAuditLog

	mu sync.RWMutex
}

// NewResponseActor creates a new response actor.
func NewResponseActor(mode string) *ResponseActor {
	return NewResponseActorWithConfig(mode, DefaultResponseActorConfig())
}

// NewResponseActorWithConfig creates a new response actor with explicit configuration.
func NewResponseActorWithConfig(mode string, cfg ResponseActorConfig) *ResponseActor {
	window := time.Duration(cfg.WindowSeconds) * time.Second
	if window <= 0 {
		window = 60 * time.Second
	}
	maxKills := cfg.MaxKillsPerPod
	if maxKills <= 0 {
		maxKills = 10
	}

	return &ResponseActor{
		config:      cfg,
		mode:        mode,
		rateLimiter: NewRateLimiter(maxKills, window),
		agentPID:    os.Getpid(),
		auditLog:    NewEnforcementAuditLog(),
	}
}

// SetMode changes the operating mode.
func (r *ResponseActor) SetMode(mode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
}

// AuditLog returns the enforcement audit log.
func (r *ResponseActor) AuditLog() *EnforcementAuditLog {
	return r.auditLog
}

// Enforce executes enforcement action on the matched event.
// Returns the enforcement result. The 7-rule safety protocol is applied.
func (r *ResponseActor) Enforce(event *EnrichedEvent, match *rules.RuleMatch) EnforcementResult {
	start := time.Now()

	result := EnforcementResult{
		Action:    EnforceSIGKILL, // default action type
		TargetPID: event.RawEvent.PID,
		RuleID:    match.RuleID,
		Container: event.ContainerName,
		Namespace: event.Namespace,
		Timestamp: start,
	}

	// ═══ 7-Rule Enforcement Safety Protocol ═══
	// These 7 rules are MANDATORY and must NEVER be removed or bypassed.
	// They protect against accidental enforcement on the wrong target.

	// Rule 1: No container ID, no enforce
	if !event.ContainerAttributed || event.ContainerID == "" {
		result.Success = false
		result.Reason = "no_container_id"
		log.Printf("[response] Enforcement skipped: no container ID (rule=%s pid=%d)",
			match.RuleID, event.RawEvent.PID)
		r.auditLog.Record(result)
		return result
	}

	// Rule 2: Simulate mode check
	r.mu.RLock()
	currentMode := r.mode
	r.mu.RUnlock()
	if currentMode == "simulate" {
		result.Success = false
		result.Reason = "simulate_mode"
		log.Printf("[response] Enforcement simulated: rule=%s pid=%d process=%s",
			match.RuleID, event.RawEvent.PID, event.RawEvent.CommString())
		r.auditLog.Record(result)
		return result
	}

	// Rule 3: Protected namespaces (configurable, defaults: kube-system, kube-public)
	protectedNS := make(map[string]bool, len(r.config.ProtectedNamespaces))
	for _, ns := range r.config.ProtectedNamespaces {
		protectedNS[ns] = true
	}
	if protectedNS[event.Namespace] {
		result.Success = false
		result.Reason = "protected_namespace"
		log.Printf("[response] Enforcement skipped: protected namespace %s (rule=%s pid=%d)",
			event.Namespace, match.RuleID, event.RawEvent.PID)
		r.auditLog.Record(result)
		return result
	}

	// Rule 4: PID 0 and PID 1 are untouchable
	if event.RawEvent.PID == 0 || event.RawEvent.PID == 1 {
		result.Success = false
		result.Reason = "init_process"
		log.Printf("[response] Enforcement skipped: PID %d is untouchable (rule=%s)",
			event.RawEvent.PID, match.RuleID)
		r.auditLog.Record(result)
		return result
	}

	// Rule 5: Self-preservation — never kill agent's own process tree
	if int(event.RawEvent.PID) == r.agentPID || int(event.RawEvent.PPID) == r.agentPID {
		result.Success = false
		result.Reason = "self_preservation"
		log.Printf("[response] Enforcement skipped: self-preservation (rule=%s pid=%d)",
			match.RuleID, event.RawEvent.PID)
		r.auditLog.Record(result)
		return result
	}

	// Rule 6: Rate limiting — max kills per pod per window
	podKey := event.Namespace + "/" + event.PodName
	if !r.rateLimiter.Allow(podKey) {
		result.Success = false
		result.Reason = "rate_limited"
		log.Printf("[response] Enforcement rate-limited: pod %s exceeded kill budget (rule=%s)",
			podKey, match.RuleID)
		r.auditLog.Record(result)
		return result
	}

	// Rule 7: Namespace scope required
	if event.Namespace == "" {
		result.Success = false
		result.Reason = "no_namespace_scope"
		log.Printf("[response] Enforcement skipped: no namespace specified (rule=%s pid=%d)",
			match.RuleID, event.RawEvent.PID)
		r.auditLog.Record(result)
		return result
	}

	// ═══ Execute Enforcement ═══

	if match.Action == rules.ActionEnforce {
		switch r.config.Mode {
		case EnforceModeGraceful:
			result = r.executeGracefulKill(event, match, start)
		case EnforceModeImmediate:
			fallthrough
		default:
			result = r.executeImmediateKill(event, match, start)
		}

		r.auditLog.Record(result)
	}

	return result
}

// executeImmediateKill sends SIGKILL immediately (no grace period).
func (r *ResponseActor) executeImmediateKill(event *EnrichedEvent, match *rules.RuleMatch, start time.Time) EnforcementResult {
	result := EnforcementResult{
		Action:    EnforceSIGKILL,
		Signal:    "SIGKILL",
		TargetPID: event.RawEvent.PID,
		RuleID:    match.RuleID,
		Container: event.ContainerName,
		Namespace: event.Namespace,
		Timestamp: start,
	}

	killErr := r.sendSIGKILL(event.RawEvent.PID)
	elapsed := time.Since(start)
	result.LatencyUS = elapsed.Microseconds()

	if killErr != nil {
		result.Success = false
		result.Reason = fmt.Sprintf("kill_failed: %v", killErr)
		log.Printf("[response] SIGKILL failed: pid=%d error=%v (rule=%s latency=%dµs)",
			event.RawEvent.PID, killErr, match.RuleID, result.LatencyUS)
	} else {
		result.Success = true
		result.Reason = "killed"
		log.Printf("[response] SIGKILL delivered: pid=%d process=%s container=%s (rule=%s latency=%dµs)",
			event.RawEvent.PID, event.RawEvent.CommString(),
			event.ContainerName, match.RuleID, result.LatencyUS)
	}

	return result
}

// executeGracefulKill sends SIGTERM first, waits the configured grace period,
// then escalates to SIGKILL if the process is still alive.
func (r *ResponseActor) executeGracefulKill(event *EnrichedEvent, match *rules.RuleMatch, start time.Time) EnforcementResult {
	gracePeriod := time.Duration(r.config.GracePeriodSeconds) * time.Second
	if gracePeriod <= 0 {
		gracePeriod = 5 * time.Second
	}

	result := EnforcementResult{
		Action:    EnforceSIGTERM,
		Signal:    "SIGTERM",
		TargetPID: event.RawEvent.PID,
		RuleID:    match.RuleID,
		Container: event.ContainerName,
		Namespace: event.Namespace,
		Timestamp: start,
	}

	// Phase 1: Send SIGTERM
	termErr := r.sendSIGTERM(event.RawEvent.PID)
	if termErr != nil {
		// SIGTERM failed — escalate immediately to SIGKILL
		log.Printf("[response] SIGTERM failed (pid=%d), escalating to SIGKILL: %v",
			event.RawEvent.PID, termErr)
		return r.executeImmediateKill(event, match, start)
	}

	log.Printf("[response] SIGTERM delivered: pid=%d process=%s container=%s (rule=%s grace=%v)",
		event.RawEvent.PID, event.RawEvent.CommString(),
		event.ContainerName, match.RuleID, gracePeriod)

	// Phase 2: Wait grace period, then check if process is still alive
	time.Sleep(gracePeriod)

	targetPID := int(event.RawEvent.PID)
	if err := syscall.Kill(targetPID, 0); err != nil {
		// Process is gone — SIGTERM was sufficient
		elapsed := time.Since(start)
		result.LatencyUS = elapsed.Microseconds()
		result.Success = true
		result.Reason = "graceful_killed"
		result.Signal = "SIGTERM"
		log.Printf("[response] Process terminated gracefully after SIGTERM: pid=%d (rule=%s latency=%dµs)",
			event.RawEvent.PID, match.RuleID, result.LatencyUS)
		return result
	}

	// Process still alive after grace period — escalate to SIGKILL
	killErr := r.sendSIGKILL(event.RawEvent.PID)
	elapsed := time.Since(start)
	result.LatencyUS = elapsed.Microseconds()

	if killErr != nil {
		result.Success = false
		result.Reason = fmt.Sprintf("kill_failed_after_grace: %v", killErr)
		result.Signal = "SIGKILL"
		log.Printf("[response] SIGKILL after grace failed: pid=%d error=%v (rule=%s latency=%dµs)",
			event.RawEvent.PID, killErr, match.RuleID, result.LatencyUS)
	} else {
		result.Success = true
		result.Reason = "killed_after_grace"
		result.Signal = "SIGKILL"
		result.Action = EnforceSIGKILL
		log.Printf("[response] SIGKILL after grace period: pid=%d process=%s container=%s (rule=%s latency=%dµs)",
			event.RawEvent.PID, event.RawEvent.CommString(),
			event.ContainerName, match.RuleID, result.LatencyUS)
	}

	return result
}

// sendSIGKILL sends SIGKILL to the target process.
func (r *ResponseActor) sendSIGKILL(pid uint32) error {
	targetPID := int(pid)

	// Send SIGKILL
	err := syscall.Kill(targetPID, syscall.Signal(9))
	if err != nil {
		return fmt.Errorf("kill(%d, SIGKILL): %w", targetPID, err)
	}

	// Wait briefly to confirm process death
	time.Sleep(10 * time.Millisecond)

	// Check if process still exists
	if err := syscall.Kill(targetPID, 0); err == nil {
		// Process still exists — might be a zombie
		log.Printf("[response] Warning: PID %d still exists after SIGKILL (may be zombie)", targetPID)
	}

	return nil
}

// sendSIGTERM sends SIGTERM to the target process for graceful termination.
func (r *ResponseActor) sendSIGTERM(pid uint32) error {
	targetPID := int(pid)

	err := syscall.Kill(targetPID, syscall.Signal(15))
	if err != nil {
		return fmt.Errorf("kill(%d, SIGTERM): %w", targetPID, err)
	}

	return nil
}

// ── Rate Limiter ──────────────────────────────────────────────────────

// RateLimiter implements per-pod kill rate limiting.
type RateLimiter struct {
	maxPerWindow int
	window       time.Duration
	mu           sync.RWMutex
	counters     map[string]*rateCounter
}

type rateCounter struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a rate limiter: max N actions per window.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		maxPerWindow: max,
		window:       window,
		counters:     make(map[string]*rateCounter),
	}

	// Clean up expired counters periodically
	go rl.cleanup()
	return rl
}

// Allow checks if the given key is within rate limits.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	counter, exists := rl.counters[key]
	if !exists || now.After(counter.resetAt) {
		rl.counters[key] = &rateCounter{
			count:   1,
			resetAt: now.Add(rl.window),
		}
		return true
	}

	if counter.count >= rl.maxPerWindow {
		return false
	}

	counter.count++
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, counter := range rl.counters {
			if now.After(counter.resetAt) {
				delete(rl.counters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// ── Unused import guard ───────────────────────────────────────────────

var (
	_ = ebpf.CatProcess  // ensure package reference
	_ = rules.ActionEnforce
)