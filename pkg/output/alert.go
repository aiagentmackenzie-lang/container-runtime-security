// Package output provides alert emission and Prometheus metrics export
// for the SecurityScarlet Runtime agent.
package output

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ── Action Constants ─────────────────────────────────────────────────

const (
	ActionAlert     = "alert"
	ActionEnforce   = "enforce"
	ActionSimulated = "simulate"
)

// ── Alert ─────────────────────────────────────────────────────────────

// Alert represents a security alert emitted by the rule engine.
type Alert struct {
	Timestamp      time.Time              `json:"timestamp"`
	RuleID         string                  `json:"rule_id"`
	RuleName       string                  `json:"rule_name"`
	Priority       string                  `json:"priority"`
	Action         string                  `json:"action"`
	Output         string                  `json:"output"`
	ProcessName    string                  `json:"process_name"`
	PID            uint32                  `json:"pid"`
	PPID           uint32                  `json:"ppid"`
	UID            uint32                  `json:"uid"`
	GID            uint32                  `json:"gid"`
	Category       string                  `json:"category"`
	EventType      string                  `json:"event_type"`
	ContainerID    string                  `json:"container_id,omitempty"`
	ContainerName  string                  `json:"container_name,omitempty"`
	ContainerImage string                  `json:"container_image,omitempty"`
	PodName        string                  `json:"pod_name,omitempty"`
	Namespace      string                  `json:"namespace,omitempty"`
	ServiceAccount string                  `json:"service_account,omitempty"`
	NodeName       string                  `json:"node_name,omitempty"`
	Tags           []string                `json:"tags,omitempty"`
	Simulated      bool                    `json:"simulated,omitempty"`
	EnforcementResult *EnforcementResultAlert `json:"enforcement_result,omitempty"`
	CorrelationResult *CorrelationResultAlert  `json:"correlation_result,omitempty"`
	EventCount     uint64                  `json:"event_count,omitempty"`
	Coalesced      bool                    `json:"coalesced,omitempty"`

	// Event-specific fields
	Filename    string `json:"filename,omitempty"`
	CmdLine     string `json:"cmdline,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	FileFlags   uint32 `json:"file_flags,omitempty"`
	FileMode    uint32 `json:"file_mode,omitempty"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	RemotePort  uint16 `json:"remote_port,omitempty"`
	LocalIP     string `json:"local_ip,omitempty"`
	LocalPort   uint16 `json:"local_port,omitempty"`
	NSType      uint32 `json:"ns_type,omitempty"`
	OldUID      uint32 `json:"old_uid,omitempty"`
	NewUID      uint32 `json:"new_uid,omitempty"`
	Capability  uint32 `json:"capability,omitempty"`
	ModeFlags   uint32 `json:"mode_flags,omitempty"`

	// Anomaly score from n-gram analysis (0.0 = normal, 1.0 = highly anomalous)
	AnomalyScore float64 `json:"anomaly_score,omitempty"`
}

// EnforcementResultAlert records enforcement outcome for the alert.
type EnforcementResultAlert struct {
	Action    string `json:"action"`
	Signal    string `json:"signal,omitempty"`  // SIGTERM or SIGKILL
	TargetPID uint32 `json:"target_pid"`
	Success   bool   `json:"success"`
	Reason    string `json:"reason"`
	LatencyUS int64  `json:"latency_us"`
	RuleID    string `json:"rule_id,omitempty"`
}

// CorrelationResultAlert records correlation context when a multi-signal
// correlation fires. This enriches the alert with information about which
// signals contributed to the correlation and the time window.
type CorrelationResultAlert struct {
	RuleID         string    `json:"rule_id"`
	GroupKey       string    `json:"group_key"`
	MatchedSignals int       `json:"matched_signals"`
	WindowStart    time.Time `json:"window_start"`
	WindowEnd      time.Time `json:"window_end"`
	Description    string    `json:"description"`
}

// ── Alert Emitter ─────────────────────────────────────────────────────

// AlertEmitter sends alerts to configured outputs (file, stdout, webhook).
type AlertEmitter struct {
	config AlertEmitterConfig

	file    *os.File
	encoder *json.Encoder

	mu     sync.Mutex
	count  uint64
}

// AlertEmitterConfig holds alert emitter configuration.
type AlertEmitterConfig struct {
	AlertFile      string
	WebhookURL     string
	WebhookHeaders map[string]string
	Mode           string // audit, enforce, simulate

	// WebhookManager forwards alerts to configured webhook sinks.
	// If set, this takes priority over the legacy WebhookURL path.
	WebhookManager *WebhookManager
}

// NewAlertEmitter creates a new alert emitter.
func NewAlertEmitter(cfg AlertEmitterConfig) (*AlertEmitter, error) {
	e := &AlertEmitter{
		config: cfg,
	}

	// Open alert file (NDJSON format)
	if cfg.AlertFile != "" {
		// Ensure directory exists
		dir := ""
		if lastSlash := lastIndex(cfg.AlertFile, '/'); lastSlash >= 0 {
			dir = cfg.AlertFile[:lastSlash]
		}
		if dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create alert directory %s: %w", dir, err)
			}
		}

		f, err := os.OpenFile(cfg.AlertFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("[output] Warning: cannot open alert file %s: %v (using stdout)", cfg.AlertFile, err)
		} else {
			e.file = f
			e.encoder = json.NewEncoder(f)
		}
	}

	return e, nil
}

// Emit sends an alert to all configured outputs.
func (e *AlertEmitter) Emit(alert *Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.count++

	// Ensure timestamp is set
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	// Format as NDJSON
	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("[output] Warning: failed to marshal alert: %v", err)
		return
	}

	// Write to file
	if e.file != nil {
		if _, err := e.file.Write(append(data, '\n')); err != nil {
			log.Printf("[output] Warning: failed to write alert to file: %v", err)
		}
	} else {
		// Fallback to stdout
		log.Printf("[output] ALERT: %s", string(data))
	}

	// Send to webhook (async)
	if e.config.WebhookURL != "" || e.config.WebhookManager != nil {
		go e.sendWebhook(alert, data)
	}
}

// Flush flushes any buffered alerts.
func (e *AlertEmitter) Flush() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.file != nil {
		e.file.Sync()
	}

	if e.config.WebhookManager != nil {
		e.config.WebhookManager.Flush()
	}
}

// Close closes the alert emitter.
func (e *AlertEmitter) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.file != nil {
		e.file.Close()
	}

	if e.config.WebhookManager != nil {
		e.config.WebhookManager.Close()
	}
}

// Count returns the total number of alerts emitted.
func (e *AlertEmitter) Count() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.count
}

// sendWebhook sends an alert to the configured webhook destinations.
// If a WebhookManager is configured, it forwards the alert to all sinks.
// Otherwise, falls back to the legacy single-URL webhook (Phase 1 stub).
func (e *AlertEmitter) sendWebhook(alert *Alert, _ []byte) {
	if e.config.WebhookManager != nil {
		e.config.WebhookManager.Send(alert)
		return
	}

	// Legacy fallback: single-URL webhook (Phase 1 stub)
	log.Printf("[output] Webhook: rule=%s action=%s container=%s",
		alert.RuleID, alert.Action, alert.ContainerName)
}

// ── Helpers ──────────────────────────────────────────────────────────

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ── Test Helpers ────────────────────────────────────────────────────────

// AlertEmitterForTest creates a test alert emitter that captures alerts in memory.
// This is intended for use in tests only.
func NewAlertEmitterForTest() *TestAlertEmitter {
	return &TestAlertEmitter{
		alerts: make([]*Alert, 0),
	}
}

// TestAlertEmitter is a test double for AlertEmitter that records alerts in memory.
type TestAlertEmitter struct {
	mu     sync.Mutex
	alerts []*Alert
}

// Emit records an alert for later inspection.
func (t *TestAlertEmitter) Emit(alert *Alert) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.alerts = append(t.alerts, alert)
}

// Count returns the number of alerts emitted.
func (t *TestAlertEmitter) Count() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return uint64(len(t.alerts))
}

// LastAlert returns the most recently emitted alert, or nil if none.
func (t *TestAlertEmitter) LastAlert() *Alert {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.alerts) == 0 {
		return nil
	}
	return t.alerts[len(t.alerts)-1]
}

// Alerts returns all emitted alerts.
func (t *TestAlertEmitter) Alerts() []*Alert {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]*Alert, len(t.alerts))
	copy(result, t.alerts)
	return result
}

// Flush is a no-op for the test emitter.
func (t *TestAlertEmitter) Flush() {}

// Close is a no-op for the test emitter.
func (t *TestAlertEmitter) Close() {}