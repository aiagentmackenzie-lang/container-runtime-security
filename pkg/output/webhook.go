// Package output - webhook.go
// Alert forwarding to external destinations via webhooks.
//
// Implements three webhook sink types:
//   - Slack: Slack Incoming Webhook with rich message formatting
//   - PagerDuty: PagerDuty Events API v2 with severity mapping
//   - Generic: Configurable HTTP POST with custom headers and payload
//
// Features:
//   - Retry logic with exponential backoff (3 retries, max 30s total)
//   - Batching: multiple alerts coalesced into a single request (up to cap)
//   - Configurable TLS (skip verify, custom CA)
//   - Structured payloads per destination
//   - Circuit breaker: disables sink after consecutive failures

package output

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Sink Types ────────────────────────────────────────────────────────

// WebhookSinkType identifies the type of webhook destination.
type WebhookSinkType string

const (
	WebhookSinkSlack     WebhookSinkType = "slack"
	WebhookSinkPagerDuty WebhookSinkType = "pagerduty"
	WebhookSinkGeneric   WebhookSinkType = "generic"
)

// ── Configuration ─────────────────────────────────────────────────────

// WebhookSinkConfig holds configuration for a single webhook destination.
type WebhookSinkConfig struct {
	// Type is the webhook destination type: "slack", "pagerduty", or "generic".
	Type WebhookSinkType `json:"type" yaml:"type"`

	// URL is the webhook endpoint URL.
	URL string `json:"url" yaml:"url"`

	// Headers are additional HTTP headers to send with each request.
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`

	// RetryCount is the maximum number of retries per request (default: 3).
	RetryCount int `json:"retry_count,omitempty" yaml:"retry_count,omitempty"`

	// RetryDelay is the initial delay between retries, doubled each attempt (default: 1s).
	RetryDelay time.Duration `json:"retry_delay,omitempty" yaml:"retry_delay,omitempty"`

	// Timeout is the HTTP client timeout per request (default: 10s).
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	// BatchSize is the maximum number of alerts to batch into a single
	// request. 0 or 1 means no batching (one request per alert).
	BatchSize int `json:"batch_size,omitempty" yaml:"batch_size,omitempty"`

	// BatchInterval is the maximum time to wait before sending a batch
	// that hasn't reached BatchSize. Only used when BatchSize > 1.
	BatchInterval time.Duration `json:"batch_interval,omitempty" yaml:"batch_interval,omitempty"`

	// TLSInsecureSkipVerify disables TLS certificate verification.
	TLSInsecureSkipVerify bool `json:"tls_insecure_skip_verify,omitempty" yaml:"tls_insecure_skip_verify,omitempty"`

	// TLSMinVersion sets the minimum TLS version (default: TLS 1.2).
	TLSMinVersion uint16 `json:"tls_min_version,omitempty" yaml:"tls_min_version,omitempty"`

	// CircuitResetAfter is how long after the last failure before the circuit
	// breaker attempts a half-open probe (default: 60s). Without this, a
	// tripped breaker never recovers until process restart.
	CircuitResetAfter time.Duration `json:"circuit_reset_after,omitempty" yaml:"circuit_reset_after,omitempty"`

	// Enabled controls whether this sink is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// PagerDuty-specific: RoutingKey is the PagerDuty integration key.
	PagerDutyRoutingKey string `json:"pagerduty_routing_key,omitempty" yaml:"pagerduty_routing_key,omitempty"`

	// Slack-specific: Channel overrides the default webhook channel.
	SlackChannel string `json:"slack_channel,omitempty" yaml:"slack_channel,omitempty"`

	// Slack-specific: Username overrides the bot username.
	SlackUsername string `json:"slack_username,omitempty" yaml:"slack_username,omitempty"`
}

// DefaultWebhookSinkConfig returns a WebhookSinkConfig with sensible defaults.
func DefaultWebhookSinkConfig() WebhookSinkConfig {
	return WebhookSinkConfig{
		Type:           WebhookSinkGeneric,
		RetryCount:     3,
		RetryDelay:     1 * time.Second,
		Timeout:        10 * time.Second,
		BatchSize:      1,
		BatchInterval:  5 * time.Second,
		TLSMinVersion:  tls.VersionTLS12,
		Enabled:        true,
	}
}

// ── Webhook Sink Interface ────────────────────────────────────────────

// WebhookSink forwards alerts to an external webhook destination.
type WebhookSink interface {
	// Send forwards one or more alerts to the webhook destination.
	// Returns nil on success (or when the sink is disabled/circuit-broken).
	Send(alerts []*Alert) error

	// SendSingle forwards a single alert.
	SendSingle(alert *Alert) error

	// Flush sends any batched alerts immediately.
	Flush() error

	// Close cleans up resources and flushes any remaining batched alerts.
	Close() error

	// Stats returns sink statistics.
	Stats() WebhookSinkStats

	// SetEnabled enables or disables the sink at runtime.
	SetEnabled(enabled bool)
}

// WebhookSinkStats holds statistics for a webhook sink.
type WebhookSinkStats struct {
	URL         string        `json:"url"`
	Type        WebhookSinkType `json:"type"`
	Enabled     bool          `json:"enabled"`
	Sent        int64         `json:"sent"`
	Failed      int64         `json:"failed"`
	Retried     int64         `json:"retried"`
	Batched     int64         `json:"batched"`
	CircuitOpen bool          `json:"circuit_open"`
}

// ── Base Sink ─────────────────────────────────────────────────────────

// baseWebhookSink provides shared functionality for all webhook sinks.
type baseWebhookSink struct {
	config WebhookSinkConfig
	client *http.Client

	// Stats
	mu         sync.Mutex
	sent       int64
	failed     int64
	retried    int64
	batched    int64

	// Circuit breaker
	consecutiveFailures int
	circuitOpen         bool
	maxFailures         int // Opens circuit after this many consecutive failures (default: 5)
	circuitResetAfter   time.Duration
	lastFailureAt       time.Time // when the last failure happened (for half-open recovery)

	// Batch
	batchMu    sync.Mutex
	batchBuf   []*Alert
	batchTimer *time.Timer
	batchDone  chan struct{}

	// Enabled
	enabled bool
}

// newBaseWebhookSink creates the base sink with retry logic and HTTP client.
func newBaseWebhookSink(cfg WebhookSinkConfig) *baseWebhookSink {
	// Apply defaults
	if cfg.RetryCount <= 0 {
		cfg.RetryCount = 3
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 1 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.BatchSize < 0 {
		cfg.BatchSize = 1
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1
	}
	if cfg.BatchInterval <= 0 {
		cfg.BatchInterval = 5 * time.Second
	}
	if cfg.TLSMinVersion == 0 {
		cfg.TLSMinVersion = tls.VersionTLS12
	}

	// Build HTTP client with TLS config
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			MinVersion:         cfg.TLSMinVersion,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	resetAfter := cfg.CircuitResetAfter
	if resetAfter <= 0 {
		resetAfter = 60 * time.Second
	}

	return &baseWebhookSink{
		config:            cfg,
		client:            client,
		enabled:           cfg.Enabled,
		maxFailures:       5,
		circuitResetAfter: resetAfter,
		batchBuf:          make([]*Alert, 0, cfg.BatchSize),
		batchDone:         make(chan struct{}),
	}
}

// sendWithRetry sends an HTTP POST with exponential backoff retry.
func (b *baseWebhookSink) sendWithRetry(payload []byte) error {
	if !b.enabled {
		return nil
	}

	// Check circuit breaker — allow a half-open probe after circuitResetAfter
	// so the breaker can recover without a process restart.
	b.mu.Lock()
	if b.circuitOpen {
		if time.Since(b.lastFailureAt) > b.circuitResetAfter {
			// Half-open: allow this single attempt to probe the endpoint.
			b.circuitOpen = false
			log.Printf("[webhook] Circuit breaker half-open for %s (probing after %v)",
				b.config.URL, b.circuitResetAfter)
		} else {
			b.mu.Unlock()
			return fmt.Errorf("webhook circuit breaker open for %s", b.config.URL)
		}
	}
	b.mu.Unlock()

	var lastErr error
	for attempt := 0; attempt <= b.config.RetryCount; attempt++ {
		if attempt > 0 {
			delay := b.config.RetryDelay * time.Duration(1<<(attempt-1))
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			time.Sleep(delay)

			b.mu.Lock()
			b.retried++
			b.mu.Unlock()
		}

		req, err := http.NewRequest(http.MethodPost, b.config.URL, bytes.NewReader(payload))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SecurityScarlet/1.0")
		for k, v := range b.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := b.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			b.mu.Lock()
			b.sent++
			b.consecutiveFailures = 0
			b.circuitOpen = false
			b.mu.Unlock()
			return nil
		}

		// Non-retryable status codes: don't retry 4xx except 429
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			b.mu.Lock()
			b.failed++
			b.consecutiveFailures++
			b.lastFailureAt = time.Now()
			if b.consecutiveFailures >= b.maxFailures {
				b.circuitOpen = true
				log.Printf("[webhook] Circuit breaker OPEN for %s after %d consecutive failures",
					b.config.URL, b.consecutiveFailures)
			}
			b.mu.Unlock()
			return fmt.Errorf("webhook returned status %d (non-retryable)", resp.StatusCode)
		}

		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	// All retries exhausted
	b.mu.Lock()
	b.failed++
	b.consecutiveFailures++
	b.lastFailureAt = time.Now()
	if b.consecutiveFailures >= b.maxFailures {
		b.circuitOpen = true
		log.Printf("[webhook] Circuit breaker OPEN for %s after %d consecutive failures",
			b.config.URL, b.consecutiveFailures)
	}
	b.mu.Unlock()

	return fmt.Errorf("webhook failed after %d retries: %w", b.config.RetryCount, lastErr)
}

// SetEnabled enables or disables the sink at runtime.
func (b *baseWebhookSink) SetEnabled(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.enabled = enabled
}

// Stats returns sink statistics.
func (b *baseWebhookSink) Stats() WebhookSinkStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return WebhookSinkStats{
		URL:         b.config.URL,
		Type:        b.config.Type,
		Enabled:     b.enabled,
		Sent:        b.sent,
		Failed:      b.failed,
		Retried:     b.retried,
		Batched:     b.batched,
		CircuitOpen: b.circuitOpen,
	}
}

// ── Slack Sink ────────────────────────────────────────────────────────

// SlackWebhookSink forwards alerts to Slack via Incoming Webhooks.
type SlackWebhookSink struct {
	base *baseWebhookSink
}

// NewSlackWebhookSink creates a new Slack webhook sink.
func NewSlackWebhookSink(cfg WebhookSinkConfig) *SlackWebhookSink {
	cfg.Type = WebhookSinkSlack
	return &SlackWebhookSink{
		base: newBaseWebhookSink(cfg),
	}
}

// SlackAttachment represents a Slack message attachment.
type SlackAttachment struct {
	Color     string                 `json:"color,omitempty"`
	Title     string                 `json:"title,omitempty"`
	Text      string                 `json:"text,omitempty"`
	Fields   []SlackField            `json:"fields,omitempty"`
	MrkdwnIn []string                `json:"mrkdwn_in,omitempty"`
	Footer   string                 `json:"footer,omitempty"`
	Ts       int64                  `json:"ts,omitempty"`
	Metadata map[string]interface{} `json:"-"`
}

// SlackField represents a single Slack attachment field.
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SlackPayload represents a Slack Incoming Webhook payload.
type SlackPayload struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// Send forwards one or more alerts to Slack.
func (s *SlackWebhookSink) Send(alerts []*Alert) error {
	if !s.base.enabled {
		return nil
	}

	// Slack has a 20-attachment limit per message, so batch if needed
	if len(alerts) > 20 {
		// Split into chunks
		for i := 0; i < len(alerts); i += 20 {
			end := i + 20
			if end > len(alerts) {
				end = len(alerts)
			}
			if err := s.Send(alerts[i:end]); err != nil {
				return err
			}
		}
		return nil
	}

	payload := s.buildPayload(alerts)

	s.base.mu.Lock()
	batched := len(alerts) > 1
	s.base.mu.Unlock()
	if batched {
		s.base.mu.Lock()
		s.base.batched++
		s.base.mu.Unlock()
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	return s.base.sendWithRetry(data)
}

// SendSingle forwards a single alert to Slack.
func (s *SlackWebhookSink) SendSingle(alert *Alert) error {
	return s.Send([]*Alert{alert})
}

// Flush is a no-op for Slack (no batching at the sink level).
func (s *SlackWebhookSink) Flush() error {
	return nil
}

// Close cleans up resources.
func (s *SlackWebhookSink) Close() error {
	return nil
}

// SetEnabled enables or disables the sink at runtime.
func (s *SlackWebhookSink) SetEnabled(enabled bool) {
	s.base.SetEnabled(enabled)
}

// Stats returns sink statistics.
func (s *SlackWebhookSink) Stats() WebhookSinkStats {
	return s.base.Stats()
}

// buildPayload constructs a Slack message from one or more alerts.
func (s *SlackWebhookSink) buildPayload(alerts []*Alert) *SlackPayload {
	// Choose emoji based on the highest priority in the batch
	emoji := ":rotating_light:"
	if len(alerts) == 1 {
		emoji = priorityEmoji(alerts[0].Priority)
	}

	summary := fmt.Sprintf("%d security alert(s)", len(alerts))
	if len(alerts) == 1 {
		summary = fmt.Sprintf("Security alert: %s", alerts[0].RuleName)
	}

	payload := &SlackPayload{
		Text:     fmt.Sprintf("%s %s", emoji, summary),
		Username: s.base.config.SlackUsername,
	}

	if s.base.config.SlackChannel != "" {
		payload.Channel = s.base.config.SlackChannel
	}
	if payload.Username == "" {
		payload.Username = "SecurityScarlet"
	}

	for _, alert := range alerts {
		attachment := s.buildAttachment(alert)
		payload.Attachments = append(payload.Attachments, attachment)
	}

	return payload
}

// buildAttachment constructs a Slack attachment from a single alert.
func (s *SlackWebhookSink) buildAttachment(alert *Alert) SlackAttachment {
	color := priorityColor(alert.Priority)

	attachment := SlackAttachment{
		Color: color,
		Title: fmt.Sprintf("[%s] %s", alert.RuleID, alert.RuleName),
		Text:  alert.Output,
		Footer: "SecurityScarlet Runtime",
		Ts:    alert.Timestamp.Unix(),
		Fields: []SlackField{
			{Title: "Priority", Value: alert.Priority, Short: true},
			{Title: "Action", Value: alert.Action, Short: true},
			{Title: "Process", Value: alert.ProcessName, Short: true},
			{Title: "PID", Value: fmt.Sprintf("%d", alert.PID), Short: true},
		},
		MrkdwnIn: []string{"text"},
	}

	// Add container info if available
	if alert.ContainerName != "" {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Container", Value: alert.ContainerName, Short: true})
	}
	if alert.Namespace != "" {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Namespace", Value: alert.Namespace, Short: true})
	}
	if alert.PodName != "" {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Pod", Value: alert.PodName, Short: true})
	}
	if alert.ContainerImage != "" {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Image", Value: alert.ContainerImage, Short: true})
	}

	// Add network info if available
	if alert.RemoteIP != "" {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Remote", Value: fmt.Sprintf("%s:%d", alert.RemoteIP, alert.RemotePort), Short: true})
	}

	// Add anomaly score if available
	if alert.AnomalyScore > 0 {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Anomaly", Value: fmt.Sprintf("%.2f", alert.AnomalyScore), Short: true})
	}

	// Add correlation result if available
	if alert.CorrelationResult != nil {
		attachment.Fields = append(attachment.Fields,
			SlackField{Title: "Correlation", Value: alert.CorrelationResult.RuleID, Short: true},
			SlackField{Title: "Signals", Value: fmt.Sprintf("%d matched", alert.CorrelationResult.MatchedSignals), Short: true})
	}

	return attachment
}

// priorityColor maps a priority string to a Slack color.
func priorityColor(priority string) string {
	switch priority {
	case "critical":
		return "#ff0000" // Red
	case "error":
		return "#ff6600" // Orange
	case "warning":
		return "#ffcc00" // Yellow
	case "info":
		return "#3399ff" // Blue
	default:
		return "#cccccc" // Gray
	}
}

// priorityEmoji maps a priority string to a Slack emoji.
func priorityEmoji(priority string) string {
	switch priority {
	case "critical":
		return ":rotating_light:"
	case "error":
		return ":x:"
	case "warning":
		return ":warning:"
	case "info":
		return ":information_source:"
	default:
		return ":grey_question:"
	}
}

// ── PagerDuty Sink ────────────────────────────────────────────────────

// PagerDutyWebhookSink forwards alerts to PagerDuty via Events API v2.
type PagerDutyWebhookSink struct {
	base *baseWebhookSink
}

// NewPagerDutyWebhookSink creates a new PagerDuty webhook sink.
func NewPagerDutyWebhookSink(cfg WebhookSinkConfig) *PagerDutyWebhookSink {
	cfg.Type = WebhookSinkPagerDuty
	return &PagerDutyWebhookSink{
		base: newBaseWebhookSink(cfg),
	}
}

// PagerDutyPayload represents a PagerDuty Events API v2 payload.
type PagerDutyPayload struct {
	RoutingKey  string             `json:"routing_key"`
	EventAction string             `json:"event_action"`
	DedupKey    string             `json:"dedup_key,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	Source      string             `json:"source"`
	Component   string             `json:"component,omitempty"`
	Group       string             `json:"group,omitempty"`
	Class       string             `json:"class,omitempty"`
	Summary     string             `json:"summary"`
	Timestamp   string             `json:"timestamp,omitempty"`
	CustomDetails map[string]string `json:"custom_details,omitempty"`
	Links       []PagerDutyLink     `json:"links,omitempty"`
}

// PagerDutyLink represents a PagerDuty event link.
type PagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text,omitempty"`
}

// PagerDutyEvent represents the outer PagerDuty Events API v2 event.
type PagerDutyEvent struct {
	Payload PagerDutyPayload `json:"payload"`
}

// Send forwards one or more alerts to PagerDuty.
// PagerDuty doesn't natively batch, so each alert is sent individually.
func (p *PagerDutyWebhookSink) Send(alerts []*Alert) error {
	if !p.base.enabled {
		return nil
	}

	var lastErr error
	for _, alert := range alerts {
		if err := p.SendSingle(alert); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// SendSingle forwards a single alert to PagerDuty.
func (p *PagerDutyWebhookSink) SendSingle(alert *Alert) error {
	if !p.base.enabled {
		return nil
	}

	event := p.buildEvent(alert)

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal PagerDuty payload: %w", err)
	}

	return p.base.sendWithRetry(data)
}

// Flush is a no-op for PagerDuty (no batching).
func (p *PagerDutyWebhookSink) Flush() error {
	return nil
}

// Close cleans up resources.
func (p *PagerDutyWebhookSink) Close() error {
	return nil
}

// SetEnabled enables or disables the sink at runtime.
func (p *PagerDutyWebhookSink) SetEnabled(enabled bool) {
	p.base.SetEnabled(enabled)
}

// Stats returns sink statistics.
func (p *PagerDutyWebhookSink) Stats() WebhookSinkStats {
	return p.base.Stats()
}

// buildEvent constructs a PagerDuty event from a single alert.
func (p *PagerDutyWebhookSink) buildEvent(alert *Alert) PagerDutyEvent {
	// Map priority to PagerDuty severity
	severity := alertPriorityToPagerDutySeverity(alert.Priority)

	// Derive dedup key from rule ID + container
	dedupKey := fmt.Sprintf("scarlet:%s:%s", alert.RuleID, alert.ContainerID)
	if alert.ContainerID == "" {
		dedupKey = fmt.Sprintf("scarlet:%s:pid-%d", alert.RuleID, alert.PID)
	}

	// Choose event action based on action type
	eventAction := "trigger"
	if alert.Action == ActionSimulated {
		eventAction = "trigger" // Simulated alerts still trigger events
	}

	// Determine source
	source := "SecurityScarlet Runtime"
	if alert.NodeName != "" {
		source = alert.NodeName
	}

	summary := alert.Output
	if len(summary) > 1024 {
		summary = summary[:1021] + "..."
	}

	details := map[string]string{
		"rule_id":     alert.RuleID,
		"rule_name":   alert.RuleName,
		"priority":    alert.Priority,
		"action":      alert.Action,
		"process":     alert.ProcessName,
		"pid":         fmt.Sprintf("%d", alert.PID),
		"category":    alert.Category,
		"event_type":  alert.EventType,
	}

	if alert.ContainerName != "" {
		details["container_name"] = alert.ContainerName
	}
	if alert.Namespace != "" {
		details["namespace"] = alert.Namespace
	}
	if alert.PodName != "" {
		details["pod"] = alert.PodName
	}
	if alert.RemoteIP != "" {
		details["remote_ip"] = alert.RemoteIP
		details["remote_port"] = fmt.Sprintf("%d", alert.RemotePort)
	}
	if alert.AnomalyScore > 0 {
		details["anomaly_score"] = fmt.Sprintf("%.2f", alert.AnomalyScore)
	}
	if alert.CorrelationResult != nil {
		details["correlation_rule"] = alert.CorrelationResult.RuleID
		details["matched_signals"] = fmt.Sprintf("%d", alert.CorrelationResult.MatchedSignals)
	}

	event := PagerDutyEvent{
		Payload: PagerDutyPayload{
			RoutingKey:  p.base.config.PagerDutyRoutingKey,
			EventAction:  eventAction,
			DedupKey:     dedupKey,
			Severity:     severity,
			Source:       source,
			Component:    "container-runtime",
			Class:        alert.Category,
			Summary:      summary,
			Timestamp:    alert.Timestamp.Format(time.RFC3339),
			CustomDetails: details,
		},
	}

	return event
}

// alertPriorityToPagerDutySeverity maps alert priority to PagerDuty severity.
func alertPriorityToPagerDutySeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "critical":
		return "critical"
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "info":
		return "info"
	default:
		return "warning"
	}
}

// ── Generic Webhook Sink ──────────────────────────────────────────────

// GenericWebhookSink forwards alerts to a generic webhook endpoint.
// The payload is a JSON array of alerts (or a single alert object).
type GenericWebhookSink struct {
	base *baseWebhookSink
}

// NewGenericWebhookSink creates a new generic webhook sink.
func NewGenericWebhookSink(cfg WebhookSinkConfig) *GenericWebhookSink {
	cfg.Type = WebhookSinkGeneric
	return &GenericWebhookSink{
		base: newBaseWebhookSink(cfg),
	}
}

// Send forwards one or more alerts to the generic webhook.
func (g *GenericWebhookSink) Send(alerts []*Alert) error {
	if !g.base.enabled {
		return nil
	}

	if len(alerts) == 0 {
		return nil
	}

	// If batching, send as an array; otherwise send single
	if len(alerts) == 1 {
		data, err := json.Marshal(alerts[0])
		if err != nil {
			return fmt.Errorf("failed to marshal alert: %w", err)
		}
		return g.base.sendWithRetry(data)
	}

	g.base.mu.Lock()
	g.base.batched++
	g.base.mu.Unlock()

	data, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("failed to marshal alerts: %w", err)
	}
	return g.base.sendWithRetry(data)
}

// SendSingle forwards a single alert to the generic webhook.
func (g *GenericWebhookSink) SendSingle(alert *Alert) error {
	return g.Send([]*Alert{alert})
}

// Flush is a no-op for the generic sink (no buffering).
func (g *GenericWebhookSink) Flush() error {
	return nil
}

// Close cleans up resources.
func (g *GenericWebhookSink) Close() error {
	return nil
}

// SetEnabled enables or disables the sink at runtime.
func (g *GenericWebhookSink) SetEnabled(enabled bool) {
	g.base.SetEnabled(enabled)
}

// Stats returns sink statistics.
func (g *GenericWebhookSink) Stats() WebhookSinkStats {
	return g.base.Stats()
}

// ── Webhook Manager ───────────────────────────────────────────────────

// webhookMaxConcurrent bounds the number of in-flight webhook HTTP requests
// across all sinks managed by a single WebhookManager. This prevents goroutine
// and connection explosion under alert storms (each request can hold a
// connection for up to RetryCount × RetryDelay × 2).
const webhookMaxConcurrent = 16

// WebhookManager coordinates multiple webhook sinks and forwards alerts
// to all active sinks concurrently.
type WebhookManager struct {
	sinks []WebhookSink
	sem   chan struct{} // counting semaphore bounding concurrent sends
	mu    sync.RWMutex
}

// NewWebhookManager creates a webhook manager from the given configs.
func NewWebhookManager(configs []WebhookSinkConfig) *WebhookManager {
	wm := &WebhookManager{
		sem: make(chan struct{}, webhookMaxConcurrent),
	}

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		if cfg.URL == "" {
			continue
		}

		sink, err := NewWebhookSink(cfg)
		if err != nil {
			log.Printf("[webhook] Warning: failed to create %s sink for %s: %v", cfg.Type, cfg.URL, err)
			continue
		}

		wm.sinks = append(wm.sinks, sink)
		log.Printf("[webhook] Configured %s sink: %s", cfg.Type, cfg.URL)
	}

	return wm
}

// NewWebhookSink creates a webhook sink based on the config type.
func NewWebhookSink(cfg WebhookSinkConfig) (WebhookSink, error) {
	switch cfg.Type {
	case WebhookSinkSlack:
		return NewSlackWebhookSink(cfg), nil
	case WebhookSinkPagerDuty:
		return NewPagerDutyWebhookSink(cfg), nil
	case WebhookSinkGeneric:
		return NewGenericWebhookSink(cfg), nil
	default:
		return nil, fmt.Errorf("unknown webhook sink type: %s", cfg.Type)
	}
}

// Send forwards an alert to all active webhook sinks concurrently.
// Concurrent sends are bounded by webhookMaxConcurrent; when all slots are
// taken this call blocks (backpressure to the alert emitter) rather than
// spawning unbounded goroutines.
func (wm *WebhookManager) Send(alert *Alert) {
	wm.mu.RLock()
	sinks := wm.sinks
	wm.mu.RUnlock()

	for _, sink := range sinks {
		wm.sem <- struct{}{} // acquire a slot (blocks at cap)
		go func(s WebhookSink) {
			defer func() { <-wm.sem }() // release
			if err := s.SendSingle(alert); err != nil {
				log.Printf("[webhook] Error sending alert to %s: %v", s.Stats().URL, err)
			}
		}(sink)
	}
}

// Flush flushes all sinks.
func (wm *WebhookManager) Flush() {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	for _, sink := range wm.sinks {
		if err := sink.Flush(); err != nil {
			log.Printf("[webhook] Error flushing sink %s: %v", sink.Stats().URL, err)
		}
	}
}

// Close closes all sinks and releases resources.
func (wm *WebhookManager) Close() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for _, sink := range wm.sinks {
		if err := sink.Close(); err != nil {
			log.Printf("[webhook] Error closing sink %s: %v", sink.Stats().URL, err)
		}
	}
	wm.sinks = nil
}

// AddSink adds a webhook sink at runtime.
func (wm *WebhookManager) AddSink(sink WebhookSink) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.sinks = append(wm.sinks, sink)
}

// RemoveSink removes a webhook sink by URL.
func (wm *WebhookManager) RemoveSink(url string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for i, sink := range wm.sinks {
		if sink.Stats().URL == url {
			wm.sinks = append(wm.sinks[:i], wm.sinks[i+1:]...)
			_ = sink.Close()
			return
		}
	}
}

// Stats returns statistics from all sinks.
func (wm *WebhookManager) Stats() []WebhookSinkStats {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	stats := make([]WebhookSinkStats, len(wm.sinks))
	for i, sink := range wm.sinks {
		stats[i] = sink.Stats()
	}
	return stats
}

// SinkCount returns the number of active sinks.
func (wm *WebhookManager) SinkCount() int {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return len(wm.sinks)
}