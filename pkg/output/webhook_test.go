package output

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ── Test Helpers ───────────────────────────────────────────────────────

// newTestAlert creates a minimal alert for testing.
func newTestAlert(ruleID, priority, action string) *Alert {
	return &Alert{
		Timestamp:     time.Now(),
		RuleID:        ruleID,
		RuleName:      "Test Rule " + ruleID,
		Priority:      priority,
		Action:        action,
		Output:        "Test alert output for " + ruleID,
		ProcessName:   "testproc",
		PID:           1234,
		ContainerID:   "abc123",
		ContainerName: "test-container",
		Namespace:     "default",
		PodName:       "test-pod",
	}
}

// newCriticalAlert creates a critical priority alert.
func newCriticalAlert() *Alert {
	return newTestAlert("R009", "critical", "enforce")
}

// newWarningAlert creates a warning priority alert.
func newWarningAlert() *Alert {
	return newTestAlert("R014", "warning", "alert")
}

// ── Generic Webhook Sink Tests ────────────────────────────────────────

func TestGenericWebhookSink_SendSingle(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 1
	cfg.Timeout = 5 * time.Second

	sink := NewGenericWebhookSink(cfg)
	alert := newCriticalAlert()

	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("SendSingle failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("Expected webhook payload, got empty")
	}

	// Verify the payload is valid JSON
	var decoded Alert
	if err := json.Unmarshal(received, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}
	if decoded.RuleID != "R009" {
		t.Errorf("Expected RuleID=R009, got %s", decoded.RuleID)
	}
}

func TestGenericWebhookSink_SendBatch(t *testing.T) {
	var receivedCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 1

	sink := NewGenericWebhookSink(cfg)

	alerts := []*Alert{newCriticalAlert(), newWarningAlert()}
	if err := sink.Send(alerts); err != nil {
		t.Fatalf("Send batch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedCount != 1 {
		t.Errorf("Expected 1 request for batch of %d alerts, got %d", len(alerts), receivedCount)
	}
}

func TestGenericWebhookSink_Retry(t *testing.T) {
	var attemptCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptCount++
		count := attemptCount
		mu.Unlock()

		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError) // Fail first 2
		} else {
			w.WriteHeader(http.StatusOK) // Succeed on 3rd
		}
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 3
	cfg.RetryDelay = 10 * time.Millisecond // Fast retries for testing

	sink := NewGenericWebhookSink(cfg)
	alert := newCriticalAlert()

	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("SendSingle with retry failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if attemptCount < 3 {
		t.Errorf("Expected at least 3 attempts (1 initial + 2 retries), got %d", attemptCount)
	}

	stats := sink.Stats()
	if stats.Sent != 1 {
		t.Errorf("Expected Sent=1, got %d", stats.Sent)
	}
	if stats.Retried < 2 {
		t.Errorf("Expected Retried>=2, got %d", stats.Retried)
	}
}

func TestGenericWebhookSink_Disabled(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Enabled = false

	sink := NewGenericWebhookSink(cfg)
	alert := newCriticalAlert()

	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("SendSingle on disabled sink should succeed (nil), got: %v", err)
	}

	if requestCount != 0 {
		t.Errorf("Expected 0 requests to disabled sink, got %d", requestCount)
	}
}

func TestGenericWebhookSink_SetEnabled(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Enabled = true

	sink := NewGenericWebhookSink(cfg)

	// Should send when enabled
	if err := sink.SendSingle(newCriticalAlert()); err != nil {
		t.Fatalf("SendSingle failed: %v", err)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Disable
	sink.SetEnabled(false)

	// Should not send when disabled
	if err := sink.SendSingle(newCriticalAlert()); err != nil {
		t.Fatalf("SendSingle on disabled sink should succeed (nil)")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request (disabled), got %d", requestCount)
	}

	// Re-enable
	sink.SetEnabled(true)
	if err := sink.SendSingle(newCriticalAlert()); err != nil {
		t.Fatalf("SendSingle after re-enable failed: %v", err)
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests (re-enabled), got %d", requestCount)
	}
}

// ── Slack Webhook Sink Tests ──────────────────────────────────────────

func TestSlackWebhookSink_Send(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Type = WebhookSinkSlack
	cfg.SlackChannel = "#security-alerts"
	cfg.SlackUsername = "SecurityScarlet"

	sink := NewSlackWebhookSink(cfg)
	alert := newCriticalAlert()

	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("Slack SendSingle failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	var payload SlackPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Failed to unmarshal Slack payload: %v", err)
	}

	if payload.Username != "SecurityScarlet" {
		t.Errorf("Expected username=SecurityScarlet, got %s", payload.Username)
	}
	if payload.Channel != "#security-alerts" {
		t.Errorf("Expected channel=#security-alerts, got %s", payload.Channel)
	}
	if len(payload.Attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(payload.Attachments))
	}

	att := payload.Attachments[0]
	if att.Title != "[R009] Test Rule R009" {
		t.Errorf("Expected title '[R009] Test Rule R009', got %s", att.Title)
	}
	if att.Color != "#ff0000" { // critical = red
		t.Errorf("Expected color #ff0000 (critical), got %s", att.Color)
	}
}

func TestSlackWebhookSink_PriorityColors(t *testing.T) {
	tests := []struct {
		priority string
		color    string
	}{
		{"critical", "#ff0000"},
		{"error", "#ff6600"},
		{"warning", "#ffcc00"},
		{"info", "#3399ff"},
		{"unknown", "#cccccc"},
	}

	for _, tt := range tests {
		got := priorityColor(tt.priority)
		if got != tt.color {
			t.Errorf("priorityColor(%q) = %q, want %q", tt.priority, got, tt.color)
		}
	}
}

func TestSlackWebhookSink_MultipleAlerts(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Type = WebhookSinkSlack

	sink := NewSlackWebhookSink(cfg)
	alerts := []*Alert{newCriticalAlert(), newWarningAlert()}

	if err := sink.Send(alerts); err != nil {
		t.Fatalf("Slack Send batch failed: %v", err)
	}

	var payload SlackPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Failed to unmarshal Slack payload: %v", err)
	}
	if len(payload.Attachments) != 2 {
		t.Errorf("Expected 2 attachments, got %d", len(payload.Attachments))
	}
}

func TestSlackWebhookSink_WithContainerAndNetwork(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Type = WebhookSinkSlack

	sink := NewSlackWebhookSink(cfg)
	alert := newCriticalAlert()
	alert.RemoteIP = "1.2.3.4"
	alert.RemotePort = 4444
	alert.AnomalyScore = 0.85

	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("SendSingle failed: %v", err)
	}

	var payload SlackPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	att := payload.Attachments[0]
	// Should have container, namespace, pod, image, remote, and anomaly fields
	foundRemote := false
	foundAnomaly := false
	for _, field := range att.Fields {
		if field.Title == "Remote" {
			foundRemote = true
			if field.Value != "1.2.3.4:4444" {
				t.Errorf("Expected Remote=1.2.3.4:4444, got %s", field.Value)
			}
		}
		if field.Title == "Anomaly" {
			foundAnomaly = true
		}
	}
	if !foundRemote {
		t.Error("Expected Remote field in Slack attachment")
	}
	if !foundAnomaly {
		t.Error("Expected Anomaly field in Slack attachment")
	}
}

// ── PagerDuty Webhook Sink Tests ───────────────────────────────────────

func TestPagerDutyWebhookSink_Send(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Type = WebhookSinkPagerDuty
	cfg.PagerDutyRoutingKey = "test-routing-key-12345"

	sink := NewPagerDutyWebhookSink(cfg)
	alert := newCriticalAlert()

	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("PagerDuty SendSingle failed: %v", err)
	}

	var event PagerDutyEvent
	if err := json.Unmarshal(received, &event); err != nil {
		t.Fatalf("Failed to unmarshal PagerDuty event: %v", err)
	}

	if event.Payload.RoutingKey != "test-routing-key-12345" {
		t.Errorf("Expected routing key test-routing-key-12345, got %s", event.Payload.RoutingKey)
	}
	if event.Payload.EventAction != "trigger" {
		t.Errorf("Expected event_action=trigger, got %s", event.Payload.EventAction)
	}
	if event.Payload.Severity != "critical" {
		t.Errorf("Expected severity=critical, got %s", event.Payload.Severity)
	}
	if event.Payload.Source == "" {
		t.Error("Expected non-empty source")
	}
}

func TestPagerDutyWebhookSink_SeverityMapping(t *testing.T) {
	tests := []struct {
		priority string
		severity string
	}{
		{"critical", "critical"},
		{"error", "error"},
		{"warning", "warning"},
		{"info", "info"},
		{"unknown", "warning"},
	}

	for _, tt := range tests {
		got := alertPriorityToPagerDutySeverity(tt.priority)
		if got != tt.severity {
			t.Errorf("alertPriorityToPagerDutySeverity(%q) = %q, want %q", tt.priority, got, tt.severity)
		}
	}
}

func TestPagerDutyWebhookSink_DedupKey(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.PagerDutyRoutingKey = "test-key"

	sink := NewPagerDutyWebhookSink(cfg)

	// Alert with container ID
	alert1 := newCriticalAlert()
	alert1.ContainerID = "container-abc"
	sink.SendSingle(alert1)

	var event1 PagerDutyEvent
	mu.Lock()
	json.Unmarshal(received, &event1)
	mu.Unlock()

	expectedKey := "scarlet:R009:container-abc"
	if event1.Payload.DedupKey != expectedKey {
		t.Errorf("Expected dedup_key=%s, got %s", expectedKey, event1.Payload.DedupKey)
	}

	// Alert without container ID
	alert2 := newWarningAlert()
	alert2.ContainerID = ""
	sink.SendSingle(alert2)

	var event2 PagerDutyEvent
	mu.Lock()
	json.Unmarshal(received, &event2)
	mu.Unlock()

	if event2.Payload.DedupKey == "" {
		t.Error("Expected non-empty dedup_key for alert without container")
	}
	if event2.Payload.DedupKey != "scarlet:R014:pid-1234" {
		t.Errorf("Expected dedup_key=scarlet:R014:pid-1234, got %s", event2.Payload.DedupKey)
	}
}

func TestPagerDutyWebhookSink_DowngradeOnPartialBatch(t *testing.T) {
	// PagerDuty sends each alert individually, even with batch Send()
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.PagerDutyRoutingKey = "test-key"

	sink := NewPagerDutyWebhookSink(cfg)

	alerts := []*Alert{newCriticalAlert(), newWarningAlert()}
	if err := sink.Send(alerts); err != nil {
		t.Fatalf("PagerDuty Send batch failed: %v", err)
	}

	// Each alert goes individually
	if requestCount != 2 {
		t.Errorf("Expected 2 individual HTTP requests, got %d", requestCount)
	}
}

func TestPagerDutyWebhookSink_WithCorrelationResult(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.PagerDutyRoutingKey = "test-key"

	sink := NewPagerDutyWebhookSink(cfg)

	alert := newCriticalAlert()
	alert.CorrelationResult = &CorrelationResultAlert{
		RuleID:         "COR-001",
		MatchedSignals: 3,
	}
	sink.SendSingle(alert)

	var event PagerDutyEvent
	if err := json.Unmarshal(received, &event); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if event.Payload.CustomDetails["correlation_rule"] != "COR-001" {
		t.Errorf("Expected correlation_rule=COR-001, got %s", event.Payload.CustomDetails["correlation_rule"])
	}
}

// ── Circuit Breaker Tests ────────────────────────────────────────────────

func TestWebhookSink_CircuitBreaker(t *testing.T) {
	var attemptCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptCount++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError) // Always fail
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 1
	cfg.RetryDelay = 10 * time.Millisecond

	sink := NewGenericWebhookSink(cfg)

	// Trigger 5 failures to open circuit breaker
	for i := 0; i < 6; i++ {
		sink.SendSingle(newCriticalAlert())
	}

	stats := sink.Stats()
	if !stats.CircuitOpen {
		t.Error("Expected circuit breaker to be open after 5+ failures")
	}
}

func TestWebhookSink_NonRetryableStatus(t *testing.T) {
	var attemptCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptCount++
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest) // 4xx not retried except 429
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 3
	cfg.RetryDelay = 10 * time.Millisecond

	sink := NewGenericWebhookSink(cfg)
	sink.SendSingle(newCriticalAlert())

	mu.Lock()
	defer mu.Unlock()
	// 400 should NOT be retried — only 1 attempt
	if attemptCount != 1 {
		t.Errorf("Expected 1 attempt for 400 (non-retryable), got %d", attemptCount)
	}
}

func TestWebhookSink_RetryOn429(t *testing.T) {
	var attemptCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptCount++
		mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests) // 429 IS retried
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 2
	cfg.RetryDelay = 10 * time.Millisecond

	sink := NewGenericWebhookSink(cfg)
	sink.SendSingle(newCriticalAlert())

	mu.Lock()
	defer mu.Unlock()
	// 429 should be retried — attempt + 2 retries = 3 total
	if attemptCount != 3 {
		t.Errorf("Expected 3 attempts for 429 (retried), got %d", attemptCount)
	}
}

// ── Webhook Manager Tests ─────────────────────────────────────────────

func TestWebhookManager_MultipleSinks(t *testing.T) {
	var count1, count2 int
	var mu1, mu2 sync.Mutex

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu1.Lock()
		count1++
		mu1.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu2.Lock()
		count2++
		mu2.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	configs := []WebhookSinkConfig{
		{Type: WebhookSinkGeneric, URL: server1.URL, Enabled: true, RetryCount: 1, Timeout: 5 * time.Second},
		{Type: WebhookSinkGeneric, URL: server2.URL, Enabled: true, RetryCount: 1, Timeout: 5 * time.Second},
	}

	wm := NewWebhookManager(configs)
	defer wm.Close()

	alert := newCriticalAlert()
	wm.Send(alert)

	// Give goroutines time to complete
	time.Sleep(100 * time.Millisecond)

	mu1.Lock()
	mu2.Lock()
	if count1 != 1 || count2 != 1 {
		t.Errorf("Expected both sinks to receive 1 alert, got sink1=%d sink2=%d", count1, count2)
	}
	mu1.Unlock()
	mu2.Unlock()
}

func TestWebhookManager_SkipsDisabledSinks(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	configs := []WebhookSinkConfig{
		{Type: WebhookSinkGeneric, URL: server.URL, Enabled: false}, // disabled
	}

	wm := NewWebhookManager(configs)
	defer wm.Close()

	if wm.SinkCount() != 0 {
		t.Errorf("Expected 0 sinks (disabled skipped), got %d", wm.SinkCount())
	}
}

func TestWebhookManager_SkipsEmptyURL(t *testing.T) {
	configs := []WebhookSinkConfig{
		{Type: WebhookSinkGeneric, URL: "", Enabled: true}, // empty URL
	}

	wm := NewWebhookManager(configs)
	defer wm.Close()

	if wm.SinkCount() != 0 {
		t.Errorf("Expected 0 sinks (empty URL skipped), got %d", wm.SinkCount())
	}
}

func TestWebhookManager_AddRemoveSink(t *testing.T) {
	var requestCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wm := NewWebhookManager(nil)
	if wm.SinkCount() != 0 {
		t.Errorf("Expected 0 sinks, got %d", wm.SinkCount())
	}

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	sink := NewGenericWebhookSink(cfg)

	wm.AddSink(sink)
	if wm.SinkCount() != 1 {
		t.Errorf("Expected 1 sink after AddSink, got %d", wm.SinkCount())
	}

	alert := newCriticalAlert()
	wm.Send(alert)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}
	mu.Unlock()

	// Remove by URL
	wm.RemoveSink(server.URL)
	if wm.SinkCount() != 0 {
		t.Errorf("Expected 0 sinks after RemoveSink, got %d", wm.SinkCount())
	}
}

func TestWebhookManager_Stats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	configs := []WebhookSinkConfig{
		{Type: WebhookSinkGeneric, URL: server.URL, Enabled: true, RetryCount: 1, Timeout: 5 * time.Second},
	}

	wm := NewWebhookManager(configs)
	defer wm.Close()

	stats := wm.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 sink stats, got %d", len(stats))
	}

	if stats[0].Type != WebhookSinkGeneric {
		t.Errorf("Expected type=generic, got %s", stats[0].Type)
	}
}

// ── AlertEmitter Webhook Integration Test ──────────────────────────────

func TestAlertEmitter_WithWebhookManager(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		r.Body.Close()
		mu.Lock()
		received = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Type = WebhookSinkGeneric
	cfg.RetryCount = 1
	cfg.Timeout = 5 * time.Second

	wm := NewWebhookManager([]WebhookSinkConfig{cfg})

	tmpFile := t.TempDir() + "/test_alerts.jsonl"
	emitter, err := NewAlertEmitter(AlertEmitterConfig{
		AlertFile:      tmpFile,
		WebhookManager: wm,
	})
	if err != nil {
		t.Fatalf("NewAlertEmitter failed: %v", err)
	}
	defer emitter.Close()

	alert := newCriticalAlert()
	emitter.Emit(alert)

	// Give the goroutine time to send (Emit runs sendWebhook in goroutine + WebhookManager.Send in goroutine)
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("Expected webhook to be called via WebhookManager, got no payload")
	}

	var decoded Alert
	if err := json.Unmarshal(received, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal webhook payload: %v", err)
	}
	if decoded.RuleID != "R009" {
		t.Errorf("Expected RuleID=R009 in webhook payload, got %s", decoded.RuleID)
	}
}

func TestAlertEmitter_LegacyWebhookFallback(t *testing.T) {
	// When WebhookManager is nil but WebhookURL is set, the legacy
	// log-only path should still work.
	tmpFile := t.TempDir() + "/test_alerts.jsonl"
	emitter, err := NewAlertEmitter(AlertEmitterConfig{
		AlertFile:  tmpFile,
		WebhookURL: "http://example.com/webhook",
	})
	if err != nil {
		t.Fatalf("NewAlertEmitter failed: %v", err)
	}
	defer emitter.Close()

	alert := newCriticalAlert()
	emitter.Emit(alert) // should not panic with legacy webhook

	if emitter.Count() != 1 {
		t.Errorf("Expected alert count=1, got %d", emitter.Count())
	}
}

// ── DefaultWebhookSinkConfig Tests ─────────────────────────────────────

func TestDefaultWebhookSinkConfig(t *testing.T) {
	cfg := DefaultWebhookSinkConfig()
	if cfg.RetryCount != 3 {
		t.Errorf("Expected default RetryCount=3, got %d", cfg.RetryCount)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Expected default Timeout=10s, got %v", cfg.Timeout)
	}
	if cfg.BatchSize != 1 {
		t.Errorf("Expected default BatchSize=1, got %d", cfg.BatchSize)
	}
	if cfg.Type != WebhookSinkGeneric {
		t.Errorf("Expected default Type=generic, got %s", cfg.Type)
	}
	if !cfg.Enabled {
		t.Error("Expected default Enabled=true")
	}
}

func TestNewWebhookSink_UnknownType(t *testing.T) {
	cfg := DefaultWebhookSinkConfig()
	cfg.Type = "unknown"
	_, err := NewWebhookSink(cfg)
	if err == nil {
		t.Error("Expected error for unknown sink type")
	}
}

func TestSlackWebhookSink_LargeBatch(t *testing.T) {
	var requestCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.Type = WebhookSinkSlack

	sink := NewSlackWebhookSink(cfg)

	// Create 25 alerts (> 20 attachment limit per Slack message)
	alerts := make([]*Alert, 25)
	for i := range alerts {
		alerts[i] = newTestAlert("R001", "warning", "alert")
	}

	if err := sink.Send(alerts); err != nil {
		t.Fatalf("Slack Send large batch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// 25 alerts / 20 per message = 2 requests
	if requestCount != 2 {
		t.Errorf("Expected 2 requests for 25 alerts, got %d", requestCount)
	}
}

// TestWebhookCircuitBreaker_Recovery verifies the circuit breaker opens after
// consecutive failures and recovers via a half-open probe after
// CircuitResetAfter (regression guard for the previously-dead circuitResetAfter
// field that left the breaker permanently open).
func TestWebhookCircuitBreaker_Recovery(t *testing.T) {
	var mu sync.Mutex
	failing := true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := failing
		mu.Unlock()
		if f {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultWebhookSinkConfig()
	cfg.URL = server.URL
	cfg.RetryCount = 0
	cfg.RetryDelay = 1 * time.Millisecond
	cfg.Timeout = time.Second
	cfg.CircuitResetAfter = 40 * time.Millisecond // fast recovery for the test

	sink := NewGenericWebhookSink(cfg)
	alert := newTestAlert("RTEST", "critical", ActionAlert)

	// Drive failures until the breaker opens (maxFailures default = 5).
	for i := 0; i < 7; i++ {
		_ = sink.SendSingle(alert)
	}
	stats := sink.Stats()
	if !stats.CircuitOpen {
		t.Fatalf("expected circuit breaker OPEN after 7 failures, got stats=%+v", stats)
	}

	// While open, sends are short-circuited (no HTTP hit).
	mu.Lock()
	beforeFlips := stats.Failed
	_ = beforeFlips
	failing = false // endpoint now healthy
	mu.Unlock()

	// Wait past CircuitResetAfter so the next send is a half-open probe.
	time.Sleep(60 * time.Millisecond)

	// First send after the reset window should probe and succeed, closing the breaker.
	if err := sink.SendSingle(alert); err != nil {
		t.Fatalf("expected half-open probe to succeed, got err=%v", err)
	}
	stats = sink.Stats()
	if stats.CircuitOpen {
		t.Fatalf("expected circuit breaker CLOSED after successful probe, still open: %+v", stats)
	}
	if stats.Sent < 1 {
		t.Fatalf("expected Sent>=1 after recovery, got %d", stats.Sent)
	}
}
