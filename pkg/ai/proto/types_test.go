// Package proto_test — tests for SecurityScarletAI gRPC protocol types.
package proto_test

import (
	"context"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/ai/proto"
)

// ── Client Construction Tests ──────────────────────────────────────────

func TestNewSecurityScarletAIClient(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 5*time.Second)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.IsConnected() {
		t.Error("Client should not be connected initially")
	}
}

func TestNewSecurityScarletAIClient_DefaultTimeout(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 0)
	if client == nil {
		t.Fatal("Expected non-nil client with zero timeout")
	}
	// Zero timeout should default to 5s
}

// ── Disconnected Behavior Tests ────────────────────────────────────────

func TestDisconnected_AnalyzeEvents(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 1*time.Second)

	result, err := client.AnalyzeEvents(context.Background(), &proto.SecurityEvent{
		PID:       1234,
		Category:  1,
		EventType: 1,
		Comm:      "bash",
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result even when disconnected")
	}
	if result.AnomalyScore != 0.0 {
		t.Errorf("Expected 0.0 anomaly score when disconnected, got %f", result.AnomalyScore)
	}
	if result.EnforceRecommended {
		t.Error("Should not recommend enforcement when disconnected")
	}
}

func TestDisconnected_GetProfile(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 1*time.Second)

	profile, err := client.GetProfile(context.Background(), &proto.ProfileRequest{
		Image: "nginx:latest",
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if profile == nil {
		t.Fatal("Expected non-nil profile even when disconnected")
	}
	if profile.Image != "nginx:latest" {
		t.Errorf("Expected image 'nginx:latest', got %s", profile.Image)
	}
	if profile.Confidence != 0.0 {
		t.Errorf("Expected 0.0 confidence when disconnected, got %f", profile.Confidence)
	}
}

func TestDisconnected_TriageAlert(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 1*time.Second)

	result, err := client.TriageAlert(context.Background(), &proto.Alert{
		RuleID:   "R008",
		Priority: "CRITICAL",
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil triage result even when disconnected")
	}
	if result.FalsePositiveScore != 0.5 {
		t.Errorf("Expected neutral FP score 0.5 when disconnected, got %f", result.FalsePositiveScore)
	}
}

func TestDisconnected_SuggestRule(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 1*time.Second)

	result, err := client.SuggestRule(context.Background(), &proto.IncidentContext{
		RuleID: "R008",
	})
	if err == nil {
		t.Error("Expected error when disconnected for SuggestRule")
	}
	if result != nil {
		t.Error("Expected nil result when disconnected for SuggestRule")
	}
}

// ── Connection Tests ────────────────────────────────────────────────────

func TestConnect_InvalidEndpoint(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("invalid-host-that-does-not-exist:9999", 1*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Error("Expected error connecting to invalid endpoint")
		client.Disconnect()
	}
}

func TestDisconnect_WhenNotConnected(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 1*time.Second)

	// Should not panic
	err := client.Disconnect()
	if err != nil {
		t.Errorf("Unexpected error on disconnect when not connected: %v", err)
	}
}

// ── Message Type Tests ────────────────────────────────────────────────────

func TestSecurityEvent_WithPayloads(t *testing.T) {
	event := &proto.SecurityEvent{
		PID:        1234,
		PPID:       100,
		Category:   1, // PROCESS
		EventType:  1,
		Comm:       "bash",
		ProcessPayload: &proto.ProcessPayload{
			Filename: "/bin/bash",
			Args:     "-i",
		},
	}

	if event.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", event.PID)
	}
	if event.ProcessPayload == nil {
		t.Fatal("Expected non-nil process payload")
	}
	if event.ProcessPayload.Filename != "/bin/bash" {
		t.Errorf("Expected filename '/bin/bash', got %s", event.ProcessPayload.Filename)
	}
}

func TestNetworkPayload_Fields(t *testing.T) {
	payload := &proto.NetworkPayload{
		RemoteAddr: []byte{192, 168, 1, 1},
		RemotePort: 4444,
		LocalPort:  54321,
		Protocol:   6, // TCP
	}

	if payload.RemotePort != 4444 {
		t.Errorf("Expected remote port 4444, got %d", payload.RemotePort)
	}
	if len(payload.RemoteAddr) != 4 {
		t.Errorf("Expected 4 bytes in remote addr, got %d", len(payload.RemoteAddr))
	}
}

func TestAnalysisResult_Fields(t *testing.T) {
	result := &proto.AnalysisResult{
		AnomalyScore:       0.85,
		Classification:     "cryptojacking",
		Description:        "Detected repetitive syscall pattern consistent with mining",
		EnforceRecommended: true,
		Confidence:         0.9,
		ModelVersion:       "v1.2",
	}

	if result.AnomalyScore != 0.85 {
		t.Errorf("Expected anomaly score 0.85, got %f", result.AnomalyScore)
	}
	if result.Classification != "cryptojacking" {
		t.Errorf("Expected classification 'cryptojacking', got %s", result.Classification)
	}
}

func TestTriageResult_Fields(t *testing.T) {
	result := &proto.TriageResult{
		FalsePositiveScore: 0.92,
		Priority:          "INFO",
		Reasoning:         "Likely false positive from CI/CD pipeline",
		SuppressRecommended: true,
		Confidence:        0.85,
	}

	if result.FalsePositiveScore != 0.92 {
		t.Errorf("Expected FP score 0.92, got %f", result.FalsePositiveScore)
	}
	if !result.SuppressRecommended {
		t.Error("Expected suppress recommendation")
	}
}

func TestRuleSuggestion_Fields(t *testing.T) {
	suggestion := &proto.RuleSuggestion{
		RuleYAML:        "- rule: Test Rule\n  condition: test",
		Reasoning:       "Based on 3 incidents",
		BasedOnIncidents: 3,
		Confidence:       0.7,
		Status:          "draft",
	}

	if suggestion.BasedOnIncidents != 3 {
		t.Errorf("Expected 3 incidents, got %d", suggestion.BasedOnIncidents)
	}
	if suggestion.Status != "draft" {
		t.Errorf("Expected status 'draft', got %s", suggestion.Status)
	}
}

// ── Event Stream Tests ────────────────────────────────────────────────────

func TestEventStream_SendRecv(t *testing.T) {
	stream := proto.NewEventStream()

	event := &proto.SecurityEvent{
		PID:       1234,
		Category:  1,
		EventType: 1,
		Comm:      "test",
	}

	err := stream.Send(event)
	if err != nil {
		t.Errorf("Unexpected error sending event: %v", err)
	}

	result, err := stream.Recv()
	if err != nil {
		t.Errorf("Unexpected error receiving result: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestEventStream_Close(t *testing.T) {
	stream := proto.NewEventStream()

	err := stream.Close()
	if err != nil {
		t.Errorf("Unexpected error closing stream: %v", err)
	}

	// After close, send should return EOF
	err = stream.Send(&proto.SecurityEvent{PID: 1})
	if err == nil {
		t.Error("Expected error sending after close")
	}
}

// ── BehavioralProfile Tests ───────────────────────────────────────────────

func TestBehavioralProfile_WithSyscallProfile(t *testing.T) {
	profile := &proto.BehavioralProfile{
		Image: "nginx:1.25",
		SyscallProfile: &proto.SyscallProfile{
			TopSyscalls: map[string]float64{
				"read":     0.25,
				"write":    0.15,
				"epoll_wait": 0.20,
			},
			UniqueSyscallCount: 42,
			NgramHashes:       []uint64{0x1234, 0x5678},
		},
		BaselineEvents: 10000,
		Confidence:     0.95,
	}

	if profile.SyscallProfile == nil {
		t.Fatal("Expected non-nil syscall profile")
	}
	if profile.SyscallProfile.UniqueSyscallCount != 42 {
		t.Errorf("Expected 42 unique syscalls, got %d", profile.SyscallProfile.UniqueSyscallCount)
	}
	if len(profile.SyscallProfile.TopSyscalls) != 3 {
		t.Errorf("Expected 3 top syscalls, got %d", len(profile.SyscallProfile.TopSyscalls))
	}
}

func TestProfileRequest(t *testing.T) {
	req := &proto.ProfileRequest{
		Image:        "redis:7",
		ForceRebuild: true,
	}

	if req.Image != "redis:7" {
		t.Errorf("Expected image 'redis:7', got %s", req.Image)
	}
	if !req.ForceRebuild {
		t.Error("Expected ForceRebuild to be true")
	}
}

// ── ServiceName Test ────────────────────────────────────────────────────

func TestServiceName(t *testing.T) {
	if proto.ServiceName == "" {
		t.Error("ServiceName should not be empty")
	}
	if proto.ServiceName != "securityscarlet.ai.v1.SecurityScarletAI" {
		t.Errorf("Unexpected service name: %s", proto.ServiceName)
	}
}

// ── Health Check Test (disconnected) ─────────────────────────────────────

func TestHealthCheck_WhenDisconnected(t *testing.T) {
	client := proto.NewSecurityScarletAIClient("localhost:9443", 1*time.Second)

	healthy, err := client.CheckHealth(context.Background())
	if err == nil {
		t.Error("Expected error when checking health on disconnected client")
	}
	if healthy {
		t.Error("Should not be healthy when disconnected")
	}
}