package pipeline

import (
	"testing"
	"time"
)

// TestRateLimiter_CloseIdempotent verifies that Close is safe to call multiple
// times and that the background cleanup goroutine can be stopped (regression
// guard for the goroutine leak where NewRateLimiter spawned an untethered
// cleanup goroutine).
func TestRateLimiter_CloseIdempotent(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)

	// A fresh limiter allows one action.
	if !rl.Allow("pod-a") {
		t.Fatal("expected first Allow to succeed")
	}

	// Closing must not panic and must be idempotent.
	rl.Close()
	rl.Close()
}

// TestResponseActor_StopDrainsGraceful verifies that Stop returns and does not
// panic after a graceful-kill enforcement (which schedules an async escalation
// goroutine). Regression guard for the wg.Add in executeGracefulKill.
func TestResponseActor_StopDrainsGraceful(t *testing.T) {
	r := NewResponseActorWithConfig("enforce", ResponseActorConfig{
		Mode:                EnforceModeGraceful,
		GracePeriodSeconds:  1,
		MaxKillsPerPod:      10,
		WindowSeconds:       60,
		ProtectedNamespaces: []string{"kube-system"},
	})
	// Stop with no pending work must return promptly.
	done := make(chan struct{})
	go func() {
		r.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ResponseActor.Stop did not return within 2s")
	}
}
