//go:build linux

// This file is compiled only on Linux. It contains a real-eBPF regression test
// that verifies the loader actually loads/attaches eBPF programs when not in
// mock mode. It is skipped when the compiled .o objects are absent (e.g. on a
// dev box that hasn't run `make generate-ebpf`) or when BTF is unavailable.
//
// Run on a Linux CI runner after `make generate-ebpf`:
//
//	go test -count=1 -v ./pkg/ebpf/

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// objectDir returns the directory holding compiled eBPF objects, or skips.
func objectDir(t *testing.T) string {
	t.Helper()
	// CI convention: objects are in build/bpf (from `make generate-ebpf`).
	for _, candidate := range []string{"../../build/bpf", "./build/bpf", "/opt/scarlet/bpf"} {
		if _, err := os.Stat(filepath.Join(candidate, "process.o")); err == nil {
			return candidate
		}
	}
	t.Skip("compiled eBPF .o files not found — run `make generate-ebpf` on a Linux host with BTF")
	return ""
}

// TestRealEBPFLoadAttach verifies that, on a real Linux+BTF host with compiled
// objects, Loader.Load + Attach actually populate collections and links
// (regression guard against re-stubbing the kernel path).
func TestRealEBPFLoadAttach(t *testing.T) {
	if !isBPFAvailable() {
		t.Skip("BTF not available — skipping real-eBPF test")
	}

	l := NewLoader(LoaderConfig{
		BPFObjectDir:    objectDir(t),
		RingBufSizeMB:   4,
		EventBufferSize: 128,
	})
	if l.IsMockMode() {
		t.Skip("loader in mock mode despite Linux+BTF (isBPFAvailable false?)")
	}

	ctx := context.Background()
	if err := l.Load(ctx); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	t.Cleanup(func() { _ = l.Stop() })

	if l.CollectionCount() == 0 {
		t.Fatal("expected at least one loaded collection after Load")
	}

	if err := l.Attach(ctx); err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	if l.LinkCount() == 0 {
		t.Fatal("expected at least one attached link after Attach — probes were not attached")
	}
	t.Logf("loaded %d collections, attached %d probes", l.CollectionCount(), l.LinkCount())
}

// TestRealEBPFStartStop verifies Start/Stop don't error and clean up readers.
func TestRealEBPFStartStop(t *testing.T) {
	if !isBPFAvailable() {
		t.Skip("BTF not available — skipping real-eBPF test")
	}

	l := NewLoader(LoaderConfig{
		BPFObjectDir:    objectDir(t),
		RingBufSizeMB:   4,
		EventBufferSize: 128,
	})
	if l.IsMockMode() {
		t.Skip("loader in mock mode")
	}

	ctx := context.Background()
	if err := l.Load(ctx); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := l.Attach(ctx); err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := l.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}