# SecurityScarlet Runtime — Remediation Plan

**Authored:** 2026-06-20
**Author:** Mackenzie (lead security engineer, handover audit)
**Status:** Phases A, B, D complete and green (378 tests, race-clean). Phase C spec'd in `docs/phase_c_ebpf_handover.md` (pending Linux). Phase E deferred.

This plan tracks the work to lift SecurityScarlet Runtime from its current
state (B-tier engineering wrapped in S-tier claims) to honest production-grade.

The audit that produced this plan is captured in the 2026-06-20 memory log.
Headline finding: **the Go scaffolding is clean and well-tested, but the eBPF
load/attach path and the TC network-enforcement path are stubs.** The product
does not, in any build that exists, actually monitor syscalls at the kernel
level or drop packets at TC.

## Verification status at audit time

| Check | Result |
|---|---|
| `go build ./...` | ✅ clean |
| `go vet ./...` | ✅ clean |
| `go test -count=1 ./...` | ✅ 375 pass |
| `go test -race` (pipeline/correlate/ebpf/enrichment/output) | ✅ clean |
| eBPF load/attach | ❌ stub (`loadMockCollection`, log-only `Attach`) |
| TC enforcement | ❌ stub (TODO log-only map ops) |
| AI connector | ❌ stub (neutral returns, no gRPC dial) |
| CLI control commands | ❌ stub (`fmt.Println` only) |

## Phases

Each phase is gated: `go build && go vet && go test` must be green before
the next phase begins. No merge to `main` until Phase C lands (the product
is not honest until real eBPF exists).

### Phase A — Stop the lies (docs + dead code)

**Goal:** README and CLI text stop claiming what isn't true.

- [x] Internal session docs already gitignored (HANDOVER/SRD/PUSH_PROMPT) — verified untracked, no action.
- [x] Rewrite README enforcement-safety list to match the 7 actual rules in `response.go`.
- [x] Mark eBPF load, TC enforcement, AI triage, CLI control commands with ✅/⚠️/❌ status in README (new Implementation Status table).
- [x] Fix category count to 9 everywhere (README components table, README rule catalog, `catalog.go` comment x2, `default_rules.yaml` header; CLI `rules list` now reads the real engine).
- [x] Fix LOC / file counts to real numbers (~28.4k LOC, 54 source files) in README.
- [x] Delete dead code: `IPv4ToUint32` (loader.go) deleted. Webhook dead batch fields (`batchBuf`/`batchTimer`/`batchDone`) left in place — low-risk; `circuitResetAfter` is now wired (Phase D) and configurable.

### Phase B — Rule integrity

**Goal:** One rule source of truth; config flags actually work.

- [x] `Engine.loadRules()` honors `RulePaths` (was ignored — only embedded catalog loaded).
- [x] Eliminate divergence between `catalog.go` embedded YAML and `rules/default_rules.yaml` — disk file synced byte-identical to the embedded canonical catalog.
- [x] `scarletctl rules validate` actually parses + compiles (uses new `rules.ValidateFile`).
- [x] `scarletctl rules list` reads from a real engine via `AllRules()` (30 rules: 12 enforce / 18 alert).

### Phase C — Real eBPF (Linux verification workstream — see `docs/phase_c_ebpf_handover.md`)

**Goal:** The product actually monitors syscalls at the kernel level and
enforces at TC. **The real loader/TC code is now written and mock-gated**
(compiles on macOS, cross-vets on Linux, 378 tests green). What remains is
**Linux runtime verification** — compiling the C probes and running the
e2e smoke test on a real kernel. This cannot be done on this macOS box.

- [x] `Loader.Load()` / `Attach()` via `cilium/ebpf` `LoadCollection` + `link.Tracepoint`/`Kprobe` (mock-gated).
- [x] Ring buffer reader: real `ringbuf.Reader` per collection (`readEvents`).
- [x] `TCLoader` production path: real `LoadCollection` + `AttachTCX` + blocklist map `Update`/`Delete`.
- [x] `BlocklistValue` Go struct fixed to match C `network_block_value` layout.
- [x] Dockerfile Stage 1 fixed (`libbpf-dev`, `bpftool`, vmlinux.h generation, all 5 probes incl. `network_tc`).
- [x] Makefile `generate-ebpf` fixed (all 5 probes + vmlinux.h).
- [x] Helm `securityContext` grants `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` (TC attach).
- [x] Linux-only regression test `loader_linux_test.go` (skips on macOS, runs on Linux CI).
- [ ] **Linux runtime smoke:** compile probes on a BTF kernel, run `TestRealEBPFLoadAttach` + e2e in kind.
- [ ] bpf2go codegen for the `ScarletEvent` Go/C struct mirror (optional; current hand-maintained struct + `DecodeEvent` works; bpf2go removes the drift risk).
- [ ] Classic clsact TC attach for kernels < 6.6 (TCX needs 6.6+; netlink-based fallback is a follow-up).

### Phase D — Runtime bug fixes (macOS-doable)

**Goal:** The Go runtime stops leaking, stalling, and misreporting.

- [x] `RateLimiter.Close()` + wired into `ResponseActor.Stop()` (goroutine leak fix; `Stop` drains pending escalations).
- [x] `executeGracefulKill` moved async so the pipeline doesn't stall 5s per enforcement.
- [x] Webhook circuit-breaker half-open recovery (`circuitResetAfter` now used + configurable).
- [x] `WebhookManager.Send` bounded with a counting semaphore (`webhookMaxConcurrent = 16`).
- [x] `sendSIGKILL` no longer reports success on zombies (returns error if still alive).
- [x] `Enforce()` audit-log gap closed for non-enforce actions.
- [x] `NetworkEnforcer` restartable (recreates `stopCh` on Start).
- New regression tests: `TestWebhookCircuitBreaker_Recovery`, `TestRateLimiter_CloseIdempotent`, `TestResponseActor_StopDrainsGraceful` (378 total, race-clean).

### Phase E — AI: build it or remove it (decision deferred to Phase C)

- [ ] **Recommended:** reduce `pkg/ai/` to the real pieces (`FeatureExtractor`, `NgramBaseline`, `ScoreAnomaly`) and remove the gRPC connector + hand-written proto client until a real AI service exists.
- [ ] **Alternative:** generate proto from `securityscarlet.proto`, wire real `grpc.Dial`, implement `TriageAlert` against a real backend.

## Merge gate (not before Phase C)

- All phases A/B/D green on this machine.
- Phase C green on a Linux CI runner.
- README ✅/⚠️/❌ triples reviewed and accurate.
- `git status --short` clean, `--no-ff` merge, main == origin == sha verified pre/post.