# SecurityScarlet Runtime

**eBPF-based container runtime security monitoring and enforcement for Kubernetes.**

SecurityScarlet Runtime is a real-time threat detection system that monitors syscall activity, process lifecycle, network connections, DNS queries, and TLS handshakes at the kernel level using eBPF. It provides Falco-compatible rule-based detection with built-in enforcement, multi-signal correlation, anomaly detection, AI-powered triage, and webhook alerting.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  eBPF Probes │────▶│  Agent Core  │────▶│  Rule Engine │
│ (5 programs) │     │  (pipeline)  │     │  (30 rules)  │
└──────────────┘     └──────┬───────┘     └──────┬───────┘
                            │                     │
┌──────────────┐     ┌──────▼───────┐     ┌───────▼────────┐
│  AI Triage   │     │  Enrichment  │     │  Enforcement   │
│  (advisory)  │     │  (container)  │     │ (kill/block)   │
└──────────────┘     └──────────────┘     └────────────────┘
                            │                     │
┌──────────────┐     ┌──────▼───────┐     ┌──────▼────────┐
│ Correlation  │     │    Output     │     │  Webhook      │
│  (7 rules)   │     │ (NDJSON +     │     │ (Slack/PD/    │
│              │     │  Prometheus)  │     │  generic)     │
└──────────────┘     └──────────────┘     └───────────────┘
```

### Components

| Component | Path | Description |
|-----------|------|-------------|
| eBPF Probes | `pkg/ebpf/probes/` | 5 C eBPF programs: process, file, network, escape, network_tc |
| eBPF Loader | `pkg/ebpf/` | Ring buffer reader, event decoder, DNS/TLS parser, kernel-side filtering |
| Agent | `pkg/agent/` | Orchestrator: component wiring, startup/shutdown, configuration |
| Pipeline | `pkg/pipeline/` | Event processing, anomaly scoring, container enrichment, coalescing |
| Rule Engine | `pkg/rules/` | 30 compiled rules across 9 categories with O(1) bucket evaluation |
| Correlator | `pkg/correlate/` | 7 multi-signal correlation rules (shell→network, DNS+TLS, etc.) |
| Enforcement | `pkg/enforcement/` | TC-based network blocking, 7-rule safety protocol, audit logging |
| Enrichment | `pkg/enrichment/` | Container ID resolution (PID → CRI → K8s), LRU caches |
| Output | `pkg/output/` | NDJSON alerts, Prometheus metrics, webhook sinks (Slack/PagerDuty/generic) |
| AI | `pkg/ai/` | gRPC-based triage (advisory), rule suggestions, behavioral profiling |
| CRD | `pkg/crd/` | Kubernetes CustomResourceDefinition types and policy management |
| CLI | `pkg/cli/` | `scarletctl` control interface |
| Docs | `docs/` | API reference, rule writing guide, deployment guide |

> ~28,400 lines of code across 54 source files (Go, C, YAML, Proto). **375 tests passing.** ~73k events/sec single-core throughput (rule engine + correlation, benchmarked via synthetic event injection).
>
> **Implementation status:** the Go pipeline, rule engine, correlator, enrichment, anomaly scoring, and webhook sinks are implemented and unit-tested. The eBPF kernel load/attach path and TC network-enforcement path are **stubs pending Phase C** (see [docs/remediation_plan.md](docs/remediation_plan.md) and [docs/phase_c_ebpf_handover.md](docs/phase_c_ebpf_handover.md)). The AI triage connector degrades to neutral. See [Implementation Status](#implementation-status) below.

## Rule Catalog

30 built-in rules across 9 categories:

| Category | Rules | IDs |
|----------|-------|-----|
| Container Escape | 7 | R001–R007 |
| Cryptojacking | 6 | R008–R013 |
| Reverse Shell | 4 | R014–R017 |
| Credential Access | 3 | R018–R020 |
| Privilege Escalation | 3 | R021–R023 |
| Container Drift | 2 | R024–R025 |
| Network Anomaly | 3 | R026–R028 |
| Process Injection | 1 | R029 |
| Known CVE | 1 | R030 |

## Detection Coverage

### Container Escape (R001–R007)
- `setns()` namespace join (R001)
- `unshare()` namespace creation (R002)
- Cgroup filesystem mount (R003)
- Docker socket access (R004)
- Host procfs access `/proc/1`, `/proc/self` (R005)
- Kernel module load (R006)
- eBPF program load from container (R007)

### Cryptojacking (R008–R013)
- Known miner binary execution — xmrig, ccminer, etc. (R008)
- Mining pool connections (port 4444, stratum) (R009)
- Stratum protocol in command line (R010)
- Behavioral CPU + network indicators (R011)
- SUID bit before mining (R012)
- Container drift — new binary at runtime (R013)

### Reverse Shell (R014–R017)
- Shell with outbound network (R014)
- `dup2` socket redirect (R015)
- Shell on C2 port (R016)
- Pipe-based shell `/dev/tcp` (R017)

### Credential & Privilege (R018–R023)
- Sensitive file read: `/etc/shadow`, SSH keys, Docker socket (R018)
- Cloud metadata SSRF: `169.254.169.254` (R019)
- K8s service account token access (R020)
- SetUID transition (R021)
- SUID/SGID bit set (R022)
- Capability set change (R023)

### Drift, Network & Injection (R024–R030)
- New executable creation at runtime (R024)
- Execution from `/tmp` (R025)
- Rogue listener (R026)
- C2 port connections (R027)
- Raw socket creation (R028)
- Ptrace from container (R029)
- Dirty Pipe pattern (R030)

### Multi-Signal Correlation (7 Rules)
- Shell + Network (reverse shell pattern)
- Miner + Mining Pool (cryptojacking)
- Namespace Join + Privilege Escalation (escape chain)
- Cgroup Mount + Namespace Escalation (escape chain)
- DNS Suspicious + TLS Suspicious SNI (C2 beaconing)
- TLS Suspicious SNI + Stratum Protocol (mining + TLS)
- DNS Suspicious + Mining Pool Connection (cryptojacking)

## Enforcement Safety

The system implements a 7-rule enforcement safety protocol in `pkg/pipeline/response.go`.
These are mandatory and applied in order before any kill is delivered:

1. **Container attribution** — no enforcement without a resolved container ID
2. **Simulate-mode check** — simulate mode never delivers signals
3. **Protected namespaces** — `kube-system`, `kube-public` are exempt (configurable)
4. **PID 0/1 protection** — never kill PID 0 or 1
5. **Self-preservation** — never kill the agent's own PID or PPID
6. **Rate limiting** — max kills per pod per window (default 10 per 60s)
7. **Namespace scope required** — enforcements are namespace-scoped, never global

Failed kill attempts (e.g. permission denied, process already gone) are recorded
in the enforcement audit log and an alert is still emitted alongside the attempt.
Operating mode can be changed at runtime via the `SetMode` API; CLI mode-switch
commands are pending implementation (see status table).

## Quick Start

### Prerequisites
- Go 1.22+
- Linux kernel 5.8+ (for eBPF features)
- clang/LLVM 12+ (for eBPF compilation)

### Build

```bash
make build          # Go binary
make ebpf           # Compile eBPF probes (requires Linux + clang)
make docker         # Multi-stage Docker image
```

### Run

```bash
# Start the agent (requires root or CAP_BPF + CAP_SYS_ADMIN)
sudo scarletctl start

# Check status
scarletctl status

# List loaded rules
scarletctl rules list

# View live events
scarletctl events

# Enable enforcement mode
scarletctl enforce
```

### Deploy to Kubernetes

```bash
helm install scarlet-runtime deploy/helm/scarlet-runtime/ \
  --namespace scarlet-system --create-namespace \
  --set agent.mode=enforce
```

## Configuration

Agent configuration via `configs/scarlet-config.yaml`:

```yaml
agent:
  mode: audit          # audit | enforce | simulate
  logLevel: info        # debug | info | warn | error
  ringBufferSizeMB: 4   # per-node ring buffer size

enrichment:
  criEndpoint: /run/containerd/containerd.sock
  pidCacheSize: 10000

enforcement:
  protectedNamespaces:
    - kube-system
    - kube-public
  maxKillsPerPod: 10

output:
  alertFile: /var/log/scarlet/alerts.jsonl
  webhook_url: ""

ai:
  enabled: false
  endpoint: scarlet-ai:9443

metrics:
  enabled: true
  port: 9090
```

## Testing

```bash
# Run all unit tests
go test -count=1 ./...

# Run with verbose output
go test -v -count=1 ./pkg/...

# Run specific test suites
go test -v -count=1 ./test/cryptojacking/
go test -v -count=1 ./test/escape_scenarios/
go test -v -count=1 ./test/integration/

# Run benchmarks
go test -bench=. -benchmem ./pkg/pipeline/

# Lint
go vet ./...
```

## Documentation

- [API Reference](docs/api_reference.md) — Full package and type documentation
- [Rule Writing Guide](docs/rule_writing_guide.md) — How to write custom YAML detection rules
- [Deployment Guide](docs/deployment_guide.md) — K8s deployment, Helm config, eBPF requirements

## Implementation Status

Honest per-component status. ✅ = implemented & tested · ⚠️ = partial/local-only · ❌ = stub/pending.

| Component | Status | Notes |
|-----------|--------|-------|
| Rule engine + compiler | ✅ | 30 rules, 9 categories, exception model |
| Correlator (7 rules) | ✅ | bounded windows, purge loop |
| Enrichment (CRI/K8s, LRU caches) | ✅ | unit-tested; live CRI needs Linux |
| Anomaly n-gram scoring | ✅ | JS-divergence + heuristic fallback |
| Webhook sinks (Slack/PagerDuty/generic) | ✅ | retry, circuit breaker (recovery in Phase D) |
| Enforcement safety protocol (7 rules) | ✅ | guards a kill path that fires on injected/test events |
| eBPF probe load + attach | ⚠️ | real `cilium/ebpf` `LoadCollection` + `link.Tracepoint`/`Kprobe`; mock-gated; Linux runtime smoke pending |
| Ring buffer event reader | ⚠️ | real `ringbuf.Reader` per collection; mock-gated; Linux runtime smoke pending |
| TC network blocking (kernel) | ⚠️ | real `AttachTCX` + blocklist map `Update`/`Delete`; mock-gated; needs kernel 6.6+ for TCX (classic clsact follow-up) |
| AI triage connector | ⚠️ | graceful-degradation stub; returns neutral; no gRPC dial — Phase E |
| OPA exception evaluator | ⚠️ | placeholder, always returns false |
| `scarletctl` control commands | ⚠️ | `start` runs the agent; `stop`/`status`/`rules`/`events`/mode-switch are stubs — Phase B |

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Foundation — rule engine, enrichment, pipeline | ✅ Complete |
| Phase 2 | Enforcement — safety protocol, audit, userspace blocklist | ✅ Complete |
| Phase 2b | TC kernel enforcement | ❌ Phase C |
| Phase 3 | Intelligence — correlation, anomaly, CRD policies | ✅ Complete |
| Phase 3b | AI triage (real gRPC) | ⚠️ Phase E |
| Phase 4 | Hardening & Scale — webhooks, DNS/TLS, LRU caches, benchmarks | ✅ Complete |
| Phase C | Real eBPF load/attach + TC | 🔲 Pending (Linux) |

## License

See [LICENSE](LICENSE) for details.