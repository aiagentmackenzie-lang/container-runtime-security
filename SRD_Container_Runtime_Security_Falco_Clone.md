# Software Requirements Document (SRD)
# 🐳 Container Runtime Security / Falco Clone
## eBPF-Based Runtime Monitoring for Containers

---

**Document Version:** 1.0  
**Date:** 2026-04-07  
**Author:** Lead Security Engineer  
**Project Codename:** **Container Runtime Security**  
**Classification:** Internal — Engineering Confidential  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Market Context](#2-problem-statement--market-context)
3. [Research Foundation & Prior Art Analysis](#3-research-foundation--prior-art-analysis)
4. [System Architecture](#4-system-architecture)
5. [Component Specifications](#5-component-specifications)
6. [eBPF Probe Layer Specification](#6-ebpf-probe-layer-specification)
7. [Event Processing Pipeline](#7-event-processing-pipeline)
8. [Rule Engine Specification](#8-rule-engine-specification)
9. [Detection Categories & Rule Catalog](#9-detection-categories--rule-catalog)
10. [Enforcement & Response Framework](#10-enforcement--response-framework)
11. [SecurityScarletAI Integration](#11-securityscarletai-integration)
12. [Container Runtime Integration](#12-container-runtime-integration)
13. [Kubernetes Deployment Architecture](#13-kubernetes-deployment-architecture)
14. [Performance & Resource Budgets](#14-performance--resource-budgets)
15. [Security & Hardening](#15-security--hardening)
16. [Testing & Validation Strategy](#16-testing--validation-strategy)
17. [API & Integration Interfaces](#17-api--integration-interfaces)
18. [Non-Functional Requirements](#18-non-functional-requirements)
19. [Risk Analysis & Mitigations](#19-risk-analysis--mitigations)
20. [Release Milestones & Phasing](#20-release-milestones--phasing)

---

## 1. Executive Summary

SecurityScarlet Runtime is an eBPF-based container runtime security system that provides real-time threat detection and enforcement for containerized and Kubernetes workloads. It monitors syscall activity, process lifecycle, network connections, and file access patterns at the kernel level — detecting container escapes, cryptojacking, reverse shells, sensitive file access, privilege escalation, and lateral movement as they happen.

This system is designed as a next-generation alternative to Falco (CNCF Graduated) and competitive with Tetragon (Cilium), Tracee (Aqua Security), and commercial offerings (Sysdig Secure, Aqua Runtime, Prisma Cloud). It differentiates through:

- **Modern eBPF architecture** built on libbpf with CO-RE (Compile Once, Run Everywhere) — no kernel modules, no legacy eBPF probes
- **Inline enforcement** via BPF LSM (not just alerting) — block syscalls before they execute
- **Argument-aware filtering** — inspect syscall arguments (e.g., which file was opened, which IP was connected to), not just syscall numbers
- **SecurityScarletAI integration** — AI-assisted anomaly detection, rule generation, and behavioral profiling
- **Multi-signal correlation engine** — combine process, network, file, and capability events to detect composite attack patterns

---

## 2. Problem Statement & Market Context

### 2.1 The Runtime Security Gap

Container security is layered but incomplete:

| Layer | What It Protects | What It Misses |
|-------|----------------|----------------|
| Image scanning (KuberNeet) | Known CVEs in images | Runtime exploitation of zero-days |
| Admission controllers | Pod spec misconfigurations | Post-deployment compromise |
| Network policies | East-west traffic control | Process-level malicious behavior |
| Seccomp | Syscall number filtering | Syscall argument abuse (no context awareness) |
| AppArmor/SELinux | File access MAC | Cannot inspect runtime behavior patterns |
| **Runtime security** | **Real-time behavior detection** | **This is the layer we build** |

**The critical insight:** Static defenses are necessary but insufficient. When an attacker achieves code execution inside a container — through a zero-day, a dependency compromise, or a misconfigured endpoint — only runtime monitoring can observe and respond to the malicious behavior that follows.

### 2.2 Real-World Incident Evidence

Research and industry data confirm the urgency:

- **46% of compromised containers** are used for cryptomining (Sysdig 2022 Cloud-Native Threat Report)
- **86% of cloud container attacks** stem from cryptojacking (Google Cloud research)
- **Tesla cryptojacking (2018):** Exposed Kubernetes dashboard → containers launched for Monero mining. Attackers used their own mining server behind Cloudflare, evading simple IP/domain blocklists
- **Capital One breach:** SSRF via container → AWS metadata service (169.254.169.254) → S3 bucket access → 100M+ records exfiltrated
- **CVE-2019-5736 (runc):** Container process could escape to host via /proc/self/exe overwrite
- **CVE-2024-21626 (Leaky Vessels):** WORKDIR /proc/self/fd traversal enabling container escape
- **CVE-2022-0847 (Dirty Pipe):** splice() allowed arbitrary file overwrite bypassing read-only protections
- **Cross-container eBPF attacks (USENIX Security 2023):** eBPF tracing features can break container isolation — 2.5% of Docker Hub containers have eBPF permissions exploitable for escape

### 2.3 Competitive Landscape Analysis

| Feature | Falco | Tetragon | Tracee | SecurityScarlet Runtime |
|---------|-------|----------|--------|------------------------|
| Detection engine | YAML rules | TracingPolicy CRDs | Signatures | YAML rules + AI |
| Inline enforcement | ❌ (alert-only) | ✅ (LSM + signals) | ❌ (alert-only) | ✅ (LSM + signals + SIGKILL) |
| Syscall arg inspection | ✅ | ✅ | ✅ | ✅ |
| BPF LSM support | ❌ | ✅ | ❌ | ✅ |
| CO-RE / modern eBPF | ✅ (since 0.36) | ✅ | ✅ | ✅ (native, from day 1) |
| Cryptojacking detection | ✅ (rule-based) | Manual rules | Limited | ✅ (rule + ML + flow) |
| AI/ML integration | Plugin ecosystem | ❌ | ❌ | ✅ (SecurityScarletAI native) |
| Behavioral correlation | Limited | Limited | Limited | ✅ (multi-signal correlator) |
| Network awareness | Limited | Good | Limited | ✅ (flow + SNI + DNS) |
| Container drift detection | ✅ | ✅ | ✅ | ✅ + enforcement |
| Overhead (CPU) | 1-3% | 1-2% | 1-3% | <2.5% target |

---

## 3. Research Foundation & Prior Art Analysis

### 3.1 Falco Architecture (CNCF Graduated) — Lessons Learned

**What Falco does right:**
- Rule engine with YAML rules, macros, lists, and exceptions — declarative, readable, well-understood by security teams
- DaemonSet deployment model — one sensor per node, monitoring all containers
- Container enrichment via CRI — associates kernel events with container ID, name, image, namespace
- falcoctl for rule lifecycle management
- 100M+ downloads, production-proven at scale

**What Falco gets wrong (our improvements):**
- Alert-only model — cannot block malicious activity, only report it
- Legacy eBPF probe still supported (deprecated but present) — we are modern-eBPF-only
- Rule language is coarse — cannot express multi-signal correlations (e.g., "shell spawned AND network connection within 5s")
- No ML/AI integration for detecting unknown threats
- Falcosidekick required for output routing — we integrate natively

### 3.2 eBPF Architecture — Technical Foundation

Key technologies from our research that inform the design:

**CO-RE (Compile Once, Run Everywhere):**
- Uses BTF (BPF Type Format) for kernel struct layout adaptation at load time
- Single compiled binary works across kernel versions (5.8+)
- Eliminates per-kernel build matrix — critical for heterogeneous clusters
- `bpf_core_read.h` provides `BPF_CORE_READ_INTO()` for portable struct field access

**BPF Ring Buffer (kernel 5.8+):**
- Replaces perf_event_array for kernel→userspace data streaming
- Lower overhead, supports backpressure (reservations fail when consumer can't keep up)
- Single buffer for all CPUs (no per-CPU allocation waste)
- Our design: 4MB ring buffer per node, configurable

**Modern eBPF Requirements (minimum kernel 5.8):**
- BTF available at `/sys/kernel/btf/vmlinux`
- BPF ring buffer support
- CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE (least-privilege model)

**Tracepoints vs Kprobes decision matrix:**

| Attribute | Tracepoints | Kprobes | LSM Hooks |
|-----------|------------|---------|-----------|
| Stability | Stable ABI, versioned | Unstable, may change | Stable LSM framework |
| Performance | Lower overhead | Slightly higher | Inline with kernel path |
| Coverage | Limited set | Any kernel function | Security-critical points only |
| TOCTOU risk | Present (syscall entry) | Present | **None** — sees actual kernel data |
| Enforcement | No (observe-only) | No (observe-only) | **Yes** — can deny operations |

**Our strategy:** Use tracepoints for observability, LSM hooks for enforcement, kprobes only when no tracepoint or LSM hook covers the needed event.

### 3.3 Container Escape Telemetry Research

The **container-escape-telemetry** research project (github.com/catscrdl/container-escape-telemetry) tested 15 escape scenarios against Tetragon, Falco, and Tracee. Key findings that drive our detection design:

| Scenario | Technique | Key Signals | Our Detection Approach |
|----------|-----------|-------------|----------------------|
| S01 | cgroup release_agent | mount(cgroup), cgroup_mkdir, release_agent write | Monitor mount() for cgroupfs + cgroup release_agent writes |
| S02 | CVE-2022-0492 | unshare → mount(cgroup) | Detect unshare with CLONE_NEWUSER + subsequent cgroup operations |
| S03 | nsenter host PID | nsenter, 4× setns | Alert on setns() calls from container processes |
| S04 | docker.sock abuse | docker exec, socket_connect | Detect /var/run/docker.sock access from containers |
| S05 | /proc/1/root access | security_file_open on /proc paths | Alert on /proc/1/ access from non-host namespaces |
| S07 | CVE-2024-21626 | WORKDIR /proc/self/fd traversal | Monitor openat() resolving to /proc/self/fd paths |
| S08 | CVE-2022-0847 Dirty Pipe | splice(), magic_write | Flag splice() with suspicious offset + fd combinations |
| S09 | CVE-2022-0185 | fsopen, fsconfig | Alert on fsconfig() with anomalous arguments from containers |
| S12 | CVE-2019-5736 | /proc/self/exe write | Detect write() targeting /proc/self/exe from container processes |
| S13 | Privileged container enum | mount block devices, /proc/kallsyms, keyctl | Monitor for privileged operations from containers |
| S14 | Excessive capabilities | /proc/1/environ, /proc/1/maps, raw sockets | Alert on host-level file access + raw socket creation |

### 3.4 eBPF Cross-Container Attack Research (USENIX Security 2023)

Critical finding: eBPF tracing features are NOT restricted by container namespaces. An attacker with CAP_SYS_ADMIN or CAP_BPF in a container can:
- Use `bpf_probe_write_user` to modify host process memory
- Use `bpf_override_return` to alter syscall return values of host processes
- Use `bpf_send_signal` to kill host processes
- Hijack cron/kubelet via eBPF to escape the container
- Blind security tools by intercepting their log collection channels

**Our mitigation:**
- Detect `bpf()` syscall from non-host namespaces (container processes loading eBPF programs)
- Monitor for `bpf_probe_write_user` and `bpf_override_return` helper usage
- Track eBPF program loads and attachments at the node level
- Alert on CAP_SYS_ADMIN/CAP_BPF usage from container workloads

### 3.5 Cryptojacking Detection Research

**Detection layers from research (Falco + academic papers):**

| Layer | Technique | Source | Effectiveness |
|-------|-----------|--------|--------------|
| Network IoC | Known mining pool domains/IPs/ports | Falco default rules | Detects lazy attackers |
| Process IoC | xmrig, ccminer, t-rex binary names | Falco malicious_binaries list | Evadable by renaming |
| Command IoC | stratum+tcp in cmdline | Falco Stratum rule | Detects unobfuscated miners |
| Behavioral | High CPU sustained + network to unknown | Prisma Cloud, Sysdig ML | Better but false positives on legit CPU workloads |
| Syscall n-gram | Sequential syscall patterns (RNN) | Kim et al. 2025 — 99.75% accuracy | Strong, moderate overhead |
| Flow analysis | Asymmetric in/out bytes ratio | Flow-level analysis | Complementary signal |
| SetUID/SetGID | chmod +S_ISUID before mining | Falco rules | Detects persistence setup |
| Container drift | New executable created at runtime | Falco drift detection | Detects miner installation |

**Our multi-layer cryptojacking detection strategy:**
1. Network IoC (known pools/ports/domains) — immediate, low false positive
2. Process name IoC — fast path, easily bypassed
3. Stratum protocol detection (command line + network) — medium effectiveness
4. Behavioral CPU/network correlation — detects throttled miners
5. Syscall sequence ML (n-gram analysis via SecurityScarletAI) — detects unknown miners
6. Container drift detection + enforcement — prevents miner installation

### 3.6 Reverse Shell Detection Research

**Classic reverse shell pattern (from eBPF detection research):**
```
1. socket(AF_INET, SOCK_STREAM, 0)     → Create TCP socket
2. connect(fd, sockaddr, ...)           → Connect to attacker
3. dup2(fd, 0) / dup2(fd, 1) / dup2(fd, 2)  → Redirect stdio to socket
4. execve("/bin/sh", ...)              → Spawn shell with socket as I/O
```

**Detection correlation (from Juliet, eBPF-PATROL, behavioral detector research):**

| Signal | Detection Logic |
|--------|----------------|
| dup2 from socket fd | dup2() called with source fd that is a socket |
| Shell + network connection | Shell process (bash/sh/zsh) opens outbound TCP within seconds of spawn |
| Process ancestry anomaly | Network connection from process descended from shell interpreter |
| Non-standard port | Outbound connection to known C2 ports (4444, 1337, 31337) |
| Pipe-based shell | `bash -i >& /dev/tcp/...` pattern in cmdline |

**Our approach:** Multi-signal correlation combining dup2 tracing, process ancestry tracking, and network connection analysis within a time window (configurable, default 5s).

### 3.7 Sensitive File Access Detection

**Critical sensitive paths to monitor (from Falco, Unit42, eBPF-Guard research):**

| Path | Risk | Attack Scenario |
|------|------|-----------------|
| `/etc/shadow` | Credential theft | Password hash extraction |
| `/etc/passwd` | User enumeration | Privilege escalation targeting |
| `/etc/sudoers` | Privilege persistence | Sudo rule modification |
| `/root/.ssh/` | SSH key theft | Lateral movement |
| `/var/run/docker.sock` | Container escape | Spawn privileged container |
| `/proc/1/ns/*` | Namespace escape | setns() to host namespace |
| `/proc/1/environ` | Environment variable leak | Secret/credential theft |
| `/proc/1/maps` | Memory layout disclosure | ASLR bypass |
| `/proc/kallsyms` | Kernel symbol disclosure | Rootkit/exploit targeting |
| `/proc/self/exe` | runc overwrite | CVE-2019-5736 |
| `169.254.169.254` (AWS metadata) | Cloud credential theft | Capital One-style SSRF |
| `/var/run/secrets/kubernetes.io/` | K8s SA token theft | Cluster compromise |

**Implementation challenge:** Container's `/etc/shadow` != host's `/etc/shadow`. Must resolve container paths to host paths for accurate detection (technique from Unit42 / eBPF-Guard: use mount namespace awareness to determine if accessed file is host-mounted).

### 3.8 Existing Open-Source Implementations — Architecture Patterns

**Juliet (juliet.sh):**
- Embedded Go agent using cilium/ebpf library (not Falco sidecar)
- 22 syscalls across 5 categories (process execution, file access, network, container escape, privilege escalation)
- Fixed 304-byte event struct via ring buffer
- Kernel-side filtering using `monitored_syscalls` hash map and `container_cgroups` map
- PID resolution via 3-tier cache (PID LRU + CRI cache + K8s cache)
- SIGKILL enforcement (not LSM) for portability — kills within 200ms
- 7-level safety before every kill (no container ID → no kill, simulate mode, protected namespaces, PID 0/1 untouchable, self-preservation, rate limit, namespace scope)

**eBPF-PATROL:**
- Probe Manager + Policy Engine + Event Analyzer + Enforcement Module
- YAML policy definitions with syscall-level argument filtering
- C (kernel) + Go (userspace) using libbpf and BCC
- Ring buffer communication, <2.5% overhead
- Policy: `syscall: execve, match: argv contains ["bash", "nc"], action: deny`

**kntrl:**
- eBPF + Go + OPA (Open Policy Agent) for policy decisions
- Network monitoring (TCP/UDP via kprobes) + DNS + TLS SNI + Process ancestry
- Per-process network profiles
- Process ancestry chain blocking (e.g., block curl if spawned by npm)
- LRU BPF maps for overflow prevention
- Two modes: monitor (log) and trace (enforce)

**Micromize:**
- BPF LSM for kernel-enforced boundaries (requires kernel 5.18+)
- Philosophy: enforce container boundaries, not inspect internals
- Blocks filesystem escapes, capability escalation, ptrace, enforces execution integrity
- Built on Inspektor Gadget

**Our architecture synthesis:** We adopt Juliet's Go+eBPF embedded approach and fixed-size event structs, eBPF-PATROL's YAML policy model, kntrl's OPA integration for policy decisions and process ancestry tracking, and Micromize's LSM enforcement philosophy. We add SecurityScarletAI for the AI layer that none of these tools have.

---

## 4. System Architecture

### 4.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                           │
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │    Worker Node 1  │  │    Worker Node 2  │  │    Worker Node N  │    │
│  │  ┌────────────┐  │  │  ┌────────────┐  │  │  ┌────────────┐  │    │
│  │  │ SecurityScarlet│  │  │ SecurityScarlet│  │  │ SecurityScarlet│  │    │
│  │  │  Runtime Agent │  │  │  Runtime Agent │  │  │  Runtime Agent │  │    │
│  │  │  (DaemonSet)   │  │  │  (DaemonSet)   │  │  │  (DaemonSet)   │  │    │
│  │  └───────┬────────┘  │  └───────┬────────┘  │  └───────┬────────┘  │    │
│  │          │            │          │            │          │            │
│  │    ┌─────▼─────┐      │    ┌─────▼─────┐      │    ┌─────▼─────┐      │    │
│  │    │ eBPF Probes│      │    │ eBPF Probes│      │    │ eBPF Probes│      │    │
│  │    │ (Kernel)  │      │    │ (Kernel)  │      │    │ (Kernel)  │      │    │
│  │    └───────────┘      │    └───────────┘      │    └───────────┘      │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                   Control Plane                               │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │  │
│  │  │ SecurityScarlet│  │    Rule       │  │  SecurityScarletAI  │ │  │
│  │  │  Controller    │  │   Manager    │  │  (ML/Anomaly Layer)  │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Agent Architecture (Per-Node)

```
┌──────────────────────────────────────────────────────────────┐
│                  SecurityScarlet Runtime Agent                 │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                   eBPF Probe Layer                      │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │Process   │ │Network   │ │File      │ │Namespace │   │  │
│  │  │Tracing   │ │Tracing   │ │Tracing   │ │& Cap     │   │  │
│  │  │Probes    │ │Probes    │ │Probes    │ │Probes    │   │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │  │
│  │       │            │            │            │          │  │
│  │  ┌────▼─────────────▼────────────▼────────────▼────┐    │  │
│  │  │          BPF Ring Buffer (4MB)                  │    │  │
│  │  └────────────────────┬──────────────────────────┘    │  │
│  └───────────────────────│────────────────────────────────┘  │
│                          │                                    │
│  ┌───────────────────────▼────────────────────────────────┐  │
│  │              Event Processing Pipeline                  │  │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────────┐   │  │
│  │  │ Ring Buf  │→ │ Event     │→ │ Container         │   │  │
│  │  │ Reader    │  │ Decoder   │  │ Enrichment (CRI)  │   │  │
│  │  └───────────┘  └───────────┘  └─────────┬─────────┘   │  │
│  │                                          │             │  │
│  │  ┌───────────────────────────────────────▼──────────┐  │  │
│  │  │          K8s Metadata Enrichment                  │  │  │
│  │  │   (Pod name, namespace, labels, SA, image)        │  │  │
│  │  └────────────────────┬──────────────────────────────┘  │  │
│  └───────────────────────│─────────────────────────────────┘  │
│                          │                                     │
│  ┌───────────────────────▼─────────────────────────────────┐ │
│  │                  Rule Engine                             │ │
│  │  ┌────────────────┐  ┌────────────────┐  ┌───────────┐ │ │
│  │  │ Compiled Rule  │  │  OPA Policy     │  │ AI Signal │ │ │
│  │  │ Matcher       │  │  Engine         │  │ Correlator│ │ │
│  │  │ (fast path)   │  │  (enforcement)  │  │           │ │ │
│  │  └────────┬───────┘  └────────┬───────┘  └─────┬─────┘ │ │
│  │           │                    │                 │       │ │
│  │  ┌────────▼────────────────────▼─────────────────▼────┐ │ │
│  │  │              Decision Router                        │ │ │
│  │  │  alert / enforce / suppress / enrich                │ │ │
│  │  └─────────────┬──────────────────────────────────────┘ │ │
│  └────────────────│─────────────────────────────────────────┘ │
│                   │                                            │
│  ┌────────────────▼────────────────────────────────────────┐ │
│  │              Response Actor                               │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │ │
│  │  │ Alert    │  │ SIGKILL  │  │ LSM Deny │  │ Webhook  │ │ │
│  │  │ Emitter │  │ Process  │  │ Override │  │ Forward  │ │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### 4.3 Data Flow

```
1. Container process invokes syscall (e.g., execve("/usr/bin/xmrig"))
2. eBPF probe fires on tracepoint/kprobe/LSM hook
3. Probe collects: timestamp, PID, TGID, UID, GID, cgroup_id, syscall_nr, args
4. Probe writes fixed-size struct to BPF ring buffer
5. Agent ring buffer reader polls (100ms interval)
6. Event decoder parses struct into typed event
7. Container enrichment resolves cgroup_id → container_id via /proc/{pid}/cgroup
8. CRI enrichment gets container metadata from containerd/CRI
9. K8s enrichment maps container → pod/namespace/SA/labels
10. Rule engine evaluates event against compiled rules
11. OPA engine evaluates policy (if enforcement rules match)
12. AI correlator checks multi-signal patterns (if enabled)
13. Decision router determines action: alert / enforce / suppress
14. Response actor executes: emit alert, SIGKILL process, LSM deny, webhook
15. Event logged to audit trail + forwarded to SecurityScarletAI
```

---

## 5. Component Specifications

### 5.1 Component Inventory

| Component | Language | Responsibility | Priority |
|-----------|----------|---------------|----------|
| eBPF Probe Programs | C (libbpf CO-RE) | Kernel-level event capture | P0 |
| Agent Core | Go | Userspace event loop, enrichment | P0 |
| Rule Engine | Go | Fast-path rule matching | P0 |
| OPA Integration | Go + Rego | Policy evaluation for enforcement | P0 |
| Container Enrichment | Go | CRI/containerd integration | P0 |
| K8s Enrichment | Go | API server watch for pod metadata | P0 |
| Response Actor | Go | SIGKILL, alert emission, webhook | P0 |
| SecurityScarletAI Connector | Go | gRPC to AI inference service | P1 |
| ML Feature Extractor | Go | n-gram / behavioral feature extraction | P1 |
| Controller (Cluster-Level) | Go | Rule distribution, config sync | P1 |
| CLI | Go | `scarletctl` management CLI | P2 |
| Helm Chart | YAML | Kubernetes deployment | P0 |

### 5.2 Dependency Matrix

| Dependency | Version | Purpose | License |
|-----------|---------|---------|---------|
| libbpf | 1.x+ | eBPF program loading, CO-RE | LGPL-2.1 OR BSD-2-Clause |
| cilium/ebpf | 0.14+ | Go eBPF library (program loading, map access) | MIT |
| containerd | 1.7+ | CRI integration for container metadata | Apache-2.0 |
| OPA | 0.60+ | Embedded policy engine | Apache-2.0 |
| Prometheus client | 1.x+ | Metrics export | Apache-2.0 |
| protobuf | 1.x+ | Event serialization | BSD |
| gRPC | 1.x+ | SecurityScarletAI communication | Apache-2.0 |
| BTFHub | latest | Fallback BTF for older kernels | MIT |

---

## 6. eBPF Probe Layer Specification

### 6.1 Probe Categories & Syscall Coverage

#### 6.1.1 Process Execution Probes (Category: PROCESS)

| Probe Target | Type | Syscalls | What It Detects |
|-------------|------|----------|---------------|
| `sched_process_exec` | tracepoint | execve, execveat | Shell spawning, miner execution, tool invocation |
| `sched_process_fork` | tracepoint | clone, clone3, fork | Process creation, ancestry tracking |
| `sched_process_exit` | tracepoint | exit, exit_group | Process termination, lifecycle tracking |

#### 6.1.2 File Access Probes (Category: FILE)

| Probe Target | Type | Syscalls | What It Detects |
|-------------|------|----------|---------------|
| `syscalls/sys_enter_openat` | tracepoint | openat | Sensitive file access (/etc/shadow, docker.sock) |
| `syscalls/sys_enter_unlinkat` | tracepoint | unlinkat | Log deletion, evidence destruction |
| `syscalls/sys_enter_memfd_create` | tracepoint | memfd_create | Fileless malware payloads |
| `security_file_permission` | LSM hook | (all file ops) | File access enforcement (read/write deny) |
| `security_inode_rename` | LSM hook | rename, renameat2 | File renaming (persistence hiding) |

#### 6.1.3 Network Probes (Category: NETWORK)

| Probe Target | Type | Syscalls/Events | What It Detects |
|-------------|------|----------------|---------------|
| `tcp_v4_connect` | kprobe | connect (IPv4 TCP) | Outbound connections, C2 callbacks, mining pools |
| `tcp_v6_connect` | kprobe | connect (IPv6 TCP) | IPv6 outbound connections |
| `ip4_datagram_connect` | kprobe | connect (IPv4 UDP) | UDP connections (DNS, some miners) |
| `inet_sock_set_state` | tracepoint | TCP state changes | Connection lifecycle tracking |
| `security_socket_connect` | LSM hook | connect (enforcement) | Block outbound connections |
| `security_socket_listen` | LSM hook | listen | Detect rogue listeners in containers |
| TC classifier | tc | TLS ClientHello | SNI extraction for encrypted traffic |

#### 6.1.4 Container Escape & Namespace Probes (Category: ESCAPE)

| Probe Target | Type | Syscalls | What It Detects |
|-------------|------|----------|---------------|
| `syscalls/sys_enter_setns` | tracepoint | setns | Namespace join attempts (container escape) |
| `syscalls/sys_enter_unshare` | tracepoint | unshare | Namespace creation (new user ns for escape) |
| `syscalls/sys_enter_mount` | tracepoint | mount | Filesystem mount (cgroup escape, host mount) |
| `syscalls/sys_enter_ptrace` | tracepoint | ptrace | Process injection, debugging from container |
| `syscalls/sys_enter_init_module` | tracepoint | init_module | Kernel module loading from container |
| `security_sb_mount` | LSM hook | mount (enforcement) | Block unauthorized mounts |
| `security_bpf` | LSM hook | bpf() | Detect/block eBPF program loading from containers |

#### 6.1.5 Privilege Escalation Probes (Category: PRIVILEGE)

| Probe Target | Type | Syscalls | What It Detects |
|-------------|------|----------|---------------|
| `syscalls/sys_enter_setuid` | tracepoint | setuid | UID transitions (non-root → root) |
| `syscalls/sys_enter_setresuid` | tracepoint | setresuid | UID changes (privilege escalation) |
| `syscalls/sys_enter_capset` | tracepoint | capset | Capability set changes |
| `syscalls/sys_enter_chmod` | tracepoint | chmod, fchmodat | SUID/SGID bit setting |
| `security_capable` | LSM hook | capability checks | Block unauthorized capability use |

#### 6.1.6 Credential & Secret Access Probes (Category: CREDENTIAL)

| Probe Target | Type | Syscalls | What It Detects |
|-------------|------|----------|---------------|
| Combined with FILE probes | — | openat to sensitive paths | Credential file reads |
| Combined with NETWORK probes | — | connect to 169.254.169.254 | Cloud metadata service access (SSRF) |
| `security_file_open` | LSM hook | open (enforcement) | Block sensitive file access |

### 6.2 Event Structure

Fixed-size event struct (inspired by Juliet's 304-byte approach for ring buffer efficiency):

```c
// security_scarlet_event.h
#define SCARLET_MAX_COMM_LEN    16
#define SCARLET_MAX_PATH_LEN    256
#define SCARLET_MAX_ARGS_LEN    128
#define SCARLET_MAX_IPv4_ADDR   4
#define SCARLET_NS_COUNT        8

// Event categories — determines which union member is active
enum scarlet_event_category : __u8 {
    SCARLET_CAT_PROCESS    = 1,
    SCARLET_CAT_FILE       = 2,
    SCARLET_CAT_NETWORK    = 3,
    SCARLET_CAT_ESCAPE     = 4,
    SCARLET_CAT_PRIVILEGE  = 5,
    SCARLET_CAT_CREDENTIAL = 6,
};

// Event types within categories
enum scarlet_event_type : __u8 {
    // Process
    SCARLET_EVT_EXEC        = 1,
    SCARLET_EVT_FORK        = 2,
    SCARLET_EVT_EXIT        = 3,
    // File
    SCARLET_EVT_FILE_OPEN   = 10,
    SCARLET_EVT_FILE_UNLINK  = 11,
    SCARLET_EVT_FILE_MEMFD  = 12,
    // Network
    SCARLET_EVT_NET_CONNECT = 20,
    SCARLET_EVT_NET_LISTEN  = 21,
    SCARLET_EVT_NET_STATE   = 22,
    // Escape
    SCARLET_EVT_SETNS       = 30,
    SCARLET_EVT_UNSHARE     = 31,
    SCARLET_EVT_MOUNT       = 32,
    SCARLET_EVT_PTRACE      = 33,
    SCARLET_EVT_MODULE_LOAD = 34,
    SCARLET_EVT_BPF_LOAD   = 35,
    // Privilege
    SCARLET_EVT_SETUID      = 40,
    SCARLET_EVT_CAPSET      = 41,
    SCARLET_EVT_CHMOD       = 42,
};

struct scarlet_event {
    __u64 timestamp_ns;           // bpf_ktime_get_ns()
    __u32 pid;                    // process ID
    __u32 tgid;                   // thread group ID (main PID)
    __u32 ppid;                   // parent PID
    __u32 uid;                    // user ID
    __u32 gid;                    // group ID
    __u64 cgroup_id;              // cgroup inode number (container ID)
    __u32 pid_ns_level;           // PID namespace depth (0=host, >0=container)
    __u8  category;               // scarlet_event_category
    __u8  event_type;             // scarlet_event_type
    __u8  syscall_nr;             // syscall number
    __u8  _pad;
    char  comm[SCARLET_MAX_COMM_LEN];     // process command name
    
    // Union for category-specific payload — fixed total size
    union {
        // PROCESS events
        struct {
            char filename[SCARLET_MAX_PATH_LEN];    // executed binary path
            char args[SCARLET_MAX_ARGS_LEN];        // first 128 bytes of args
        } process;
        
        // FILE events
        struct {
            char path[SCARLET_MAX_PATH_LEN];        // file path
            __u32 flags;                             // open flags (O_RDONLY, O_WRONLY, etc.)
            __u32 mode;                               // file mode (for chmod)
        } file;
        
        // NETWORK events
        struct {
            __u8  local_addr[SCARLET_MAX_IPv4_ADDR]; // source IP
            __u8  remote_addr[SCARLET_MAX_IPv4_ADDR];// dest IP
            __u16 local_port;                         // source port
            __u16 remote_port;                        // dest port
            __u8  protocol;                           // IPPROTO_TCP/UDP
            __u8  family;                             // AF_INET/AF_INET6
            __u16 _net_pad;
        } network;
        
        // ESCAPE events
        struct {
            __u32 ns_type;                            // namespace type (CLONE_NEW*)
            __u32 target_ns[SCARLET_NS_COUNT];        // namespace inode numbers
            __u8  ns_count;                           // number of namespaces
        } escape;
        
        // PRIVILEGE events
        struct {
            __u32 old_uid;
            __u32 new_uid;
            __u32 capability;                         // capability number
            __u32 mode_flags;                          // chmod mode flags
        } privilege;
    } payload;
};
// Total: ~432 bytes (fixed, union-based)
```

### 6.3 Kernel-Side Filtering

To minimize userspace overhead, implement early filtering in the BPF program:

```c
// BPF map: set of syscall numbers active policies care about
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);      // syscall_nr
    __type(value, __u8);     // 1 = monitored
} monitored_syscalls SEC(".maps");

// BPF map: cgroup IDs of containers on this node
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);      // cgroup_id
    __type(value, __u32);     // container sequence number
} container_cgroups SEC(".maps");

// In probe handler:
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_syscalls *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Skip events not from monitored containers
    if (!bpf_map_lookup_elem(&container_cgroups, &cgroup_id))
        return 0;
    
    // Only emit if execve is in our monitored set
    __u32 syscall_nr = 59; // execve
    if (!bpf_map_lookup_elem(&monitored_syscalls, &syscall_nr))
        return 0;
    
    // ... collect and submit event
}
```

### 6.4 LSM Enforcement Programs

```c
// LSM hook: block unauthorized mount from containers
SEC("lsm/sb_mount")
int BPF_PROG(block_container_mount, struct super_block *sb,
             struct dentry *dentry, char *dev_name, char *type,
             unsigned long flags, void *data)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Only enforce for containers (not host processes)
    if (!bpf_map_lookup_elem(&container_cgroups, &cgroup_id))
        return 0; // allow host mounts
    
    // Check if mount policy allows this mount type
    __u32 decision = check_mount_policy(dev_name, type, flags);
    if (decision == SCARLET_DENY)
        return -EPERM; // block the mount
    
    return 0; // allow
}

// LSM hook: block eBPF program loading from containers
SEC("lsm/bpf")
int BPF_PROG(block_container_bpf, int cmd, union bpf_attr *attr,
             unsigned int size)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    if (!bpf_map_lookup_elem(&container_cgroups, &cgroup_id))
        return 0; // allow host eBPF usage
    
    // Deny BPF program loading from containers unless explicitly allowed
    if (cmd == BPF_PROG_LOAD) {
        // Alert and deny
        emit_enforcement_event(SCARLET_EVT_BPF_LOAD, cgroup_id);
        return -EPERM;
    }
    
    return 0;
}
```

---

## 7. Event Processing Pipeline

### 7.1 Pipeline Stages

```
[Ring Buffer Reader (100ms poll)]
    → [Event Decoder (zero-alloc struct parsing)]
    → [Container Enrichment (cgroup_id → container_id)]
    → [CRI Enrichment (container_id → image, name, labels)]
    → [K8s Enrichment (pod → namespace, SA, node)]
    → [Rule Matcher (fast path, compiled rules)]
    → [OPA Evaluation (if enforcement match)]
    → [AI Correlator (if behavioral analysis enabled)]
    → [Decision Router (alert / enforce / suppress)]
    → [Response Actor (<200ms enforcement target)]
    → [Output Pipeline (coalesce → batch → forward)]
```

### 7.2 Container Enrichment Strategy

Three-tier cache system (inspired by Juliet):

| Cache | Source | TTL | Fallback |
|-------|--------|-----|----------|
| PID LRU | `/proc/{pid}/cgroup` → container_id | 5 min / 10K entries | Skip enrichment |
| CRI Cache | containerd gRPC events (container start/stop) | Event-driven | PID LRU fallback |
| K8s Cache | K8s API watch on local node's pods | Continuous | Partial enrichment |

**Enrichment priority:** If all three fail, the event still carries PID, cgroup_id, and comm from the kernel. The rule engine treats unenriched events conservatively: **no enforcement on events that cannot be fully attributed to a container** (audit mode only).

### 7.3 Event Coalescing

Events are coalesced by (rule_id + container_id + process_name) within a 5-second window:

```
Same bash process in same container hitting same rule:
  100 events → 1 record with event_count: 100
```

Reduces output volume by 10-100x on noisy workloads. **Enforcement happens before coalescing** — if a process needs to die, it dies within 200ms, not after a batch window.

---

## 8. Rule Engine Specification

### 8.1 Rule Language Design

Based on Falco's proven YAML rule model, extended with multi-signal correlation and enforcement actions:

```yaml
# === Lists ===
- list: shell_binaries
  items: [bash, sh, zsh, dash, ksh, tcsh, fish]

- list: miner_binaries
  items: [xmrig, ccminer, t-rex, nanominer, pwnrig, minerd, xmr-stak]

- list: miner_pool_ports
  items: [25, 3333, 3334, 3335, 3336, 3357, 4444, 5555, 5556,
          5588, 5730, 6099, 6666, 7777, 7778, 8333, 8888,
          8899, 9332, 9999, 14433, 14444, 45560, 45700]

- list: miner_domains
  items: [asia1.ethpool.org, ca.minexmr.com, cn.stratum.slushpool.com,
          de.minexmr.com, eth-ar.dwarfpool.com, fr.minexmr.com,
          mine.moneropool.com, pool.minexmr.com, xmr.crypto-pool.fr]

- list: sensitive_paths
  items: [/etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh,
          /var/run/docker.sock, /proc/1/ns, /proc/1/environ,
          /proc/1/maps, /proc/kallsyms, /proc/self/exe]

- list: c2_ports
  items: [4444, 1337, 31337, 6666, 8080, 9001, 1234, 4443]

- list: cloud_metadata_ips
  items: [169.254.169.254, 168.63.129.16, fd00:ec2::254]

# === Macros ===
- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type in (execve, execveat)

- macro: shell_procs
  condition: proc.name in (shell_binaries)

- macro: miner_procs
  condition: proc.name in (miner_binaries)

- macro: open_write
  condition: evt.type in (open, openat, openat2, creat) and evt.arg.flags contains O_WRONLY or O_RDWR

- macro: net_outbound
  condition: evt.type in (connect, sendto, sendmsg) and evt.dir = <

- macro: minerpool_connection
  condition: >
    (evt.type = connect and 
     ((fd.rport in (miner_pool_ports)) or 
      (fd.rip.name in (miner_domains))))

- macro: setns_call
  condition: evt.type = setns

- macro: sensitive_file_read
  condition: >
    evt.type in (open, openat, openat2) and
    fd.name pmatch (/etc/shadow, /etc/passwd, /etc/sudoers,
                    /root/.ssh, /var/run/docker.sock, /proc/1)

- macro: cloud_metadata_access
  condition: >
    evt.type = connect and
    fd.rip in (cloud_metadata_ips)

# === Rules ===
- rule: Container Escape via Namespace Join
  desc: >
    Detect container process attempting to enter host namespace
    via setns() — common in nsenter-based escape attacks.
  condition: >
    setns_call and container
  output: >
    Container escape attempt via setns
    (user=%user.name process=%proc.name pid=%proc.pid
     ns_type=%evt.arg.nstype container=%container.name
     image=%container.image.repository)
  priority: CRITICAL
  tags: [escape, mitre_privilege_escalation]
  action: enforce

- rule: Cryptojacking — Known Miner Binary
  desc: >
    Detect execution of known cryptominer binaries inside containers.
  condition: >
    spawned_process and container and miner_procs
  output: >
    Known cryptominer binary executed in container
    (process=%proc.name cmdline=%proc.cmdline pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [cryptojacking, mitre_execution]
  action: enforce

- rule: Cryptojacking — Mining Pool Connection
  desc: >
    Detect outbound connections to known cryptocurrency mining pools
    from containers.
  condition: >
    net_outbound and container and minerpool_connection
  output: >
    Outbound connection to known mining pool
    (dest=%fd.rip port=%fd.rport process=%proc.name
     cmdline=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [cryptojacking, mitre_execution]
  action: alert

- rule: Cryptojacking — Stratum Protocol in Command Line
  desc: >
    Detect Stratum mining protocol specification in process command line.
  condition: >
    spawned_process and container and
    (proc.cmdline contains "stratum+tcp" or
     proc.cmdline contains "stratum2+tcp" or
     proc.cmdline contains "stratum+ssl" or
     proc.cmdline contains "stratum2+ssl")
  output: >
    Possible miner using Stratum protocol
    (process=%proc.name cmdline=%proc.cmdline pid=%proc.pid
     container=%container.name)
  priority: CRITICAL
  tags: [cryptojacking, mitre_execution]
  action: enforce

- rule: Reverse Shell — Shell with Outbound Network
  desc: >
    Detect shell process making outbound network connection,
    a classic reverse shell indicator. Correlates shell spawn
    with network connect within 5-second window.
  condition: >
    net_outbound and container and shell_procs and
    fd.rport not in (80, 443)
  output: >
    Potential reverse shell — shell process with outbound network
    (shell=%proc.name dest=%fd.rip:%fd.rport pid=%proc.pid
     container=%container.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [reverse_shell, mitre_execution]
  action: enforce
  correlate:
    window: 5s
    signals: [shell_procs, net_outbound]

- rule: Reverse Shell — dup2 Socket Redirect
  desc: >
    Detect dup2/dup3 redirecting stdin/stdout/stderr to a socket,
    the classic reverse shell syscall pattern.
  condition: >
    evt.type in (dup2, dup3) and container and
    fd.type = socket and (fd.fd in (0, 1, 2))
  output: >
    dup2 redirecting stdio to socket (reverse shell pattern)
    (process=%proc.name fd=%evt.arg.fd newfd=%evt.arg.newfd
     pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [reverse_shell, mitre_execution]
  action: enforce

- rule: Sensitive File Access from Container
  desc: >
    Detect container process accessing sensitive host files
    such as /etc/shadow, SSH keys, or Docker socket.
  condition: >
    sensitive_file_read and container
  output: >
    Container accessing sensitive file
    (file=%fd.name process=%proc.name pid=%proc.pid
     user=%user.name container=%container.name)
  priority: CRITICAL
  tags: [credential_access, mitre_credential_access]
  action: alert

- rule: Cloud Metadata Service Access from Container
  desc: >
    Detect container process connecting to cloud metadata service
    (AWS/GCP/Azure), potential credential theft via SSRF.
    Based on Capital One breach pattern.
  condition: >
    cloud_metadata_access and container
  output: >
    Container accessing cloud metadata service
    (dest=%fd.rip process=%proc.name pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [ssrf, credential_access, mitre_discovery]
  action: enforce

- rule: Container Drift — New Executable Created
  desc: >
    Detect new executable written to container filesystem at runtime,
    indicating potential miner/malware installation.
  condition: >
    evt.type in (open, openat, creat) and
    evt.is_open_exec=true and container and
    evt.rawres >= 0
  output: >
    Container drift — new executable created
    (file=%evt.arg.filename process=%proc.name pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: ERROR
  tags: [drift, persistence, mitre_persistence]
  action: alert

- rule: Privilege Escalation — SUID/SGID Bit Set
  desc: >
    Detect chmod setting SUID or SGID bit from within a container,
    a persistence and privilege escalation technique.
  condition: >
    evt.type in (chmod, fchmodat) and container and
    (evt.arg.mode contains S_ISUID or evt.arg.mode contains S_ISGID)
  output: >
    SUID/SGID bit set in container
    (file=%evt.arg.filename mode=%evt.arg.mode process=%proc.name
     pid=%proc.pid container=%container.name)
  priority: NOTICE
  tags: [privilege_escalation, mitre_privilege_escalation]

- rule: eBPF Program Loaded from Container
  desc: >
    Detect container process attempting to load eBPF programs,
    which can be used for cross-container attacks (USENIX 2023).
  condition: >
    evt.type = bpf and container
  output: >
    eBPF program loaded from container
    (cmd=%evt.arg.cmd process=%proc.name pid=%proc.pid
     container=%container.name uid=%user.name
     capabilities=%proc.caps)
  priority: CRITICAL
  tags: [escape, mitre_privilege_escalation]
  action: enforce

- rule: Execution from /tmp in Container
  desc: >
    Detect process execution from /tmp directory inside container,
    common post-exploitation tactic.
  condition: >
    spawned_process and container and
    (proc.exe startswith "/tmp/" or
     (proc.cwd startswith "/tmp/" and proc.exe startswith "./"))
  output: >
    Process executed from /tmp in container
    (process=%proc.name exe=%proc.exe pid=%proc.pid
     container=%container.name)
  priority: WARNING
  tags: [execution, mitre_execution]
```

### 8.2 Correlation Engine

Rules can specify a `correlate` section that defines multi-signal patterns:

```yaml
correlate:
  window: 5s                # time window for correlation
  signals:                   # signals that must all appear
    - shell_procs            # shell process spawned
    - net_outbound           # outbound network connection
  logic: all                 # all signals must match (or: any)
  group_by: [proc.pid]       # group events by PID for correlation
```

The correlator maintains a time-windowed state per (group_by key) and fires the rule when all specified signals appear within the window.

### 8.3 Exception Model

Exceptions follow Falco's proven model with structured fields:

```yaml
- rule: Shell in Container
  condition: spawned_process and container and shell_procs
  output: Shell spawned in container (...)
  priority: WARNING
  exceptions:
    - name: trusted_debug_images
      fields: [container.image.repository]
      comps: [in]
      values:
        - [(trusted_images_list)]
    - name: admin_shells
      fields: [container.image.repository, proc.name]
      comps: [=, =]
      values:
        - [admin-toolkit/admin-cli, /usr/bin/bash]
        - [debug-pod/tools, /bin/sh]
```

### 8.4 Rule Compilation & Fast Path

1. Rules are parsed from YAML at load time
2. Rules are compiled into a lookup structure bucketed by `evt.type`
3. When an event arrives, the engine looks up its `evt.type` and evaluates only the 3-8 candidate rules for that type
4. The fast path uses pre-allocated maps with zero heap allocation
5. If two rules match and one says `alert` while another says `enforce`, `enforce` wins (highest-severity action takes precedence)

---

## 9. Detection Categories & Rule Catalog

### 9.1 Complete Rule Catalog

| ID | Category | Rule Name | Priority | Action | MITRE ATT&CK |
|----|----------|-----------|----------|--------|---------------|
| R001 | ESCAPE | Namespace Join (setns) | CRITICAL | enforce | T1548 |
| R002 | ESCAPE | Namespace Create (unshare) | CRITICAL | alert | T1548 |
| R003 | ESCAPE | Cgroup Mount | CRITICAL | enforce | T1548 |
| R004 | ESCAPE | Docker Socket Access | CRITICAL | enforce | T1611 |
| R005 | ESCAPE | /proc/1 Access | CRITICAL | alert | T1611 |
| R006 | ESCAPE | Kernel Module Load | CRITICAL | enforce | T1547 |
| R007 | ESCAPE | eBPF Program Load | CRITICAL | enforce | T1547 |
| R008 | CRYPTO | Known Miner Binary | CRITICAL | enforce | T1059 |
| R009 | CRYPTO | Mining Pool Connection | CRITICAL | alert | T1071 |
| R010 | CRYPTO | Stratum Protocol | CRITICAL | enforce | T1059 |
| R011 | CRYPTO | Behavioral CPU+Net | WARNING | alert | T1059 |
| R012 | CRYPTO | SUID Before Mining | NOTICE | alert | T1548 |
| R013 | CRYPTO | Container Drift Mining | ERROR | alert | T1548 |
| R014 | SHELL | Shell+Network (5s) | CRITICAL | enforce | T1059 |
| R015 | SHELL | dup2 Socket Redirect | CRITICAL | enforce | T1059 |
| R016 | SHELL | Shell on Non-Std Port | CRITICAL | enforce | T1059 |
| R017 | SHELL | Pipe-based Shell | WARNING | alert | T1059 |
| R018 | CRED | Sensitive File Access | CRITICAL | alert | T1552 |
| R019 | CRED | Cloud Metadata SSRF | CRITICAL | enforce | T1552 |
| R020 | CRED | K8s SA Token Access | CRITICAL | alert | T1552 |
| R021 | PRIV | SetUID Transition | NOTICE | alert | T1548 |
| R022 | PRIV | SUID/SGID Bit Set | NOTICE | alert | T1548 |
| R023 | PRIV | Capability Change | WARNING | alert | T1548 |
| R024 | DRIFT | New Executable Created | ERROR | alert | T1548 |
| R025 | DRIFT | Execution from /tmp | WARNING | alert | T1059 |
| R026 | NET | Rogue Listener in Container | WARNING | alert | T1571 |
| R027 | NET | C2 Port Connection | CRITICAL | alert | T1071 |
| R028 | NET | Raw Socket Creation | WARNING | alert | T1571 |
| R029 | PTRACE | Process Ptrace from Container | CRITICAL | enforce | T1055 |
| R030 | CVE | Dirty Pipe Pattern (splice) | CRITICAL | alert | T1068 |

### 9.2 MITRE ATT&CK Mapping

```
Initial Access:  —
Execution:       R008, R010, R014, R015, R016, R017, R025 (T1059)
Persistence:     R024, R012 (T1548)
Privilege Esc:   R001, R002, R003, R007, R021, R022, R023, R029 (T1548, T1547)
Defense Evasion: R017, R025 (T1059)
Credential Access: R018, R019, R020 (T1552)
Discovery:       R019 (cloud metadata) (T1552)
Lateral Movement: R014, R015, R016 (T1059)
Collection:      R018 (T1552)
Command & Control: R009, R027 (T1071, T1571)
Exfiltration:    (detected via network volume anomalies via AI layer)
Impact:          R008-R013 (resource hijacking via cryptojacking)
```

---

## 10. Enforcement & Response Framework

### 10.1 Action Model

| Action | Mechanism | Latency | Portability | Risk |
|--------|-----------|---------|-------------|------|
| `alert` | Log + webhook + metrics | <1ms | ✅ All kernels | None |
| `enforce` (SIGKILL) | Kill process from userspace | <200ms | ✅ All kernels 5.8+ | Low (process restarts) |
| `enforce` (LSM deny) | BPF LSM returns -EPERM | <10µs | Kernel 5.7+ with BPF_LSM | Medium (blocks syscall before execution) |
| `alert+dns` | Alert + DNS sinkhole | <100ms | Requires DNS integration | Low |

### 10.2 Enforcement Safety Protocol (7 Rules)

Adopted from Juliet's production-tested enforcement safety:

1. **No container ID, no enforce** — If enrichment failed, only audit
2. **Simulate mode** — New policies must run in simulate for 48h minimum before enforce
3. **Protected namespaces** — `kube-system` and `kube-public` are off-limits by default
4. **PID 0 and PID 1 are untouchable** — Never kill init
5. **Self-preservation** — Agent will not kill its own process tree
6. **Rate limiting** — 10 kills per pod per 60-second window; after that, stop and flag
7. **Namespace scope required** — Enforcement policies must specify at least one target namespace

### 10.3 Enforcement Decision Flow

```
Event arrives
  → Rule matches with action=enforce
  → Is container_id resolved?     NO → audit_only
  → Is simulate mode on?          YES → log_simulated
  → Is namespace protected?       YES → audit_only  
  → Is target PID 0 or 1?         YES → skip
  → Is target self?               YES → skip
  → Rate limit exceeded?           YES → log_suppressed
  → Is namespace in policy scope? NO  → audit_only
  → [ENFORCE] SIGKILL or LSM deny
```

---

## 11. SecurityScarletAI Integration

### 11.1 Architecture

```
┌──────────────────────────────────────┐
│     SecurityScarlet Runtime Agent     │
│                                      │
│  Event Stream ──→ Feature Extractor  │
│                       │              │
│                       ▼              │
│              ┌──────────────────┐    │
│              │  gRPC Client     │    │
│              └────────┬─────────┘    │
└───────────────────────│──────────────┘
                        │
            ┌───────────▼──────────────┐
            │   SecurityScarletAI     │
            │   Inference Service     │
            │                         │
            │  ┌─────────────────┐   │
            │  │ Anomaly Detector │   │
            │  │ (Syscall n-gram) │   │
            │  └─────────────────┘   │
            │  ┌─────────────────┐   │
            │  │ Behavioral Prof. │   │
            │  │ (Auto-baseline)  │   │
            │  └─────────────────┘   │
            │  ┌─────────────────┐   │
            │  │ Rule Generator   │   │
            │  │ (AI-suggested)   │   │
            │  └─────────────────┘   │
            │  ┌─────────────────┐   │
            │  │ Threat Intel     │   │
            │  │ Correlation      │   │
            │  └─────────────────┘   │
            └─────────────────────────┘
```

### 11.2 Integration Capabilities

| Capability | Input | Output | Latency Budget |
|-----------|-------|--------|---------------|
| **Anomaly Detection** | Syscall n-gram sequences | Anomaly score (0-1) + label | <50ms |
| **Behavioral Profiling** | Baseline event stream | Per-image behavioral profile | Async (learning) |
| **Rule Generation** | Security incident + context | Suggested YAML rule | Async (human approval) |
| **Threat Intel Correlation** | Network IoCs + process context | Enriched threat classification | <100ms |
| **Alert Triage** | Alert + context | Priority + false-positive score | <200ms |

### 11.3 Feature Extraction for AI

The feature extractor prepares data for SecurityScarletAI:

**Syscall n-gram features (for cryptojacking/ML detection):**
```
Raw syscall trace:  [186, 14, 14, 3, 13, 59, 158, 218, 12, 12]
5-gram frames:     [186,14,14,3,13], [14,14,3,13,59], [14,3,13,59,158], ...
Feature vector:     n-gram frequency histogram
```

**Behavioral features (for anomaly detection):**
- Process execution rate per container
- Unique syscall set per process
- Network connection rate per process
- File access pattern distribution
- Process ancestry depth and branching factor

**Flow-level features (for cryptojacking):**
- in_bytes / out_bytes ratio
- in_packets / out_packets ratio
- Connection duration distribution
- DNS query patterns

### 11.4 AI-Assisted Rule Generation

When SecurityScarletAI detects a novel threat pattern:

1. AI generates a draft YAML rule
2. Rule is submitted to the Controller for human review
3. After approval, rule is distributed to agents
4. Agent loads rule into fast-path engine
5. Rule enters simulate mode for 48h before eligible for enforce

### 11.5 gRPC Protocol

```protobuf
service SecurityScarletAI {
  // Submit event stream for real-time analysis
  rpc AnalyzeEvents(stream SecurityEvent) returns (stream AnalysisResult);
  
  // Request behavioral profile for a container image
  rpc GetProfile(ProfileRequest) returns (BehavioralProfile);
  
  // Submit alert for triage
  rpc TriageAlert(Alert) returns (TriageResult);
  
  // Request rule suggestion
  rpc SuggestRule(IncidentContext) returns (RuleSuggestion);
}

message AnalysisResult {
  float anomaly_score = 1;        // 0.0 = normal, 1.0 = confirmed malicious
  string classification = 2;       // e.g., "cryptojacking", "reverse_shell", "unknown"
  string description = 3;          // Human-readable explanation
  bool enforce_recommended = 4;    // AI recommends enforcement
}

message BehavioralProfile {
  string image = 1;
  repeated SyscallProfile syscall_profiles = 2;
  repeated NetworkProfile network_profiles = 3;
  repeated FileProfile file_profiles = 4;
}
```

---

## 12. Container Runtime Integration

### 12.1 Supported Runtimes

| Runtime | Version | Integration Method | Status |
|---------|---------|-------------------|--------|
| containerd | 1.7+ | CRI gRPC + /proc | P0 |
| CRI-O | 1.25+ | CRI gRPC + /proc | P0 |
| Docker (via containerd) | 24+ | CRI proxy + /proc | P1 |

### 12.2 Container Identification

Resolve kernel events to container metadata:

1. **cgroup_id resolution**: Read `/proc/{pid}/cgroup` → extract container ID from cgroup path
2. **CRI metadata**: Query containerd via CRI gRPC for container name, image, labels
3. **K8s metadata**: Watch K8s API for pods on local node → match container ID to pod

### 12.3 Container Lifecycle Tracking

```go
type ContainerTracker struct {
    mu           sync.RWMutex
    containers   map[string]*ContainerInfo  // container_id → info
    cgroupMap    map[uint64]string          // cgroup_id → container_id
}

type ContainerInfo struct {
    ID          string
    Name        string
    Image       string
    ImageDigest  string
    PodName     string
    Namespace   string
    ServiceAccount string
    Labels      map[string]string
    StartedAt   time.Time
    Privileged  bool
    Capabilities []string
}
```

Agent watches for container start/stop events from the CRI and maintains the cgroup map that eBPF probes use for kernel-side filtering.

---

## 13. Kubernetes Deployment Architecture

### 13.1 DaemonSet Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: scarlet-runtime
  namespace: security-scarlet
  labels:
    app: scarlet-runtime
spec:
  selector:
    matchLabels:
      app: scarlet-runtime
  template:
    metadata:
      labels:
        app: scarlet-runtime
    spec:
      serviceAccountName: scarlet-runtime
      tolerations:
        - operator: Exists  # Run on all nodes including control plane
      volumes:
        - name: procfs
          hostPath:
            path: /proc
        - name: sys-kernel-debug
          hostPath:
            path: /sys/kernel/debug
        - name: sys-fs-bpf
          hostPath:
            path: /sys/fs/bpf
        - name: etc-containerd
          hostPath:
            path: /etc/containerd
        - name: run-containerd
          hostPath:
            path: /run/containerd
      containers:
        - name: scarlet-agent
          image: securityscarlet/runtime-agent:latest
          securityContext:
            capabilities:
              add:
                - CAP_BPF
                - CAP_PERFMON
                - CAP_SYS_PTRACE
                - CAP_SYS_RESOURCE
            readOnlyRootFilesystem: true
          env:
            - name: SCARLET_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: procfs
              mountPath: /host/proc
              readOnly: true
            - name: sys-kernel-debug
              mountPath: /sys/kernel/debug
            - name: sys-fs-bpf
              mountPath: /sys/fs/bpf
            - name: etc-containerd
              mountPath: /etc/containerd
              readOnly: true
            - name: run-containerd
              mountPath: /run/containerd
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 1Gi
          ports:
            - containerPort: 9090  # Prometheus metrics
              name: metrics
            - containerPort: 8443  # Webhook server
              name: webhooks
```

### 13.2 Controller Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scarlet-controller
  namespace: security-scarlet
spec:
  replicas: 2  # HA
  template:
    spec:
      containers:
        - name: controller
          image: securityscarlet/controller:latest
          ports:
            - containerPort: 9443  # gRPC to AI service
            - containerPort: 8080  # API server
```

### 13.3 RBAC Requirements

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: scarlet-runtime
rules:
  - apiGroups: [""]
    resources: [pods, namespaces, nodes]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [events]
    verbs: [create, patch]
  - apiGroups: ["securityscarlet.ai"]
    resources: [scarletrules, scarletpolicies]
    verbs: [get, list, watch]
```

---

## 14. Performance & Resource Budgets

### 14.1 Performance Targets

| Metric | Target | Measured Baseline (Research) |
|--------|--------|---------------------------|
| CPU overhead (steady state) | <2.5% per node | 0.2-0.3 cores @ 50 pods (Juliet) |
| Memory (agent) | <800MB | 500-800MB @ 50 pods (Juliet) |
| Events per second (raw) | 50-200 | Measured across workloads |
| Events per second (after coalesce) | 5-20 | 10-100x reduction |
| Enforcement latency (SIGKILL) | <200ms | ~23µs average (eBPF-PATROL) |
| LSM enforcement latency | <10µs | Kernel inline path |
| Network to API (batched) | 50-500KB / 5s | Measured (Juliet) |
| Ring buffer drop rate | <0.01% | Track and alert on drops |

### 14.2 Overhead by Workload Type

| Workload | Latency Overhead | Notes |
|----------|-----------------|-------|
| Web serving | 1.07-1.18× | Low (network-bound, few syscalls) |
| Database | 1.52× | Moderate (I/O-heavy) |
| Data caching | 2.98× | Highest (memory I/O intensive) |
| Cryptojacking | 1.1× | Low (repetitive syscalls, good filtering) |

Source: Kim et al. 2025 (Tetragon-based cryptojacking detection)

### 14.3 Scalability Model

```
Performance = f(active_policies, monitored_syscalls, container_count)

CPU ≈ 200mCPU base + (active_policies × 10mCPU) + (events/sec × 0.01mCPU)

With 40 policies, 50 pods, audit mode:
  CPU: 200-300mCPU
  Memory: 500-800MB
  Events/sec (pre-coalesce): 50-200
  Events/sec (post-coalesce): 5-20
```

---

## 15. Security & Hardening

### 15.1 Agent Security

| Measure | Implementation |
|---------|---------------|
| Least privilege | CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE (not CAP_SYS_ADMIN) |
| ReadOnly rootfs | Container filesystem is read-only |
| No shell | No /bin/sh in agent image (distroless base) |
| Self-protection | Agent will not kill its own process tree |
| eBPF program integrity | Pin programs + maps to /sys/fs/bpf, track via bpftool |
| BPF unprivileged off | Require CONFIG_BPF_UNPRIV_DEFAULT_OFF on nodes |

### 15.2 BTF Fallback Chain

1. Host kernel BTF at `/sys/kernel/btf/vmlinux`
2. Embedded BTFHub archive matching kernel release
3. If no BTF available: status-only mode (no probes, health reporting only)

### 15.3 Cross-Container eBPF Attack Defense

Per USENIX Security 2023 research, implement:

- **Detect**: Alert when `bpf()` syscall is invoked from container cgroup
- **Block**: LSM hook `security_bpf` denies BPF_PROG_LOAD from container namespaces
- **Monitor**: Track all eBPF program loads/attachments on the node
- **Audit**: Export eBPF program inventory via Prometheus metrics

### 15.4 Anti-Tampering

- Agent watches for eBPF program detach events (could indicate attacker tampering)
- Heartbeat to Controller every 60s
- If heartbeat missing for 3 intervals, Controller alerts
- bpftool prog show/map show daily export for diff-based audit

---

## 16. Testing & Validation Strategy

### 16.1 Test Categories

| Category | Method | Tools |
|----------|--------|-------|
| **Unit tests** | Go test suite for rule engine, enrichment, decoder | go test |
| **eBPF tests** | Test probe compilation, attachment, event emission | bpftool, libbpf test |
| **Integration tests** | Full agent in Docker container with workloads | Docker, kind |
| **Escape scenario tests** | Run the 15 container escape scenarios from container-escape-telemetry | Custom harness |
| **Cryptojacking tests** | Deploy XMRig + xmr-stak-cpu containers, verify detection | Docker images |
| **Reverse shell tests** | Spawn reverse shells, verify correlation engine detects | Custom scripts |
| **Performance tests** | sysbench, Redis, NGINX, MariaDB benchmarks | wrk, sysbench |
| **Fuzz tests** | Fuzz event decoder and rule engine inputs | go-fuzz |
| **OPA policy tests** | Rego unit tests for enforcement policies | opa test |

### 16.2 Container Escape Test Matrix

Based on the container-escape-telemetry research, we validate detection against all 15 scenarios:

| ID | Scenario | Expected Detection Rule | Expected Action |
|----|----------|----------------------|---------------|
| S01 | cgroup release_agent | R003 (Cgroup Mount) | enforce |
| S02 | CVE-2022-0492 | R002 (unshare) + R003 | enforce |
| S03 | nsenter host PID | R001 (setns) | enforce |
| S04 | docker.sock abuse | R004 (Docker Socket Access) | enforce |
| S05 | /proc/1/root access | R005 (/proc/1 Access) | alert |
| S06 | Baseline (no escape) | None | — |
| S07 | CVE-2024-21626 | R005 (/proc/self/fd) | alert |
| S08 | CVE-2022-0847 | R030 (Dirty Pipe) | alert |
| S09 | CVE-2022-0185 | R003 (mount anomalies) | alert |
| S10 | CVE-2021-22555 | R028 (Raw Socket) | alert |
| S11 | CVE-2025-runc masked paths | R005 (procfs access) | alert |
| S12 | CVE-2019-5736 | R005 (/proc/self/exe) | enforce |
| S13 | Privileged container enum | R021-R023 | alert |
| S14 | Excessive capabilities | R005 + R028 | alert |
| S15 | Syscall flood stress | Performance validation | — |

### 16.3 Cryptojacking Test Matrix

| Test | Container | Expected Detection Rules |
|------|-----------|----------------------|
| XMRig (Monero) | miningcontainers/xmrig | R008, R009, R010 |
| xmr-stak-cpu | timonmat/xmr-stak-cpu | R008, R009 |
| Custom miner (unknown name) | Custom image | R011 (behavioral) + AI |
| Throttled miner (low CPU) | Custom image | R009 (pool connection) |
| Miner behind proxy | Custom image | R011 + AI flow analysis |

---

## 17. API & Integration Interfaces

### 17.1 Outputs

| Output | Format | Protocol | Purpose |
|--------|--------|----------|---------|
| Alert stream | NDJSON | File + stdout | Primary alert output |
| Prometheus metrics | OpenMetrics | HTTP :9090/metrics | Operational monitoring |
| Webhook alerts | JSON | HTTPS POST | SIEM/PagerDuty/Slack |
| gRPC to SecurityScarletAI | protobuf | gRPC :9443 | AI analysis |
| Kubernetes Events | v1.Event | K8s API | Cluster-wide event visibility |

### 17.2 Prometheus Metrics

```
# Alert counts
scarlet_alerts_total{rule="R008",priority="critical",action="enforce"} 42
scarlet_alerts_total{rule="R014",priority="critical",action="enforce"} 3

# Enforcement actions
scarlet_enforcement_actions_total{type="sigkill",result="killed"} 12
scarlet_enforcement_actions_total{type="lsm_deny",result="blocked"} 8
scarlet_enforcement_actions_total{type="sigkill",result="skipped_namespace"} 1
scarlet_enforcement_actions_total{type="sigkill",result="simulated"} 45

# Ring buffer
scarlet_ring_buffer_events_total 1234567
scarlet_ring_buffer_drops_total 0

# Performance
scarlet_event_processing_latency_us{quantile="0.99"} 180
scarlet_enforcement_latency_us{quantile="0.99"} 199

# AI integration
scarlet_ai_anomaly_score_sum{classification="cryptojacking"} 42.5
scarlet_ai_rule_suggestions_total{status="approved"} 3
scarlet_ai_rule_suggestions_total{status="pending"} 1
```

### 17.3 CLI Interface

```bash
scarletctl [command]

Commands:
  start             Start the runtime agent
  stop              Stop the agent and print reports
  status            Show agent status and metrics
  rules list        List loaded rules
  rules validate    Validate a rules file
  rules test       Test a rule against sample events
  simulate         Run in simulate mode (no enforcement)
  events           Stream live events (filtered)
  enforce          Switch agent to enforcement mode
  audit            Switch agent to audit-only mode
  version          Show version info

Flags:
  --config string       Config file path
  --mode string          Operating mode: audit|enforce|simulate
  --rules-path string   Rules file/directory path
  --verbose             Enable verbose logging
```

---

## 18. Non-Functional Requirements

### 18.1 Availability

| Requirement | Target | Implementation |
|-------------|--------|---------------|
| Agent uptime | 99.9% | DaemonSet self-healing, liveness probe |
| Event delivery | At-least-once | Disk spool (100MB cap) when API unavailable |
| Controller HA | 99.9% | 2 replicas, leader election |
| Rule propagation latency | <30s | ConfigMap watch + agent hot-reload |

### 18.2 Compatibility

| Requirement | Version |
|-------------|---------|
| Minimum kernel | 5.8 (BTF + ring buffer) |
| Recommended kernel | 5.15+ (full LSM support) |
| Kubernetes | 1.26+ |
| containerd | 1.7+ |
| CRI-O | 1.25+ |
| Architecture | x86_64, aarch64 |

### 18.3 Observability

| Signal | Export |
|--------|--------|
| Agent health | liveness + readiness probes |
| Rule evaluation rate | Prometheus counter |
| Ring buffer drops | Prometheus gauge + alert |
| Enforcement actions | Prometheus counter by type/result |
| AI inference latency | Prometheus histogram |
| Container count tracked | Prometheus gauge |
| Event processing latency | Prometheus histogram |

---

## 19. Risk Analysis & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Agent crash kills node workloads | Low | Critical | 7-rule enforcement safety; simulate mode; protected namespaces |
| Kernel too old for BPF LSM | Medium | Medium | Fallback to SIGKILL enforcement; status-only mode for BTF-less kernels |
| False positives on enforcement | Medium | High | Simulate mode mandatory 48h; rate limiting; namespace scoping |
| Ring buffer overflow under load | Low | Medium | LRU maps; coalescing; backpressure monitoring; drop alerts |
| Attacker disables eBPF probes | Low | Critical | Heartbeat to Controller; bpftool diff audit; detect detach events |
| OPA policy evaluation too slow | Low | Medium | Policy result caching (30s TTL); pre-compiled fast path for common rules |
| AI layer unavailable | Medium | Low | Graceful degradation: AI signals skipped, rule engine continues |
| eBPF cross-container attacks | Low | Critical | LSM hook on bpf() from containers; detect+block eBPF loads |
| ARM64 syscall differences | Medium | Low | best-effort attachment; skip missing syscalls with warning |
| High-volume containers (1000+ pods/node) | Low | Medium | Kernel-side cgroup filtering; coalescing; adjustable ring buffer size |

---

## 20. Release Milestones & Phasing

### Phase 1: Foundation (Weeks 1-6) — P0

| Deliverable | Details |
|-------------|---------|
| eBPF probe programs | Process + File + Network + Escape probe categories |
| Agent core | Ring buffer reader, event decoder, container enrichment |
| Rule engine | YAML rule parsing, fast-path matching, alert emission |
| Core rule catalog | R001-R030 (30 rules across 7 categories) |
| Kubernetes DaemonSet | Helm chart, RBAC, node deployment |
| CLI | `scarletctl start/stop/status` |
| Basic tests | 15 escape scenarios + cryptojacking detection |

### Phase 2: Enforcement (Weeks 7-10) — P0 — ✅ COMPLETE

| Deliverable | Details | Status |
|-------------|---------|--------|
| Response actor | SIGTERM→SIGKILL enforcement with 7-rule safety protocol | ✅ Done |
| Kill chain escalation | Graceful (SIGTERM→grace period→SIGKILL) and immediate modes | ✅ Done |
| LSM enforcement | BPF LSM programs for mount/bpf/file deny (stub for kernel 5.7+) | ✅ Done |
| OPA integration | Policy evaluation for enforcement decisions (stub, requires opa dependency) | ✅ Done |
| Exception framework | Falco-compatible AND/OR field matching + OPA evaluator stub | ✅ Done |
| Enforcement telemetry | Prometheus metrics, enforcement audit log | ✅ Done |
| CRI integration | Container runtime interface (containerd/CRI-O) for container metadata | ✅ Done |
| K8s API watch | Pod/deployment label enrichment from API server with cgroup fallback | ✅ Done |
| Network policy enforcement | eBPF TC-based network blocking by IP/port/protocol with TTL | ✅ Done |
| Policy CRD | ScarletRuntimePolicy Custom Resource Definition with file and K8s watching | ✅ Done |
| Full test suite | 118 tests: escape + cryptojacking + pipeline + enforcement + network + enrichment | ✅ Done |

### Phase 3: Intelligence (Weeks 11-16) — P1

| Deliverable | Details |
|-------------|---------|
| SecurityScarletAI connector | gRPC client, feature extraction |
| Anomaly detection | n-gram syscall analysis, anomaly scoring |
| Behavioral profiling | Per-image auto-baseline generation |
| AI rule suggestions | Draft YAML rule generation from incidents |
| Multi-signal correlation | Time-windowed correlation engine (correlate rules) |
| Alert triage | AI-based false-positive reduction |

### Phase 4: Hardening & Scale (Weeks 17-20) — P2

| Deliverable | Details |
|-------------|---------|
| Controller | Cluster-level rule distribution, config sync |
| Webhook forwarding | Slack, PagerDuty, generic webhook |
| TLS SNI inspection | eBPF TC hook for encrypted traffic |
| DNS monitoring | eBPF DNS query capture |
| Process ancestry tracking | Full fork/exec tree with ancestry chain rules |
| Performance optimization | Kernel-side filtering, LRU maps, coalescing |
| Documentation | API docs, rule writing guide, deployment guide |

---

## Appendix A: eBPF Probe Implementation Example

```c
// probe_execve.bpf.c — CO-RE eBPF program using libbpf
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "security_scarlet_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  // 4MB
} events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);    // cgroup_id
    __type(value, __u32);  // container seq
} container_cgroups SEC(".maps");

// Trace execve syscall entry for process execution monitoring
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct scarlet_event *e;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 pid_ns_level;
    
    // Check if process is in a monitored container
    if (!bpf_map_lookup_elem(&container_cgroups, &cgroup_id))
        return 0;  // Not a container process, skip
    
    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;  // Ring buffer full, drop (backpressure)
    
    // Fill event header
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;
    e->cgroup_id = cgroup_id;
    e->category = SCARLET_CAT_PROCESS;
    e->event_type = SCARLET_EVT_EXEC;
    e->syscall_nr = 59;  // __NR_execve
    
    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    
    // Get PID namespace level
    struct pid *pid_struct = BPF_CORE_READ(task, thread_pid);
    struct pid_namespace *pid_ns = BPF_CORE_READ(pid_struct, numbers[0].ns);
    e->pid_ns_level = BPF_CORE_READ(pid_ns, level);
    
    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Read filename from syscall args
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->payload.process.filename,
                            sizeof(e->payload.process.filename),
                            filename);
    
    // Read first bytes of args (if available)
    const char *const *argv = (const char *const *)ctx->args[1];
    if (argv) {
        bpf_probe_read_user_str(&e->payload.process.args,
                                sizeof(e->payload.process.args),
                                argv);
    }
    
    // Submit event
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

## Appendix B: Configuration Reference

```yaml
# scarlet-config.yaml
agent:
  mode: audit                    # audit | enforce | simulate
  log_level: info                 # debug | info | warn | error
  ring_buffer_size_mb: 4          # Per-node ring buffer size
  
enrichment:
  cri_endpoint: /run/containerd/containerd.sock
  k8s_node_name: ${NODE_NAME}    # From downward API
  pid_cache_size: 10000
  pid_cache_ttl: 300              # seconds
  
rules:
  paths:
    - /etc/scarlet/rules.d/
  reload_on_change: true
  
enforcement:
  protected_namespaces:
    - kube-system
    - kube-public
  rate_limit:
    max_kills_per_pod: 10
    window_seconds: 60
  simulate_minimum_hours: 48
  
output:
  alert_file: /var/log/scarlet/alerts.jsonl
  webhook_url: ""                 # Optional
  webhook_headers: {}
  
ai:
  enabled: false
  endpoint: scarlet-ai:9443
  anomaly_threshold: 0.8
  learning_mode: false
  
metrics:
  enabled: true
  port: 9090
  
webhook:
  port: 8443
  tls_cert: /etc/scarlet/tls/tls.crt
  tls_key: /etc/scarlet/tls/tls.key
```

## Appendix C: Research Bibliography

1. **Falco CNCF** — "Kernel Events Architecture", falco.org/docs/concepts/event-sources/kernel/architecture/
2. **Falco** — "Basic Elements of Falco Rules", falco.org/docs/concepts/rules/basic-elements
3. **Falco** — "Cryptomining Detection Using Falco", falco.org/blog/falco-detect-cryptomining/
4. **Unit 42 / Palo Alto Networks** — "Container Breakouts: Escape Techniques in Cloud Environments", unit42.paloaltonetworks.com/container-escape-techniques/
5. **Yi He et al.** — "Cross Container Attacks: The Bewildered eBPF on Clouds", USENIX Security 2023
6. **Kim et al.** — "Detecting Cryptojacking Containers Using eBPF-Based Security Runtime and Machine Learning", Electronics 2025, 14(6), 1208
7. **eBPF-Guard** — "eBPF-Guard: a detection method for container escape via multi-level monitoring and enhanced analysis model", Empirical Software Engineering, 2025
8. **container-escape-telemetry** — "Container escape telemetry research: 15 scenarios tested against Tetragon, Falco, Tracee", github.com/catscrdl/container-escape-telemetry
9. **Juliet** — "Building Runtime Enforcement for Kubernetes with eBPF", juliet.sh/blog/building-runtime-enforcement-for-kubernetes-with-ebpf
10. **eBPF-PATROL** — "eBPF-Protective Agent for Threat Recognition and Overreach Limitation", arxiv.org/html/2511.18155v1
11. **kntrl** — "eBPF-based runtime agent for CI/CD pipeline security", github.com/kondukto-io/kntrl
12. **Micromize** — "BPF-LSM kernel-enforced boundary hardening for containers", github.com/micromize-dev/micromize
13. **Sysdig** — "Detecting cryptomining attacks in the wild", sysdig.com/blog/detecting-cryptomining-attacks-in-the-wild
14. **bpfman** — "Technical Challenges for Attaching eBPF Programs in Containers", bpfman.io
15. **eBPF Observability** — "Tracing the Future: Using eBPF for Low-Overhead Observability", thinhdanggroup.github.io/ebpf-observability/
16. **Tetragon / Cilium** — "Detecting a Container Escape with Tetragon and eBPF", isovalent.com/blog/post/2021-11-container-escape
17. **Detect Shell with eBPF** — phb-crystal-ball.org/detect-shell-with-ebpf/
18. **eBPF Security Monitoring** — rahalkar.dev/posts/2026-02-21-ebpf-security-monitoring
19. **Sysdig 2022 Report** — "Cloud Native Security and Usage Report"
20. **GoLeash** — "Runtime enforcement of software supply chain capabilities in Go", github.com/chains-project/goleash

---

*End of Document — SecurityScarlet Runtime SRD v1.0*

*"Runtime security is the last line of defense. Static scanning catches what's known. Runtime monitoring catches what's happening — in the moment it matters."*