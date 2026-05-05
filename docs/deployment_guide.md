# SecurityScarlet Runtime — Deployment Guide

This guide covers deploying SecurityScarlet Runtime on Kubernetes using
Helm, configuring eBPF requirements, and setting up the agent DaemonSet.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Helm Chart Configuration](#helm-chart-configuration)
- [eBPF Requirements](#ebpf-requirements)
- [Kubernetes Setup](#kubernetes-setup)
- [Operating Modes](#operating-modes)
- [Configuration Reference](#configuration-reference)
- [Webhook Configuration](#webhook-configuration)
- [AI Integration](#ai-integration)
- [Metrics & Monitoring](#metrics--monitoring)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Kernel Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Linux Kernel | 5.4+ | 5.10+ |
| BTF Support | `/sys/kernel/btf/vmlinux` must exist | Kernel built with `CONFIG_DEBUG_INFO_BTF=y` |
| eBPF Features | Ring buffer, perf events | CO-RE (Compile Once – Run Everywhere) |

### Runtime Requirements

| Requirement | Version |
|-------------|---------|
| Kubernetes | 1.25+ |
| containerd | 1.7+ |
| CRI-O | 1.25+ (alternative) |
| Helm | 3.10+ |
| Go | 1.21+ (for building) |

### Check eBPF Support

```bash
# Check kernel version
uname -r

# Check BTF availability
ls /sys/kernel/btf/vmlinux

# Check eBPF features
bpftool feature probe

# Check containerd
containerd --version
```

---

## Helm Chart Configuration

### Installation

```bash
helm repo add securityscarlet https://charts.securityscarlet.dev
helm repo update
helm install securityscarlet securityscarlet/scarlet-runtime \
  --namespace scarlet \
  --create-namespace \
  -f values.yaml
```

### Minimal values.yaml

```yaml
agent:
  mode: audit
  nodeSelector:
    kubernetes.io/os: linux

ebpf:
  enabled: true
  ringBufferSizeMB: 4

enrichment:
  criEndpoint: "/run/containerd/containerd.sock"
  pidCacheSize: 10000
  pidCacheTTLSeconds: 300

rules:
  paths:
    - /etc/scarlet/rules.d/
  reloadOnChange: true

output:
  alertFile: "/var/log/scarlet/alerts.jsonl"

ai:
  enabled: false
  endpoint: "scarlet-ai:9443"
  anomalyThreshold: 0.8

webhook:
  sinks: []

metrics:
  enabled: true
  port: 9090
```

### Full values.yaml (with all options)

```yaml
agent:
  mode: audit               # audit | enforce | simulate
  logLevel: info
  ringBufferSizeMB: 4
  bpfObjectDir: /opt/scarlet/bpf
  procfsPath: /host/proc
  sysfsPath: /sys/kernel/debug
  k8sNodeName: ""           # Auto-detected from NODE_NAME env var

enrichment:
  criEndpoint: /run/containerd/containerd.sock
  k8sNodeName: ""           # Auto-detected
  pidCacheSize: 10000
  pidCacheTTLSeconds: 300

rules:
  paths:
    - /etc/scarlet/rules.d/
  reloadOnChange: true

enforcement:
  protectedNamespaces:
    - kube-system
    - kube-public
  maxKillsPerPod: 10
  windowSeconds: 60
  simulateMinimumHours: 48

output:
  alertFile: /var/log/scarlet/alerts.jsonl
  webhookURL: ""
  webhookHeaders: {}

ai:
  enabled: false
  endpoint: scarlet-ai:9443
  anomalyThreshold: 0.8
  learningMode: false         # Defaults to true in pipeline; use this to disable

webhook:
  port: 8443
  tlsCert: /etc/scarlet/tls/tls.crt
  tlsKey: /etc/scarlet/tls/tls.key
  sinks:
    - type: slack
      url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
      slackChannel: "#security-alerts"
      slackUsername: "SecurityScarlet"
      enabled: true
    - type: pagerduty
      url: "https://events.pagerduty.com/v2/enqueue"
      pagerdutyRoutingKey: "your-routing-key"
      retryCount: 3
      timeout: 10
      enabled: true
    - type: generic
      url: "https://your-webhook.example.com/alerts"
      headers:
        Authorization: "Bearer your-token"
      batchSize: 5
      batchInterval: 10
      enabled: true

metrics:
  enabled: true
  port: 9090
```

---

## eBPF Requirements

### Kernel Configuration

The following kernel features must be enabled:

```kconfig
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_EVENTS=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_CLS_BPF=y
```

### eBPF Maps

SecurityScarlet uses the following eBPF maps:

| Map | Purpose | Size |
|-----|---------|------|
| `container_cgroups` | Container cgroup ID → sequence number | 4096 entries |
| `monitored_syscalls` | Syscall numbers to monitor | 512 entries |
| `sensitive_paths` | Paths to monitor for file access | Configurable |
| `miner_pool_ports` | Mining pool ports for kernel filtering | 24 entries |
| `c2_ports` | C2 ports for kernel filtering | 8 entries |
| `cloud_metadata_ips` | Cloud metadata IPs for kernel filtering | 2 entries |

### TC (Traffic Control) Programs

Network enforcement uses TC eBPF programs attached to network interfaces:

```bash
# Verify TC support
tc qdisc show dev eth0

# Check BPF programs
bpftool prog show
bpftool map show
```

### Ring Buffer Configuration

The ring buffer size controls the event channel capacity between kernel
and userspace:

| Size | Events/sec | Memory |
|------|-----------|--------|
| 4 MB | ~50k/s | 4 MB |
| 8 MB | ~100k/s | 8 MB |
| 16 MB | ~200k/s | 16 MB |

> **Note**: The ring buffer size must be a power of 2 and page-aligned.
> Default is 4 MB.

### Kernel-Side Filtering

Use the `RingBufferFilter` to reduce userspace processing:

- **Category filter**: Only pass process and network events
- **PID filter**: Only pass events from specific PIDs
- **Cgroup filter**: Only pass events from specific containers
- **Syscall filter**: Only pass specific syscall numbers
- **Drop probability**: Load shedding under high load

Configuration via agent config:

```yaml
ebpf:
  categoryFilter: [1, 3]  # CatProcess=1, CatNetwork=3
  pidFilter: []
  cgroupFilter: []
  syscallFilter: []
```

---

## Kubernetes Setup

### Service Account and RBAC

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: scarlet-agent
  namespace: scarlet
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: scarlet-agent
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["security.scarlet.dev"]
    resources: ["securitypolicies", "policyexceptions", "blocklistentries"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: scarlet-agent
subjects:
  - kind: ServiceAccount
    name: scarlet-agent
    namespace: scarlet
roleRef:
  kind: ClusterRole
  name: scarlet-agent
  apiGroup: rbac.authorization.k8s.io
```

### DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: scarlet-agent
  namespace: scarlet
spec:
  selector:
    matchLabels:
      app: scarlet-agent
  template:
    metadata:
      labels:
        app: scarlet-agent
    spec:
      serviceAccountName: scarlet-agent
      hostPID: true
      hostNetwork: true
      containers:
        - name: agent
          image: securityscarlet/runtime:latest
          securityContext:
            privileged: true
            capabilities:
              add:
                - SYS_ADMIN
                - NET_ADMIN
                - BPF
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: SCARLET_MODE
              value: "audit"
          volumeMounts:
            - name: bpf
              mountPath: /sys/kernel/debug
              readOnly: true
            - name: proc
              mountPath: /host/proc
              readOnly: true
            - name: cgroup
              mountPath: /sys/fs/cgroup
              readOnly: true
            - name: containerd
              mountPath: /run/containerd/containerd.sock
            - name: rules
              mountPath: /etc/scarlet/rules.d
              readOnly: true
            - name: alerts
              mountPath: /var/log/scarlet
      volumes:
        - name: bpf
          hostPath:
            path: /sys/kernel/debug
        - name: proc
          hostPath:
            path: /proc
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
        - name: containerd
          hostPath:
            path: /run/containerd/containerd.sock
            type: Socket
        - name: rules
          configMap:
            name: scarlet-rules
        - name: alerts
          emptyDir: {}
```

---

## Operating Modes

### Audit Mode (Recommended for Initial Deployment)

- Logs all alerts
- No enforcement actions
- Lowest risk

```yaml
agent:
  mode: audit
```

### Simulate Mode (Pre-Enforcement Validation)

- Logs alerts with simulated enforcement actions
- Shows what WOULD have been enforced
- **Required for 48 hours before switching to enforce mode**

```yaml
agent:
  mode: simulate
```

### Enforce Mode (Production)

- Logs alerts AND takes enforcement actions
- SIGKILL processes that match enforce rules
- Blocks network connections to mining pools, C2 servers
- LSM inline deny (kernel 5.7+)

```yaml
agent:
  mode: enforce
```

> **Important**: Always start in audit mode, then move to simulate for 48+ hours
> before switching to enforce. Review the enforcement audit log before promotion.

---

## Configuration Reference

### Complete Config File

```yaml
# SecurityScarlet Runtime Configuration
agent:
  mode: audit
  logLevel: info
  ringBufferSizeMB: 4
  k8sNodeName: ""      # Auto-detected
  bpfObjectDir: /opt/scarlet/bpf
  procfsPath: /host/proc
  sysfsPath: /sys/kernel/debug

enrichment:
  criEndpoint: /run/containerd/containerd.sock
  k8sNodeName: ""      # Auto-detected
  pidCacheSize: 10000  # LRU cache max size
  pidCacheTTLSeconds: 300

rules:
  paths:
    - /etc/scarlet/rules.d/
  reloadOnChange: true

enforcement:
  protectedNamespaces:
    - kube-system
    - kube-public
  maxKillsPerPod: 10
  windowSeconds: 60
  simulateMinimumHours: 48

output:
  alertFile: /var/log/scarlet/alerts.jsonl
  webhookURL: ""
  webhookHeaders: {}

ai:
  enabled: false
  endpoint: scarlet-ai:9443
  anomalyThreshold: 0.8
  # Learning mode defaults to true. Set to false to disable baseline learning.
  # Use SetLearningMode(false) to disable at runtime.
  learningMode: false

# AI triage thresholds (configurable, not hardcoded):
#   TriageSuppressThreshold: 0.9  (fpScore >= 0.9 → suppress)
#   TriageDowngradeThreshold: 0.7 (fpScore >= 0.7 → downgrade non-enforce)
#   TriageAdjustThreshold: 0.5   (fpScore >= 0.5 → adjust priority)

webhook:
  port: 8443
  tlsCert: /etc/scarlet/tls/tls.crt
  tlsKey: /etc/scarlet/tls/tls.key
  sinks: []

metrics:
  enabled: true
  port: 9090
```

---

## Webhook Configuration

### Slack Webhook

```yaml
webhook:
  sinks:
    - type: slack
      url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
      slackChannel: "#security-alerts"
      slackUsername: "SecurityScarlet"
      retryCount: 3
      timeout: 10
      enabled: true
```

### PagerDuty Webhook

```yaml
webhook:
  sinks:
    - type: pagerduty
      url: "https://events.pagerduty.com/v2/enqueue"
      pagerdutyRoutingKey: "your-routing-key"
      retryCount: 3
      timeout: 10
      enabled: true
```

### Generic Webhook

```yaml
webhook:
  sinks:
    - type: generic
      url: "https://your-webhook.example.com/alerts"
      headers:
        Authorization: "Bearer your-token"
      batchSize: 5
      batchIntervalSeconds: 10
      retryCount: 3
      timeout: 10
      tlsInsecureSkipVerify: false
      enabled: true
```

### Webhook Retry Logic

- Exponential backoff: 1s → 2s → 4s → ... → 30s max
- Configurable retry count (default: 3)
- Circuit breaker opens after 5 consecutive failures
- TLS minimum version: TLS 1.2 (configurable)

---

## AI Integration

### SecurityScarlet AI Service

The AI service provides two advisory functions:

1. **Alert Triage**: Assesses whether alerts are false positives
2. **Rule Suggestions**: Generates draft YAML rules from incident context

> **Important**: Both functions are advisory-only. AI triage cannot upgrade
> alerts to enforce. Suggestions are logged for human review only.

### Configuration

```yaml
ai:
  enabled: true
  endpoint: scarlet-ai:9443
  anomalyThreshold: 0.8
```

### gRPC Connection

The AI service uses gRPC for low-latency communication:

```go
client := proto.NewSecurityScarletAIClient("scarlet-ai:9443", 5*time.Second)
client.Connect(ctx)
```

### Triage Thresholds

AI triage thresholds are configurable (not hardcoded):

```go
pipeline.SetTriageThresholds(
    0.9,  // suppress:  fpScore >= 0.9 → suppress alert
    0.7,  // downgrade: fpScore >= 0.7 → downgrade non-enforce
    0.5,  // adjust:    fpScore >= 0.5 → adjust priority
)
```

---

## Metrics & Monitoring

### Prometheus Metrics

SecurityScarlet exposes Prometheus metrics on the configured port (default: 9090):

| Metric | Type | Description |
|--------|------|-------------|
| `scarlet_events_processed_total` | Counter | Total events processed |
| `scarlet_alerts_emitted_total` | Counter | Total alerts emitted |
| `scarlet_enforcements_total` | Counter | Total enforcement actions |
| `scarlet_rule_matches_total` | CounterVec | Rule matches by rule ID |
| `scarlet_events_by_category_total` | CounterVec | Events by category |
| `scarlet_enforcement_actions_total` | CounterVec | Enforcement actions |

### Grafana Dashboard

A sample Grafana dashboard is available at `deploy/grafana/scarlet-dashboard.json`.

### Health Check

```bash
curl http://localhost:9090/metrics
curl http://localhost:9090/healthz
```

---

## Troubleshooting

### eBPF Programs Fail to Load

```bash
# Check BTF
ls /sys/kernel/btf/vmlinux

# If missing, install BTFHub
bpftool btf dump file /sys/kernel/btf/vmlinux

# Check kernel version
uname -r  # Must be 5.4+
```

### Container Enrichment Not Working

```bash
# Check containerd socket
ls /run/containerd/containerd.sock

# Check CRI endpoint connectivity
crictl --runtime-endpoint unix:///run/containerd/containerd.sock pods

# Check /proc access
ls /host/proc/1/cgroup
```

### High CPU Usage

```yaml
# Reduce ring buffer processing
ebpf:
  ringBufferSizeMB: 4
  pollInterval: 100ms

# Enable kernel-side filtering
ebpf:
  categoryFilter: [1, 3]  # Only process and network events

# Reduce worker count
agent:
  workers: 2
```

### Missing Alerts

1. Check the operating mode — `audit` mode only logs, never enforces
2. Check AI triage thresholds — alerts may be suppressed
3. Check the coalescing window — similar alerts are merged
4. Check rule conditions — rules may not match your events
5. Check enrichment — events without container attribution are downgraded

### Performance Tuning

| Parameter | Default | Tuning |
|-----------|---------|--------|
| `ringBufferSizeMB` | 4 | Increase to 8–16 for high-throughput |
| `pidCacheSize` | 10000 | Increase for nodes with many containers |
| `pidCacheTTLSeconds` | 300 | Decrease for faster churn detection |
| `workers` | 4 | Increase to match CPU cores |
| `coalesceWindow` | 5s | Increase to reduce alert volume |

### LRU Cache Pruning

Enrichment caches implement LRU eviction and idle pruning:

```go
// Prune idle entries (not accessed in the last 10 minutes)
pruned := enricher.PruneCaches(10 * time.Minute)

// Set CRI cache max size for automatic LRU eviction
criCache := enrichment.NewCRICacheWithMaxSize(5000)
```

### Ring Buffer Filter

Configure kernel-side filtering to reduce userspace overhead:

```go
filter := loader.Filter()
// Only pass process and network events
filter.SetCategoryFilter([]uint8{ebpf.CatProcess, ebpf.CatNetwork})
// Drop events from PID 1 (init)
filter.AddPIDBlacklist(1)
// Load shedding: drop 10% of events
filter.SetDropProbability(0.1)
```