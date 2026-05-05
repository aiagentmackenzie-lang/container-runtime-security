# SecurityScarlet Runtime — Rule Writing Guide

This guide explains how to write, configure, and deploy security detection rules
for SecurityScarlet Runtime using YAML.

---

## Table of Contents

- [Rule Format](#rule-format)
- [Rule Fields](#rule-fields)
- [Condition Syntax](#condition-syntax)
- [Operating Modes](#operating-modes)
- [Priority Levels](#priority-levels)
- [Correlation Rules](#correlation-rules)
- [Exceptions](#exceptions)
- [Complete Examples](#complete-examples)
- [Rule IDs](#rule-ids)
- [Testing Rules](#testing-rules)

---

## Rule Format

Rules are defined in YAML files loaded from a directory (default:
`/etc/scarlet/rules.d/`). Each file can contain one or more rules.

### Basic Structure

```yaml
- id: R031
  name: "My Custom Rule"
  description: "Detects suspicious activity X"
  condition: "container and net_outbound and fd.rport = 4444"
  priority: CRITICAL
  action: enforce
  tags: [custom, network]
  output: "Suspicious outbound connection to port 4444 from container"
```

### Multiple Rules in One File

```yaml
- id: R031
  name: "First Rule"
  condition: "..."
  priority: WARNING
  action: alert

- id: R032
  name: "Second Rule"
  condition: "..."
  priority: CRITICAL
  action: enforce
```

---

## Rule Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | Yes | string | Unique rule identifier (R001–R030 reserved) |
| `name` | Yes | string | Human-readable rule name |
| `description` | No | string | Detailed description |
| `condition` | Yes | string | Detection condition expression |
| `priority` | Yes | string | CRITICAL, ERROR, WARNING, or INFO |
| `action` | Yes | string | `alert`, `enforce`, or `simulate` |
| `tags` | No | []string | Categorization tags |
| `output` | Yes | string | Alert message template |
| `correlate` | No | object | Correlation configuration |
| `exceptions` | No | []string | Exception rule IDs to skip |

---

## Condition Syntax

Conditions use a declarative expression language with field references,
comparisons, and logical operators.

### Event Fields

| Field | Description | Example Values |
|-------|-------------|----------------|
| `container` | Event from a container (PIDNSLevel > 0) | `true`, `false` |
| `net_outbound` | Outbound network connection | `true`, `false` |
| `shell_procs` | Shell process (bash, sh, zsh, etc.) | `true`, `false` |
| `miner_procs` | Known miner binary | `true`, `false` |
| `fd.rport` | Remote port number | `3333`, `4444`, `443` |
| `fd.lport` | Local port number | `8080` |
| `fdrip` | Remote IP address | `169.254.169.254` |
| `proc.name` | Process name | `"xmrig"`, `"bash"` |
| `proc.pid` | Process ID | `1234` |
| `proc.ppid` | Parent process ID | `1` |
| `proc.uid` | User ID | `0`, `1000` |
| `proc.gid` | Group ID | `0` |
| `container.id` | Container ID | `"abc123..."` |
| `container.image` | Container image | `"alpine:latest"` |
| `container.privileged` | Privileged container | `true`, `false` |
| `k8s.ns` | Kubernetes namespace | `"default"`, `"kube-system"` |
| `k8s.pod` | Pod name | `"my-pod-abc"` |
| `k8s.sa` | Service account | `"default"` |
| `file.path` | File path | `"/etc/shadow"` |

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `and` | All conditions must be true | `shell_procs and net_outbound` |
| `or` | Any condition can be true | `miner_procs or shell_procs` |
| `not` | Negation | `not container` |
| `()` | Grouping | `(shell_procs or miner_procs) and net_outbound` |

### Comparisons

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equality | `fd.rport = 4444` |
| `!=` | Inequality | `proc.uid != 0` |
| `in` | List membership | `fd.rport in (3333, 4444, 5555)` |
| `not in` | List exclusion | `fd.rport not in (80, 443)` |
| `contains` | String contains | `proc.name contains "xmrig"` |
| `startswith` | String prefix | `file.path startswith "/etc/shadow"` |

---

## Operating Modes

Rules can specify one of three actions:

### `alert` — Alert Only

Logs the detection without taking enforcement action. Use for monitoring
and awareness.

```yaml
action: alert
```

### `enforce` — Alert + Enforcement

Logs the alert AND takes enforcement action:
- SIGTERM → grace period → SIGKILL (if process still alive)
- TC-based network blocking for network rules (R009, R027, R019)
- LSM inline deny (kernel 5.7+, future)

```yaml
action: enforce
```

> **Safety**: Enforcement is subject to the 7-rule safety protocol.
> Events that cannot be attributed to a container are downgraded to alert-only.

### `simulate` — Simulated Enforcement

Logs what WOULD have been enforced, but takes no action. All new
policies must run in simulate mode for 48 hours before enforce.

```yaml
action: simulate
```

---

## Priority Levels

| Priority | Description | Color | Typical Use |
|----------|-------------|-------|-------------|
| CRITICAL | Immediate threat | Red | Container escape, active exploitation |
| ERROR | High-confidence threat | Orange | Cryptojacking, reverse shell |
| WARNING | Suspicious activity | Yellow | Sensitive file access, unusual connections |
| INFO | Informational | Blue | Baseline deviations, low-risk events |

---

## Correlation Rules

Correlation rules detect composite attack patterns by matching multiple
signals within a time window.

### Syntax

```yaml
- id: R031
  name: "Custom Correlation Rule"
  condition: "shell_procs and net_outbound"
  priority: CRITICAL
  action: alert
  output: "Custom correlation detected"
  correlate:
    window: 5s
    signals: [shell_procs, net_outbound]
    logic: all
    group_by: [proc.pid]
```

### Correlation Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `window` | Yes | duration | Time window for signal correlation |
| `signals` | Yes | []string | Signal names to correlate |
| `logic` | Yes | string | `all` (AND) or `any` (OR) |
| `group_by` | Yes | []string | Fields to group signals by |

### Logic Types

- **`all`**: All specified signals must appear within the window.
  Example: `shell_procs + net_outbound` within 5s = reverse shell.

- **`any`**: Any specified signal fires the rule.
  Example: `tls_suspicious_sni OR minerpool_connection` = cryptojacking via TLS.

### Group By Options

| Group By | Key Format | Use Case |
|----------|-----------|----------|
| `[proc.pid]` | `pid:1234` | Per-process correlation |
| `[container.id]` | `cid:abc123` | Per-container correlation |
| `[]` | `global` | Cross-container correlation |

### Built-in Correlation Signals

| Signal Name | Produced By |
|-------------|-------------|
| `shell_procs` | Shell binary execution (R014, R015, R016, R017) |
| `net_outbound` | Outbound network connection (R027, R019, R026) |
| `minerpool_connection` | Mining pool port connection (R009) |
| `miner_procs` | Known miner binary (R008, R010) |
| `high_cpu` | Behavioral CPU spike (R011) |
| `setuid_transition` | setuid syscall (R021) |
| `sensitive_file_read` | Sensitive file access (R018, R020) |
| `namespace_join` | setns syscall (R001) |
| `unshare` | unshare syscall (R002) |
| `cgroup_mount` | cgroup mount (R003) |
| `tls_suspicious_sni` | Suspicious TLS SNI (TLS-SNI-001) |
| `dns_suspicious_query` | Suspicious DNS query (DNS-001) |
| `tls_connection` | Port 443 connection |
| `dns_query` | Port 53 connection |

---

## Exceptions

Exceptions allow specific containers, namespaces, or processes to bypass
rules. They are defined as CRD objects in Kubernetes.

### Exception Fields

```yaml
apiVersion: security.scarlet.dev/v1
kind: PolicyException
metadata:
  name: allow-debug-shells
spec:
  ruleIDs: [R014]
  namespaces: ["debug-ns"]
  containers: ["debug-container"]
  processNames: ["bash"]
  expiry: "2025-12-31T23:59:59Z"
  reason: "Debug troubleshooting window"
```

> Exceptions are only checked for `alert` action rules. Enforce rules
> cannot be bypassed by exceptions.

---

## Complete Examples

### Example 1: Detect Reverse Shell

```yaml
- id: R031
  name: "Reverse Shell — Bash with Outbound Connection"
  description: "Detects a shell process making an outbound network connection to a non-standard port"
  condition: "shell_procs and net_outbound and fd.rport not in (80, 443)"
  priority: CRITICAL
  action: alert
  tags: [reverse_shell, network, process]
  output: "Reverse shell detected: proc=%proc.name pid=%proc.pid port=%fd.rport container=%container.id"
  correlate:
    window: 5s
    signals: [shell_procs, net_outbound]
    logic: all
    group_by: [proc.pid]
```

### Example 2: Detect Cryptojacking

```yaml
- id: R032
  name: "Cryptojacking — Mining Pool Connection"
  description: "Detects connections to known cryptocurrency mining pool ports"
  condition: "container and net_outbound and fd.rport in (3333, 4444, 5555, 5588)"
  priority: CRITICAL
  action: enforce
  tags: [cryptojacking, network, enforcement]
  output: "Mining pool connection: port=%fd.rport ip=%fdrip container=%container.id image=%container.image"
```

### Example 3: Detect Container Escape via Namespace Join

```yaml
- id: R033
  name: "Container Escape — Namespace Join"
  description: "Detects a container process joining another namespace (setns)"
  condition: "container and evt.type = SETNS"
  priority: CRITICAL
  action: enforce
  tags: [escape, container]
  output: "Namespace join detected: pid=%proc.pid ns_type=%evt.arg0 container=%container.id"
```

### Example 4: Detect Cloud Metadata SSRF

```yaml
- id: R034
  name: "Cloud Metadata SSRF"
  description: "Detects attempts to access cloud metadata service (169.254.169.254)"
  condition: "container and net_outbound and fdrip = 169.254.169.254"
  priority: ERROR
  action: alert
  tags: [ssrf, cloud, network]
  output: "Cloud metadata SSRF attempt: ip=%fdrip pid=%proc.pid container=%container.id namespace=%k8s.ns"
```

### Example 5: Detect Suspicious TLS SNI

```yaml
- id: R035
  name: "Suspicious TLS SNI — Mining Domain"
  description: "Detects TLS connections to domains matching known mining pool patterns"
  condition: "container and net_outbound and fd.rport = 443"
  priority: ERROR
  action: alert
  tags: [tls, cryptojacking, network]
  output: "Suspicious TLS SNI: sni=%tls.sni container=%container.id image=%container.image"
  correlate:
    window: 30s
    signals: [tls_suspicious_sni, minerpool_connection]
    logic: any
    group_by: [container.id]
```

### Example 6: Detect DGA-like DNS Queries

```yaml
- id: R036
  name: "Suspicious DNS Query — DGA Pattern"
  description: "Detects DNS queries with long random subdomains suggesting DGA or DNS tunneling"
  condition: "container and fd.rport = 53"
  priority: WARNING
  action: alert
  tags: [dns, c2, network]
  output: "Suspicious DNS query: domain=%dns.qname container=%container.id pid=%proc.pid"
  correlate:
    window: 60s
    signals: [dns_suspicious_query]
    logic: any
    group_by: [container.id]
```

### Example 7: Privilege Escalation Chain

```yaml
- id: R037
  name: "Privilege Escalation Chain"
  description: "Detects setuid transition followed by sensitive file read"
  condition: "setuid_transition and sensitive_file_read"
  priority: CRITICAL
  action: alert
  tags: [privilege, credentials]
  output: "Privilege escalation: pid=%proc.pid old_uid=%proc.uid container=%container.id"
  correlate:
    window: 10s
    signals: [setuid_transition, sensitive_file_read]
    logic: all
    group_by: [proc.pid]
```

---

## Rule IDs

- **R001–R030**: Reserved for built-in system rules. Do not renumber these.
- **R031+**: Available for custom rules.
- **TLS-SNI-001, DNS-SNI-001, DNS-001**: Reserved for correlation rules.

### Built-in Rule Summary

| ID | Name | Action |
|----|------|--------|
| R001 | Container Escape — Namespace Join | enforce |
| R002 | Container Escape — Unshare | enforce |
| R003 | Container Escape — cgroup Mount | enforce |
| R004 | Container Escape — PTRACE | enforce |
| R005 | Container Escape — Module Load | enforce |
| R006 | Container Escape — BPF Load | enforce |
| R007 | Container Escape — Privileged Container | alert |
| R008 | Cryptojacking — Known Miner Binary | enforce |
| R009 | Cryptojacking — Mining Pool Connection | enforce |
| R010 | Cryptojacking — Stratum Protocol | enforce |
| R011 | Cryptojacking — Behavioral (CPU+Net) | enforce |
| R012 | SUID/SGID Binary Execution | alert |
| R013 | Sensitive File Read (host) | alert |
| R014 | Reverse Shell — Shell + Network | enforce |
| R015 | Reverse Shell — dup2 | enforce |
| R016 | Reverse Shell — Non-standard Port | alert |
| R017 | Reverse Shell — Pipe | alert |
| R018 | Sensitive File Read (container) | alert |
| R019 | Cloud Metadata SSRF | enforce |
| R020 | K8s Service Account Token Read | alert |
| R021 | SetUID Binary Transition | alert |
| R022 | SUID/SGID Bit Set | alert |
| R023 | File Capability Set | alert |
| R024 | chmod SUID Bit | alert |
| R025 | memfd_create Execution | enforce |
| R026 | Rogue Listener | alert |
| R027 | C2 Port Connection | enforce |
| R028 | LD_PRELOAD Injection | alert |
| R029 | Container Drift — New Binary | alert |
| R030 | Suspicious Process Ancestor | alert |

---

## Testing Rules

### 1. Use Simulate Mode

Before enabling enforcement, test in simulate mode:

```yaml
action: simulate
```

This will log what WOULD happen without actually enforcing.

### 2. Check Rule Loading

```bash
scarletctl rules list
scarletctl rules validate /etc/scarlet/rules.d/
```

### 3. Test with Synthetic Events

Use the agent's `InjectEvent` API to send synthetic events and verify
that your rules match correctly.

### 4. Review AI Triage

The AI triage system may suppress or downgrade alerts that it assesses
as likely false positives. Check the pipeline logs for triage decisions.

### 5. Hot Reload

Rules can be reloaded without restarting the agent:

```bash
kill -HUP $(pidof scarletctl)
```

Or via the K8s ConfigMap watcher when `reload_on_change: true` is set.