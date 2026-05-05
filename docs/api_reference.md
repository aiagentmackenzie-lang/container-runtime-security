# SecurityScarlet Runtime — API Reference

This document provides a reference for all exported types and functions in
SecurityScarlet Runtime, organized by package.

---

## Table of Contents

- [pkg/agent](#pkgagent)
- [pkg/ebpf](#pkgebpf)
- [pkg/enrichment](#pkgenrichment)
- [pkg/rules](#pkgrules)
- [pkg/pipeline](#pkgpipeline)
- [pkg/correlate](#pkgcorrelate)
- [pkg/enforcement](#pkgenforcement)
- [pkg/output](#pkgoutput)
- [pkg/ai](#pkgai)
- [pkg/crd](#pkgcrd)

---

## pkg/agent

### Types

#### `Mode`

```go
type Mode string
const (
    ModeAudit    Mode = "audit"     // Log alerts, no enforcement
    ModeEnforce  Mode = "enforce"  // Log alerts AND enforce (SIGKILL, LSM deny)
    ModeSimulate Mode = "simulate" // Log what WOULD have been enforced
)
```

#### `Agent`

The main runtime security agent that coordinates all components.

```go
type Agent struct { ... }
```

| Method | Description |
|--------|-------------|
| `New(cfg *Config) (*Agent, error)` | Creates a new Agent from configuration |
| `Start(ctx context.Context) error` | Starts the agent (blocks until context cancelled) |
| `GetStatus() AgentStatus` | Returns current agent status |
| `SetMode(mode Mode)` | Changes operating mode at runtime |
| `InjectEvent(event *ebpf.ScarletEvent)` | Injects a synthetic event for testing |
| `GetPipeline() *pipeline.Pipeline` | Returns the event processing pipeline |
| `GetRuleEngine() *rules.Engine` | Returns the rule engine |
| `GetEnricher() *enrichment.Manager` | Returns the enrichment manager |
| `GetCorrelator() *correlate.Correlator` | Returns the correlation engine |
| `GetAIConnector() *ai.AIConnector` | Returns the AI connector |
| `GetNetworkEnforcer() *enforcement.NetworkEnforcer` | Returns the network enforcer |
| `GetTCLOader() *ebpf.TCLoader` | Returns the TC loader |
| `GetGRPCClient() *proto.SecurityScarletAIClient` | Returns the gRPC AI client |

#### `Config`

Top-level configuration structure.

```go
type Config struct {
    Agent      AgentConfig
    Enrichment EnrichmentConfig
    Rules      RulesConfig
    Enforcement EnforcementConfig
    Output     OutputConfig
    AI         AIConfig
    Metrics    MetricsConfig
    Webhook    WebhookConfig
}
```

| Method | Description |
|--------|-------------|
| `DefaultConfig() *Config` | Returns sensible defaults |
| `LoadConfig(path string) (*Config, error)` | Loads config from YAML file |
| `Validate() error` | Validates config fields |
| `ApplyOverrides(mode, rulesPath string, verbose bool)` | Applies CLI flag overrides |

#### `AgentStatus`

```go
type AgentStatus struct {
    Status      Status   `json:"status"`
    Mode        Mode     `json:"mode"`
    StartTime   time.Time `json:"start_time"`
    Uptime      string   `json:"uptime"`
    Version     string   `json:"version"`
    NodeName    string   `json:"node_name"`
    Containers  int      `json:"containers_tracked"`
    RulesLoaded int      `json:"rules_loaded"`
    EventsTotal uint64   `json:"events_total"`
    AlertsTotal uint64   `json:"alerts_total"`
    EnforceTotal uint64  `json:"enforcement_total"`
    EBPFStatus  string   `json:"ebpf_status"`
}
```

---

## pkg/ebpf

### Event Types

#### `ScarletEvent`

The primary data structure flowing through the event pipeline.

```go
type ScarletEvent struct {
    TimestampNS uint64
    PID         uint32
    TGID        uint32
    PPID        uint32
    UID         uint32
    GID         uint32
    CgroupID    uint64
    PIDNSLevel  uint32
    Category    uint8    // CatProcess, CatFile, CatNetwork, CatEscape, CatPrivilege
    EventType   uint8
    SyscallNr   uint16
    Comm        [16]byte
    Payload     EventPayload
}
```

| Method | Description |
|--------|-------------|
| `CategoryString() string` | Human-readable category name |
| `EventTypeString() string` | Human-readable event type name |
| `CommString() string` | Process command name |
| `Filename() string` | Process filename (PROCESS events) |
| `Args() string` | Process arguments (PROCESS events) |
| `FilePath() string` | File path (FILE events) |
| `RemoteIP() string` | Remote IP as dotted-quad (NETWORK events) |
| `LocalIP() string` | Local IP as dotted-quad |
| `RemotePort() uint16` | Remote port in host byte order |
| `LocalPort() uint16` | Local port |
| `IsContainer() bool` | True if event from container (PIDNSLevel > 0) |
| `IsHost() bool` | True if event from host (PIDNSLevel == 0) |

### Category Constants

```go
const (
    CatProcess    uint8 = 1
    CatFile       uint8 = 2
    CatNetwork    uint8 = 3
    CatEscape     uint8 = 4
    CatPrivilege  uint8 = 5
    CatCredential uint8 = 6
)
```

### Event Type Constants

```go
const (
    EvtExec       uint8 = 1   // Process exec
    EvtFork       uint8 = 2   // Process fork
    EvtExit       uint8 = 3   // Process exit
    EvtFileOpen   uint8 = 10  // File open
    EvtFileUnlink uint8 = 11  // File unlink
    EvtFileMemfd  uint8 = 12  // memfd_create
    EvtNetConnect uint8 = 20  // TCP connect
    EvtNetListen  uint8 = 21  // TCP listen
    EvtSetns      uint8 = 30  // setns (namespace join)
    EvtUnshare    uint8 = 31  // unshare
    EvtMount      uint8 = 32  // mount
    EvtPtrace     uint8 = 33  // ptrace
    EvtSetuid     uint8 = 40  // setuid
    EvtCapset     uint8 = 42  // capset
    // ... and more
)
```

### Detection Helpers

| Function | Description |
|----------|-------------|
| `IsShellProcess(comm string) bool` | Checks if command is a known shell |
| `IsMinerProcess(comm string) bool` | Checks if command is a known miner |
| `IsMinerPoolPort(port uint16) bool` | Checks if port is a known mining pool |
| `IsC2Port(port uint16) bool` | Checks if port is a known C2 port |
| `IsCloudMetadataIP(ip string) bool` | Checks if IP is a cloud metadata endpoint |
| `IsSensitivePath(path string) bool` | Checks if path is a security-sensitive file |
| `IsDNSPort(port uint16) bool` | Checks if port is DNS (53) |

### TLS SNI Inspection

| Function | Description |
|----------|-------------|
| `ExtractTLSClientHelloSNI(payload []byte) *TLSSNIResult` | Extracts SNI from TLS ClientHello |
| `CheckSuspiciousSNI(sni string) []string` | Checks SNI for suspicious patterns |

### DNS Monitoring

| Function | Description |
|----------|-------------|
| `ParseDNSMessage(data []byte) (*DNSMessage, error)` | Parses DNS wire format (RFC 1035) |
| `CheckSuspiciousDNS(name string, qtype uint16) *SuspiciousDNSQuery` | Detects suspicious DNS queries |
| `IsDNSPort(port uint16) bool` | Checks if port is DNS (53) |

### Loader

```go
type Loader struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewLoader(cfg LoaderConfig) *Loader` | Creates new eBPF loader |
| `Load(ctx context.Context) error` | Loads eBPF programs into kernel |
| `Attach(ctx context.Context) error` | Attaches probes to tracepoints |
| `Start(ctx context.Context) error` | Starts ring buffer reader |
| `Stop() error` | Stops and detaches all programs |
| `Events() <-chan *ScarletEvent` | Returns event channel |
| `InjectEvent(event *ScarletEvent)` | Injects synthetic event (testing) |
| `Filter() *RingBufferFilter` | Returns the ring buffer filter |
| `SetTestEventChannel(ch chan *ScarletEvent)` | Sets test event channel (testing) |
| `AddContainerCgroup(cgroupID uint64, seq uint32) error` | Registers container for kernel-side filtering |
| `RemoveContainerCgroup(cgroupID uint64) error` | Removes container from kernel-side filtering |
| `AddMonitoredSyscall(syscallNr uint32) error` | Adds syscall to kernel-side filter |

### RingBufferFilter

Kernel-side event filtering to reduce userspace processing overhead.

```go
type RingBufferFilter struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewRingBufferFilter() *RingBufferFilter` | Creates new filter (no filtering by default) |
| `SetCategoryFilter(categories []uint8)` | Sets category whitelist |
| `AddCategory(cat uint8)` | Adds category to whitelist |
| `RemoveCategory(cat uint8)` | Removes category from whitelist |
| `SetPIDFilter(pids []uint32)` | Sets PID whitelist |
| `AddPID(pid uint32)` | Adds PID to whitelist |
| `AddPIDBlacklist(pid uint32)` | Adds PID to blacklist (always drop) |
| `SetCgroupFilter(cgroupIDs []uint64)` | Sets cgroup ID whitelist |
| `AddCgroup(cgroupID uint64)` | Adds cgroup ID to whitelist |
| `RemoveCgroup(cgroupID uint64)` | Removes cgroup ID from whitelist |
| `SetSyscallFilter(syscalls []uint16)` | Sets syscall number whitelist |
| `SetDropProbability(p float64)` | Sets load-shedding drop probability (0.0–1.0) |
| `ShouldPass(event *ScarletEvent) bool` | Checks if event should pass the filter |
| `FilterStats() RingBufferFilterStats` | Returns filter statistics |
| `ResetStats()` | Resets filter statistics |
| `IsActive() bool` | Returns true if any filter is configured |

---

## pkg/enrichment

### Manager

```go
type Manager struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewManager(cfg ManagerConfig) (*Manager, error)` | Creates enrichment manager |
| `Start(ctx context.Context)` | Starts background goroutines |
| `Stop()` | Gracefully stops manager |
| `ResolveContainerID(cgroupID uint64, pid uint32) string` | Maps cgroup_id/PID to container ID |
| `GetContainerInfo(containerID string) *ContainerInfo` | Gets cached container metadata |
| `RegisterContainer(info *ContainerInfo)` | Registers a new container |
| `UnregisterContainer(containerID string)` | Unregisters a container |
| `ContainerCount() int` | Returns tracked container count |
| `PruneCaches(idleThreshold time.Duration) int` | Prunes idle entries from all caches |

### ContainerInfo

```go
type ContainerInfo struct {
    ID             string
    Name           string
    Image          string
    ImageDigest    string
    PodName        string
    Namespace      string
    ServiceAccount string
    Labels         map[string]string
    StartedAt      time.Time
    Privileged     bool
    Capabilities   []string
    CgroupID       uint64
}
```

### PIDCache

LRU cache mapping PID → container_id with TTL and pruning.

| Method | Description |
|--------|-------------|
| `NewPIDCache(size int, ttl time.Duration) *PIDCache` | Creates PID cache |
| `Get(pid uint32) string` | Gets container ID for PID |
| `Set(pid uint32, containerID string)` | Sets container ID for PID |
| `Reap()` | Removes expired entries |
| `Prune(idleThreshold time.Duration) int` | Prunes idle entries |
| `Size() int` | Returns number of entries |

### CRICache

LRU cache mapping container ID → ContainerInfo.

| Method | Description |
|--------|-------------|
| `NewCRICache() *CRICache` | Creates CRI cache (unlimited) |
| `NewCRICacheWithMaxSize(maxSize int) *CRICache` | Creates CRI cache with LRU eviction |
| `Get(containerID string) *ContainerInfo` | Gets container info |
| `Set(containerID string, info *ContainerInfo)` | Sets container info |
| `Delete(containerID string)` | Removes a container |
| `Size() int` | Returns number of entries |
| `Prune(idleThreshold time.Duration) int` | Prunes idle entries |
| `GetAllContainerIDs() []string` | Returns all container IDs |

---

## pkg/rules

### Engine

```go
type Engine struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewEngine(cfg EngineConfig) (*Engine, error)` | Creates and loads default rules |
| `EvaluateRule(event *EnrichedEventForRule) *RuleMatch` | Evaluates event against rules |
| `RuleCount() int` | Returns total rule count |
| `EnforceCount() int` | Returns enforce-mode rule count |
| `AlertCount() int` | Returns alert-mode rule count |
| `Reload() error` | Hot-reloads rules from disk |
| `CorrelationRules() []CorrelationRule` | Returns rules with correlation specs |

### RuleMatch

Result of a successful rule evaluation.

```go
type RuleMatch struct {
    RuleID   string
    RuleName string
    Priority string    // CRITICAL, ERROR, WARNING, INFO
    Action   string    // alert, enforce, suppress
    Output   string
    Tags     []string
}
```

### Priority Constants

```go
const (
    PriorityCritical string = "CRITICAL"
    PriorityError    string = "ERROR"
    PriorityWarning  string = "WARNING"
    PriorityInfo     string = "INFO"
)
```

---

## pkg/pipeline

### Pipeline

Core event processing pipeline.

```go
type Pipeline struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewPipeline(cfg PipelineConfig) *Pipeline` | Creates new pipeline |
| `Start(ctx context.Context)` | Starts event processing |
| `Stop()` | Gracefully stops pipeline |
| `ProcessEvent(event *ebpf.ScarletEvent)` | Processes a single event (testing) |
| `SetMode(mode string)` | Changes mode at runtime |
| `SetNetworkEnforcer(ne *enforcement.NetworkEnforcer)` | Sets network enforcer |
| `SetCorrelator(c *correlate.Correlator)` | Sets correlation engine |
| `SetAIAlertTrier(trier AIAlertTrier)` | Sets AI triage service |
| `SetAIRuleSuggester(suggester AIRuleSuggester)` | Sets AI rule suggestion service |
| `InitCorrelationRules()` | Registers correlation rules |
| `SetAnomalyEnabled(enabled bool)` | Enables/disables anomaly scoring |
| `SetBaseline(image string, baseline *ai.NgramBaseline)` | Sets n-gram baseline |
| `SetTriageThresholds(suppress, downgrade, adjust float64)` | Sets AI triage thresholds |
| `SetLearningMode(enabled bool)` | Enables/disables baseline learning |
| `EventsProcessed() uint64` | Returns total events processed |
| `AlertsEmitted() uint64` | Returns total alerts emitted |
| `EnforcementsExecuted() uint64` | Returns total enforcements |

### Interfaces

#### `AlertEmitter`

```go
type AlertEmitter interface {
    Emit(alert *output.Alert)
}
```

#### `AIAlertTrier`

```go
type AIAlertTrier interface {
    TriageAlert(ruleID, priority, namespace, container string) (fpScore float64, recommendedPriority string, reasoning string)
}
```

#### `AIRuleSuggester`

```go
type AIRuleSuggester interface {
    SuggestRule(ctx context.Context, incident *ai.IncidentContext) (*ai.RuleSuggestion, error)
}
```

### PipelineConfig

```go
type PipelineConfig struct {
    EventChannel    <-chan *ebpf.ScarletEvent
    RuleEngine      *rules.Engine
    Enricher        *enrichment.Manager
    AlertEmitter    AlertEmitter
    MetricsExporter  *output.MetricsExporter
    NetworkEnforcer *enforcement.NetworkEnforcer
    Correlator      *correlate.Correlator
    AIConnector     AIAlertTrier
    Mode            string   // audit, enforce, simulate
    AnomalyThreshold float64 // default: 0.8
    AnomalyEnabled   bool    // default: true
    AIRuleSuggester  AIRuleSuggester
    SuggestionMinConfidence float64 // default: 0.5
    TriageSuppressThreshold   float64 // default: 0.9
    TriageDowngradeThreshold  float64 // default: 0.7
    TriageAdjustThreshold     float64 // default: 0.5
    LearningMode        bool // default: true (use SetLearningMode to disable)
    MinEventsForBaseline int  // default: 100
    Workers        int // default: 4
    BatchSize      int // default: 1
    CoalesceWindow time.Duration
}
```

### ResponseActor

Executes enforcement with the 7-rule safety protocol.

| Method | Description |
|--------|-------------|
| `NewResponseActor(mode string) *ResponseActor` | Creates response actor |
| `Enforce(event *EnrichedEvent, match *rules.RuleMatch) EnforcementResult` | Executes enforcement action |
| `SetMode(mode string)` | Changes mode at runtime |
| `AuditLog() *EnforcementAuditLog` | Returns enforcement audit log |

### EventCategorySignal

```go
func EventCategorySignal(event *ebpf.ScarletEvent) string
```

Maps event categories to correlation signal names. Key mappings:
- Port 4444 → `"minerpool_connection"` (not net_outbound)
- Port 443 → `"tls_connection"`
- Port 53 → `"dns_query"`
- Shell exec → `"shell_procs"`
- Mining pool port → `"minerpool_connection"`

---

## pkg/correlate

### Correlator

```go
type Correlator struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewCorrelator() *Correlator` | Creates correlator |
| `AddRule(spec *CorrelationSpec)` | Adds correlation rule |
| `RemoveRule(ruleID string)` | Removes rule |
| `RuleCount() int` | Returns rule count |
| `ProcessSignal(signal *Signal) *CorrelationResult` | Processes a signal against all rules |
| `SetResultChannel(ch chan<- CorrelationResult)` | Sets output channel |
| `Start()` | Starts background goroutines |
| `Stop()` | Gracefully stops |
| `Stats() CorrelatorStats` | Returns statistics |

### CorrelationSpec

```go
type CorrelationSpec struct {
    RuleID  string
    Window  time.Duration
    Signals []string
    Logic   CorrelationLogic  // LogicAll or LogicAny
    GroupBy []string
}
```

### Default Correlation Rules (7 total)

| Rule ID | Signals | Logic | Window | Group By |
|---------|---------|-------|--------|----------|
| R014 | shell_procs + net_outbound | All | 5s | proc.pid |
| R011 | high_cpu + minerpool_connection | All | 30s | container.id |
| R021-R018 | setuid_transition + sensitive_file_read | All | 10s | proc.pid |
| R003-R001 | cgroup_mount + namespace_join | All | 5s | container.id |
| TLS-SNI-001 | tls_suspicious_sni + minerpool_connection | Any | 30s | container.id |
| DNS-SNI-001 | dns_suspicious_query + tls_suspicious_sni | Any | 10s | container.id |
| DNS-001 | dns_suspicious_query | Any | 60s | container.id |

---

## pkg/enforcement

### NetworkEnforcer

TC-based network blocking with IP:port rules.

| Method | Description |
|--------|-------------|
| `NewNetworkEnforcer() *NetworkEnforcer` | Creates network enforcer |
| `Start()` | Starts background routines |
| `Stop()` | Stops enforcer |
| `BlockMiningPool(ip net.IP, port uint16) error` | Blocks mining pool destination |
| `BlockC2Port(ip net.IP, port uint16) error` | Blocks C2 destination |
| `BlockCloudMetadata() error` | Blocks 169.254.169.254 |
| `SetBlocklistUpdater(updater BlocklistUpdater)` | Sets blocklist update handler |
| `BlockCount() int` | Returns block count |
| `Stats() NetworkEnforcerStats` | Returns statistics |

---

## pkg/output

### AlertEmitter

```go
type AlertEmitter struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewAlertEmitter(cfg AlertEmitterConfig) (*AlertEmitter, error)` | Creates alert emitter |
| `Emit(alert *Alert)` | Emits an alert |
| `Flush()` | Flushes buffered output |
| `Close()` | Closes emitter |
| `Count() uint64` | Returns alert count |

### Alert

```go
type Alert struct {
    Timestamp      time.Time
    RuleID         string
    RuleName       string
    Priority       string     // CRITICAL, ERROR, WARNING, INFO
    Action         string     // alert, enforce, simulate
    Output         string
    ProcessName    string
    PID            uint32
    ContainerID    string
    ContainerName  string
    ContainerImage string
    PodName        string
    Namespace      string
    AnomalyScore   float64
    Tags           []string
    // ... and more
}
```

### WebhookManager

| Method | Description |
|--------|-------------|
| `NewWebhookManager(sinks []WebhookSinkConfig) *WebhookManager` | Creates webhook manager |
| `Send(alert *Alert)` | Sends alert to all sinks (async) |
| `AddSink(sink WebhookSink)` | Adds a sink at runtime |
| `RemoveSink(sinkType WebhookSinkType, url string)` | Removes a sink |
| `Flush()` | Flushes all sinks |
| `Close()` | Closes all sinks |
| `Stats() WebhookManagerStats` | Returns stats |

### MetricsExporter

```go
type MetricsExporter struct { ... }
```

| Method | Description |
|--------|-------------|
| `NewMetricsExporter(port int) *MetricsExporter` | Creates metrics exporter |
| `Start(ctx context.Context)` | Starts HTTP server |
| `Stop()` | Stops server |
| `RecordRuleMatch(ruleID, action string)` | Records rule match metric |
| `RecordEventProcessed(action, category string)` | Records event processed metric |
| `RecordEnforcement(action, reason string)` | Records enforcement metric |

---

## pkg/ai

### AIConnector

Implements both `AIAlertTrier` and `AIRuleSuggester` interfaces.

| Method | Description |
|--------|-------------|
| `NewAIConnector(cfg AIConnectorConfig) *AIConnector` | Creates AI connector |
| `TriageAlert(ruleID, priority, namespace, container string) (float64, string, string)` | AI alert triage |
| `SuggestRule(ctx, incident) (*RuleSuggestion, error)` | AI rule suggestion |
| `AnalyzeEvent(ctx, event) (*AIEventResult, error)` | Event analysis |
| `IsEnabled() bool` | Returns whether AI is enabled |
| `Stop()` | Stops connector |

### Key Types

```go
type IncidentContext struct {
    RuleID         string
    ContainerImage string
    Namespace      string
    Timestamp      time.Time
    Events         []AIEvent
}

type RuleSuggestion struct {
    RuleYAML    string
    Confidence  float64
    Status      string  // draft, approved, rejected
    Reasoning   string
}

type NgramBaseline struct {
    Image         string
    Confidence    float64
    TotalNgrams   uint64
    UniqueNgrams  uint64
}
```

---

## pkg/crd

Custom Resource Definition types for Kubernetes integration. See `pkg/crd/types.go`
for the full list of CRD types including `SecurityPolicy`, `EnforcementAction`,
`PolicyException`, and `BlocklistEntry`.