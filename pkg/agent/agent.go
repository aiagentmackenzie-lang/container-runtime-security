// Package agent implements the SecurityScarlet Runtime agent.
// The agent runs as a DaemonSet on each Kubernetes node and coordinates
// eBPF probe loading, event processing, rule evaluation, and enforcement.
package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/securityscarlet/runtime/pkg/ai"
	"github.com/securityscarlet/runtime/pkg/ai/proto"
	"github.com/securityscarlet/runtime/pkg/correlate"
	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/enrichment"
	"github.com/securityscarlet/runtime/pkg/output"
	"github.com/securityscarlet/runtime/pkg/pipeline"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Operating Modes ──────────────────────────────────────────────────

// Mode defines the agent's operating mode.
type Mode string

const (
	// ModeAudit logs alerts but does not enforce.
	ModeAudit Mode = "audit"

	// ModeEnforce logs alerts AND takes enforcement action (SIGKILL, LSM deny).
	ModeEnforce Mode = "enforce"

	// ModeSimulate logs what WOULD have been enforced, but takes no action.
	// New policies must run in simulate mode for 48h before enforce.
	ModeSimulate Mode = "simulate"
)

// ModeFromString converts a string to a Mode, returning an error if invalid.
func ModeFromString(s string) (Mode, error) {
	switch s {
	case string(ModeAudit):
		return ModeAudit, nil
	case string(ModeEnforce):
		return ModeEnforce, nil
	case string(ModeSimulate):
		return ModeSimulate, nil
	default:
		return "", fmt.Errorf("invalid mode: %s (must be audit, enforce, or simulate)", s)
	}
}

// ── Agent Status ─────────────────────────────────────────────────────

// Status represents the current state of the agent.
type Status string

const (
	StatusStarting Status = "starting"
	StatusRunning  Status = "running"
	StatusStopping Status = "stopping"
	StatusStopped  Status = "stopped"
	StatusError    Status = "error"
)

// AgentStatus holds detailed agent status information.
type AgentStatus struct {
	Status      Status     `json:"status"`
	Mode        Mode       `json:"mode"`
	StartTime   time.Time  `json:"start_time"`
	Uptime      string     `json:"uptime"`
	Version     string     `json:"version"`
	NodeName    string     `json:"node_name"`
	Containers  int        `json:"containers_tracked"`
	RulesLoaded int        `json:"rules_loaded"`
	EventsTotal uint64     `json:"events_total"`
	AlertsTotal uint64     `json:"alerts_total"`
	EnforceTotal uint64    `json:"enforcement_total"`
	EBPFStatus  string     `json:"ebpf_status"`
}

// ── Agent ─────────────────────────────────────────────────────────────

// Agent is the main runtime security agent that coordinates all components.
type Agent struct {
	config    *Config
	mode      Mode
	status    Status
	startTime time.Time

	// Core components
	loader      *ebpf.Loader
	pipeline    *pipeline.Pipeline
	ruleEngine  *rules.Engine
	enricher    *enrichment.Manager
	alertEmit   *output.AlertEmitter
	metrics     *output.MetricsExporter

	// Intelligence components (Phase 3)
	tcLoader     *ebpf.TCLoader
	netEnforcer  *enforcement.NetworkEnforcer
	correlator   *correlate.Correlator
	aiConnector  *ai.AIConnector
	grpcClient   *proto.SecurityScarletAIClient

	// Counters
	eventsTotal    uint64
	alertsTotal    uint64
	enforceTotal   uint64

	mu sync.RWMutex
}

// New creates a new Agent from the given configuration.
func New(cfg *Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	mode, err := ModeFromString(cfg.Agent.Mode)
	if err != nil {
		return nil, err
	}

	a := &Agent{
		config:    cfg,
		mode:      mode,
		status:    StatusStarting,
		startTime: time.Now(),
	}

	return a, nil
}

// Start runs the agent. This is the main entry point; it blocks until
// the context is cancelled or a termination signal is received.
func (a *Agent) Start(ctx context.Context) error {
	log.Printf("[agent] SecurityScarlet Runtime Agent starting...")
	log.Printf("[agent] Mode: %s", a.mode)
	log.Printf("[agent] Version: %s", a.config.Version)
	log.Printf("[agent] Node: %s", a.config.Agent.K8sNodeName)

	a.setStatus(StatusStarting)

	// Initialize components in order
	if err := a.initComponents(ctx); err != nil {
		a.setStatus(StatusError)
		return fmt.Errorf("agent initialization failed: %w", err)
	}

	// Start the event processing loop
	a.setStatus(StatusRunning)
	log.Printf("[agent] Agent is running in %s mode", a.mode)

	// Block until context cancelled or signal
	a.runLoop(ctx)

	// Graceful shutdown
	a.setStatus(StatusStopping)
	a.shutdown()
	a.setStatus(StatusStopped)

	log.Printf("[agent] Agent stopped. Uptime: %s", time.Since(a.startTime))
	return nil
}

// initComponents initializes all agent components in dependency order.
func (a *Agent) initComponents(ctx context.Context) error {
	var err error

	// 1. Initialize metrics exporter
	log.Printf("[agent] Initializing metrics exporter on :%d", a.config.Metrics.Port)
	a.metrics = output.NewMetricsExporter(a.config.Metrics.Port)

	// 2. Initialize alert emitter
	log.Printf("[agent] Initializing alert emitter -> %s", a.config.Output.AlertFile)

	// Build webhook manager from configured sinks
	var webhookManager *output.WebhookManager
	if len(a.config.Webhook.Sinks) > 0 {
		sinkConfigs := make([]output.WebhookSinkConfig, 0, len(a.config.Webhook.Sinks))
		for _, ref := range a.config.Webhook.Sinks {
			cfg := output.DefaultWebhookSinkConfig()
			cfg.Type = output.WebhookSinkType(ref.Type)
			cfg.URL = ref.URL
			cfg.Headers = ref.Headers
			if ref.RetryCount > 0 {
				cfg.RetryCount = ref.RetryCount
			}
			if ref.Timeout > 0 {
				cfg.Timeout = time.Duration(ref.Timeout) * time.Second
			}
			if ref.BatchSize > 0 {
				cfg.BatchSize = ref.BatchSize
			}
			cfg.TLSInsecureSkipVerify = ref.TLSInsecureSkipVerify
			cfg.Enabled = ref.Enabled
			cfg.PagerDutyRoutingKey = ref.PagerDutyRoutingKey
			cfg.SlackChannel = ref.SlackChannel
			cfg.SlackUsername = ref.SlackUsername
			sinkConfigs = append(sinkConfigs, cfg)
		}
		webhookManager = output.NewWebhookManager(sinkConfigs)
		log.Printf("[agent] Webhook manager configured with %d sinks", len(sinkConfigs))
	}

	a.alertEmit, err = output.NewAlertEmitter(output.AlertEmitterConfig{
		AlertFile:      a.config.Output.AlertFile,
		WebhookURL:     a.config.Output.WebhookURL,
		WebhookHeaders: a.config.Output.WebhookHeaders,
		Mode:           string(a.mode),
		WebhookManager: webhookManager,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize alert emitter: %w", err)
	}

	// 3. Initialize enrichment manager
	log.Printf("[agent] Initializing container enrichment (CRI: %s)", a.config.Enrichment.CRIEndpoint)
	a.enricher, err = enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:   a.config.Enrichment.CRIEndpoint,
		K8sNodeName:   a.config.Agent.K8sNodeName,
		PIDCacheSize:  a.config.Enrichment.PIDCacheSize,
		PIDCacheTTL:   time.Duration(a.config.Enrichment.PIDCacheTTL) * time.Second,
		ProcFSPath:    a.config.Agent.ProcFSPath,
	})
	if err != nil {
		log.Printf("[agent] Warning: enrichment initialization failed: %v (proceeding with limited enrichment)", err)
	}

	// 4. Initialize rule engine
	log.Printf("[agent] Loading rules from %s", a.config.Rules.Paths)
	a.ruleEngine, err = rules.NewEngine(rules.EngineConfig{
		RulePaths:     a.config.Rules.Paths,
		DefaultMode:   string(a.mode),
		ReloadOnWatch: a.config.Rules.ReloadOnChange,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize rule engine: %w", err)
	}
	ruleCount := a.ruleEngine.RuleCount()
	log.Printf("[agent] Loaded %d rules (%d enforce, %d alert)", ruleCount,
		a.ruleEngine.EnforceCount(), a.ruleEngine.AlertCount())

	// 5. Initialize eBPF loader
	log.Printf("[agent] Initializing eBPF probes")
	a.loader = ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjectDir:    a.config.Agent.BPFObjectDir,
		RingBufSizeMB:   a.config.Agent.RingBufferSizeMB,
		PollInterval:    100 * time.Millisecond,
		EventBufferSize: 2048,
	})

	// Load eBPF programs
	if err := a.loader.Load(ctx); err != nil {
		log.Printf("[agent] Warning: eBPF load failed: %v (running in fallback mode)", err)
	} else {
		// Attach probes
		if err := a.loader.Attach(ctx); err != nil {
			log.Printf("[agent] Warning: eBPF attach failed: %v", err)
		}
	}

	// 6. Initialize network enforcer with TC loader
	log.Printf("[agent] Initializing network policy enforcer")
	a.netEnforcer = enforcement.NewNetworkEnforcer()

	// Create and load TC programs for network blocking
	a.tcLoader = ebpf.NewTCLoader(ebpf.TCLoaderConfig{
		BPFObjectDir: a.config.Agent.BPFObjectDir,
		Interfaces:   []string{"eth0"},
	})
	if err := a.tcLoader.Load(); err != nil {
		log.Printf("[agent] Warning: TC loader failed to load: %v (network enforcement in userspace-only mode)", err)
	} else {
		if err := a.tcLoader.Attach(); err != nil {
			log.Printf("[agent] Warning: TC loader attach failed: %v", err)
		}
		// Wire TC loader to network enforcer for BPF map operations
		a.netEnforcer.SetTCLoader(a.tcLoader)
		log.Printf("[agent] TC loader wired to network enforcer")
	}
	a.netEnforcer.Start()

	// 7. Initialize multi-signal correlation engine
	log.Printf("[agent] Initializing correlation engine")
	a.correlator = correlate.NewCorrelator()
	a.correlator.Start()

	// 8. Initialize AI connector (SecurityScarletAI gRPC)
	log.Printf("[agent] Initializing AI connector (endpoint=%s enabled=%v)",
		a.config.AI.Endpoint, a.config.AI.Enabled)
	a.aiConnector = ai.NewAIConnector(ai.AIConnectorConfig{
		Endpoint: a.config.AI.Endpoint,
		Timeout:  5 * time.Second,
		Enabled:  a.config.AI.Enabled,
	})

	// Create gRPC client for the AI service
	a.grpcClient = proto.NewSecurityScarletAIClient(a.config.AI.Endpoint, 5*time.Second)
	if a.config.AI.Enabled {
		// Attempt gRPC connection (non-blocking — degrades gracefully)
		if err := a.grpcClient.Connect(ctx); err != nil {
			log.Printf("[agent] Warning: AI gRPC connection failed: %v (operating in degraded mode)", err)
		}
	}

	// 9. Initialize event processing pipeline with all components
	log.Printf("[agent] Initializing event processing pipeline")
	a.pipeline = pipeline.NewPipeline(pipeline.PipelineConfig{
		EventChannel:    a.loader.Events(),
		RuleEngine:      a.ruleEngine,
		Enricher:        a.enricher,
		AlertEmitter:    a.alertEmit,
		MetricsExporter: a.metrics,
		NetworkEnforcer: a.netEnforcer,
		Correlator:      a.correlator,
		AIConnector:     a.aiConnector,
		Mode:            string(a.mode),

		AnomalyThreshold: a.config.AI.AnomalyThreshold,
		// LearningMode defaults to true in the pipeline; use SetLearningMode to disable
	})

	// Wire intelligence components into pipeline
	a.pipeline.SetAIAlertTrier(a.aiConnector)
	a.pipeline.SetAIRuleSuggester(a.aiConnector)
	a.pipeline.InitCorrelationRules()

	log.Printf("[agent] Pipeline wired: correlator=%d rules, AI triage=%v, network enforcer=%v",
		a.correlator.Stats().RulesCount, a.config.AI.Enabled, a.tcLoader != nil)

	// Register containers already running on this node
	if a.enricher != nil {
		a.enricher.Start(ctx)
		containerCount := a.enricher.ContainerCount()
		log.Printf("[agent] Tracking %d existing containers", containerCount)
	}

	return nil
}

// runLoop is the main agent loop — processes events until context is cancelled.
func (a *Agent) runLoop(ctx context.Context) {
	// Start the pipeline
	pipelineCtx, pipelineCancel := context.WithCancel(ctx)
	defer pipelineCancel()

	a.pipeline.Start(pipelineCtx)

	// Start metrics HTTP server
	if a.metrics != nil {
		go a.metrics.Start(ctx)
	}

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Main loop
	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] Context cancelled, shutting down...")
			return
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("[agent] Received signal %v, shutting down...", sig)
				return
			case syscall.SIGHUP:
				log.Printf("[agent] Received SIGHUP, reloading rules...")
				a.reloadRules()
			}
		}
	}
}

// shutdown gracefully stops all components.
func (a *Agent) shutdown() {
	log.Printf("[agent] Shutting down agent...")

	// Stop pipeline first (drain events)
	if a.pipeline != nil {
		a.pipeline.Stop()
	}

	// Stop AI connector
	if a.aiConnector != nil {
		a.aiConnector.Stop()
	}

	// Disconnect gRPC client
	if a.grpcClient != nil {
		a.grpcClient.Disconnect()
	}

	// Stop correlation engine
	if a.correlator != nil {
		a.correlator.Stop()
	}

	// Stop network enforcer
	if a.netEnforcer != nil {
		a.netEnforcer.Stop()
	}

	// Detach and close TC programs
	if a.tcLoader != nil {
		a.tcLoader.Close()
	}

	// Stop eBPF loader
	if a.loader != nil {
		a.loader.Stop()
	}

	// Stop enrichment
	if a.enricher != nil {
		a.enricher.Stop()
	}

	// Flush alerts
	if a.alertEmit != nil {
		a.alertEmit.Flush()
	}

	// Final metrics export
	if a.metrics != nil {
		a.metrics.Stop()
	}

	log.Printf("[agent] Shutdown complete")
}

// reloadRules hot-reloads the rule set from disk.
func (a *Agent) reloadRules() {
	if a.ruleEngine == nil {
		return
	}

	if err := a.ruleEngine.Reload(); err != nil {
		log.Printf("[agent] Rule reload failed: %v", err)
		return
	}

	count := a.ruleEngine.RuleCount()
	log.Printf("[agent] Rules reloaded: %d rules (%d enforce, %d alert)",
		count, a.ruleEngine.EnforceCount(), a.ruleEngine.AlertCount())
}

// GetStatus returns the current agent status.
func (a *Agent) GetStatus() AgentStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := AgentStatus{
		Status:    a.status,
		Mode:      a.mode,
		StartTime: a.startTime,
		Version:   a.config.Version,
		NodeName:  a.config.Agent.K8sNodeName,
	}

	status.Uptime = time.Since(a.startTime).Round(time.Second).String()

	if a.ruleEngine != nil {
		status.RulesLoaded = a.ruleEngine.RuleCount()
	}

	if a.enricher != nil {
		status.Containers = a.enricher.ContainerCount()
	}

	if a.pipeline != nil {
		status.EventsTotal = a.pipeline.EventsProcessed()
		status.AlertsTotal = a.pipeline.AlertsEmitted()
		status.EnforceTotal = a.pipeline.EnforcementsExecuted()
	}

	return status
}

// SetMode changes the agent's operating mode at runtime.
func (a *Agent) SetMode(mode Mode) {
	a.mu.Lock()
	defer a.mu.Unlock()

	oldMode := a.mode
	a.mode = mode

	log.Printf("[agent] Mode changed: %s → %s", oldMode, mode)

	if a.pipeline != nil {
		a.pipeline.SetMode(string(mode))
	}
}

// InjectEvent injects a synthetic event for testing.
func (a *Agent) InjectEvent(event *ebpf.ScarletEvent) {
	if a.loader != nil {
		a.loader.InjectEvent(event)
	}
}

// GetTCLOader returns the TC loader (for testing/inspection).
func (a *Agent) GetTCLOader() *ebpf.TCLoader {
	return a.tcLoader
}

// GetNetworkEnforcer returns the network enforcer (for testing/inspection).
func (a *Agent) GetNetworkEnforcer() *enforcement.NetworkEnforcer {
	return a.netEnforcer
}

// GetCorrelator returns the correlation engine (for testing/inspection).
func (a *Agent) GetCorrelator() *correlate.Correlator {
	return a.correlator
}

// GetAIConnector returns the AI connector (for testing/inspection).
func (a *Agent) GetAIConnector() *ai.AIConnector {
	return a.aiConnector
}

// GetPipeline returns the event processing pipeline (for testing/inspection).
func (a *Agent) GetPipeline() *pipeline.Pipeline {
	return a.pipeline
}

// GetRuleEngine returns the rule engine (for testing/inspection).
func (a *Agent) GetRuleEngine() *rules.Engine {
	return a.ruleEngine
}

// GetEnricher returns the enrichment manager (for testing/inspection).
func (a *Agent) GetEnricher() *enrichment.Manager {
	return a.enricher
}

// GetGRPCClient returns the gRPC AI client (for testing/inspection).
func (a *Agent) GetGRPCClient() *proto.SecurityScarletAIClient {
	return a.grpcClient
}

func (a *Agent) setStatus(s Status) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = s
}