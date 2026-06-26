// Package agent - config.go
// Configuration for the SecurityScarlet Runtime agent.

package agent

import (
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

// Config is the top-level configuration for the SecurityScarlet Runtime agent.
type Config struct {
	Agent       AgentConfig       `json:"agent"`
	Enrichment  EnrichmentConfig  `json:"enrichment"`
	Rules       RulesConfig       `json:"rules"`
	Enforcement EnforcementConfig `json:"enforcement"`
	Output      OutputConfig      `json:"output"`
	AI          AIConfig          `json:"ai"`
	Metrics     MetricsConfig     `json:"metrics"`
	Webhook     WebhookConfig     `json:"webhook"`

	// Internal fields (not from YAML)
	Version string `json:"-"`
}

// AgentConfig holds agent-level settings.
type AgentConfig struct {
	Mode             string `json:"mode"`
	LogLevel         string `json:"log_level"`
	RingBufferSizeMB int    `json:"ring_buffer_size_mb"`
	K8sNodeName      string `json:"k8s_node_name"`
	BPFObjectDir     string `json:"bpf_object_dir"`
	ProcFSPath       string `json:"procfs_path"`
	SysFSPath        string `json:"sysfs_path"`
}

// EnrichmentConfig holds container enrichment settings.
type EnrichmentConfig struct {
	CRIEndpoint  string `json:"cri_endpoint"`
	K8sNodeName  string `json:"k8s_node_name"`
	PIDCacheSize int    `json:"pid_cache_size"`
	PIDCacheTTL  int    `json:"pid_cache_ttl"` // seconds
	ProcFSPath   string `json:"procfs_path"`
}

// RulesConfig holds rule engine settings.
type RulesConfig struct {
	Paths          []string `json:"paths"`
	ReloadOnChange bool     `json:"reload_on_change"`
}

// EnforcementConfig holds enforcement policy settings.
type EnforcementConfig struct {
	ProtectedNamespaces []string `json:"protected_namespaces"`
	MaxKillsPerPod      int      `json:"max_kills_per_pod"`
	WindowSeconds       int      `json:"window_seconds"`
	SimulateMinHours    int      `json:"simulate_minimum_hours"`
}

// OutputConfig holds output destination settings.
type OutputConfig struct {
	AlertFile      string            `json:"alert_file"`
	WebhookURL     string            `json:"webhook_url"`
	WebhookHeaders map[string]string `json:"webhook_headers"`
}

// AIConfig holds SecurityScarletAI integration settings.
type AIConfig struct {
	Enabled          bool    `json:"enabled"`
	Endpoint         string  `json:"endpoint"`
	AnomalyThreshold float64 `json:"anomaly_threshold"`
	LearningMode     bool    `json:"learning_mode"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// WebhookConfig holds webhook receiver settings.
type WebhookConfig struct {
	Port    int    `json:"port"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`

	// Sinks is a list of webhook destination configurations.
	// Each sink describes a type (slack, pagerduty, generic), URL, and settings.
	Sinks []WebhookSinkConfigRef `json:"sinks,omitempty"`
}

// WebhookSinkConfigRef is the agent-level representation of a webhook sink.
// It mirrors the output.WebhookSinkConfig fields relevant to YAML config.
type WebhookSinkConfigRef struct {
	Type                  string            `json:"type"  yaml:"type"`
	URL                   string            `json:"url"   yaml:"url"`
	Headers               map[string]string `json:"headers,omitempty"             yaml:"headers,omitempty"`
	RetryCount            int               `json:"retry_count,omitempty"        yaml:"retry_count,omitempty"`
	Timeout               int               `json:"timeout,omitempty"             yaml:"timeout,omitempty"` // seconds
	BatchSize             int               `json:"batch_size,omitempty"          yaml:"batch_size,omitempty"`
	TLSInsecureSkipVerify bool              `json:"tls_insecure_skip_verify,omitempty" yaml:"tls_insecure_skip_verify,omitempty"`
	Enabled               bool              `json:"enabled,omitempty"             yaml:"enabled,omitempty"`
	PagerDutyRoutingKey   string            `json:"pagerduty_routing_key,omitempty" yaml:"pagerduty_routing_key,omitempty"`
	SlackChannel          string            `json:"slack_channel,omitempty"       yaml:"slack_channel,omitempty"`
	SlackUsername         string            `json:"slack_username,omitempty"      yaml:"slack_username,omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		hostname, _ := os.Hostname()
		nodeName = hostname
	}

	return &Config{
		Agent: AgentConfig{
			Mode:             "audit",
			LogLevel:         "info",
			RingBufferSizeMB: 4,
			K8sNodeName:      nodeName,
			BPFObjectDir:     "/opt/scarlet/bpf",
			ProcFSPath:       "/host/proc",
			SysFSPath:        "/sys/kernel/debug",
		},
		Enrichment: EnrichmentConfig{
			CRIEndpoint:  "/run/containerd/containerd.sock",
			K8sNodeName:  nodeName,
			PIDCacheSize: 10000,
			PIDCacheTTL:  300,
			ProcFSPath:   "/host/proc",
		},
		Rules: RulesConfig{
			Paths:          []string{"/etc/scarlet/rules.d/"},
			ReloadOnChange: true,
		},
		Enforcement: EnforcementConfig{
			ProtectedNamespaces: []string{"kube-system", "kube-public"},
			MaxKillsPerPod:      10,
			WindowSeconds:       60,
			SimulateMinHours:    48,
		},
		Output: OutputConfig{
			AlertFile:      "/var/log/scarlet/alerts.jsonl",
			WebhookURL:     "",
			WebhookHeaders: map[string]string{},
		},
		AI: AIConfig{
			Enabled:          false,
			Endpoint:         "scarlet-ai:9443",
			AnomalyThreshold: 0.8,
			LearningMode:     false,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9090,
		},
		Webhook: WebhookConfig{
			Port:    8443,
			TLSCert: "/etc/scarlet/tls/tls.crt",
			TLSKey:  "/etc/scarlet/tls/tls.key",
		},
	}
}

// LoadConfig reads configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return cfg, nil
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	// Validate mode
	validModes := map[string]bool{"audit": true, "enforce": true, "simulate": true}
	if !validModes[c.Agent.Mode] {
		return fmt.Errorf("invalid agent mode: %s", c.Agent.Mode)
	}

	// Validate ring buffer size
	if c.Agent.RingBufferSizeMB < 1 || c.Agent.RingBufferSizeMB > 64 {
		return fmt.Errorf("ring buffer size must be between 1 and 64 MB, got %d", c.Agent.RingBufferSizeMB)
	}

	// Validate enforcement
	if c.Enforcement.MaxKillsPerPod < 1 {
		return fmt.Errorf("max_kills_per_pod must be >= 1, got %d", c.Enforcement.MaxKillsPerPod)
	}
	if c.Enforcement.WindowSeconds < 1 {
		return fmt.Errorf("window_seconds must be >= 1, got %d", c.Enforcement.WindowSeconds)
	}
	if c.Enforcement.SimulateMinHours < 0 {
		return fmt.Errorf("simulate_minimum_hours must be >= 0, got %d", c.Enforcement.SimulateMinHours)
	}

	// Validate metrics port
	if c.Metrics.Port < 1 || c.Metrics.Port > 65535 {
		return fmt.Errorf("invalid metrics port: %d", c.Metrics.Port)
	}

	// Validate AI config if enabled
	if c.AI.Enabled {
		if c.AI.Endpoint == "" {
			return fmt.Errorf("AI endpoint must be specified when AI is enabled")
		}
		if c.AI.AnomalyThreshold < 0 || c.AI.AnomalyThreshold > 1 {
			return fmt.Errorf("anomaly_threshold must be between 0 and 1, got %f", c.AI.AnomalyThreshold)
		}
	}

	return nil
}

// ApplyOverrides applies command-line flag overrides to the config.
func (c *Config) ApplyOverrides(mode string, rulesPath string, verbose bool) {
	if mode != "" {
		c.Agent.Mode = mode
	}
	if rulesPath != "" {
		c.Rules.Paths = []string{rulesPath}
	}
	if verbose {
		c.Agent.LogLevel = "debug"
	}
}

// Uptime returns the config's enforcement simulate minimum as a duration.
func (c *Config) SimulateMinimumDuration() time.Duration {
	return time.Duration(c.Enforcement.SimulateMinHours) * time.Hour
}
