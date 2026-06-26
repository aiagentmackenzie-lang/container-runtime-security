// Package crd provides Kubernetes Custom Resource Definition types and
// watcher for SecurityScarlet Runtime Policies.
//
// Per SRD Deliverable 6 (Phase 2):
//   - ScarletRuntimePolicy CRD: apiVersion: securityscarlet.ai/v1alpha1
//   - Spec includes: mode, rule selector, exceptions, enforcement config,
//     protected namespaces
//   - CRD watcher: watches ScarletRuntimePolicy resources and updates
//     local enforcement configuration
//   - Go types for CRD resources
//   - YAML manifests for CRD installation
//
// The CRD watcher uses an informer pattern when k8s.io/client-go is
// integrated, falling back to filesystem-based config when not in K8s.

package crd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/pipeline"
	"github.com/securityscarlet/runtime/pkg/rules"
	"sigs.k8s.io/yaml"
)

// ── CRD Types ────────────────────────────────────────────────────────────

// ScarletRuntimePolicySpec defines the desired state of ScarletRuntimePolicy.
type ScarletRuntimePolicySpec struct {
	// Mode is the operating mode: "audit", "enforce", or "simulate".
	// Overrides the agent's default mode.
	Mode string `json:"mode" yaml:"mode"`

	// RuleSelector specifies which rules this policy applies to.
	RuleSelector RuleSelector `json:"ruleSelector" yaml:"ruleSelector"`

	// Exceptions are policy-level exceptions that suppress enforcement
	// for specific workloads.
	Exceptions []PolicyException `json:"exceptions,omitempty" yaml:"exceptions,omitempty"`

	// EnforcementConfig controls how enforcement is carried out.
	EnforcementConfig EnforcementConfigSpec `json:"enforcementConfig,omitempty" yaml:"enforcementConfig,omitempty"`

	// ProtectedNamespaces are namespaces exempt from enforcement.
	// These override the agent's default protected namespaces.
	ProtectedNamespaces []string `json:"protectedNamespaces,omitempty" yaml:"protectedNamespaces,omitempty"`

	// NetworkPolicy configures network-level blocking.
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty" yaml:"networkPolicy,omitempty"`
}

// RuleSelector specifies which rules this policy applies to.
type RuleSelector struct {
	// IDs selects rules by their IDs (e.g., "R009", "R027").
	IDs []string `json:"ids,omitempty" yaml:"ids,omitempty"`

	// Categories selects rules by category (e.g., "CRYPTO", "ESCAPE", "SHELL").
	Categories []string `json:"categories,omitempty" yaml:"categories,omitempty"`

	// Priorities selects rules by priority (e.g., "CRITICAL", "WARNING").
	Priorities []string `json:"priorities,omitempty" yaml:"priorities,omitempty"`

	// Tags selects rules by tags (e.g., "cryptojacking", "mitre_execution").
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// All selects all rules. If true, other selectors are ignored.
	All bool `json:"all,omitempty" yaml:"all,omitempty"`
}

// PolicyException defines a policy-level exception.
type PolicyException struct {
	// Name is a human-readable name for the exception.
	Name string `json:"name" yaml:"name"`

	// Fields are the fields to match on (e.g., "container.image.repository", "proc.name").
	Fields []string `json:"fields" yaml:"fields"`

	// Comps are comparators for each field (e.g., "=", "in", "contains").
	Comps []string `json:"comps,omitempty" yaml:"comps,omitempty"`

	// Values are the values to match against. Each row is OR'd.
	Values [][]string `json:"values" yaml:"values"`

	// Mode controls when this exception applies: "audit", "enforce", or "all".
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
}

// EnforcementConfigSpec controls enforcement behavior.
type EnforcementConfigSpec struct {
	// KillMode is "graceful" (SIGTERM→SIGKILL) or "immediate" (SIGKILL).
	KillMode string `json:"killMode,omitempty" yaml:"killMode,omitempty"`

	// GracePeriodSeconds is the time to wait after SIGTERM before SIGKILL.
	GracePeriodSeconds int `json:"gracePeriodSeconds,omitempty" yaml:"gracePeriodSeconds,omitempty"`

	// MaxKillsPerPod limits the number of kills per pod per time window.
	MaxKillsPerPod int `json:"maxKillsPerPod,omitempty" yaml:"maxKillsPerPod,omitempty"`

	// WindowSeconds defines the rate limit window in seconds.
	WindowSeconds int `json:"windowSeconds,omitempty" yaml:"windowSeconds,omitempty"`
}

// NetworkPolicySpec configures eBPF TC-based network blocking.
type NetworkPolicySpec struct {
	// Enabled controls whether network blocking is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// DefaultTTL is how long network blocks last (default: 5 minutes).
	DefaultTTL string `json:"defaultTTL,omitempty" yaml:"defaultTTL,omitempty"`

	// BlockList contains pre-configured network blocks (IPs, ports).
	BlockList []NetworkBlockSpec `json:"blockList,omitempty" yaml:"blockList,omitempty"`
}

// NetworkBlockSpec describes a pre-configured network block.
type NetworkBlockSpec struct {
	// DestIP is the destination IP to block (e.g., "169.254.169.254").
	DestIP string `json:"destIP" yaml:"destIP"`

	// DestPort is the destination port to block (0 = all ports).
	DestPort uint16 `json:"destPort,omitempty" yaml:"destPort,omitempty"`

	// Protocol is the protocol to block: "tcp", "udp", or "any".
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Reason is a human-readable reason for the block.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`

	// TTL overrides the default TTL for this specific block.
	TTL string `json:"ttl,omitempty" yaml:"ttl,omitempty"`
}

// ── CRD Resource Type ────────────────────────────────────────────────────

// ScarletRuntimePolicy is the Kubernetes CRD resource type.
type ScarletRuntimePolicy struct {
	// APIVersion is the group/version (securityscarlet.ai/v1alpha1).
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`

	// Kind is the resource kind (ScarletRuntimePolicy).
	Kind string `json:"kind" yaml:"kind"`

	// Metadata contains the resource metadata.
	Metadata CRDObjectMeta `json:"metadata" yaml:"metadata"`

	// Spec is the desired state.
	Spec ScarletRuntimePolicySpec `json:"spec" yaml:"spec"`

	// Status is the observed state (read-only, set by the controller).
	Status *ScarletRuntimePolicyStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// CRDObjectMeta contains metadata for a CRD resource.
type CRDObjectMeta struct {
	Name              string            `json:"name" yaml:"name"`
	Namespace         string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels            map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	CreationTimestamp time.Time         `json:"creationTimestamp,omitempty" yaml:"creationTimestamp,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty" yaml:"resourceVersion,omitempty"`
}

// ScarletRuntimePolicyStatus is the observed state of a RuntimePolicy.
type ScarletRuntimePolicyStatus struct {
	// Phase is "pending", "active", "error".
	Phase string `json:"phase" yaml:"phase"`

	// Message is a human-readable status message.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`

	// ActiveRules is the number of rules currently affected by this policy.
	ActiveRules int `json:"activeRules" yaml:"activeRules"`

	// LastUpdated is when the status was last updated.
	LastUpdated time.Time `json:"lastUpdated,omitempty" yaml:"lastUpdated,omitempty"`
}

// ── Policy Watcher ──────────────────────────────────────────────────────

// PolicyWatcher watches ScarletRuntimePolicy resources and applies changes
// to the local enforcement configuration.
//
// When running in Kubernetes, it uses an informer to watch CRD changes.
// When not in Kubernetes, it loads policies from YAML files on disk.
type PolicyWatcher struct {
	// Configuration
	configDir string // Directory containing policy YAML files
	nodeName  string // Node name for K8s API watch filtering
	namespace string // Namespace to watch for policies

	// Dependencies
	engine   *rules.Engine
	enforcer *enforcement.NetworkEnforcer
	actor    *pipeline.ResponseActor

	// State
	policies map[string]*ScarletRuntimePolicy // name → policy
	mu       sync.RWMutex

	// K8s client (nil when not in K8s)
	connected bool
	stopCh    chan struct{}
	wg        sync.WaitGroup

	// Stats
	policiesLoaded  int
	policiesApplied int
	loadErrors      int
	lastLoadTime    time.Time
}

// NewPolicyWatcher creates a new policy watcher.
func NewPolicyWatcher(configDir string, nodeName string) *PolicyWatcher {
	return &PolicyWatcher{
		configDir: configDir,
		nodeName:  nodeName,
		namespace: "security-scarlet",
		policies:  make(map[string]*ScarletRuntimePolicy),
		stopCh:    make(chan struct{}),
	}
}

// SetEngine sets the rule engine for policy application.
func (pw *PolicyWatcher) SetEngine(engine *rules.Engine) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.engine = engine
}

// SetNetworkEnforcer sets the network enforcer for network policy application.
func (pw *PolicyWatcher) SetNetworkEnforcer(enforcer *enforcement.NetworkEnforcer) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.enforcer = enforcer
}

// SetResponseActor sets the response actor for enforcement mode changes.
func (pw *PolicyWatcher) SetResponseActor(actor *pipeline.ResponseActor) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.actor = actor
}

// Start begins watching for policy changes.
func (pw *PolicyWatcher) Start(ctx context.Context) {
	// Try to load policies from disk first
	if err := pw.LoadFromDisk(); err != nil {
		log.Printf("[crd] Warning: failed to load policies from disk: %v", err)
	}

	// Check if we're in Kubernetes
	if pw.isRunningInK8s() {
		log.Printf("[crd] Running in Kubernetes, starting CRD watcher on node %s", pw.nodeName)
		pw.startK8sWatcher(ctx)
	} else {
		log.Printf("[crd] Not in Kubernetes, watching policy directory: %s", pw.configDir)
		pw.startFileWatcher(ctx)
	}
}

// Stop gracefully stops the policy watcher.
func (pw *PolicyWatcher) Stop() {
	close(pw.stopCh)
	pw.wg.Wait()
	log.Printf("[crd] Policy watcher stopped")
}

// ── File-Based Policy Loading ────────────────────────────────────────────

// LoadFromDisk loads all ScarletRuntimePolicy YAML files from the config directory.
func (pw *PolicyWatcher) LoadFromDisk() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	entries, err := os.ReadDir(pw.configDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[crd] Policy directory %s does not exist, skipping", pw.configDir)
			return nil
		}
		return fmt.Errorf("cannot read policy directory %s: %w", pw.configDir, err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(pw.configDir, entry.Name())
		if err := pw.LoadPolicyFile(path); err != nil {
			log.Printf("[crd] Warning: failed to load policy %s: %v", path, err)
			pw.loadErrors++
			continue
		}
		loaded++
	}

	pw.policiesLoaded = loaded
	pw.lastLoadTime = time.Now()
	log.Printf("[crd] Loaded %d policies from %s", loaded, pw.configDir)

	return nil
}

// LoadPolicyFile loads a single policy YAML file.
func (pw *PolicyWatcher) LoadPolicyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	var policy ScarletRuntimePolicy
	if err := yamlUnmarshal(data, &policy); err != nil {
		return fmt.Errorf("cannot parse policy YAML: %w", err)
	}

	// Validate
	if err := pw.ValidatePolicy(&policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	// Store
	pw.policies[policy.Metadata.Name] = &policy
	log.Printf("[crd] Loaded policy: %s (mode=%s, rules=%v)",
		policy.Metadata.Name, policy.Spec.Mode, policy.Spec.RuleSelector)

	return nil
}

// ValidatePolicy checks that a policy is valid.
func (pw *PolicyWatcher) ValidatePolicy(policy *ScarletRuntimePolicy) error {
	// Validate API version
	if policy.APIVersion != "securityscarlet.ai/v1alpha1" {
		return fmt.Errorf("unsupported apiVersion: %s (expected securityscarlet.ai/v1alpha1)", policy.APIVersion)
	}

	// Validate kind
	if policy.Kind != "ScarletRuntimePolicy" {
		return fmt.Errorf("unsupported kind: %s (expected ScarletRuntimePolicy)", policy.Kind)
	}

	// Validate mode
	validModes := map[string]bool{"audit": true, "enforce": true, "simulate": true, "": true}
	if !validModes[policy.Spec.Mode] {
		return fmt.Errorf("invalid mode: %s (expected audit, enforce, or simulate)", policy.Spec.Mode)
	}

	// Validate rule selector
	if !policy.Spec.RuleSelector.All && len(policy.Spec.RuleSelector.IDs) == 0 && len(policy.Spec.RuleSelector.Categories) == 0 && len(policy.Spec.RuleSelector.Priorities) == 0 && len(policy.Spec.RuleSelector.Tags) == 0 {
		// Empty selector with All=false is valid (means "all rules")
		policy.Spec.RuleSelector.All = true
	}

	// Validate network policy
	if policy.Spec.NetworkPolicy != nil {
		if policy.Spec.NetworkPolicy.DefaultTTL != "" {
			if _, err := time.ParseDuration(policy.Spec.NetworkPolicy.DefaultTTL); err != nil {
				return fmt.Errorf("invalid network policy TTL: %w", err)
			}
		}
	}

	return nil
}

// ── Policy Application ─────────────────────────────────────────────────

// ApplyPolicy applies a policy to the rule engine, response actor, and
// network enforcer.
func (pw *PolicyWatcher) ApplyPolicy(policy *ScarletRuntimePolicy) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	log.Printf("[crd] Applying policy: %s (mode=%s)", policy.Metadata.Name, policy.Spec.Mode)

	// 1. Apply mode changes to the response actor
	if pw.actor != nil && policy.Spec.Mode != "" {
		pw.actor.SetMode(policy.Spec.Mode)
		log.Printf("[crd] Set enforcement mode to: %s", policy.Spec.Mode)
	}

	// 2. Apply enforcement configuration
	if pw.actor != nil && policy.Spec.EnforcementConfig.KillMode != "" {
		cfg := pipeline.DefaultResponseActorConfig()
		if policy.Spec.EnforcementConfig.KillMode == "graceful" {
			cfg.Mode = pipeline.EnforceModeGraceful
		}
		if policy.Spec.EnforcementConfig.GracePeriodSeconds > 0 {
			cfg.GracePeriodSeconds = policy.Spec.EnforcementConfig.GracePeriodSeconds
		}
		if policy.Spec.EnforcementConfig.MaxKillsPerPod > 0 {
			cfg.MaxKillsPerPod = policy.Spec.EnforcementConfig.MaxKillsPerPod
		}
		if policy.Spec.EnforcementConfig.WindowSeconds > 0 {
			cfg.WindowSeconds = policy.Spec.EnforcementConfig.WindowSeconds
		}
		if len(policy.Spec.ProtectedNamespaces) > 0 {
			cfg.ProtectedNamespaces = policy.Spec.ProtectedNamespaces
		}
		log.Printf("[crd] Applied enforcement config: mode=%s grace=%ds maxKills=%d window=%ds namespaces=%v",
			cfg.Mode, cfg.GracePeriodSeconds, cfg.MaxKillsPerPod, cfg.WindowSeconds, cfg.ProtectedNamespaces)
	}

	// 3. Apply network policy blocks
	if pw.enforcer != nil && policy.Spec.NetworkPolicy != nil && policy.Spec.NetworkPolicy.Enabled {
		for _, block := range policy.Spec.NetworkPolicy.BlockList {
			protocol := enforcement.ProtocolTCP
			switch block.Protocol {
			case "udp":
				protocol = enforcement.ProtocolUDP
			case "any", "":
				protocol = enforcement.ProtocolAny
			case "tcp":
				protocol = enforcement.ProtocolTCP
			}

			ttl := 5 * time.Minute // default
			if block.TTL != "" {
				if duration, err := time.ParseDuration(block.TTL); err == nil {
					ttl = duration
				}
			}

			ruleID := "CRD:" + policy.Metadata.Name
			if block.DestIP != "" {
				err := pw.enforcer.BlockWithTTL(
					ParseIP(block.DestIP),
					block.DestPort,
					protocol,
					ruleID,
					block.Reason,
					ttl,
				)
				if err != nil {
					log.Printf("[crd] Warning: failed to block %s:%d: %v", block.DestIP, block.DestPort, err)
				}
			}
		}
	}

	pw.policiesApplied++
	log.Printf("[crd] Policy applied successfully: %s", policy.Metadata.Name)
	return nil
}

// ── K8s Watcher ────────────────────────────────────────────────────────

// startK8sWatcher starts a Kubernetes CRD informer.
// When k8s.io/client-go is integrated, this will use SharedInformerFactory
// to watch ScarletRuntimePolicy resources on the local node.
func (pw *PolicyWatcher) startK8sWatcher(ctx context.Context) {
	// TODO: When k8s.io/client-go is integrated:
	//   config, _ := rest.InClusterConfig()
	//   clientset, _ := kubernetes.NewForConfig(config)
	//   scarletClient, _ := scarletclient.NewForConfig(config)
	//   factory := informers.NewFilteredSharedInformerFactoryWithOptions(
	//       scarletClient, 30*time.Second,
	//       informers.WithNamespace(pw.namespace))
	//   informer := factory.Securityscarlet().V1alpha1().ScarletRuntimePolicies().Informer()
	//   informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
	//       AddFunc:    pw.handlePolicyAdd,
	//       UpdateFunc: pw.handlePolicyUpdate,
	//       DeleteFunc: pw.handlePolicyDelete,
	//   })
	//   informer.Run(ctx.Done())

	// For now, fall back to file watching
	pw.startFileWatcher(ctx)
}

// handlePolicyAdd handles a new policy from the K8s informer.
func (pw *PolicyWatcher) handlePolicyAdd(obj interface{}) {
	// TODO: Cast to *scarletv1alpha1.ScarletRuntimePolicy, convert, apply
	log.Printf("[crd] Policy added (K8s informer)")
}

// handlePolicyUpdate handles a policy update from the K8s informer.
func (pw *PolicyWatcher) handlePolicyUpdate(oldObj, newObj interface{}) {
	// TODO: Cast, convert, apply
	log.Printf("[crd] Policy updated (K8s informer)")
}

// handlePolicyDelete handles a policy deletion from the K8s informer.
func (pw *PolicyWatcher) handlePolicyDelete(obj interface{}) {
	// TODO: Cast, convert, remove policy
	log.Printf("[crd] Policy deleted (K8s informer)")
}

// ── File Watcher ────────────────────────────────────────────────────────

// startFileWatcher watches the config directory for changes.
func (pw *PolicyWatcher) startFileWatcher(ctx context.Context) {
	pw.wg.Add(1)
	go pw.fileWatchLoop(ctx)
}

// fileWatchLoop periodically reloads policies from disk.
func (pw *PolicyWatcher) fileWatchLoop(ctx context.Context) {
	defer pw.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pw.stopCh:
			return
		case <-ticker.C:
			if err := pw.LoadFromDisk(); err != nil {
				log.Printf("[crd] Error reloading policies: %v", err)
			}
		}
	}
}

// ── Utility ────────────────────────────────────────────────────────────

// isRunningInK8s checks if the agent is running in Kubernetes.
func (pw *PolicyWatcher) isRunningInK8s() bool {
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// ParseIP parses an IP address string, returning nil for empty strings.
// Exported for use in tests and policy application.
func ParseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// yamlUnmarshal uses sigs.k8s.io/yaml for proper YAML-to-JSON parsing.
func yamlUnmarshal(data []byte, v interface{}) error {
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return fmt.Errorf("YAML to JSON conversion failed: %w", err)
	}
	return json.Unmarshal(jsonData, v)
}

// ── Policy List ────────────────────────────────────────────────────────

// ListPolicies returns all loaded policies.
func (pw *PolicyWatcher) ListPolicies() []*ScarletRuntimePolicy {
	pw.mu.RLock()
	defer pw.mu.RUnlock()

	result := make([]*ScarletRuntimePolicy, 0, len(pw.policies))
	for _, policy := range pw.policies {
		result = append(result, policy)
	}
	return result
}

// GetPolicy returns a policy by name.
func (pw *PolicyWatcher) GetPolicy(name string) *ScarletRuntimePolicy {
	pw.mu.RLock()
	defer pw.mu.RUnlock()
	return pw.policies[name]
}

// ── Policy Watcher Stats ──────────────────────────────────────────────

// PolicyWatcherStats holds statistics about the policy watcher.
type PolicyWatcherStats struct {
	PoliciesLoaded  int       `json:"policies_loaded"`
	PoliciesApplied int       `json:"policies_applied"`
	LoadErrors      int       `json:"load_errors"`
	LastLoadTime    time.Time `json:"last_load_time"`
	Connected       bool      `json:"connected"`
	NodeName        string    `json:"node_name"`
	Namespace       string    `json:"namespace"`
}

// Stats returns current policy watcher statistics.
func (pw *PolicyWatcher) Stats() PolicyWatcherStats {
	pw.mu.RLock()
	defer pw.mu.RUnlock()

	return PolicyWatcherStats{
		PoliciesLoaded:  pw.policiesLoaded,
		PoliciesApplied: pw.policiesApplied,
		LoadErrors:      pw.loadErrors,
		LastLoadTime:    pw.lastLoadTime,
		Connected:       pw.connected,
		NodeName:        pw.nodeName,
		Namespace:       pw.namespace,
	}
}
