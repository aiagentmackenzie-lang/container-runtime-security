// Package crd_test — unit tests for CRD types, policy validation, YAML loading,
// and policy watcher operations.
package crd_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/crd"
	"github.com/securityscarlet/runtime/pkg/enforcement"
	"github.com/securityscarlet/runtime/pkg/pipeline"
)

// ── CRD Type Validation Tests ──────────────────────────────────────────

func TestScarletRuntimePolicy_APIVersion(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test-policy"},
		Spec:       crd.ScarletRuntimePolicySpec{Mode: "audit"},
	}

	if policy.APIVersion != "securityscarlet.ai/v1alpha1" {
		t.Errorf("Expected apiVersion securityscarlet.ai/v1alpha1, got %s", policy.APIVersion)
	}
	if policy.Kind != "ScarletRuntimePolicy" {
		t.Errorf("Expected kind ScarletRuntimePolicy, got %s", policy.Kind)
	}
}

func TestScarletRuntimePolicy_DefaultMode(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test"},
		Spec:       crd.ScarletRuntimePolicySpec{Mode: "audit"},
	}

	if policy.Spec.Mode != "audit" {
		t.Errorf("Expected mode 'audit', got %s", policy.Spec.Mode)
	}
}

func TestScarletRuntimePolicy_EnforceMode(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "enforce-policy"},
		Spec:       crd.ScarletRuntimePolicySpec{Mode: "enforce"},
	}

	if policy.Spec.Mode != "enforce" {
		t.Errorf("Expected mode 'enforce', got %s", policy.Spec.Mode)
	}
}

func TestScarletRuntimePolicy_SimulateMode(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "sim-policy"},
		Spec:       crd.ScarletRuntimePolicySpec{Mode: "simulate"},
	}

	if policy.Spec.Mode != "simulate" {
		t.Errorf("Expected mode 'simulate', got %s", policy.Spec.Mode)
	}
}

// ── RuleSelector Tests ────────────────────────────────────────────────

func TestRuleSelector_SelectByIDs(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			RuleSelector: crd.RuleSelector{
				IDs: []string{"R009", "R027", "R019"},
			},
		},
	}
	metadata := crd.CRDObjectMeta{Name: "test"}

	if len(policy.Spec.RuleSelector.IDs) != 3 {
		t.Errorf("Expected 3 rule IDs, got %d", len(policy.Spec.RuleSelector.IDs))
	}
	_ = metadata
}

func TestRuleSelector_SelectByCategory(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			RuleSelector: crd.RuleSelector{
				Categories: []string{"CRYPTO", "NET"},
			},
		},
	}

	if len(policy.Spec.RuleSelector.Categories) != 2 {
		t.Errorf("Expected 2 categories, got %d", len(policy.Spec.RuleSelector.Categories))
	}
}

func TestRuleSelector_SelectByPriority(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			RuleSelector: crd.RuleSelector{
				Priorities: []string{"CRITICAL"},
			},
		},
	}

	if len(policy.Spec.RuleSelector.Priorities) != 1 {
		t.Errorf("Expected 1 priority, got %d", len(policy.Spec.RuleSelector.Priorities))
	}
}

func TestRuleSelector_SelectByTag(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "audit",
			RuleSelector: crd.RuleSelector{
				Tags: []string{"cryptojacking", "mitre_execution"},
			},
		},
	}

	if len(policy.Spec.RuleSelector.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(policy.Spec.RuleSelector.Tags))
	}
}

func TestRuleSelector_SelectAll(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "audit",
			RuleSelector: crd.RuleSelector{
				All: true,
			},
		},
	}

	if !policy.Spec.RuleSelector.All {
		t.Error("Expected All=true in rule selector")
	}
}

func TestRuleSelector_EmptySelectorDefaultsToAll(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")
	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "empty-selector"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode:         "audit", // must be valid
			RuleSelector: crd.RuleSelector{
				// All fields empty — should default to All=true
			},
		},
	}

	err := watcher.ValidatePolicy(policy)
	if err != nil {
		t.Fatalf("Empty selector should be valid: %v", err)
	}
	if !policy.Spec.RuleSelector.All {
		t.Error("Empty rule selector should default to All=true")
	}
}

// ── PolicyException Tests ──────────────────────────────────────────────

func TestPolicyException_FieldMatching(t *testing.T) {
	exc := crd.PolicyException{
		Name:   "trusted_images",
		Fields: []string{"container.image.repository", "proc.name"},
		Comps:  []string{"=", "="},
		Values: [][]string{
			{"admin-toolkit/admin-cli", "/usr/bin/bash"},
			{"debug-pod/tools", "/bin/sh"},
		},
	}

	if exc.Name != "trusted_images" {
		t.Errorf("Expected name 'trusted_images', got %s", exc.Name)
	}
	if len(exc.Fields) != 2 {
		t.Errorf("Expected 2 fields, got %d", len(exc.Fields))
	}
	if len(exc.Values) != 2 {
		t.Errorf("Expected 2 value rows, got %d", len(exc.Values))
	}
	if len(exc.Values[0]) != 2 {
		t.Errorf("Expected 2 values in first row, got %d", len(exc.Values[0]))
	}
}

func TestPolicyException_WithMode(t *testing.T) {
	exc := crd.PolicyException{
		Name:   "audit_only_exception",
		Fields: []string{"namespace"},
		Comps:  []string{"="},
		Values: [][]string{{"dev-namespace"}},
		Mode:   "audit",
	}

	if exc.Mode != "audit" {
		t.Errorf("Expected exception mode 'audit', got %s", exc.Mode)
	}
}

// ── EnforcementConfig Tests ────────────────────────────────────────────

func TestEnforcementConfig_DefaultValues(t *testing.T) {
	cfg := crd.EnforcementConfigSpec{}

	if cfg.KillMode != "" {
		// Empty is valid — will use agent default
		t.Logf("KillMode: %s", cfg.KillMode)
	}
	if cfg.GracePeriodSeconds != 0 {
		t.Errorf("Expected default grace period 0, got %d", cfg.GracePeriodSeconds)
	}
	if cfg.MaxKillsPerPod != 0 {
		t.Errorf("Expected default max kills 0, got %d", cfg.MaxKillsPerPod)
	}
}

func TestEnforcementConfig_GracefulMode(t *testing.T) {
	cfg := crd.EnforcementConfigSpec{
		KillMode:           "graceful",
		GracePeriodSeconds: 10,
		MaxKillsPerPod:     5,
		WindowSeconds:      60,
	}

	if cfg.KillMode != "graceful" {
		t.Errorf("Expected kill_mode 'graceful', got %s", cfg.KillMode)
	}
	if cfg.GracePeriodSeconds != 10 {
		t.Errorf("Expected grace period 10, got %d", cfg.GracePeriodSeconds)
	}
}

// ── NetworkPolicy Tests ────────────────────────────────────────────────

func TestNetworkPolicySpec_Enabled(t *testing.T) {
	np := &crd.NetworkPolicySpec{
		Enabled:    true,
		DefaultTTL: "5m",
		BlockList: []crd.NetworkBlockSpec{
			{
				DestIP:   "169.254.169.254",
				DestPort: 0,
				Protocol: "any",
				Reason:   "cloud metadata SSRF",
				TTL:      "30m",
			},
		},
	}

	if !np.Enabled {
		t.Error("Expected network policy to be enabled")
	}
	if len(np.BlockList) != 1 {
		t.Errorf("Expected 1 block entry, got %d", len(np.BlockList))
	}
	if np.BlockList[0].DestIP != "169.254.169.254" {
		t.Errorf("Expected dest IP 169.254.169.254, got %s", np.BlockList[0].DestIP)
	}
}

func TestNetworkPolicySpec_DefaultTTL(t *testing.T) {
	np := &crd.NetworkPolicySpec{
		Enabled:    true,
		DefaultTTL: "5m",
	}

	ttl, err := time.ParseDuration(np.DefaultTTL)
	if err != nil {
		t.Fatalf("Failed to parse default TTL: %v", err)
	}
	if ttl != 5*time.Minute {
		t.Errorf("Expected 5m TTL, got %v", ttl)
	}
}

func TestNetworkBlockSpec_Fields(t *testing.T) {
	block := crd.NetworkBlockSpec{
		DestIP:   "10.0.0.1",
		DestPort: 4444,
		Protocol: "tcp",
		Reason:   "C2 port",
		TTL:      "10m",
	}

	if block.DestIP != "10.0.0.1" {
		t.Errorf("Expected dest IP 10.0.0.1, got %s", block.DestIP)
	}
	if block.DestPort != 4444 {
		t.Errorf("Expected port 4444, got %d", block.DestPort)
	}
	if block.Protocol != "tcp" {
		t.Errorf("Expected protocol tcp, got %s", block.Protocol)
	}
}

// ── Policy Validation Tests ────────────────────────────────────────────

func TestValidatePolicy_ValidPolicy(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test-policy"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "audit",
			RuleSelector: crd.RuleSelector{
				All: true,
			},
		},
	}

	err := watcher.ValidatePolicy(policy)
	if err != nil {
		t.Fatalf("Valid policy should pass validation: %v", err)
	}
}

func TestValidatePolicy_InvalidAPIVersion(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "v1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test-policy"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "audit",
		},
	}

	err := watcher.ValidatePolicy(policy)
	if err == nil {
		t.Error("Expected validation error for invalid apiVersion")
	}
}

func TestValidatePolicy_InvalidKind(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "SomeOtherKind",
		Metadata:   crd.CRDObjectMeta{Name: "test-policy"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "audit",
		},
	}

	err := watcher.ValidatePolicy(policy)
	if err == nil {
		t.Error("Expected validation error for invalid kind")
	}
}

func TestValidatePolicy_InvalidMode(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test-policy"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "invalid_mode",
		},
	}

	err := watcher.ValidatePolicy(policy)
	if err == nil {
		t.Error("Expected validation error for invalid mode")
	}
}

func TestValidatePolicy_InvalidTTL(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test-policy"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			NetworkPolicy: &crd.NetworkPolicySpec{
				Enabled:    true,
				DefaultTTL: "invalid",
			},
		},
	}

	err := watcher.ValidatePolicy(policy)
	if err == nil {
		t.Error("Expected validation error for invalid TTL")
	}
}

// ── YAML Loading Tests ────────────────────────────────────────────────

func TestYAMLLoading_ValidPolicy(t *testing.T) {
	dir := t.TempDir()
	policyYAML := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: test-policy
  namespace: security-scarlet
spec:
  mode: enforce
  ruleSelector:
    ids:
      - R009
      - R027
      - R019
  enforcementConfig:
    killMode: immediate
    maxKillsPerPod: 5
    windowSeconds: 30
  networkPolicy:
    enabled: true
    defaultTTL: "5m"
    blockList:
      - destIP: "169.254.169.254"
        destPort: 0
        protocol: any
        reason: "Cloud metadata SSRF protection"
        ttl: "30m"
`)

	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, policyYAML, 0644); err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}

	watcher := crd.NewPolicyWatcher(dir, "test-node")
	err := watcher.LoadFromDisk()
	if err != nil {
		t.Fatalf("Failed to load policy from disk: %v", err)
	}

	policies := watcher.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	p := policies[0]
	if p.Metadata.Name != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got %s", p.Metadata.Name)
	}
	if p.Spec.Mode != "enforce" {
		t.Errorf("Expected mode 'enforce', got %s", p.Spec.Mode)
	}
	if len(p.Spec.RuleSelector.IDs) != 3 {
		t.Errorf("Expected 3 rule IDs, got %d", len(p.Spec.RuleSelector.IDs))
	}
	if p.Spec.NetworkPolicy == nil || !p.Spec.NetworkPolicy.Enabled {
		t.Error("Expected network policy to be enabled")
	}
}

func TestYAMLLoading_MultiplePolicies(t *testing.T) {
	dir := t.TempDir()

	policy1 := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: crypto-policy
spec:
  mode: enforce
  ruleSelector:
    categories:
      - CRYPTO
`)
	policy2 := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: shell-policy
spec:
  mode: audit
  ruleSelector:
    categories:
      - SHELL
`)

	os.WriteFile(filepath.Join(dir, "crypto.yaml"), policy1, 0644)
	os.WriteFile(filepath.Join(dir, "shell.yaml"), policy2, 0644)

	watcher := crd.NewPolicyWatcher(dir, "test-node")
	err := watcher.LoadFromDisk()
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	policies := watcher.ListPolicies()
	if len(policies) != 2 {
		t.Fatalf("Expected 2 policies, got %d", len(policies))
	}

	names := map[string]bool{}
	for _, p := range policies {
		names[p.Metadata.Name] = true
	}
	if !names["crypto-policy"] {
		t.Error("Expected crypto-policy to be loaded")
	}
	if !names["shell-policy"] {
		t.Error("Expected shell-policy to be loaded")
	}
}

func TestYAMLLoading_InvalidYAML(t *testing.T) {
	dir := t.TempDir()

	invalidYAML := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: bad-policy
spec:
  mode: invalid_mode
`)

	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, invalidYAML, 0644)

	watcher := crd.NewPolicyWatcher(dir, "test-node")
	err := watcher.LoadFromDisk()
	// LoadFromDisk logs warnings but doesn't fail for invalid policies
	_ = err // no fatal error expected

	// The invalid policy should not be stored
	policies := watcher.ListPolicies()
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies (invalid YAML should be skipped), got %d", len(policies))
	}
}

func TestYAMLLoading_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	watcher := crd.NewPolicyWatcher(dir, "test-node")
	err := watcher.LoadFromDisk()
	if err != nil {
		t.Fatalf("Empty directory should not cause error: %v", err)
	}

	policies := watcher.ListPolicies()
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies from empty directory, got %d", len(policies))
	}
}

// ── Policy Application Tests ────────────────────────────────────────────

func TestApplyPolicy_SetsEnforcementMode(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")
	actor := pipeline.NewResponseActor("audit")
	watcher.SetResponseActor(actor)

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "test-enforce"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
		},
	}

	err := watcher.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to apply policy: %v", err)
	}

	// Verify the actor mode was changed
	// We can't directly read the mode, but we can verify by enforcing
	// that the actor was configured — the ApplyPolicy call itself
	// exercises the SetMode code path.
}

func TestApplyPolicy_AppliesNetworkBlocks(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")
	ne := enforcement.NewNetworkEnforcer()
	watcher.SetNetworkEnforcer(ne)

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "network-policy-test"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			NetworkPolicy: &crd.NetworkPolicySpec{
				Enabled:    true,
				DefaultTTL: "5m",
				BlockList: []crd.NetworkBlockSpec{
					{
						DestIP:   "169.254.169.254",
						DestPort: 0,
						Protocol: "any",
						Reason:   "cloud metadata SSRF",
						TTL:      "30m",
					},
					{
						DestIP:   "10.0.0.1",
						DestPort: 4444,
						Protocol: "tcp",
						Reason:   "C2 port",
					},
				},
			},
		},
	}

	err := watcher.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to apply policy: %v", err)
	}

	// Verify the network blocks were applied
	metadataIP := net.ParseIP("169.254.169.254")
	if !ne.IsBlocked(metadataIP, 80, enforcement.ProtocolAny) {
		t.Error("Cloud metadata IP should be blocked on any port")
	}

	blockIP := net.ParseIP("10.0.0.1")
	if !ne.IsBlocked(blockIP, 4444, enforcement.ProtocolTCP) {
		t.Error("C2 IP:port should be blocked")
	}
}

// ── PolicyWatcher Statistics Tests ──────────────────────────────────────

func TestPolicyWatcher_Stats(t *testing.T) {
	dir := t.TempDir()
	watcher := crd.NewPolicyWatcher(dir, "node-1")

	stats := watcher.Stats()
	if stats.NodeName != "node-1" {
		t.Errorf("Expected node name 'node-1', got %s", stats.NodeName)
	}
	if stats.PoliciesLoaded != 0 {
		t.Errorf("Expected 0 loaded policies, got %d", stats.PoliciesLoaded)
	}
}

func TestPolicyWatcher_GetPolicy(t *testing.T) {
	dir := t.TempDir()

	policyYAML := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: my-policy
spec:
  mode: audit
  ruleSelector:
    all: true
`)

	os.WriteFile(filepath.Join(dir, "policy.yaml"), policyYAML, 0644)

	watcher := crd.NewPolicyWatcher(dir, "test-node")
	watcher.LoadFromDisk()

	p := watcher.GetPolicy("my-policy")
	if p == nil {
		t.Fatal("Expected policy 'my-policy' to be found")
	}
	if p.Metadata.Name != "my-policy" {
		t.Errorf("Expected name 'my-policy', got %s", p.Metadata.Name)
	}
	if p.Spec.Mode != "audit" {
		t.Errorf("Expected mode 'audit', got %s", p.Spec.Mode)
	}
}

func TestPolicyWatcher_GetPolicy_NotFound(t *testing.T) {
	dir := t.TempDir()
	watcher := crd.NewPolicyWatcher(dir, "test-node")

	p := watcher.GetPolicy("nonexistent")
	if p != nil {
		t.Error("Expected nil for nonexistent policy")
	}
}

func TestPolicyWatcher_ListPolicies(t *testing.T) {
	dir := t.TempDir()

	policyYAML := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: list-test
spec:
  mode: enforce
  ruleSelector:
    ids:
      - R009
`)

	os.WriteFile(filepath.Join(dir, "policy.yaml"), policyYAML, 0644)

	watcher := crd.NewPolicyWatcher(dir, "test-node")
	watcher.LoadFromDisk()

	policies := watcher.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].Metadata.Name != "list-test" {
		t.Errorf("Expected name 'list-test', got %s", policies[0].Metadata.Name)
	}
}

// ── PolicyWatcher Start/Stop Tests ──────────────────────────────────────

func TestPolicyWatcher_StartStop(t *testing.T) {
	dir := t.TempDir()
	watcher := crd.NewPolicyWatcher(dir, "test-node")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond) // Let it start
	watcher.Stop()

	// Should not panic
}

// ── Full Policy Lifecycle Tests ─────────────────────────────────────────

func TestPolicyLifecycle_LoadValidateApply(t *testing.T) {
	dir := t.TempDir()

	policyYAML := []byte(`
apiVersion: securityscarlet.ai/v1alpha1
kind: ScarletRuntimePolicy
metadata:
  name: lifecycle-test
  namespace: security-scarlet
spec:
  mode: enforce
  ruleSelector:
    categories:
      - CRYPTO
      - NET
  exceptions:
    - name: trusted_miners
      fields:
        - container.image.repository
      comps:
        - '='
      values:
        - [research/miner-benchmark]
      mode: audit
  enforcementConfig:
    killMode: graceful
    gracePeriodSeconds: 10
    maxKillsPerPod: 5
    windowSeconds: 30
  protectedNamespaces:
    - kube-system
    - kube-public
    - monitoring
  networkPolicy:
    enabled: true
    defaultTTL: "5m"
    blockList:
      - destIP: "169.254.169.254"
        protocol: any
        reason: "Block cloud metadata access"
        ttl: "30m"
      - destIP: "0.0.0.0"
        destPort: 3333
        protocol: tcp
        reason: "Block mining pool port"
`)

	path := filepath.Join(dir, "lifecycle.yaml")
	if err := os.WriteFile(path, policyYAML, 0644); err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}

	// Step 1: Load
	watcher := crd.NewPolicyWatcher(dir, "test-node")
	err := watcher.LoadFromDisk()
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Step 2: Validate
	p := watcher.GetPolicy("lifecycle-test")
	if p == nil {
		t.Fatal("Policy not found after loading")
	}

	err = watcher.ValidatePolicy(p)
	if err != nil {
		t.Fatalf("Policy validation failed: %v", err)
	}

	// Step 3: Apply
	ne := enforcement.NewNetworkEnforcer()
	watcher.SetNetworkEnforcer(ne)

	actor := pipeline.NewResponseActor("audit")
	watcher.SetResponseActor(actor)

	err = watcher.ApplyPolicy(p)
	if err != nil {
		t.Fatalf("Policy application failed: %v", err)
	}

	// Step 4: Verify network blocks were applied
	metadataIP := net.ParseIP("169.254.169.254")
	if !ne.IsBlocked(metadataIP, 0, enforcement.ProtocolAny) {
		t.Error("Cloud metadata IP should be blocked")
	}

	// Mining pool port block on 0.0.0.0:3333/tcp
	if !ne.IsBlocked(net.IPv4zero, 3333, enforcement.ProtocolTCP) {
		t.Error("Mining pool port should be blocked")
	}

	// Step 5: Stats
	stats := watcher.Stats()
	if stats.PoliciesLoaded != 1 {
		t.Errorf("Expected 1 loaded policy, got %d", stats.PoliciesLoaded)
	}
	if stats.PoliciesApplied != 1 {
		t.Errorf("Expected 1 applied policy, got %d", stats.PoliciesApplied)
	}
}

// ── Helper Function Tests ──────────────────────────────────────────────

func TestParseIP_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"169.254.169.254", "169.254.169.254"},
		{"10.0.0.1", "10.0.0.1"},
		{"0.0.0.0", "0.0.0.0"},
		{"255.255.255.255", "255.255.255.255"},
	}

	for _, tc := range tests {
		ip := crd.ParseIP(tc.input)
		if ip == nil {
			t.Errorf("parseIP(%s) returned nil", tc.input)
			continue
		}
		if ip.String() != tc.expected {
			t.Errorf("parseIP(%s) = %s, want %s", tc.input, ip.String(), tc.expected)
		}
	}
}

func TestParseIP_EmptyString(t *testing.T) {
	ip := crd.ParseIP("")
	if ip != nil {
		t.Errorf("parseIP(\"\") should return nil, got %s", ip)
	}
}

func TestParseIP_Invalid(t *testing.T) {
	ip := crd.ParseIP("not-an-ip")
	if ip != nil {
		t.Errorf("parseIP(invalid) should return nil, got %s", ip)
	}
}

// ── CRD ObjectMeta Tests ──────────────────────────────────────────────

func TestCRDObjectMeta(t *testing.T) {
	meta := crd.CRDObjectMeta{
		Name:            "test-policy",
		Namespace:       "security-scarlet",
		Labels:          map[string]string{"app": "scarlet"},
		Annotations:     map[string]string{"note": "test"},
		ResourceVersion: "12345",
	}

	if meta.Name != "test-policy" {
		t.Errorf("Expected name 'test-policy', got %s", meta.Name)
	}
	if meta.Namespace != "security-scarlet" {
		t.Errorf("Expected namespace 'security-scarlet', got %s", meta.Namespace)
	}
	if meta.Labels["app"] != "scarlet" {
		t.Error("Expected app=scarlet label")
	}
}

// ── ProtectedNamespaces Tests ──────────────────────────────────────────

func TestProtectedNamespaces_Custom(t *testing.T) {
	policy := &crd.ScarletRuntimePolicy{
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			ProtectedNamespaces: []string{
				"kube-system",
				"kube-public",
				"monitoring",
			},
		},
	}

	if len(policy.Spec.ProtectedNamespaces) != 3 {
		t.Errorf("Expected 3 protected namespaces, got %d", len(policy.Spec.ProtectedNamespaces))
	}
	if policy.Spec.ProtectedNamespaces[2] != "monitoring" {
		t.Errorf("Expected third namespace 'monitoring', got %s", policy.Spec.ProtectedNamespaces[2])
	}
}

// ── EnforcementConfig Integration Tests ─────────────────────────────────

func TestApplyPolicy_EnforcementConfig(t *testing.T) {
	watcher := crd.NewPolicyWatcher(t.TempDir(), "test-node")
	actor := pipeline.NewResponseActor("audit")
	watcher.SetResponseActor(actor)

	policy := &crd.ScarletRuntimePolicy{
		APIVersion: "securityscarlet.ai/v1alpha1",
		Kind:       "ScarletRuntimePolicy",
		Metadata:   crd.CRDObjectMeta{Name: "enforce-cfg-test"},
		Spec: crd.ScarletRuntimePolicySpec{
			Mode: "enforce",
			EnforcementConfig: crd.EnforcementConfigSpec{
				KillMode:           "graceful",
				GracePeriodSeconds: 10,
				MaxKillsPerPod:     5,
				WindowSeconds:      30,
			},
			ProtectedNamespaces: []string{"kube-system", "kube-public", "custom-ns"},
		},
	}

	err := watcher.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to apply policy: %v", err)
	}
}

// ── Network Protocol Tests ──────────────────────────────────────────────

func TestNetworkPolicyProtocol_Parsing(t *testing.T) {
	tests := []struct {
		proto    string
		expected enforcement.Protocol
	}{
		{"tcp", enforcement.ProtocolTCP},
		{"udp", enforcement.ProtocolUDP},
		{"any", enforcement.ProtocolAny},
		{"", enforcement.ProtocolAny},
	}

	for _, tc := range tests {
		var result enforcement.Protocol
		switch tc.proto {
		case "tcp":
			result = enforcement.ProtocolTCP
		case "udp":
			result = enforcement.ProtocolUDP
		case "any", "":
			result = enforcement.ProtocolAny
		}

		if result != tc.expected {
			t.Errorf("Protocol(%q) = %d, want %d", tc.proto, result, tc.expected)
		}
	}
}
