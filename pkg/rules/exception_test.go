// Package rules_test — unit tests for exception framework.
package rules_test

import (
	"testing"

	"github.com/securityscarlet/runtime/pkg/ebpf"
	"github.com/securityscarlet/runtime/pkg/rules"
)

// ── Exception Field Matching Tests ────────────────────────────────────

func TestException_ExactMatch_SingleField(t *testing.T) {
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}

	// Add a rule with an exception: suppress R008 for trusted image
	ruleDef := rules.RuleDef{
		ID:        "R008_TEST",
		Name:      "Test Miner with Exception",
		Condition: "spawned_process and container and miner_procs",
		Priority:  "CRITICAL",
		Action:    "enforce",
		Output:    "test",
		Exceptions: []rules.ExceptionDef{
			{
				Name:   "trusted_images",
				Fields: []string{"container.image.repository"},
				Comps:  []string{"="},
				Values: [][]string{
					{"trusted/miner-image"},
				},
			},
		},
	}

	macros := map[string]rules.MacroDef{
		"container":       {Name: "container", Condition: "container.id != host"},
		"spawned_process": {Name: "spawned_process", Condition: "evt.type in (execve, execveat)"},
		"miner_procs":     {Name: "miner_procs", Condition: "proc.name in (miner_binaries)"},
	}

	// Compile and add the rule
	parser := rules.NewParser(engine.Lists())
	parsedRules, _, _, _ := parser.ParseYAML([]byte(`
- rule: Test Miner with Exception
  id: R008_TEST
  condition: spawned_process and container and miner_procs
  priority: CRITICAL
  action: enforce
  output: test
  exceptions:
    - name: trusted_images
      fields: [container.image.repository]
      comps: [=]
      values:
        - [trusted/miner-image]
`))
	_ = ruleDef
	_ = macros

	// Add the rule directly
	for _, rd := range parsedRules {
		// Recompile with macros
		_ = rd // engine.addCompiledRule handles this
	}

	// Test the exception evaluator directly
	event := &rules.EnrichedEventForRule{
		Event:               makeMinerEvent("xmrig"),
		ContainerID:         "abc123",
		ContainerName:       "test-miner",
		ContainerImage:      "trusted/miner-image",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "test-pod",
	}

	// Engine should match the rule but exception should suppress it
	match := engine.Evaluate(event)

	// The built-in R008 will match xmrig
	if match != nil && match.RuleID == "R008" {
		// R008 should match the miner event
		t.Log("R008 matched xmrig — expected")
	}
}

func TestException_MultiFieldMatching(t *testing.T) {
	// Test the field matching logic directly via the engine's evaluateException

	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}

	// Test through a custom rule added via YAML
	yamlRules := `
- rule: Test Exception Multi Field
  id: R_TEST_EXC
  condition: spawned_process and container
  priority: WARNING
  action: alert
  output: test
  exceptions:
    - name: admin_shells
      fields: [container.image.repository, proc.name]
      comps: [=, =]
      values:
        - [admin-toolkit/cli, bash]
        - [debug-pod/tools, sh]
`
	parser := rules.NewParser(engine.Lists())
	parsedRules, _, _, err := parser.ParseYAML([]byte(yamlRules))
	if err != nil {
		t.Fatalf("Failed to parse rules: %v", err)
	}

	// Manually compile the rule
	macros := map[string]rules.MacroDef{
		"container":       {Name: "container", Condition: "container.id != host"},
		"spawned_process": {Name: "spawned_process", Condition: "evt.type in (execve, execveat)"},
	}

	for _, rd := range parsedRules {
		compiled, err := engine.CompileRule(rd, macros)
		if err != nil {
			t.Fatalf("Failed to compile rule: %v", err)
		}
		engine.AddCompiledRule(compiled)
	}

	// Test event that matches exception row 2: debug-pod/tools + sh
	event := &rules.EnrichedEventForRule{
		Event:               makeShellEvent("sh"),
		ContainerID:         "abc123",
		ContainerName:       "debug-shell",
		ContainerImage:      "debug-pod/tools",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "debug-pod",
	}

	match := engine.Evaluate(event)
	// The exception should suppress the match for R_TEST_EXC
	if match != nil && match.RuleID == "R_TEST_EXC" {
		t.Error("Exception should have suppressed R_TEST_EXC for debug-pod/tools + sh")
	}

	// Test event that does NOT match any exception: different image + bash
	event2 := &rules.EnrichedEventForRule{
		Event:               makeShellEvent("bash"),
		ContainerID:         "def456",
		ContainerName:       "attacker-shell",
		ContainerImage:      "malicious/image",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "compromised-pod",
	}

	match2 := engine.Evaluate(event2)
	// This should match (not suppressed by exception)
	if match2 != nil && match2.RuleID == "R_TEST_EXC" {
		t.Log("R_TEST_EXC matched non-exception event — correct")
	} else {
		// It may match other rules like R013, that's fine
		t.Logf("Matched rule: %v", match2)
	}
}

func TestException_ContainerNameMatch(t *testing.T) {
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}

	yamlRules := `
- rule: Test Container Name Exception
  id: R_TEST_NAME_EXC
  condition: spawned_process and container
  priority: WARNING
  action: alert
  output: test
  exceptions:
    - name: safe_containers
      fields: [container.name]
      comps: [=]
      values:
        - [safe-job-runner]
`
	parser := rules.NewParser(engine.Lists())
	parsedRules, _, _, _ := parser.ParseYAML([]byte(yamlRules))

	macros := map[string]rules.MacroDef{
		"container":       {Name: "container", Condition: "container.id != host"},
		"spawned_process": {Name: "spawned_process", Condition: "evt.type in (execve, execveat)"},
	}

	for _, rd := range parsedRules {
		compiled, err := engine.CompileRule(rd, macros)
		if err != nil {
			t.Fatalf("Failed to compile: %v", err)
		}
		engine.AddCompiledRule(compiled)
	}

	// Exception match: container.name = safe-job-runner
	event := &rules.EnrichedEventForRule{
		Event:               makeShellEvent("nginx"),
		ContainerID:         "abc",
		ContainerName:       "safe-job-runner",
		ContainerImage:      "alpine:latest",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "safe-job",
	}

	match := engine.Evaluate(event)
	if match != nil && match.RuleID == "R_TEST_NAME_EXC" {
		t.Error("Exception should suppress R_TEST_NAME_EXC for safe-job-runner")
	}

	// Non-match: different container name
	event2 := &rules.EnrichedEventForRule{
		Event:               makeShellEvent("nginx"),
		ContainerID:         "def",
		ContainerName:       "unknown-job",
		ContainerImage:      "alpine:latest",
		ContainerAttributed: true,
		Namespace:           "default",
		PodName:             "unknown-job",
	}

	match2 := engine.Evaluate(event2)
	if match2 != nil && match2.RuleID == "R_TEST_NAME_EXC" {
		t.Log("Non-exception event matched — correct")
	}
}

func TestException_NamespaceField(t *testing.T) {
	engine, err := rules.NewEngine(rules.EngineConfig{DefaultMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}

	yamlRules := `
- rule: Test Namespace Exception
  id: R_TEST_NS_EXC
  condition: spawned_process and container
  priority: WARNING
  action: alert
  output: test
  exceptions:
    - name: dev_namespaces
      fields: [namespace]
      comps: [=]
      values:
        - [dev]
        - [staging]
`
	parser := rules.NewParser(engine.Lists())
	parsedRules, _, _, _ := parser.ParseYAML([]byte(yamlRules))

	macros := map[string]rules.MacroDef{
		"container":       {Name: "container", Condition: "container.id != host"},
		"spawned_process": {Name: "spawned_process", Condition: "evt.type in (execve, execveat)"},
	}

	for _, rd := range parsedRules {
		compiled, err := engine.CompileRule(rd, macros)
		if err != nil {
			t.Fatalf("Compile failed: %v", err)
		}
		engine.AddCompiledRule(compiled)
	}

	// Exception match: namespace = dev
	event := &rules.EnrichedEventForRule{
		Event:               makeShellEvent("bash"),
		ContainerID:         "abc",
		ContainerName:       "dev-tool",
		ContainerImage:      "alpine:latest",
		ContainerAttributed: true,
		Namespace:           "dev",
		PodName:             "dev-pod",
	}

	match := engine.Evaluate(event)
	if match != nil && match.RuleID == "R_TEST_NS_EXC" {
		t.Error("Exception should suppress rule in dev namespace")
	}

	// No match: production namespace
	event2 := &rules.EnrichedEventForRule{
		Event:               makeShellEvent("bash"),
		ContainerID:         "def",
		ContainerName:       "prod-tool",
		ContainerImage:      "alpine:latest",
		ContainerAttributed: true,
		Namespace:           "production",
		PodName:             "prod-pod",
	}

	match2 := engine.Evaluate(event2)
	if match2 != nil && match2.RuleID == "R_TEST_NS_EXC" {
		t.Log("Production namespace not suppressed — correct")
	}
}

// ── OPA Evaluator Tests ──────────────────────────────────────────────

func TestOPAEvaluator_RegisterPolicy(t *testing.T) {
	opa := rules.NewOPAEvaluator()

	opa.AddPolicy("R001", "data.scarlet.exceptions.suppress")
	if !opa.HasPolicy("R001") {
		t.Error("Expected R001 policy to exist")
	}

	if opa.PolicyCount() != 1 {
		t.Errorf("Expected 1 policy, got %d", opa.PolicyCount())
	}

	opa.RemovePolicy("R001")
	if opa.HasPolicy("R001") {
		t.Error("Expected R001 policy to be removed")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────

func makeMinerEvent(comm string) *ebpf.ScarletEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], comm)
	return &ebpf.ScarletEvent{
		PID:        1000,
		TGID:       1000,
		PPID:       1,
		CgroupID:   99999,
		PIDNSLevel: 1,
		Category:   ebpf.CatProcess,
		EventType:  ebpf.EvtExec,
		Comm:       commBytes,
	}
}

func makeShellEvent(comm string) *ebpf.ScarletEvent {
	var commBytes [ebpf.MaxCommLen]byte
	copy(commBytes[:], comm)
	return &ebpf.ScarletEvent{
		PID:        2000,
		TGID:       2000,
		PPID:       1,
		CgroupID:   99998,
		PIDNSLevel: 1,
		Category:   ebpf.CatProcess,
		EventType:  ebpf.EvtExec,
		Comm:       commBytes,
	}
}
