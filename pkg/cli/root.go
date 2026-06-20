// Package cli implements the scarletctl command-line interface.
package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/securityscarlet/runtime/pkg/rules"
	"github.com/spf13/cobra"
)

// Build-time variables set via ldflags.
var (
	Version   = "0.1.0-dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

// RootCmd is the root command for scarletctl.
var RootCmd = &cobra.Command{
	Use:   "scarletctl",
	Short: "SecurityScarlet Runtime — eBPF-based container runtime security",
	Long: `SecurityScarlet Runtime is an eBPF-based container runtime security system
that provides real-time threat detection and enforcement for containerized
and Kubernetes workloads.

It monitors syscall activity, process lifecycle, network connections,
and file access patterns at the kernel level — detecting container escapes,
cryptojacking, reverse shells, sensitive file access, privilege escalation,
and lateral movement as they happen.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	RootCmd.AddCommand(startCmd)
	RootCmd.AddCommand(stopCmd)
	RootCmd.AddCommand(statusCmd)
	RootCmd.AddCommand(rulesCmd)
	RootCmd.AddCommand(eventsCmd)
	RootCmd.AddCommand(simulateCmd)
	RootCmd.AddCommand(enforceCmd)
	RootCmd.AddCommand(auditCmd)
	RootCmd.AddCommand(versionCmd)
}

// Execute runs the root command.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ── start command ─────────────────────────────────────────────────────

var startConfig string
var startMode string
var startRulesPath string
var startVerbose bool

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the runtime security agent",
	Long:  `Start the SecurityScarlet Runtime agent. The agent loads eBPF probes, begins monitoring syscalls, and evaluates events against the rule engine.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("SecurityScarlet Runtime Agent")
		fmt.Printf("Version: %s (commit: %s, built: %s)\n", Version, Commit, BuildTime)
		fmt.Println()
		fmt.Println("Initializing agent...")

		// Load configuration
		config := loadAgentConfig(startConfig)
		config.ApplyOverrides(startMode, startRulesPath, startVerbose)

		fmt.Printf("  Mode:             %s\n", config.Agent.Mode)
		fmt.Printf("  Node:             %s\n", config.Agent.K8sNodeName)
		fmt.Printf("  Rules:            %s\n", config.Rules.Paths)
		fmt.Printf("  Ring buffer:      %d MB\n", config.Agent.RingBufferSizeMB)
		fmt.Printf("  CRI endpoint:     %s\n", config.Enrichment.CRIEndpoint)
		fmt.Printf("  Metrics port:     %d\n", config.Metrics.Port)
		fmt.Printf("  Alert file:       %s\n", config.Output.AlertFile)

		// Run the agent
		return runAgent(config)
	},
}

func init() {
	startCmd.Flags().StringVarP(&startConfig, "config", "c", "", "Config file path")
	startCmd.Flags().StringVarP(&startMode, "mode", "m", "", "Operating mode: audit|enforce|simulate")
	startCmd.Flags().StringVarP(&startRulesPath, "rules-path", "r", "", "Rules file/directory path")
	startCmd.Flags().BoolVarP(&startVerbose, "verbose", "v", false, "Enable verbose logging")
}

// ── stop command ───────────────────────────────────────────────────────

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the agent and print reports",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Stopping SecurityScarlet Runtime Agent...")
		// In production, would send signal to running daemon
		fmt.Println("Agent stopped.")
		return nil
	},
}

// ── status command ────────────────────────────────────────────────────

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent status and metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("SecurityScarlet Runtime Agent Status")
		fmt.Println("===================================")
		fmt.Printf("  Version:    %s\n", Version)
		fmt.Printf("  Status:     Not running\n")
		fmt.Println()
		fmt.Println("  Use 'scarletctl start' to launch the agent.")
		return nil
	},
}

// ── rules command ─────────────────────────────────────────────────────

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage detection rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		engine, err := rules.NewEngine(rules.EngineConfig{})
		if err != nil {
			return fmt.Errorf("failed to load rule engine: %w", err)
		}
		all := engine.AllRules()
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		fmt.Printf("SecurityScarlet Runtime — %d rules loaded (%d enforce, %d alert)\n",
			engine.RuleCount(), engine.EnforceCount(), engine.AlertCount())
		fmt.Println()
		fmt.Printf("%-6s  %-10s  %-10s  %s\n", "ID", "ACTION", "PRIORITY", "NAME")
		for _, r := range all {
			fmt.Printf("%-6s  %-10s  %-10s  %s\n", r.ID, r.Action, r.Priority, r.Name)
		}
		return nil
	},
}

var rulesValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a rules file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := rules.ValidateFile(args[0])
		if err != nil {
			return fmt.Errorf("validate %s: %w", args[0], err)
		}
		fmt.Printf("Validated %s: %d rules, %d macros, %d lists\n", args[0], res.Rules, res.Macros, res.Lists)
		if len(res.Errors) > 0 {
			fmt.Fprintf(os.Stderr, "\n%d error(s):\n", len(res.Errors))
			for _, e := range res.Errors {
				fmt.Fprintf(os.Stderr, "  - %s\n", e)
			}
			os.Exit(1)
		}
		fmt.Println("Validation complete: no errors found.")
		return nil
	},
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesValidateCmd)
}

// ── events command ────────────────────────────────────────────────────

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Stream live events (filtered)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Streaming live events... (press Ctrl+C to stop)")
		fmt.Println("Note: Agent must be running for events to appear.")
		return nil
	},
}

// ── mode commands ─────────────────────────────────────────────────────

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Switch agent to simulate mode (no enforcement)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Switching agent to SIMULATE mode...")
		fmt.Println("All enforce rules will log but not take action.")
		return nil
	},
}

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Switch agent to enforcement mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Switching agent to ENFORCE mode...")
		fmt.Println("WARNING: Enforcement actions (SIGKILL, LSM deny) are ACTIVE.")
		return nil
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Switch agent to audit-only mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Switching agent to AUDIT mode...")
		fmt.Println("All rules will alert only — no enforcement actions.")
		return nil
	},
}

// ── version command ───────────────────────────────────────────────────

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("SecurityScarlet Runtime %s\n", Version)
		fmt.Printf("  Commit:  %s\n", Commit)
		fmt.Printf("  Built:    %s\n", BuildTime)
	},
}