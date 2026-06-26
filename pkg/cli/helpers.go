// Package cli - helpers.go
// Helper functions for the CLI.

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/securityscarlet/runtime/pkg/agent"
)

// loadAgentConfig loads agent configuration from a file, falling back to defaults.
func loadAgentConfig(path string) *agent.Config {
	if path != "" {
		cfg, err := agent.LoadConfig(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load config %s: %v (using defaults)\n", path, err)
			return agent.DefaultConfig()
		}
		return cfg
	}
	return agent.DefaultConfig()
}

// runAgent creates and runs the agent.
func runAgent(cfg *agent.Config) error {
	a, err := agent.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	ctx := context.Background()
	return a.Start(ctx)
}
