package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/client"
)

// GC2Cmd garbage collects stale resources using the rule engine.
type GC2Cmd struct{}

// Run executes the gc2 command.
func (c *GC2Cmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()

	cleaned, err := b.GC2(ctx)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("gc2 is only available in local mode")
	}
	if err != nil {
		return fmt.Errorf("gc2 failed: %w", err)
	}

	if cleaned == 0 {
		fmt.Println("Nothing to clean up. (rule engine)")
		return nil
	}

	fmt.Printf("GC2 complete: %d items cleaned (rule engine)\n", cleaned)

	return nil
}
