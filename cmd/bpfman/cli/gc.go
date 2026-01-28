package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/client"
)

// GCCmd garbage collects stale database entries.
type GCCmd struct{}

// Run executes the gc command.
func (c *GCCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.GC(ctx)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("garbage collection is only available in local mode")
	}
	if err != nil {
		return fmt.Errorf("gc failed: %w", err)
	}

	if result.ProgramsRemoved == 0 && result.DispatchersRemoved == 0 && result.LinksRemoved == 0 && result.OrphanPinsRemoved == 0 {
		fmt.Println("Nothing to clean up.")
		return nil
	}

	fmt.Printf("GC complete: %d programs, %d dispatchers, %d links, %d orphan pins removed\n",
		result.ProgramsRemoved, result.DispatchersRemoved, result.LinksRemoved, result.OrphanPinsRemoved)

	return nil
}
