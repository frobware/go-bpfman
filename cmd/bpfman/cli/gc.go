package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/manager"
)

// GCCmd garbage collects stale database entries.
type GCCmd struct{}

// Run executes the gc command: mutation under lock, output outside.
func (c *GCCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	// Mutation under lock
	result, err := RunWithLockValue(ctx, cli, func(ctx context.Context) (manager.GCResult, error) {
		result, err := b.GC(ctx)
		if errors.Is(err, client.ErrNotSupported) {
			return manager.GCResult{}, fmt.Errorf("garbage collection is only available in local mode")
		}
		if err != nil {
			return manager.GCResult{}, fmt.Errorf("gc failed: %w", err)
		}
		return result, nil
	})
	if err != nil {
		return err
	}

	// Output outside lock
	if result.ProgramsRemoved == 0 && result.DispatchersRemoved == 0 && result.LinksRemoved == 0 && result.OrphanPinsRemoved == 0 {
		return cli.PrintOut("Nothing to clean up.\n")
	}

	return cli.PrintOutf("GC complete: %d programs, %d dispatchers, %d links, %d orphan pins removed\n",
		result.ProgramsRemoved, result.DispatchersRemoved, result.LinksRemoved, result.OrphanPinsRemoved)
}
