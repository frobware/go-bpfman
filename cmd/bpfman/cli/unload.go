package cli

import (
	"context"
	"fmt"
)

// UnloadCmd unloads a managed BPF program by kernel ID.
type UnloadCmd struct {
	ProgramID ProgramID `arg:"" name:"program-id" help:"Kernel program ID to unload (supports hex with 0x prefix)."`
}

// Run executes the unload command: mutation under lock, output outside.
func (c *UnloadCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	// Mutation under lock
	if err := cli.RunWithLock(ctx, func(ctx context.Context) error {
		return b.Unload(ctx, c.ProgramID.Value)
	}); err != nil {
		return err
	}

	// Output outside lock
	return cli.PrintOutf("Unloaded program %d\n", c.ProgramID.Value)
}
