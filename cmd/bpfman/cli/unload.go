package cli

import (
	"context"
	"fmt"
)

// UnloadCmd unloads a managed BPF program by kernel ID.
type UnloadCmd struct {
	ProgramID ProgramID `arg:"" name:"program-id" help:"Kernel program ID to unload (supports hex with 0x prefix)."`
}

// Run executes the unload command.
func (c *UnloadCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	if err := b.Unload(ctx, c.ProgramID.Value); err != nil {
		return err
	}

	fmt.Printf("Unloaded program %d\n", c.ProgramID.Value)
	return nil
}
