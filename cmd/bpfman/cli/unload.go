package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// UnloadCmd unloads a managed BPF program by kernel ID.
type UnloadCmd struct {
	ProgramID ProgramID `arg:"" name:"program-id" help:"Kernel program ID to unload (supports hex with 0x prefix)."`
}

// Run executes the unload command.
func (c *UnloadCmd) Run(cli *CLI) error {
	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	if err := mgr.Unload(ctx, c.ProgramID.Value); err != nil {
		return err
	}

	fmt.Printf("Unloaded program %d\n", c.ProgramID.Value)
	return nil
}
