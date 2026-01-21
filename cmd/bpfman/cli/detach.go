package cli

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// DetachCmd detaches a link.
type DetachCmd struct {
	LinkUUID LinkUUID `arg:"" name:"link-uuid" help:"UUID of the link to detach."`
}

// Run executes the detach command.
func (c *DetachCmd) Run(cli *CLI) error {
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	mgr, cleanup, err := manager.Setup(cli.DB.Path, logger)
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	if err := mgr.Detach(ctx, c.LinkUUID.Value); err != nil {
		return err
	}

	fmt.Printf("Detached link %s\n", c.LinkUUID.Value)
	return nil
}
