package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/client"
)

// DetachCmd detaches a link.
type DetachCmd struct {
	LinkID LinkID `arg:"" name:"link-id" help:"Kernel link ID to detach."`
}

// Run executes the detach command: mutation under lock, output outside.
func (c *DetachCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	// Mutation under lock
	if err := cli.RunWithLock(ctx, func(ctx context.Context) error {
		if err := b.Detach(ctx, c.LinkID.Value); err != nil {
			if errors.Is(err, client.ErrNotSupported) {
				return fmt.Errorf("detach is only available in local mode")
			}
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	// Output outside lock
	return cli.PrintOutf("Detached link %d\n", c.LinkID.Value)
}
