package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/pkg/bpfman/client"
)

// DetachCmd detaches a link.
type DetachCmd struct {
	LinkID LinkID `arg:"" name:"link-id" help:"Kernel link ID to detach."`
}

// Run executes the detach command.
func (c *DetachCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	if err := b.Detach(ctx, c.LinkID.Value); err != nil {
		if errors.Is(err, client.ErrNotSupported) {
			return fmt.Errorf("detach is only available in local mode")
		}
		return err
	}

	fmt.Printf("Detached link %d\n", c.LinkID.Value)
	return nil
}
