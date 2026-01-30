package cli

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman"
)

// DetachCmd detaches a link.
type DetachCmd struct {
	LinkID LinkID `arg:"" name:"link-id" help:"Kernel link ID to detach."`
}

// Run executes the detach command: mutation under lock, output outside.
func (c *DetachCmd) Run(cli *CLI, ctx context.Context) error {
	runtime, err := cli.NewCLIRuntime(ctx)
	if err != nil {
		return fmt.Errorf("create runtime: %w", err)
	}
	defer runtime.Close()

	// Mutation under lock
	if err := cli.RunWithLock(ctx, func(ctx context.Context) error {
		return runtime.Manager.Detach(ctx, bpfman.LinkID(c.LinkID.Value))
	}); err != nil {
		return err
	}

	// Output outside lock
	return cli.PrintOutf("Detached link %d\n", c.LinkID.Value)
}
