package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/client"
)

// GetCmd gets details of a program or link.
type GetCmd struct {
	Program GetProgramCmd `cmd:"" help:"Get a loaded eBPF program using the Program Id."`
	Link    GetLinkCmd    `cmd:"" help:"Get a loaded eBPF program's attachment using the Link Id."`
}

// GetProgramCmd gets details of a managed program by kernel ID.
type GetProgramCmd struct {
	OutputFlags
	ProgramID ProgramID `arg:"" name:"program-id" help:"Kernel program ID (supports hex with 0x prefix)."`
}

// Run executes the get program command.
func (c *GetProgramCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	info, err := b.Get(ctx, c.ProgramID.Value)
	if err != nil {
		return err
	}

	output, err := FormatProgramInfo(info, &c.OutputFlags)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}

// GetLinkCmd gets details of a link by kernel link ID.
type GetLinkCmd struct {
	OutputFlags
	LinkID LinkID `arg:"" name:"link-id" help:"Kernel link ID."`
}

// Run executes the get link command.
func (c *GetLinkCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	summary, details, err := b.GetLink(ctx, c.LinkID.Value)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("getting link details is only available in local mode")
	}
	if err != nil {
		return err
	}

	output, err := FormatLinkInfo(summary, details, &c.OutputFlags)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}
