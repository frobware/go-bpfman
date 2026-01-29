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
func (c *GetProgramCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	info, err := b.Get(ctx, c.ProgramID.Value)
	if err != nil {
		return err
	}

	output, err := FormatProgramInfo(info, &c.OutputFlags)
	if err != nil {
		return err
	}
	return cli.PrintOut(output)
}

// GetLinkCmd gets details of a link by kernel link ID.
type GetLinkCmd struct {
	OutputFlags
	LinkID LinkID `arg:"" name:"link-id" help:"Kernel link ID."`
}

// Run executes the get link command.
func (c *GetLinkCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	summary, details, err := b.GetLink(ctx, c.LinkID.Value)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("getting link details is only available in local mode")
	}
	if err != nil {
		return err
	}

	// Fetch program info to get the BPF function name
	var bpfFunction string
	progInfo, err := b.Get(ctx, summary.KernelProgramID)
	if err == nil && progInfo.Bpfman != nil && progInfo.Bpfman.Program != nil {
		bpfFunction = progInfo.Bpfman.Program.Name
	}

	output, err := FormatLinkInfo(bpfFunction, summary, details, &c.OutputFlags)
	if err != nil {
		return err
	}
	return cli.PrintOut(output)
}
