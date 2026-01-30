package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/manager"
)

// ListCmd lists managed programs or links.
type ListCmd struct {
	Programs ListProgramsCmd `cmd:"" default:"withargs" help:"List managed programs."`
	Links    ListLinksCmd    `cmd:"" help:"List managed links."`
}

// ListProgramsCmd lists managed BPF programs.
type ListProgramsCmd struct {
	OutputFlags
	Local bool `help:"Return full spec/status composite (local only, requires --json)." default:"false"`
}

// Run executes the list programs command.
func (c *ListProgramsCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	if c.Local {
		return c.runLocal(cli, ctx, b)
	}
	return c.runRemote(cli, ctx, b)
}

// runLocal returns the full Program composite with spec and status.
func (c *ListProgramsCmd) runLocal(cli *CLI, ctx context.Context, b client.Client) error {
	programs, err := b.ListPrograms(ctx)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("--local requires local mode (not available with remote daemon)")
	}
	if err != nil {
		return err
	}

	if len(programs) == 0 {
		return cli.PrintOut("No managed programs found\n")
	}

	output, err := FormatProgramsComposite(programs, &c.OutputFlags)
	if err != nil {
		return err
	}
	return cli.PrintOut(output)
}

// runRemote returns the traditional list view via gRPC.
func (c *ListProgramsCmd) runRemote(cli *CLI, ctx context.Context, b client.Client) error {
	programs, err := b.List(ctx)
	if err != nil {
		return err
	}

	// Filter to only managed programs
	managedProgs := manager.FilterManaged(programs)

	if len(managedProgs) == 0 {
		return cli.PrintOut("No managed programs found\n")
	}

	output, err := FormatProgramList(managedProgs, &c.OutputFlags)
	if err != nil {
		return err
	}
	return cli.PrintOut(output)
}

// ListLinksCmd lists managed links.
type ListLinksCmd struct {
	OutputFlags
	ProgramID *ProgramID `name:"program-id" help:"Filter by program ID (supports hex with 0x prefix)."`
}

// Run executes the list links command.
func (c *ListLinksCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	var links []bpfman.LinkRecord
	if c.ProgramID != nil {
		links, err = b.ListLinksByProgram(ctx, c.ProgramID.Value)
		if errors.Is(err, client.ErrNotSupported) {
			return fmt.Errorf("listing links by program is only available in local mode")
		}
		if err != nil {
			return err
		}
	} else {
		links, err = b.ListLinks(ctx)
		if errors.Is(err, client.ErrNotSupported) {
			return fmt.Errorf("listing links is only available in local mode")
		}
		if err != nil {
			return err
		}
	}

	if len(links) == 0 {
		return cli.PrintOut("No managed links found\n")
	}

	output, err := FormatLinkList(links, &c.OutputFlags)
	if err != nil {
		return err
	}
	return cli.PrintOut(output)
}
