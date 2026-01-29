package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
}

// Run executes the list programs command.
func (c *ListProgramsCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

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

	var links []interface{}
	if c.ProgramID != nil {
		result, err := b.ListLinksByProgram(ctx, c.ProgramID.Value)
		if errors.Is(err, client.ErrNotSupported) {
			return fmt.Errorf("listing links by program is only available in local mode")
		}
		if err != nil {
			return err
		}
		for _, l := range result {
			links = append(links, l)
		}
	} else {
		result, err := b.ListLinks(ctx)
		if errors.Is(err, client.ErrNotSupported) {
			return fmt.Errorf("listing links is only available in local mode")
		}
		if err != nil {
			return err
		}
		for _, l := range result {
			links = append(links, l)
		}
	}

	if len(links) == 0 {
		return cli.PrintOut("No managed links found\n")
	}

	output, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	return cli.PrintOutf("%s\n", output)
}
