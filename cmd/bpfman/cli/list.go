package cli

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman"
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
	runtime, err := cli.NewCLIRuntime(ctx)
	if err != nil {
		return fmt.Errorf("create runtime: %w", err)
	}
	defer runtime.Close()

	result, err := runtime.Manager.ListPrograms(ctx)
	if err != nil {
		return err
	}

	if len(result.Programs) == 0 {
		return cli.PrintOut("No managed programs found\n")
	}

	output, err := FormatProgramsComposite(result, &c.OutputFlags)
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
	runtime, err := cli.NewCLIRuntime(ctx)
	if err != nil {
		return fmt.Errorf("create runtime: %w", err)
	}
	defer runtime.Close()

	var links []bpfman.LinkRecord
	if c.ProgramID != nil {
		links, err = runtime.Manager.ListLinksByProgram(ctx, c.ProgramID.Value)
	} else {
		links, err = runtime.Manager.ListLinks(ctx)
	}
	if err != nil {
		return err
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
