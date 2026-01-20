package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
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
func (c *ListProgramsCmd) Run(cli *CLI) error {
	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	programs, err := mgr.List(ctx)
	if err != nil {
		return err
	}

	// Filter to only managed programs
	managedProgs := manager.FilterManaged(programs)

	if len(managedProgs) == 0 {
		fmt.Println("No managed programs found")
		return nil
	}

	output, err := json.MarshalIndent(managedProgs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

// ListLinksCmd lists managed links.
type ListLinksCmd struct {
	OutputFlags
	ProgramID *ProgramID `name:"program-id" help:"Filter by program ID (supports hex with 0x prefix)."`
}

// Run executes the list links command.
func (c *ListLinksCmd) Run(cli *CLI) error {
	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()

	var links []interface{}
	if c.ProgramID != nil {
		result, err := mgr.ListLinksByProgram(ctx, c.ProgramID.Value)
		if err != nil {
			return err
		}
		for _, l := range result {
			links = append(links, l)
		}
	} else {
		result, err := mgr.ListLinks(ctx)
		if err != nil {
			return err
		}
		for _, l := range result {
			links = append(links, l)
		}
	}

	if len(links) == 0 {
		fmt.Println("No managed links found")
		return nil
	}

	output, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
