package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// GetCmd gets details of a program or link.
type GetCmd struct {
	Program GetProgramCmd `cmd:"" default:"withargs" help:"Get program details."`
	Link    GetLinkCmd    `cmd:"" help:"Get link details."`
}

// GetProgramCmd gets details of a managed program by kernel ID.
type GetProgramCmd struct {
	OutputFlags
	ProgramID ProgramID `arg:"" name:"program-id" help:"Kernel program ID (supports hex with 0x prefix)."`
}

// Run executes the get program command.
func (c *GetProgramCmd) Run(cli *CLI) error {
	// Set up logger
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, logger)
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	info, err := mgr.Get(ctx, c.ProgramID.Value)
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

// GetLinkCmd gets details of a link by UUID.
type GetLinkCmd struct {
	OutputFlags
	LinkUUID LinkUUID `arg:"" name:"link-uuid" help:"Link UUID."`
}

// LinkInfo combines summary and details for JSON output.
type LinkInfo struct {
	Summary interface{} `json:"summary"`
	Details interface{} `json:"details"`
}

// Run executes the get link command.
func (c *GetLinkCmd) Run(cli *CLI) error {
	// Set up logger
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, logger)
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	summary, details, err := mgr.GetLink(ctx, c.LinkUUID.Value)
	if err != nil {
		return err
	}

	info := LinkInfo{
		Summary: summary,
		Details: details,
	}

	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
