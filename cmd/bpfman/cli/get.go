package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/pkg/bpfman/client"
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
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	summary, details, err := b.GetLink(ctx, c.LinkUUID.Value)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("getting link details is only available in local mode")
	}
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
