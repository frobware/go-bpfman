package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
)

// AttachCmd attaches a loaded program to a hook.
type AttachCmd struct {
	Tracepoint TracepointCmd `cmd:"" help:"Attach to a tracepoint."`
	Kprobe     KprobeCmd     `cmd:"" help:"Attach to a kprobe."`
	Xdp        XDPCmd        `cmd:"" help:"Attach XDP program to a network interface."`
}

// TracepointCmd attaches a program to a tracepoint.
type TracepointCmd struct {
	ProgramID   ProgramID `name:"program-id" required:"" help:"Kernel program ID to attach (supports hex with 0x prefix)."`
	Group       string    `arg:"" name:"group" help:"Tracepoint group (e.g., sched)."`
	Name        string    `arg:"" name:"name" help:"Tracepoint name (e.g., sched_switch)."`
	LinkPinPath string    `name:"link-pin-path" help:"Path to pin the link (auto-generated if not provided)."`
}

// Run executes the tracepoint attach command.
func (c *TracepointCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	result, err := b.AttachTracepoint(ctx, c.ProgramID.Value, c.Group, c.Name, c.LinkPinPath)
	if err != nil {
		return err
	}

	// Fetch full link details from the database
	summary, details, err := b.GetLink(ctx, result.KernelLinkID)
	if err != nil {
		return fmt.Errorf("failed to get link details: %w", err)
	}

	output, err := json.MarshalIndent(struct {
		Summary any `json:"summary"`
		Details any `json:"details,omitempty"`
	}{
		Summary: summary,
		Details: details,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

// KprobeCmd attaches a program to a kprobe.
type KprobeCmd struct {
	ProgramID   ProgramID `name:"program-id" required:"" help:"Kernel program ID to attach (supports hex with 0x prefix)."`
	ProgPinPath string    `arg:"" name:"prog-pin-path" help:"Path to the pinned program."`
	FnName      string    `arg:"" name:"fn-name" help:"Kernel function name."`
	Offset      uint64    `name:"offset" help:"Offset within the function." default:"0"`
	RetProbe    bool      `name:"ret" help:"Attach as kretprobe instead of kprobe."`
	LinkPinPath string    `name:"link-pin-path" help:"Path to pin the link (optional)."`
}

// Run executes the kprobe attach command.
func (c *KprobeCmd) Run(cli *CLI) error {
	// Kprobe is not yet implemented in the manager
	return fmt.Errorf("kprobe attachment not yet implemented")
}

// XDPCmd attaches an XDP program to a network interface.
type XDPCmd struct {
	ProgramID   ProgramID `name:"program-id" required:"" help:"Kernel program ID to attach (supports hex with 0x prefix)."`
	Interface   string    `arg:"" name:"interface" help:"Network interface name (e.g., eth0)."`
	LinkPinPath string    `name:"link-pin-path" help:"Path to pin the link (optional)."`
}

// Run executes the XDP attach command.
func (c *XDPCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	// Resolve interface name to ifindex
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Interface, err)
	}

	ctx := context.Background()

	// For XDP dispatcher attachments, let the manager compute the pin path
	// using the new dispatcher path convention. Only override if explicitly provided.
	linkPinPath := c.LinkPinPath

	result, err := b.AttachXDP(ctx, c.ProgramID.Value, iface.Index, c.Interface, linkPinPath)
	if err != nil {
		return err
	}

	// Fetch full link details from the database
	summary, details, err := b.GetLink(ctx, result.KernelLinkID)
	if err != nil {
		return fmt.Errorf("failed to get link details: %w", err)
	}

	output, err := json.MarshalIndent(struct {
		Summary any `json:"summary"`
		Details any `json:"details,omitempty"`
	}{
		Summary: summary,
		Details: details,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
