package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// AttachCmd attaches a loaded program to a hook.
type AttachCmd struct {
	Tracepoint TracepointCmd `cmd:"" help:"Attach to a tracepoint."`
	Kprobe     KprobeCmd     `cmd:"" help:"Attach to a kprobe."`
	Xdp        XDPCmd        `cmd:"" help:"Attach XDP program to a network interface."`
}

// TracepointCmd attaches a program to a tracepoint.
type TracepointCmd struct {
	ProgramID  ProgramID `arg:"" help:"Program ID to attach."`
	Tracepoint string    `short:"t" name:"tracepoint" required:"" help:"The tracepoint to attach to (e.g., sched/sched_switch)."`
	Metadata   string    `short:"m" name:"metadata" help:"Key/Value metadata (KEY=VALUE)."`
}

// Run executes the tracepoint attach command.
func (c *TracepointCmd) Run(cli *CLI) error {
	// Parse "group/name" format
	parts := strings.SplitN(c.Tracepoint, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("tracepoint must be in 'group/name' format, got %q", c.Tracepoint)
	}
	group, name := parts[0], parts[1]

	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()
	result, err := b.AttachTracepoint(ctx, c.ProgramID.Value, group, name, "")
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
	ProgramID ProgramID `arg:"" help:"Program ID to attach."`
	FnName    string    `short:"f" name:"fn-name" required:"" help:"Kernel function name to attach to."`
	Offset    uint64    `name:"offset" help:"Offset within the function." default:"0"`
	RetProbe  bool      `name:"ret" help:"Attach as kretprobe instead of kprobe."`
	Metadata  string    `short:"m" name:"metadata" help:"Key/Value metadata (KEY=VALUE)."`
}

// Run executes the kprobe attach command.
func (c *KprobeCmd) Run(cli *CLI) error {
	// Kprobe is not yet implemented in the manager
	return fmt.Errorf("kprobe attachment not yet implemented")
}

// XDPCmd attaches an XDP program to a network interface.
type XDPCmd struct {
	ProgramID ProgramID `arg:"" help:"Program ID to attach."`
	Iface     string    `short:"i" name:"iface" required:"" help:"Interface to attach to."`
	Priority  int       `short:"p" name:"priority" required:"" help:"Priority to run program in chain (1-1000, lower runs first)."`
	Metadata  string    `short:"m" name:"metadata" help:"Key/Value metadata (KEY=VALUE)."`
}

// Run executes the XDP attach command.
func (c *XDPCmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	// Resolve interface name to ifindex
	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	ctx := context.Background()

	result, err := b.AttachXDP(ctx, c.ProgramID.Value, iface.Index, c.Iface, "")
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
