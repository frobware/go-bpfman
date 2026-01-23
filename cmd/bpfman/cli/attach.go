package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/manager"
)

// AttachCmd attaches a loaded program to a hook.
type AttachCmd struct {
	ProgramID ProgramID `arg:"" help:"Program ID to attach."`
	Type      string    `arg:"" enum:"xdp,tracepoint,kprobe,tc,tcx,uprobe,fentry,fexit" help:"Attach type."`

	// Tracepoint flags
	Tracepoint string `short:"t" name:"tracepoint" help:"Tracepoint to attach to (group/name format, e.g., sched/sched_switch)."`

	// XDP/TC/TCX flags
	Iface    string `short:"i" name:"iface" help:"Network interface to attach to."`
	Priority int    `short:"p" name:"priority" help:"Priority in chain (1-1000, lower runs first)."`

	// TC/TCX direction flag
	Direction string `short:"d" name:"direction" help:"Direction for TC/TCX (ingress or egress)."`

	// TC proceed-on flag
	ProceedOn []string `name:"proceed-on" help:"TC actions to proceed on (can be repeated). Values: unspec, ok, reclassify, shot, pipe, stolen, queued, repeat, redirect, trap, dispatcher_return." default:"ok,pipe,dispatcher_return"`

	// Network namespace flag
	Netns string `short:"n" name:"netns" help:"Network namespace path (e.g., /var/run/netns/myns)."`

	// Kprobe/uprobe flags
	FnName   string `short:"f" name:"fn-name" help:"Function name to attach to."`
	Offset   uint64 `name:"offset" help:"Offset within the function." default:"0"`
	RetProbe bool   `name:"retprobe" help:"Attach as return probe instead of entry probe."`

	// Common flags
	Metadata []KeyValue `short:"m" name:"metadata" help:"KEY=VALUE metadata (can be repeated)."`
}

// Run executes the attach command.
func (c *AttachCmd) Run(cli *CLI) error {
	switch c.Type {
	case "tracepoint":
		return c.attachTracepoint(cli)
	case "xdp":
		return c.attachXDP(cli)
	case "tc":
		return c.attachTC(cli)
	case "kprobe":
		return c.attachKprobe(cli)
	case "tcx", "uprobe", "fentry", "fexit":
		return fmt.Errorf("%s attachment not yet implemented", c.Type)
	default:
		return fmt.Errorf("unknown attach type: %s", c.Type)
	}
}

func (c *AttachCmd) attachTracepoint(cli *CLI) error {
	if c.Tracepoint == "" {
		return fmt.Errorf("--tracepoint is required for tracepoint attachment")
	}

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

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachXDP(cli *CLI) error {
	if c.Iface == "" {
		return fmt.Errorf("--iface is required for XDP attachment")
	}

	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	ctx := context.Background()
	result, err := b.AttachXDP(ctx, c.ProgramID.Value, iface.Index, c.Iface, "")
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachTC(cli *CLI) error {
	if c.Iface == "" {
		return fmt.Errorf("--iface is required for TC attachment")
	}
	if c.Direction == "" {
		return fmt.Errorf("--direction is required for TC attachment")
	}
	if c.Priority < 1 || c.Priority > 1000 {
		return fmt.Errorf("--priority is required for TC attachment (must be 1-1000)")
	}

	direction, err := ParseTCDirection(c.Direction)
	if err != nil {
		return err
	}

	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	// Parse proceed-on values
	proceedOn, err := ParseTCActions(c.ProceedOn)
	if err != nil {
		return fmt.Errorf("invalid proceed-on value: %w", err)
	}

	ctx := context.Background()
	result, err := b.AttachTC(ctx, c.ProgramID.Value, iface.Index, c.Iface, string(direction), c.Priority, proceedOn, "")
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachKprobe(cli *CLI) error {
	if c.FnName == "" {
		return fmt.Errorf("--fn-name is required for kprobe attachment")
	}
	return fmt.Errorf("kprobe attachment not yet implemented")
}

func (c *AttachCmd) printLinkResult(ctx context.Context, b interface {
	GetLink(context.Context, uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error)
	Get(context.Context, uint32) (manager.ProgramInfo, error)
}, kernelLinkID uint32) error {
	summary, details, err := b.GetLink(ctx, kernelLinkID)
	if err != nil {
		return fmt.Errorf("failed to get link details: %w", err)
	}

	// Fetch program info to get the BPF function name
	var bpfFunction string
	progInfo, err := b.Get(ctx, summary.KernelProgramID)
	if err == nil && progInfo.Kernel != nil && progInfo.Kernel.Program != nil {
		bpfFunction = progInfo.Kernel.Program.Name
	}

	output, err := json.MarshalIndent(struct {
		BPFFunction string `json:"bpf_function,omitempty"`
		Summary     any    `json:"summary"`
		Details     any    `json:"details,omitempty"`
	}{
		BPFFunction: bpfFunction,
		Summary:     summary,
		Details:     details,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
