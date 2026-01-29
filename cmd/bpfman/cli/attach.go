package cli

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/manager"
)

// AttachCmd attaches a loaded program to a hook.
type AttachCmd struct {
	OutputFlags

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
	FnName       string `short:"f" name:"fn-name" help:"Function name to attach to."`
	Offset       uint64 `name:"offset" help:"Offset within the function." default:"0"`
	RetProbe     bool   `name:"retprobe" help:"Attach as return probe instead of entry probe."`
	Target       string `name:"target" help:"Path to target binary or library (required for uprobe)."`
	ContainerPid int32  `name:"container-pid" help:"Container PID for namespace-aware uprobe attachment."`

	// Common flags
	Metadata []KeyValue `short:"m" name:"metadata" help:"KEY=VALUE metadata (can be repeated)."`
}

// Run executes the attach command.
func (c *AttachCmd) Run(cli *CLI, ctx context.Context) error {
	return cli.RunWithLock(ctx, func(ctx context.Context) error {
		switch c.Type {
		case "tracepoint":
			return c.attachTracepoint(cli, ctx)
		case "xdp":
			return c.attachXDP(cli, ctx)
		case "tc":
			return c.attachTC(cli, ctx)
		case "tcx":
			return c.attachTCX(cli, ctx)
		case "kprobe":
			return c.attachKprobe(cli, ctx)
		case "uprobe":
			return c.attachUprobe(cli, ctx)
		case "fentry":
			return c.attachFentry(cli, ctx)
		case "fexit":
			return c.attachFexit(cli, ctx)
		default:
			return fmt.Errorf("unknown attach type: %s", c.Type)
		}
	})
}

func (c *AttachCmd) attachTracepoint(cli *CLI, ctx context.Context) error {
	if c.Tracepoint == "" {
		return fmt.Errorf("--tracepoint is required for tracepoint attachment")
	}

	parts := strings.SplitN(c.Tracepoint, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("tracepoint must be in 'group/name' format, got %q", c.Tracepoint)
	}
	group, name := parts[0], parts[1]

	spec, err := bpfman.NewTracepointAttachSpec(c.ProgramID.Value, group, name)
	if err != nil {
		return fmt.Errorf("invalid tracepoint spec: %w", err)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachTracepoint(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachXDP(cli *CLI, ctx context.Context) error {
	if c.Iface == "" {
		return fmt.Errorf("--iface is required for XDP attachment")
	}

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	spec, err := bpfman.NewXDPAttachSpec(c.ProgramID.Value, c.Iface, iface.Index)
	if err != nil {
		return fmt.Errorf("invalid XDP spec: %w", err)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachXDP(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachTC(cli *CLI, ctx context.Context) error {
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

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	// Parse proceed-on values
	proceedOn, err := ParseTCActions(c.ProceedOn)
	if err != nil {
		return fmt.Errorf("invalid proceed-on value: %w", err)
	}

	spec, err := bpfman.NewTCAttachSpec(c.ProgramID.Value, c.Iface, iface.Index, string(direction))
	if err != nil {
		return fmt.Errorf("invalid TC spec: %w", err)
	}
	spec = spec.WithPriority(c.Priority).WithProceedOn(proceedOn)

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachTC(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachTCX(cli *CLI, ctx context.Context) error {
	if c.Iface == "" {
		return fmt.Errorf("--iface is required for TCX attachment")
	}
	if c.Direction == "" {
		return fmt.Errorf("--direction is required for TCX attachment")
	}
	if c.Priority < 1 || c.Priority > 1000 {
		return fmt.Errorf("--priority is required for TCX attachment (must be 1-1000)")
	}

	direction, err := ParseTCDirection(c.Direction)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	spec, err := bpfman.NewTCXAttachSpec(c.ProgramID.Value, c.Iface, iface.Index, string(direction))
	if err != nil {
		return fmt.Errorf("invalid TCX spec: %w", err)
	}
	spec = spec.WithPriority(c.Priority)

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachTCX(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachKprobe(cli *CLI, ctx context.Context) error {
	if c.FnName == "" {
		return fmt.Errorf("--fn-name is required for kprobe attachment")
	}

	spec, err := bpfman.NewKprobeAttachSpec(c.ProgramID.Value, c.FnName)
	if err != nil {
		return fmt.Errorf("invalid kprobe spec: %w", err)
	}
	if c.Offset != 0 {
		spec = spec.WithOffset(c.Offset)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachKprobe(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachUprobe(cli *CLI, ctx context.Context) error {
	if c.Target == "" {
		return fmt.Errorf("--target is required for uprobe attachment")
	}

	spec, err := bpfman.NewUprobeAttachSpec(c.ProgramID.Value, c.Target)
	if err != nil {
		return fmt.Errorf("invalid uprobe spec: %w", err)
	}
	if c.FnName != "" {
		spec = spec.WithFnName(c.FnName)
	}
	if c.Offset != 0 {
		spec = spec.WithOffset(c.Offset)
	}
	if c.ContainerPid > 0 {
		spec = spec.WithContainerPid(c.ContainerPid)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachUprobe(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachFentry(cli *CLI, ctx context.Context) error {
	spec, err := bpfman.NewFentryAttachSpec(c.ProgramID.Value)
	if err != nil {
		return fmt.Errorf("invalid fentry spec: %w", err)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachFentry(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
}

func (c *AttachCmd) attachFexit(cli *CLI, ctx context.Context) error {
	spec, err := bpfman.NewFexitAttachSpec(c.ProgramID.Value)
	if err != nil {
		return fmt.Errorf("invalid fexit spec: %w", err)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	result, err := b.AttachFexit(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return err
	}

	return c.printLinkResult(ctx, b, result.KernelLinkID)
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

	output, err := FormatLinkResult(bpfFunction, summary, details, &c.OutputFlags)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}
