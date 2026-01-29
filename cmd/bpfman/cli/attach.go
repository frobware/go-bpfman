package cli

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/client"
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

// attachResult holds the result of an attach operation for output outside the lock.
type attachResult struct {
	KernelLinkID uint32
}

// Run executes the attach command: mutation under lock, output outside.
func (c *AttachCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	// Execute mutation under lock
	result, err := c.execute(ctx, cli, b)
	if err != nil {
		return err
	}

	// Output using same client, outside lock
	return c.output(cli, ctx, b, result)
}

// execute performs the attach operation under the global writer lock.
func (c *AttachCmd) execute(ctx context.Context, cli *CLI, b client.Client) (attachResult, error) {
	return RunWithLockValue(ctx, cli, func(ctx context.Context) (attachResult, error) {
		switch c.Type {
		case "tracepoint":
			return c.attachTracepoint(ctx, b)
		case "xdp":
			return c.attachXDP(ctx, b)
		case "tc":
			return c.attachTC(ctx, b)
		case "tcx":
			return c.attachTCX(ctx, b)
		case "kprobe":
			return c.attachKprobe(ctx, b)
		case "uprobe":
			return c.attachUprobe(ctx, b)
		case "fentry":
			return c.attachFentry(ctx, b)
		case "fexit":
			return c.attachFexit(ctx, b)
		default:
			return attachResult{}, fmt.Errorf("unknown attach type: %s", c.Type)
		}
	})
}

// output fetches link details and formats output outside the lock.
func (c *AttachCmd) output(cli *CLI, ctx context.Context, b client.Client, result attachResult) error {
	summary, details, err := b.GetLink(ctx, result.KernelLinkID)
	if err != nil {
		// Can't fetch details, print minimal result
		return cli.PrintOutf("Attached link %d\n", result.KernelLinkID)
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
	return cli.PrintOut(output)
}

func (c *AttachCmd) attachTracepoint(ctx context.Context, b client.Client) (attachResult, error) {
	if c.Tracepoint == "" {
		return attachResult{}, fmt.Errorf("--tracepoint is required for tracepoint attachment")
	}

	parts := strings.SplitN(c.Tracepoint, "/", 2)
	if len(parts) != 2 {
		return attachResult{}, fmt.Errorf("tracepoint must be in 'group/name' format, got %q", c.Tracepoint)
	}
	group, name := parts[0], parts[1]

	spec, err := bpfman.NewTracepointAttachSpec(c.ProgramID.Value, group, name)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid tracepoint spec: %w", err)
	}

	result, err := b.AttachTracepoint(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachXDP(ctx context.Context, b client.Client) (attachResult, error) {
	if c.Iface == "" {
		return attachResult{}, fmt.Errorf("--iface is required for XDP attachment")
	}

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return attachResult{}, fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	spec, err := bpfman.NewXDPAttachSpec(c.ProgramID.Value, c.Iface, iface.Index)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid XDP spec: %w", err)
	}

	result, err := b.AttachXDP(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachTC(ctx context.Context, b client.Client) (attachResult, error) {
	if c.Iface == "" {
		return attachResult{}, fmt.Errorf("--iface is required for TC attachment")
	}
	if c.Direction == "" {
		return attachResult{}, fmt.Errorf("--direction is required for TC attachment")
	}
	if c.Priority < 1 || c.Priority > 1000 {
		return attachResult{}, fmt.Errorf("--priority is required for TC attachment (must be 1-1000)")
	}

	direction, err := ParseTCDirection(c.Direction)
	if err != nil {
		return attachResult{}, err
	}

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return attachResult{}, fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	// Parse proceed-on values
	proceedOn, err := ParseTCActions(c.ProceedOn)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid proceed-on value: %w", err)
	}

	spec, err := bpfman.NewTCAttachSpec(c.ProgramID.Value, c.Iface, iface.Index, string(direction))
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid TC spec: %w", err)
	}
	spec = spec.WithPriority(c.Priority).WithProceedOn(proceedOn)

	result, err := b.AttachTC(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachTCX(ctx context.Context, b client.Client) (attachResult, error) {
	if c.Iface == "" {
		return attachResult{}, fmt.Errorf("--iface is required for TCX attachment")
	}
	if c.Direction == "" {
		return attachResult{}, fmt.Errorf("--direction is required for TCX attachment")
	}
	if c.Priority < 1 || c.Priority > 1000 {
		return attachResult{}, fmt.Errorf("--priority is required for TCX attachment (must be 1-1000)")
	}

	direction, err := ParseTCDirection(c.Direction)
	if err != nil {
		return attachResult{}, err
	}

	iface, err := net.InterfaceByName(c.Iface)
	if err != nil {
		return attachResult{}, fmt.Errorf("failed to find interface %q: %w", c.Iface, err)
	}

	spec, err := bpfman.NewTCXAttachSpec(c.ProgramID.Value, c.Iface, iface.Index, string(direction))
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid TCX spec: %w", err)
	}
	spec = spec.WithPriority(c.Priority)

	result, err := b.AttachTCX(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachKprobe(ctx context.Context, b client.Client) (attachResult, error) {
	if c.FnName == "" {
		return attachResult{}, fmt.Errorf("--fn-name is required for kprobe attachment")
	}

	spec, err := bpfman.NewKprobeAttachSpec(c.ProgramID.Value, c.FnName)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid kprobe spec: %w", err)
	}
	if c.Offset != 0 {
		spec = spec.WithOffset(c.Offset)
	}

	result, err := b.AttachKprobe(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachUprobe(ctx context.Context, b client.Client) (attachResult, error) {
	if c.Target == "" {
		return attachResult{}, fmt.Errorf("--target is required for uprobe attachment")
	}

	spec, err := bpfman.NewUprobeAttachSpec(c.ProgramID.Value, c.Target)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid uprobe spec: %w", err)
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

	result, err := b.AttachUprobe(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachFentry(ctx context.Context, b client.Client) (attachResult, error) {
	spec, err := bpfman.NewFentryAttachSpec(c.ProgramID.Value)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid fentry spec: %w", err)
	}

	result, err := b.AttachFentry(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}

func (c *AttachCmd) attachFexit(ctx context.Context, b client.Client) (attachResult, error) {
	spec, err := bpfman.NewFexitAttachSpec(c.ProgramID.Value)
	if err != nil {
		return attachResult{}, fmt.Errorf("invalid fexit spec: %w", err)
	}

	result, err := b.AttachFexit(ctx, spec, bpfman.AttachOpts{})
	if err != nil {
		return attachResult{}, err
	}
	return attachResult{KernelLinkID: result.KernelLinkID}, nil
}
