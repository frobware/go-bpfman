package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"

	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
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
	ProgPinPath string    `arg:"" name:"prog-pin-path" help:"Path to the pinned program."`
	Group       string    `arg:"" name:"group" help:"Tracepoint group (e.g., syscalls)."`
	Name        string    `arg:"" name:"name" help:"Tracepoint name (e.g., sys_enter_openat)."`
	LinkPinPath string    `name:"link-pin-path" help:"Path to pin the link (optional)."`
}

// Run executes the tracepoint attach command.
func (c *TracepointCmd) Run(cli *CLI) error {
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

	// Auto-generate link pin path if not provided.
	// Links must be pinned to persist beyond the CLI command.
	linkPinPath := c.LinkPinPath
	if linkPinPath == "" {
		linkPinPath = filepath.Join(filepath.Dir(c.ProgPinPath), "link")
	}

	ctx := context.Background()
	result, err := mgr.AttachTracepoint(ctx, c.ProgramID.Value, c.ProgPinPath, c.Group, c.Name, linkPinPath)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(result, "", "  ")
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
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	mgr, cleanup, err := manager.Setup(cli.DB.Path, logger)
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	// Resolve interface name to ifindex
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return fmt.Errorf("failed to find interface %q: %w", c.Interface, err)
	}

	ctx := context.Background()

	// Auto-generate link pin path if not provided.
	// Links must be pinned to persist beyond the CLI command.
	linkPinPath := c.LinkPinPath
	if linkPinPath == "" {
		// Get program info to derive link pin path from program's pin directory
		progInfo, err := mgr.Get(ctx, c.ProgramID.Value)
		if err != nil {
			return fmt.Errorf("failed to get program %d: %w", c.ProgramID.Value, err)
		}
		if progInfo.Bpfman == nil || progInfo.Bpfman.Program == nil {
			return fmt.Errorf("program %d not found in bpfman store", c.ProgramID.Value)
		}
		linkPinPath = filepath.Join(progInfo.Bpfman.Program.LoadSpec.PinPath, "link")
	}

	result, err := mgr.AttachXDP(ctx, c.ProgramID.Value, iface.Index, c.Interface, linkPinPath)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
