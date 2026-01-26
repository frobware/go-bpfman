// Package cli provides the command-line interface for bpfman.
package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	// Import nsenter to register the CGO constructor that handles
	// mount namespace switching before Go runtime starts.
	_ "github.com/frobware/go-bpfman/nsenter"
)

// NSCmd handles the bpfman-ns subcommand for attaching uprobes in other
// namespaces.
//
// The namespace switch happens via a CGO constructor (in the nsenter package)
// that runs before Go's runtime starts. The parent process sets _BPFMAN_MNT_NS
// environment variable, and the C code calls setns(CLONE_NEWNS) while still
// single-threaded.
type NSCmd struct {
	Uprobe NSUprobeCmd `cmd:"" help:"Attach uprobe in target namespace."`
}

// ProgramFD is the file descriptor number where the parent passes the BPF
// program. The parent uses Cmd.ExtraFiles which maps to fd 3, 4, 5, etc.
const ProgramFD = 3

// NSUprobeCmd attaches a uprobe in the target container's mount namespace.
// When this code runs, the process is already in the target namespace
// (switched by the CGO constructor before Go started).
//
// The parent process passes the BPF program via fd 3 (using Cmd.ExtraFiles),
// so we don't need access to the host's bpffs. After attaching, we print the
// link ID to stdout; the parent then uses link.NewFromID() to pin it.
type NSUprobeCmd struct {
	Target   string `arg:"" help:"Target binary path (resolved in container namespace)."`
	FnName   string `name:"fn-name" help:"Function name to attach to."`
	Offset   uint64 `name:"offset" default:"0" help:"Offset from function start."`
	Retprobe bool   `name:"retprobe" help:"Attach as uretprobe."`
}

// getMntNsInode returns the inode of a mount namespace file.
func getMntNsInode(path string) uint64 {
	stat, err := os.Stat(path)
	if err != nil {
		return 0
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return sys.Ino
}

// Run executes the uprobe attachment. We're already in the target namespace
// (the CGO constructor called setns before Go started).
//
// The BPF program is passed via fd 3 from the parent process. After attaching,
// we print the link ID to stdout so the parent can pin it.
func (cmd *NSUprobeCmd) Run() error {
	// Create a logger that writes to stderr (stdout is reserved for link ID)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Log our current state
	currentMntNs := getMntNsInode("/proc/self/ns/mnt")

	logger.Info("bpfman-ns uprobe handler started",
		"pid", os.Getpid(),
		"ppid", os.Getppid(),
		"current_mnt_ns_inode", currentMntNs,
		"target", cmd.Target,
		"fn_name", cmd.FnName,
		"offset", cmd.Offset,
		"retprobe", cmd.Retprobe,
		"program_fd", ProgramFD)

	// Create program from the inherited file descriptor.
	// The parent opened the pinned program and passed the fd via ExtraFiles.
	logger.Debug("creating program from inherited fd", "fd", ProgramFD)
	prog, err := ebpf.NewProgramFromFD(ProgramFD)
	if err != nil {
		logger.Error("failed to create program from fd",
			"fd", ProgramFD,
			"error", err)
		return fmt.Errorf("create program from fd %d: %w", ProgramFD, err)
	}
	// Don't close the program - we don't own the fd, and closing would
	// close the underlying fd which we inherited from parent.

	progInfo, _ := prog.Info()
	progID, _ := progInfo.ID()
	logger.Debug("program from inherited fd",
		"prog_id", progID,
		"prog_type", prog.Type(),
		"prog_name", progInfo.Name)

	// Verify target binary exists in current namespace
	if stat, err := os.Stat(cmd.Target); err != nil {
		logger.Error("target binary not found in current namespace",
			"target", cmd.Target,
			"error", err)
		return fmt.Errorf("target binary %s not found: %w", cmd.Target, err)
	} else {
		logger.Debug("target binary found",
			"target", cmd.Target,
			"size", stat.Size(),
			"mode", stat.Mode())
	}

	// Open the executable (resolves in current/target namespace)
	logger.Debug("opening executable", "target", cmd.Target)
	ex, err := link.OpenExecutable(cmd.Target)
	if err != nil {
		logger.Error("failed to open executable",
			"target", cmd.Target,
			"error", err)
		return fmt.Errorf("open executable %s: %w", cmd.Target, err)
	}
	logger.Debug("opened executable", "target", cmd.Target)

	// Attach uprobe
	opts := &link.UprobeOptions{Offset: cmd.Offset}
	var lnk link.Link

	attachType := "uprobe"
	if cmd.Retprobe {
		attachType = "uretprobe"
	}
	logger.Info("attaching probe",
		"type", attachType,
		"fn_name", cmd.FnName,
		"offset", cmd.Offset,
		"target", cmd.Target)

	if cmd.Retprobe {
		lnk, err = ex.Uretprobe(cmd.FnName, prog, opts)
	} else {
		lnk, err = ex.Uprobe(cmd.FnName, prog, opts)
	}
	if err != nil {
		logger.Error("failed to attach probe",
			"type", attachType,
			"fn_name", cmd.FnName,
			"target", cmd.Target,
			"error", err)
		return fmt.Errorf("attach %s to %s in %s: %w", attachType, cmd.FnName, cmd.Target, err)
	}

	// Get link info for the parent
	linkInfo, err := lnk.Info()
	if err != nil {
		logger.Error("failed to get link info", "error", err)
		lnk.Close()
		return fmt.Errorf("get link info: %w", err)
	}

	logger.Info("probe attached successfully",
		"type", attachType,
		"link_id", linkInfo.ID,
		"link_type", linkInfo.Type,
		"prog_id", progID)

	// Print link ID for the parent process to capture (to stdout).
	// The parent will use link.NewFromID() to get the link and pin it.
	logger.Debug("writing link ID to stdout", "link_id", linkInfo.ID)
	fmt.Printf("%d\n", linkInfo.ID)

	// Close the link fd - the kernel link object persists because it's
	// attached to the uprobe. The parent will re-acquire it via NewFromID.
	lnk.Close()

	logger.Info("bpfman-ns uprobe handler completed successfully",
		"link_id", linkInfo.ID)

	return nil
}

// runAsNS checks if we're running as bpfman-ns and handles it specially.
// Returns true if we handled bpfman-ns mode (caller should exit).
func runAsNS() bool {
	// Check if invoked as bpfman-ns or with "bpfman-ns" as first arg
	isBpfmanNS := false
	if filepath.Base(os.Args[0]) == "bpfman-ns" {
		isBpfmanNS = true
	} else if len(os.Args) > 1 && os.Args[1] == "bpfman-ns" {
		// Remove "bpfman-ns" from args so kong sees "uprobe" as the command
		os.Args = append(os.Args[:1], os.Args[2:]...)
		isBpfmanNS = true
	}

	if !isBpfmanNS {
		return false
	}

	// Parse and run the NS command using kong
	var cmd struct {
		Uprobe NSUprobeCmd `cmd:"" help:"Attach uprobe in target namespace."`
	}

	ctx := kong.Parse(&cmd,
		kong.Name("bpfman-ns"),
		kong.Description("BPF namespace helper for container uprobes."),
		kong.UsageOnError(),
	)

	if err := ctx.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "bpfman-ns: %v\n", err)
		os.Exit(1)
	}

	return true
}
