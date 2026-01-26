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

	"github.com/frobware/go-bpfman/nsenter"
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

// File descriptor numbers for inherited fds from parent.
// The parent uses Cmd.ExtraFiles which maps to fd 3, 4, 5, etc.
const (
	ProgramFD = 3 // BPF program fd
	SocketFD  = 4 // Unix socket for passing link fd back to parent
)

// NSUprobeCmd attaches a uprobe in the target container's mount namespace.
// When this code runs, the process is already in the target namespace
// (switched by the CGO constructor before Go started).
//
// The parent process passes:
//   - BPF program via fd 3 (ExtraFiles[0])
//   - Unix socket via fd 4 (ExtraFiles[1]) for returning the link fd
//
// After attaching, we send the link fd back to the parent via the socket.
// The parent (in host namespace) then pins the link.
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
// The BPF program is passed via fd 3, and a Unix socket via fd 4.
// After attaching, we send the link fd back to the parent over the socket.
func (cmd *NSUprobeCmd) Run() error {
	// Create a logger that writes to stderr (stdout is reserved for status)
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
		"program_fd", ProgramFD,
		"socket_fd", SocketFD)

	// Create program from the inherited file descriptor.
	// The parent opened the pinned program and passed the fd via ExtraFiles.
	logger.Debug("creating program from inherited fd", "fd", ProgramFD)
	prog, err := ebpf.NewProgramFromFD(ProgramFD)
	if err != nil {
		logger.Error("failed to create program from fd",
			"fd", ProgramFD,
			"error", err,
			"hint", "bpfman-ns must be invoked by the daemon, not directly")
		return fmt.Errorf("create program from fd %d (bpfman-ns must be invoked by daemon, not directly): %w", ProgramFD, err)
	}
	// Don't close the program - we don't own the fd.
	logger.Debug("program from inherited fd",
		"fd", ProgramFD,
		"prog_type", prog.Type())

	// Get the socket for sending link fd back to parent
	socket := os.NewFile(uintptr(SocketFD), "fdpass-socket")
	if socket == nil {
		logger.Error("failed to get socket fd",
			"fd", SocketFD,
			"hint", "bpfman-ns must be invoked by the daemon, not directly")
		return fmt.Errorf("socket fd %d not available (bpfman-ns must be invoked by daemon)", SocketFD)
	}
	defer socket.Close()

	// Verify target binary exists in current namespace.
	if stat, err := os.Stat(cmd.Target); err != nil {
		logger.Error("target binary not found in container namespace",
			"target", cmd.Target,
			"error", err,
			"current_mnt_ns_inode", currentMntNs,
			"hint", "ensure the target path exists in the container's filesystem")
		return fmt.Errorf("target binary %q not found in container (mnt ns inode %d): %w", cmd.Target, currentMntNs, err)
	} else {
		logger.Debug("target binary found in container namespace",
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
			"offset", cmd.Offset,
			"target", cmd.Target,
			"current_mnt_ns_inode", currentMntNs,
			"error", err)
		return fmt.Errorf("attach %s to %s (offset %d) in %q (mnt ns %d): %w", attachType, cmd.FnName, cmd.Offset, cmd.Target, currentMntNs, err)
	}

	logger.Info("probe attached successfully", "type", attachType)

	// Get the perf event fd from the link.
	// Uprobe links implement the PerfEvent interface.
	pe, ok := lnk.(link.PerfEvent)
	if !ok {
		logger.Error("link does not implement PerfEvent interface",
			"type", attachType)
		lnk.Close()
		return fmt.Errorf("link does not implement PerfEvent interface")
	}

	perfFile, err := pe.PerfEvent()
	if err != nil {
		logger.Error("failed to get perf event fd",
			"error", err)
		lnk.Close()
		return fmt.Errorf("get perf event fd: %w", err)
	}

	// Send the perf event fd back to the parent via the Unix socket.
	// The parent (in host namespace) will receive it and keep the link alive.
	linkFd := int(perfFile.Fd())
	logger.Debug("sending link fd to parent",
		"link_fd", linkFd,
		"socket_fd", SocketFD)

	if err := nsenter.SendFd(socket, "uprobe-link", linkFd); err != nil {
		logger.Error("failed to send link fd to parent",
			"link_fd", linkFd,
			"error", err)
		perfFile.Close()
		lnk.Close()
		return fmt.Errorf("send link fd to parent: %w", err)
	}

	logger.Info("link fd sent to parent successfully",
		"link_fd", linkFd)

	// Close our references. The parent now has the fd via SCM_RIGHTS.
	perfFile.Close()

	// Print success to stdout for the parent
	fmt.Println("ok")

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
