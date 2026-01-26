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

// NSUprobeCmd attaches a uprobe in the target container's mount namespace.
// When this code runs, the process is already in the target namespace
// (switched by the CGO constructor before Go started).
// The --host-pid argument provides access to the original namespace's bpffs
// via /proc/<host-pid>/root/... paths.
type NSUprobeCmd struct {
	ProgramPinPath string `arg:"" help:"Path to pinned BPF program (in host namespace)."`
	LinkPinPath    string `arg:"" help:"Path to pin the link (in host namespace)."`
	Target         string `arg:"" help:"Target binary path (in container)."`
	FnName         string `name:"fn-name" help:"Function name to attach to."`
	Offset         uint64 `name:"offset" default:"0" help:"Offset from function start."`
	HostPid        int32  `name:"host-pid" required:"" help:"Host PID of bpfman daemon for /proc access."`
	Retprobe       bool   `name:"retprobe" help:"Attach as uretprobe."`
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
// (the CGO constructor called setns before Go started). We access the host
// namespace's bpffs through /proc/<host-pid>/root/... which provides
// cross-namespace filesystem access.
func (cmd *NSUprobeCmd) Run() error {
	// Create a logger that writes to stderr (stdout is reserved for link ID)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Log our current state
	currentMntNs := getMntNsInode("/proc/self/ns/mnt")
	hostMntNs := getMntNsInode(fmt.Sprintf("/proc/%d/ns/mnt", cmd.HostPid))

	logger.Info("bpfman-ns uprobe handler started",
		"pid", os.Getpid(),
		"ppid", os.Getppid(),
		"host_pid", cmd.HostPid,
		"current_mnt_ns_inode", currentMntNs,
		"host_mnt_ns_inode", hostMntNs,
		"target", cmd.Target,
		"fn_name", cmd.FnName,
		"offset", cmd.Offset,
		"retprobe", cmd.Retprobe)

	// Construct paths through /proc/<host-pid>/root to access the host namespace's filesystem
	hostRoot := fmt.Sprintf("/proc/%d/root", cmd.HostPid)
	logger.Debug("host root path", "path", hostRoot)

	// Adjust program pin path to go through host namespace
	adjustedProgPath := filepath.Join(hostRoot, cmd.ProgramPinPath)
	logger.Debug("adjusted program pin path",
		"original", cmd.ProgramPinPath,
		"adjusted", adjustedProgPath)

	// Adjust link pin path to go through host namespace
	adjustedLinkPath := filepath.Join(hostRoot, cmd.LinkPinPath)
	logger.Debug("adjusted link pin path",
		"original", cmd.LinkPinPath,
		"adjusted", adjustedLinkPath)

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

	// Verify host root is accessible
	if _, err := os.Stat(hostRoot); err != nil {
		logger.Error("host root not accessible",
			"host_root", hostRoot,
			"error", err)
		return fmt.Errorf("host root %s not accessible: %w", hostRoot, err)
	}

	// Load the pinned program (via host namespace's bpffs)
	logger.Debug("loading pinned program", "path", adjustedProgPath)
	prog, err := ebpf.LoadPinnedProgram(adjustedProgPath, nil)
	if err != nil {
		logger.Error("failed to load pinned program",
			"path", adjustedProgPath,
			"error", err)
		return fmt.Errorf("load pinned program %s: %w", adjustedProgPath, err)
	}
	defer prog.Close()

	progInfo, _ := prog.Info()
	progID, _ := progInfo.ID()
	logger.Debug("loaded pinned program",
		"path", adjustedProgPath,
		"prog_id", progID,
		"prog_type", prog.Type(),
		"prog_name", progInfo.Name)

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

	// Get link info early for logging
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

	// Create link pin directory (via host namespace's bpffs)
	linkPinDir := filepath.Dir(adjustedLinkPath)
	logger.Debug("creating link pin directory", "path", linkPinDir)
	if err := os.MkdirAll(linkPinDir, 0755); err != nil {
		logger.Error("failed to create link pin directory",
			"path", linkPinDir,
			"error", err)
		lnk.Close()
		return fmt.Errorf("create link pin directory: %w", err)
	}

	// Pin the link (via host namespace's bpffs)
	logger.Debug("pinning link", "path", adjustedLinkPath)
	if err := lnk.Pin(adjustedLinkPath); err != nil {
		logger.Error("failed to pin link",
			"path", adjustedLinkPath,
			"error", err)
		lnk.Close()
		return fmt.Errorf("pin link to %s: %w", adjustedLinkPath, err)
	}
	logger.Info("link pinned successfully",
		"path", adjustedLinkPath,
		"link_id", linkInfo.ID)

	// Print link ID for the parent process to capture (to stdout)
	logger.Debug("writing link ID to stdout", "link_id", linkInfo.ID)
	fmt.Printf("%d\n", linkInfo.ID)

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
