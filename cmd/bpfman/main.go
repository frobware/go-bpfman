// bpfman is a minimal BPF program manager.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman/domain"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/kernel/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	"github.com/frobware/go-bpfman/pkg/bpfman/server"
	"github.com/frobware/go-bpfman/pkg/csi/driver"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <COMMAND>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  serve   Start the gRPC server\n")
	fmt.Fprintf(os.Stderr, "  load    Load an eBPF program from an object file\n")
	fmt.Fprintf(os.Stderr, "          [-m KEY=VALUE] metadata to attach to the program\n")
	fmt.Fprintf(os.Stderr, "          [--db PATH]    SQLite database path (default: %s)\n", server.DefaultDBPath)
	fmt.Fprintf(os.Stderr, "  attach  Attach a loaded program to a hook\n")
	fmt.Fprintf(os.Stderr, "          attach tracepoint <prog-pin-path> <group> <name> [--link-pin-path <path>]\n")
	fmt.Fprintf(os.Stderr, "  unload  Unload (unpin) an eBPF program\n")
	fmt.Fprintf(os.Stderr, "  list    List pinned eBPF programs [--maps]\n")
	fmt.Fprintf(os.Stderr, "  get     Get details of a pinned program\n")
	fmt.Fprintf(os.Stderr, "  gc      Garbage collect stale/orphaned resources (dry-run by default)\n")
	fmt.Fprintf(os.Stderr, "          [--prune]      Actually delete (default: dry-run)\n")
	fmt.Fprintf(os.Stderr, "          [--ttl 5m]     Stale loading TTL (default: 5m)\n")
	fmt.Fprintf(os.Stderr, "          [--loading]    Only stale loading reservations\n")
	fmt.Fprintf(os.Stderr, "          [--errors]     Only error entries\n")
	fmt.Fprintf(os.Stderr, "          [--orphans]    Only orphaned pins\n")
	fmt.Fprintf(os.Stderr, "          [--db PATH]    SQLite database path (default: %s)\n", server.DefaultDBPath)
	fmt.Fprintf(os.Stderr, "          [--max N]      Maximum deletions (0=unlimited)\n")
	fmt.Fprintf(os.Stderr, "  help    Print this message\n")
	os.Exit(1)
}

// CSI driver constants
const (
	// DefaultCSISocketPath is the default Unix socket path for the CSI driver.
	DefaultCSISocketPath = "/run/bpfman/csi/csi.sock"
	// DefaultCSIDriverName is the default CSI driver name.
	DefaultCSIDriverName = "csi.go-bpfman.io"
	// DefaultCSIVersion is the default CSI driver version.
	DefaultCSIVersion = "0.1.0"
)

func cmdServe(args []string) error {
	socketPath := server.DefaultSocketPath
	csiSupport := false
	csiSocketPath := DefaultCSISocketPath
	dbPath := server.DefaultDBPath

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--socket":
			if i+1 < len(args) {
				socketPath = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--csi-support":
			csiSupport = true
		case "--csi-socket":
			if i+1 < len(args) {
				csiSocketPath = args[i+1]
				i++
			}
		}
	}

	// Set up logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Open shared SQLite store
	store, err := sqlite.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open store at %s: %w", dbPath, err)
	}
	defer store.Close()

	// Create kernel adapter
	kernel := ebpf.New()

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Track CSI driver for graceful shutdown
	var csiDriver *driver.Driver

	// Start CSI driver if enabled
	if csiSupport {
		nodeID, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname for node ID: %w", err)
		}

		csiDriver = driver.New(
			DefaultCSIDriverName,
			DefaultCSIVersion,
			nodeID,
			"unix://"+csiSocketPath,
			logger,
			driver.WithStore(store),
			driver.WithKernel(kernel),
		)

		// Start CSI driver in a goroutine
		go func() {
			logger.Info("starting CSI driver",
				"socket", csiSocketPath,
				"driver", DefaultCSIDriverName,
			)
			if err := csiDriver.Run(); err != nil {
				logger.Error("CSI driver failed", "error", err)
			}
		}()
	}

	// Handle shutdown
	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig)
		if csiDriver != nil {
			csiDriver.Stop()
		}
		os.Exit(0)
	}()

	// Start bpfman gRPC server
	srv := server.NewWithStore(store)
	return srv.Serve(socketPath)
}

func cmdLoad(args []string) error {
	var objectPath, programName, pinDir string
	var dbPath string
	metadata := make(map[string]string)

	// Parse flags and positional args
	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-m", "--metadata":
			if i+1 < len(args) {
				kv := args[i+1]
				if idx := strings.Index(kv, "="); idx > 0 {
					metadata[kv[:idx]] = kv[idx+1:]
				} else {
					return fmt.Errorf("invalid metadata format %q, expected KEY=VALUE", kv)
				}
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) != 3 {
		return fmt.Errorf("usage: load [--db <path>] [-m KEY=VALUE]... <object.o> <program-name> <pin-dir>")
	}

	objectPath = positional[0]
	programName = positional[1]
	pinDir = positional[2]

	// Load the program into the kernel
	kernel := ebpf.New()
	result, err := kernel.LoadSingle(context.Background(), objectPath, programName, pinDir)
	if err != nil {
		return err
	}

	// Store metadata if any was provided or if db path was specified
	if len(metadata) > 0 || dbPath != "" {
		if dbPath == "" {
			dbPath = server.DefaultDBPath
		}

		store, err := sqlite.New(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open store at %s: %w", dbPath, err)
		}
		defer store.Close()

		programMetadata := domain.ProgramMetadata{
			LoadSpec: domain.LoadSpec{
				ObjectPath:  objectPath,
				ProgramName: programName,
				PinPath:     pinDir,
			},
			UserMetadata: metadata,
			CreatedAt:    time.Now(),
		}

		if err := store.Save(context.Background(), result.Program.ID, programMetadata); err != nil {
			return fmt.Errorf("failed to save metadata: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Stored metadata for program ID %d\n", result.Program.ID)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func cmdUnload(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: unload <pin-dir>")
	}

	pinDir := args[0]

	kernel := ebpf.New()
	unpinned, err := kernel.Unpin(pinDir)
	if err != nil {
		return err
	}

	fmt.Printf("Unpinned %d objects\n", unpinned)
	return nil
}

func cmdList(args []string) error {
	includeMaps := false
	var pinDir string

	for _, arg := range args {
		if arg == "--maps" {
			includeMaps = true
		} else if pinDir == "" {
			pinDir = arg
		}
	}

	if pinDir == "" {
		return fmt.Errorf("usage: list [--maps] <pin-dir>")
	}

	kernel := ebpf.New()
	result, err := kernel.ListPinDir(pinDir, includeMaps)
	if err != nil {
		return err
	}

	if len(result.Programs) == 0 && len(result.Maps) == 0 {
		fmt.Println("No objects found")
		return nil
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func cmdGet(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: get <pin-path>")
	}

	pinPath := args[0]

	kernel := ebpf.New()
	program, err := kernel.GetPinned(pinPath)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(program, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func cmdAttach(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: attach <type> ...\n  types: tracepoint")
	}

	attachType := args[0]
	switch attachType {
	case "tracepoint":
		return cmdAttachTracepoint(args[1:])
	default:
		return fmt.Errorf("unknown attach type: %s (supported: tracepoint)", attachType)
	}
}

func cmdAttachTracepoint(args []string) error {
	var progPinPath, group, name, linkPinPath string

	// Parse flags and positional args
	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--link-pin-path":
			if i+1 < len(args) {
				linkPinPath = args[i+1]
				i++
			}
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) != 3 {
		return fmt.Errorf("usage: attach tracepoint <prog-pin-path> <group> <name> [--link-pin-path <path>]")
	}

	progPinPath = positional[0]
	group = positional[1]
	name = positional[2]

	kernel := ebpf.New()
	result, err := kernel.AttachTracepoint(progPinPath, group, name, linkPinPath)
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

func cmdGC(args []string) error {
	cfg := manager.DefaultGCConfig()
	dbPath := server.DefaultDBPath

	// If any specific filter is provided, disable all by default
	hasFilter := false
	for _, arg := range args {
		if arg == "--loading" || arg == "--errors" || arg == "--orphans" {
			hasFilter = true
			break
		}
	}
	if hasFilter {
		cfg.IncludeLoading = false
		cfg.IncludeError = false
		cfg.IncludeOrphans = false
	}

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--prune":
			cfg.DryRun = false
		case "--ttl":
			if i+1 < len(args) {
				d, err := time.ParseDuration(args[i+1])
				if err != nil {
					return fmt.Errorf("invalid TTL %q: %w", args[i+1], err)
				}
				cfg.StaleLoadingTTL = d
				i++
			}
		case "--loading":
			cfg.IncludeLoading = true
		case "--errors":
			cfg.IncludeError = true
		case "--orphans":
			cfg.IncludeOrphans = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--max":
			if i+1 < len(args) {
				n, err := strconv.Atoi(args[i+1])
				if err != nil {
					return fmt.Errorf("invalid max %q: %w", args[i+1], err)
				}
				cfg.MaxDeletions = n
				i++
			}
		}
	}

	// Open store and create manager
	store, err := sqlite.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open store at %s: %w", dbPath, err)
	}
	defer store.Close()

	kernel := ebpf.New()
	mgr := manager.New(store, kernel)

	ctx := context.Background()

	// Plan GC
	plan, err := mgr.PlanGC(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to plan GC: %w", err)
	}

	// Print plan grouped by reason
	counts := plan.CountByReason()

	if len(plan.Items) == 0 {
		fmt.Println("Nothing to clean up.")
		return nil
	}

	// Print stale loading
	if counts[manager.GCStaleLoading] > 0 {
		fmt.Printf("Stale loading reservations (%d):\n", counts[manager.GCStaleLoading])
		for _, item := range plan.Items {
			if item.Reason == manager.GCStaleLoading {
				fmt.Printf("  uuid=%s  age=%s  pin=%s\n", item.UUID, item.Age.Truncate(time.Second), item.PinPath)
			}
		}
		fmt.Println()
	}

	// Print error entries
	if counts[manager.GCStateError] > 0 {
		fmt.Printf("Error entries (%d):\n", counts[manager.GCStateError])
		for _, item := range plan.Items {
			if item.Reason == manager.GCStateError {
				errMsg := item.ErrorMsg
				if len(errMsg) > 60 {
					errMsg = errMsg[:60] + "..."
				}
				fmt.Printf("  uuid=%s  error=%q  pin=%s\n", item.UUID, errMsg, item.PinPath)
			}
		}
		fmt.Println()
	}

	// Print orphan pins
	if counts[manager.GCOrphanPin] > 0 {
		fmt.Printf("Orphaned pins (%d):\n", counts[manager.GCOrphanPin])
		for _, item := range plan.Items {
			if item.Reason == manager.GCOrphanPin {
				fmt.Printf("  path=%s  age=%s\n", item.PinPath, item.Age.Truncate(time.Second))
			}
		}
		fmt.Println()
	}

	// Apply if not dry-run
	if cfg.DryRun {
		fmt.Printf("Total: %d items. Run with --prune to delete.\n", len(plan.Items))
		return nil
	}

	result, err := mgr.ApplyGC(ctx, plan)
	if err != nil {
		return fmt.Errorf("failed to apply GC: %w", err)
	}

	fmt.Printf("GC complete: %d deleted, %d failed, %d skipped\n",
		result.Deleted, result.Failed, result.Skipped)

	// Print failures
	for _, item := range result.Items {
		if item.Error != nil {
			fmt.Printf("  FAILED: %s (%s): %v\n", item.Item.UUID, item.Item.Reason, item.Error)
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "load":
		err = cmdLoad(os.Args[2:])
	case "attach":
		err = cmdAttach(os.Args[2:])
	case "unload":
		err = cmdUnload(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "get":
		err = cmdGet(os.Args[2:])
	case "gc":
		err = cmdGC(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
