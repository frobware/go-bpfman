// bpfman is a minimal BPF program manager.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	"github.com/frobware/go-bpfman/pkg/bpfman/server"
)

const usageText = `Usage: bpfman <COMMAND>

Commands:
  serve   Start the gRPC server
  load    Load an eBPF program from an object file
          <object.o> <program-name>
          [-m KEY=VALUE] metadata to attach to the program
          [--db PATH]    SQLite database path
  attach  Attach a loaded program to a hook
          attach tracepoint <prog-pin-path> <group> <name> [--link-pin-path <path>]
          [--db PATH]    SQLite database path
  unload  Unload a managed eBPF program by kernel ID
          <program-id>
          [--db PATH]    SQLite database path
  list    List managed eBPF programs
          [--db PATH]    SQLite database path
  get     Get details of a managed program by kernel ID
          <program-id>
          [--db PATH]    SQLite database path
  gc      Garbage collect stale/orphaned resources (dry-run by default)
          [--prune]      Actually delete (default: dry-run)
          [--ttl 5m]     Stale loading TTL (default: 5m)
          [--loading]    Only stale loading reservations
          [--errors]     Only error entries
          [--orphans]    Only orphaned pins
          [--db PATH]    SQLite database path
          [--max N]      Maximum deletions (0=unlimited)
  help    Print this message
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
	os.Exit(1)
}

func cmdServe(args []string) error {
	cfg := server.RunConfig{}

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--socket":
			if i+1 < len(args) {
				cfg.SocketPath = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				cfg.DBPath = args[i+1]
				i++
			}
		case "--csi-support":
			cfg.CSISupport = true
		case "--csi-socket":
			if i+1 < len(args) {
				cfg.CSISocketPath = args[i+1]
				i++
			}
		}
	}

	// Create context that cancels on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return server.Run(ctx, cfg)
}

func cmdLoad(args []string) error {
	var objectPath, programName string
	dbPath := server.DefaultDBPath
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

	if len(positional) != 2 {
		return fmt.Errorf("usage: load [--db <path>] [-m KEY=VALUE]... <object.o> <program-name>")
	}

	objectPath = positional[0]
	programName = positional[1]

	// Set up manager
	mgr, cleanup, err := manager.Setup(dbPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	// Generate UUID and derive pin path
	programUUID := uuid.New().String()
	pinDir := filepath.Join(server.DefaultBpfmanRoot, programUUID)

	// Build load spec and options
	spec := managed.LoadSpec{
		ObjectPath:  objectPath,
		ProgramName: programName,
		PinPath:     pinDir,
	}
	opts := manager.LoadOpts{
		UUID:         programUUID,
		UserMetadata: metadata,
	}

	// Load through manager (transactional)
	ctx := context.Background()
	loaded, err := mgr.Load(ctx, spec, opts)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func cmdUnload(args []string) error {
	dbPath := server.DefaultDBPath
	var programID uint32

	// Parse flags and positional args
	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) != 1 {
		return fmt.Errorf("usage: unload [--db <path>] <program-id>")
	}

	// Parse program ID
	id, err := strconv.ParseUint(positional[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid program ID %q: %w", positional[0], err)
	}
	programID = uint32(id)

	// Set up manager
	mgr, cleanup, err := manager.Setup(dbPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	if err := mgr.Unload(ctx, programID); err != nil {
		return err
	}

	fmt.Printf("Unloaded program %d\n", programID)
	return nil
}

func cmdList(args []string) error {
	dbPath := server.DefaultDBPath

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	// Set up manager
	mgr, cleanup, err := manager.Setup(dbPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	programs, err := mgr.List(ctx)
	if err != nil {
		return err
	}

	// Filter to only managed programs
	managedProgs := manager.FilterManaged(programs)

	if len(managedProgs) == 0 {
		fmt.Println("No managed programs found")
		return nil
	}

	output, err := json.MarshalIndent(managedProgs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func cmdGet(args []string) error {
	dbPath := server.DefaultDBPath

	// Parse flags and positional args
	positional := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) != 1 {
		return fmt.Errorf("usage: get [--db <path>] <program-id>")
	}

	id, err := strconv.ParseUint(positional[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid program ID %q: %w", positional[0], err)
	}
	programID := uint32(id)

	// Set up manager
	mgr, cleanup, err := manager.Setup(dbPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()
	metadata, err := mgr.Get(ctx, programID)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(metadata, "", "  ")
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
	dbPath := server.DefaultDBPath
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
		return fmt.Errorf("usage: attach tracepoint [--db <path>] <prog-pin-path> <group> <name> [--link-pin-path <path>]")
	}

	progPinPath = positional[0]
	group = positional[1]
	name = positional[2]

	// Set up manager
	mgr, cleanup, err := manager.Setup(dbPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	result, err := mgr.AttachTracepoint(progPinPath, group, name, linkPinPath)
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

	// Set up manager
	mgr, cleanup, err := manager.Setup(dbPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

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
