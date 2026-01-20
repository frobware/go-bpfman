// bpfman is a minimal BPF program manager.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/kernel/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/server"
	"github.com/frobware/go-bpfman/pkg/csi/driver"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <COMMAND>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  serve   Start the gRPC server\n")
	fmt.Fprintf(os.Stderr, "  load    Load an eBPF program from an object file\n")
	fmt.Fprintf(os.Stderr, "  unload  Unload (unpin) an eBPF program\n")
	fmt.Fprintf(os.Stderr, "  list    List pinned eBPF programs [--maps]\n")
	fmt.Fprintf(os.Stderr, "  get     Get details of a pinned program\n")
	fmt.Fprintf(os.Stderr, "  help    Print this message\n")
	os.Exit(1)
}

// CSI driver constants
const (
	// DefaultCSISocketPath is the default Unix socket path for the CSI driver.
	DefaultCSISocketPath = "/run/bpfman/csi/csi.sock"
	// DefaultCSIDriverName is the default CSI driver name.
	DefaultCSIDriverName = "csi.bpfman.io"
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
	if len(args) != 3 {
		return fmt.Errorf("usage: load <object.o> <program-name> <pin-dir>")
	}

	objectPath := args[0]
	programName := args[1]
	pinDir := args[2]

	kernel := ebpf.New()
	result, err := kernel.LoadSingle(context.Background(), objectPath, programName, pinDir)
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
	case "unload":
		err = cmdUnload(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "get":
		err = cmdGet(os.Args[2:])
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
