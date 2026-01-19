// bpfman is a minimal BPF program manager.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/frobware/bpffs-csi-driver/bpfman/internal/shim"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s load <object.o> <program-name> <pin-dir>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s unload <pin-dir>\n", os.Args[0])
	os.Exit(1)
}

func findShimBinary() (string, error) {
	// Look for bpfman-kernel relative to the bpfman binary
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)

	// Try bpfman-kernel/bpfman-kernel (sibling directory)
	candidate := filepath.Join(dir, "bpfman-kernel", "bpfman-kernel")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Try same directory
	candidate = filepath.Join(dir, "bpfman-kernel")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Try relative to current working directory (for development)
	candidate = "bpfman-kernel/bpfman-kernel"
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Fall back to PATH
	return "bpfman-kernel", nil
}

func cmdLoad(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("load requires: <object.o> <program-name> <pin-dir>")
	}

	objectPath := args[0]
	programName := args[1]
	pinDir := args[2]

	shimPath, err := findShimBinary()
	if err != nil {
		return fmt.Errorf("failed to find shim binary: %w", err)
	}

	s := shim.New(shimPath)
	result, err := s.Load(objectPath, programName, pinDir)
	if err != nil {
		return err
	}

	// Pretty print the result
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

func cmdUnload(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("unload requires: <pin-dir>")
	}

	pinDir := args[0]

	shimPath, err := findShimBinary()
	if err != nil {
		return fmt.Errorf("failed to find shim binary: %w", err)
	}

	s := shim.New(shimPath)
	result, err := s.Unload(pinDir)
	if err != nil {
		return err
	}

	// Pretty print the result
	output, err := json.MarshalIndent(result, "", "  ")
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
	case "load":
		err = cmdLoad(os.Args[2:])
	case "unload":
		err = cmdUnload(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
