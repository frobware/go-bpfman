// Package shim provides the interface to the bpfman-kernel C helper.
package shim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Program represents a loaded BPF program.
type Program struct {
	Name   string `json:"name"`
	Type   int    `json:"type"`
	ID     uint32 `json:"id"`
	Pinned string `json:"pinned"`
}

// Map represents a BPF map.
type Map struct {
	Name   string `json:"name"`
	Type   int    `json:"type"`
	ID     uint32 `json:"id"`
	Pinned string `json:"pinned"`
}

// LoadResult is the result of a load operation.
type LoadResult struct {
	Program Program `json:"program"`
	Maps    []Map   `json:"maps"`
}

// UnloadResult is the result of an unload operation.
type UnloadResult struct {
	Unpinned int `json:"unpinned"`
	Errors   int `json:"errors"`
}

// Shim wraps calls to the bpfman-kernel binary.
type Shim struct {
	// BinaryPath is the path to the bpfman-kernel executable.
	BinaryPath string
}

// New creates a new Shim with the given binary path.
func New(binaryPath string) *Shim {
	return &Shim{BinaryPath: binaryPath}
}

// Load loads a BPF program from an object file and pins it.
func (s *Shim) Load(objectPath, programName, pinDir string) (*LoadResult, error) {
	cmd := exec.Command(s.BinaryPath, "load", objectPath, programName, pinDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("shim failed: %w: %s", err, stderr.String())
	}

	var result LoadResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse shim output: %w: %s", err, stdout.String())
	}

	return &result, nil
}

// Unload unpins all BPF objects in the given directory.
func (s *Shim) Unload(pinDir string) (*UnloadResult, error) {
	cmd := exec.Command(s.BinaryPath, "unload", pinDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("shim failed: %w: %s", err, stderr.String())
	}

	var result UnloadResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse shim output: %w: %s", err, stdout.String())
	}

	return &result, nil
}
