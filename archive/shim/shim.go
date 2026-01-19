// Package shim provides the interface to the bpfman-kernel C helper.
package shim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// KernelResponse is the envelope for all shim responses.
type KernelResponse struct {
	Op        string         `json:"op"`
	PinDir    string         `json:"pin_dir,omitempty"`
	Program   *KernelProgram `json:"program,omitempty"`
	Maps      []KernelMap    `json:"maps,omitempty"`
	LibbpfLog []string       `json:"libbpf_log,omitempty"`
	Error     *KernelError   `json:"error,omitempty"`
}

// KernelProgram represents a loaded BPF program.
type KernelProgram struct {
	KernelID   uint32 `json:"kernel_id"`
	Name       string `json:"name"`
	Type       uint32 `json:"type"`
	PinnedPath string `json:"pinned_path"`
}

// KernelMap represents a BPF map.
type KernelMap struct {
	KernelID   uint32 `json:"kernel_id"`
	Name       string `json:"name"`
	Type       uint32 `json:"type"`
	PinnedPath string `json:"pinned_path"`
}

// KernelError represents an error from the shim.
type KernelError struct {
	Errno     int      `json:"errno"`
	Messages  []string `json:"messages"`
	LibbpfLog []string `json:"libbpf_log,omitempty"`
}

// UnpinResult is the result of an unpin operation.
type UnpinResult struct {
	Op       string `json:"op"`
	PinDir   string `json:"pin_dir"`
	Unpinned int    `json:"unpinned"`
	Errors   int    `json:"errors"`
}

// ShimError represents an error returned by the shim.
type ShimError struct {
	Errno     syscall.Errno
	Messages  []string
	LibbpfLog []string
}

func (e *ShimError) Error() string {
	return strings.Join(e.Messages, "; ")
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

// run executes the shim and returns the raw stdout bytes.
func (s *Shim) run(args ...string) ([]byte, error) {
	cmd := exec.Command(s.BinaryPath, args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	_ = cmd.Run() // Ignore exit code; we check the JSON for errors

	output := stdout.Bytes()
	if len(output) == 0 {
		return nil, fmt.Errorf("shim produced no output")
	}

	return output, nil
}

// Load loads a BPF program from an object file and pins it.
func (s *Shim) Load(objectPath, programName, pinDir string) (*KernelResponse, error) {
	output, err := s.run("load", objectPath, programName, pinDir)
	if err != nil {
		return nil, err
	}

	var resp KernelResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse shim output: %w: %s", err, string(output))
	}

	if resp.Error != nil {
		return &resp, &ShimError{
			Errno:     syscall.Errno(resp.Error.Errno),
			Messages:  resp.Error.Messages,
			LibbpfLog: resp.Error.LibbpfLog,
		}
	}

	return &resp, nil
}

// Unpin unpins all BPF objects in the given directory.
func (s *Shim) Unpin(pinDir string) (*UnpinResult, error) {
	output, err := s.run("unpin", pinDir)
	if err != nil {
		return nil, err
	}

	var result UnpinResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse unpin result: %w", err)
	}

	return &result, nil
}
