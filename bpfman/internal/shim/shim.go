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

// ShimError represents an error returned by the shim.
type ShimError struct {
	Errno    syscall.Errno
	Messages []string
}

func (e *ShimError) Error() string {
	return strings.Join(e.Messages, "; ")
}

// errorResponse is the JSON error structure from the shim.
type errorResponse struct {
	Error *struct {
		Errno    int      `json:"errno"`
		Messages []string `json:"messages"`
	} `json:"error"`
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

// run executes the shim and returns the stdout. If the shim returns an
// error response, it is converted to a ShimError.
func (s *Shim) run(args ...string) ([]byte, error) {
	cmd := exec.Command(s.BinaryPath, args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	_ = cmd.Run() // Ignore exit code; we check the JSON for errors

	output := stdout.Bytes()
	if len(output) == 0 {
		return nil, fmt.Errorf("shim produced no output")
	}

	// Check if the output contains an error response
	var errResp errorResponse
	if err := json.Unmarshal(output, &errResp); err != nil {
		return nil, fmt.Errorf("failed to parse shim output: %w: %s", err, string(output))
	}

	if errResp.Error != nil {
		return nil, &ShimError{
			Errno:    syscall.Errno(errResp.Error.Errno),
			Messages: errResp.Error.Messages,
		}
	}

	return output, nil
}

// Load loads a BPF program from an object file and pins it.
func (s *Shim) Load(objectPath, programName, pinDir string) (*LoadResult, error) {
	output, err := s.run("load", objectPath, programName, pinDir)
	if err != nil {
		return nil, err
	}

	var result LoadResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse load result: %w", err)
	}

	return &result, nil
}

// Unload unpins all BPF objects in the given directory.
func (s *Shim) Unload(pinDir string) (*UnloadResult, error) {
	output, err := s.run("unload", pinDir)
	if err != nil {
		return nil, err
	}

	var result UnloadResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse unload result: %w", err)
	}

	return &result, nil
}
