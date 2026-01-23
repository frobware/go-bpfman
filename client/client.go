// Package client provides a unified interface for BPF program management.
//
// Use Dial to connect to a running bpfman daemon:
//
//	c, err := client.Dial(client.DefaultSocketPath())
//	c, err := client.Dial("localhost:50051")
//
// Use Open for local BPF program management:
//
//	c, err := client.Open()
//	c, err := client.Open(client.WithRuntimeDir("/tmp/mybpfman"))
//
// Both return a Client that can be used identically.
package client

import (
	"context"
	"errors"
	"io"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/manager"
)

// ErrNotSupported is returned when an operation is not available on
// a particular client implementation (typically remote clients for host-only ops).
var ErrNotSupported = errors.New("operation not supported on remote client")

// LoadImageOpts configures image loading.
type LoadImageOpts struct {
	UserMetadata map[string]string
	GlobalData   map[string][]byte
}

// Client provides a transport-agnostic interface for BPF program management.
// Commands use this interface and remain unaware of whether they are
// operating locally or remotely.
type Client interface {
	io.Closer

	// Program operations
	Load(ctx context.Context, spec bpfman.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error)
	Unload(ctx context.Context, kernelID uint32) error
	List(ctx context.Context) ([]manager.ManagedProgram, error)
	Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error)

	// Attach/detach operations
	AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (bpfman.LinkSummary, error)
	AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (bpfman.LinkSummary, error)
	AttachTC(ctx context.Context, programKernelID uint32, ifindex int, ifname, direction string, priority int, proceedOn []int32, linkPinPath string) (bpfman.LinkSummary, error)
	Detach(ctx context.Context, kernelLinkID uint32) error

	// Link operations
	ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error)
	ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error)
	GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error)

	// Host-only operations (local execution required)
	PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error)
	ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error)
	Reconcile(ctx context.Context) error

	// Image operations
	PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error)
	LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []bpfman.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error)
}
