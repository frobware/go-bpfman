// Package client provides a unified interface for BPF program management
// that abstracts over local (direct manager) and remote (gRPC) transports.
//
// The client uses a composite pattern with two logical protocols:
//   - Daemon ops: load, unload, attach, detach, list - can go remote via gRPC
//   - Host ops: GC, reconcile, image pull - always execute locally
//
// Callers use a single Client interface and are unaware of the routing.
package client

import (
	"context"
	"errors"
	"io"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// ErrNotSupported is returned when an operation is not available on
// a particular client implementation (typically remote clients for host-only ops).
var ErrNotSupported = errors.New("operation not supported on remote client")

// DaemonOps are operations that can be forwarded to a remote daemon via gRPC.
type DaemonOps interface {
	Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error)
	Unload(ctx context.Context, kernelID uint32) error
	List(ctx context.Context) ([]manager.ManagedProgram, error)
	Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error)
	AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (managed.LinkSummary, error)
	AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error)
	Detach(ctx context.Context, kernelLinkID uint32) error
	ListLinks(ctx context.Context) ([]managed.LinkSummary, error)
	ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error)
	GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error)
}

// HostOps are operations that must execute on the invoking host.
type HostOps interface {
	PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error)
	ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error)
	Reconcile(ctx context.Context) error
}

// LoadImageOpts configures image loading.
type LoadImageOpts struct {
	UserMetadata map[string]string
	GlobalData   map[string][]byte
}

// Client provides a transport-agnostic interface for BPF program management.
// Commands use this interface and remain unaware of whether they are
// operating locally or remotely.
//
// The interface combines DaemonOps (remote-capable) and HostOps (local-only).
// Image operations are composite: pull locally, load via daemon path.
type Client interface {
	io.Closer
	DaemonOps
	HostOps

	// Image operations (composite: pull on host, load via daemon)
	PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error)
	LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []managed.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error)
}
