// Package client provides a unified interface for BPF program management
// that abstracts over local (direct manager) and remote (gRPC) transports.
package client

import (
	"context"
	"errors"
	"io"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// ErrNotSupported is returned when an operation is not available on
// a particular client implementation (typically remote clients).
var ErrNotSupported = errors.New("operation not supported on remote client")

// Client provides a transport-agnostic interface for BPF program management.
// Commands use this interface and remain unaware of whether they are
// operating locally or remotely.
type Client interface {
	io.Closer

	// Program operations
	Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (managed.Loaded, error)
	Unload(ctx context.Context, kernelID uint32) error
	List(ctx context.Context) ([]manager.ManagedProgram, error)
	Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error)

	// Attachment operations
	AttachTracepoint(ctx context.Context, programKernelID uint32, progPinPath, group, name, linkPinPath string) (managed.LinkSummary, error)
	AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error)
	Detach(ctx context.Context, linkUUID string) error

	// Link queries
	ListLinks(ctx context.Context) ([]managed.LinkSummary, error)
	ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error)
	GetLink(ctx context.Context, uuid string) (managed.LinkSummary, managed.LinkDetails, error)

	// Maintenance operations (local-only)
	PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error)
	ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error)
	Reconcile(ctx context.Context) error
}
