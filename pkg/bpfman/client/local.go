package client

import (
	"context"
	"log/slog"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// LocalClient wraps a manager.Manager to provide local BPF operations.
// It implements the Client interface with direct access to the manager.
type LocalClient struct {
	mgr     *manager.Manager
	cleanup func()
	logger  *slog.Logger
}

// NewLocal creates a new LocalClient using the specified database path.
// The returned client must be closed when no longer needed to release
// database resources.
func NewLocal(dbPath string, logger *slog.Logger) (*LocalClient, error) {
	mgr, cleanup, err := manager.Setup(dbPath, logger)
	if err != nil {
		return nil, err
	}
	return &LocalClient{
		mgr:     mgr,
		cleanup: cleanup,
		logger:  logger,
	}, nil
}

// Close releases resources held by the client.
func (c *LocalClient) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return nil
}

// Load loads a BPF program.
func (c *LocalClient) Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (managed.Loaded, error) {
	return c.mgr.Load(ctx, spec, opts)
}

// Unload removes a BPF program by its kernel ID.
func (c *LocalClient) Unload(ctx context.Context, kernelID uint32) error {
	return c.mgr.Unload(ctx, kernelID)
}

// List returns all managed programs.
func (c *LocalClient) List(ctx context.Context) ([]manager.ManagedProgram, error) {
	return c.mgr.List(ctx)
}

// Get retrieves a program by its kernel ID.
func (c *LocalClient) Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error) {
	return c.mgr.Get(ctx, kernelID)
}

// AttachTracepoint attaches a program to a tracepoint.
func (c *LocalClient) AttachTracepoint(ctx context.Context, programKernelID uint32, progPinPath, group, name, linkPinPath string) (managed.LinkSummary, error) {
	return c.mgr.AttachTracepoint(ctx, programKernelID, progPinPath, group, name, linkPinPath)
}

// AttachXDP attaches an XDP program to a network interface.
func (c *LocalClient) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error) {
	return c.mgr.AttachXDP(ctx, programKernelID, ifindex, ifname, linkPinPath)
}

// Detach removes a link by UUID.
func (c *LocalClient) Detach(ctx context.Context, linkUUID string) error {
	return c.mgr.Detach(ctx, linkUUID)
}

// ListLinks returns all managed links.
func (c *LocalClient) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	return c.mgr.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program.
func (c *LocalClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	return c.mgr.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by UUID.
func (c *LocalClient) GetLink(ctx context.Context, uuid string) (managed.LinkSummary, managed.LinkDetails, error) {
	return c.mgr.GetLink(ctx, uuid)
}

// PlanGC creates a garbage collection plan.
func (c *LocalClient) PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error) {
	return c.mgr.PlanGC(ctx, cfg)
}

// ApplyGC executes a garbage collection plan.
func (c *LocalClient) ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error) {
	return c.mgr.ApplyGC(ctx, plan)
}

// Reconcile cleans up orphaned store entries.
func (c *LocalClient) Reconcile(ctx context.Context) error {
	return c.mgr.Reconcile(ctx)
}
