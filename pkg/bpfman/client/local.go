package client

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/config"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// LocalClient wraps a manager.Manager to provide local BPF operations.
// It implements the Client interface with direct access to the manager.
type LocalClient struct {
	mgr     *manager.Manager
	puller  interpreter.ImagePuller
	cleanup func()
	logger  *slog.Logger
}

// NewLocal creates a new LocalClient using the specified runtime directories.
// The returned client must be closed when no longer needed to release
// database resources.
func NewLocal(dirs config.RuntimeDirs, logger *slog.Logger) (*LocalClient, error) {
	mgr, cleanup, err := manager.Setup(dirs, logger)
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
func (c *LocalClient) Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error) {
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
func (c *LocalClient) AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (managed.LinkSummary, error) {
	return c.mgr.AttachTracepoint(ctx, programKernelID, group, name, linkPinPath)
}

// AttachXDP attaches an XDP program to a network interface.
func (c *LocalClient) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error) {
	return c.mgr.AttachXDP(ctx, programKernelID, ifindex, ifname, linkPinPath)
}

// Detach removes a link by kernel link ID.
func (c *LocalClient) Detach(ctx context.Context, kernelLinkID uint32) error {
	return c.mgr.Detach(ctx, kernelLinkID)
}

// ListLinks returns all managed links.
func (c *LocalClient) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	return c.mgr.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program.
func (c *LocalClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	return c.mgr.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by kernel link ID.
func (c *LocalClient) GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	return c.mgr.GetLink(ctx, kernelLinkID)
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

// SetImagePuller configures the image puller for OCI operations.
func (c *LocalClient) SetImagePuller(p interpreter.ImagePuller) {
	c.puller = p
}

// PullImage pulls an OCI image and extracts the bytecode.
func (c *LocalClient) PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	if c.puller == nil {
		return interpreter.PulledImage{}, fmt.Errorf("PullImage: %w (no image puller configured)", ErrNotSupported)
	}
	return c.puller.Pull(ctx, ref)
}

// LoadImage pulls an OCI image and loads the specified programs.
func (c *LocalClient) LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []managed.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error) {
	// Step 1: Pull image locally
	pulled, err := c.PullImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	// Step 2: Load each program via manager
	results := make([]bpfman.ManagedProgram, 0, len(programs))
	for _, spec := range programs {
		// Override ObjectPath with pulled location
		spec.ObjectPath = pulled.ObjectPath
		spec.ImageSource = &managed.ImageSource{
			URL:        ref.URL,
			Digest:     pulled.Digest,
			PullPolicy: ref.PullPolicy,
		}

		loadOpts := manager.LoadOpts{
			UserMetadata: opts.UserMetadata,
		}

		loaded, err := c.mgr.Load(ctx, spec, loadOpts)
		if err != nil {
			return results, fmt.Errorf("load program %s: %w", spec.ProgramName, err)
		}
		results = append(results, loaded)
	}

	return results, nil
}
