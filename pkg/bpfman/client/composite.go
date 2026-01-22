package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// CompositeClient routes operations to appropriate handlers:
//   - Daemon ops (load, unload, attach, etc.): via gRPC or direct manager
//   - Host ops (GC, image pull): always local
//
// This provides uniform behaviour regardless of whether the daemon
// is remote or in-process.
type CompositeClient struct {
	daemon DaemonOps
	host   HostOps
	puller interpreter.ImagePuller
	logger *slog.Logger

	// closers to clean up on Close
	closers []io.Closer
}

// CompositeOption configures a CompositeClient.
type CompositeOption func(*CompositeClient)

// WithDaemon sets the daemon operations handler.
func WithDaemon(d DaemonOps) CompositeOption {
	return func(c *CompositeClient) {
		c.daemon = d
		if closer, ok := d.(io.Closer); ok {
			c.closers = append(c.closers, closer)
		}
	}
}

// WithHost sets the host operations handler.
func WithHost(h HostOps) CompositeOption {
	return func(c *CompositeClient) { c.host = h }
}

// WithImagePuller sets the image puller for OCI operations.
func WithImagePuller(p interpreter.ImagePuller) CompositeOption {
	return func(c *CompositeClient) { c.puller = p }
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) CompositeOption {
	return func(c *CompositeClient) { c.logger = l }
}

// NewComposite creates a CompositeClient with the given options.
func NewComposite(opts ...CompositeOption) (*CompositeClient, error) {
	c := &CompositeClient{}
	for _, opt := range opts {
		opt(c)
	}

	if c.daemon == nil {
		return nil, fmt.Errorf("daemon ops handler is required")
	}

	return c, nil
}

// Close releases all resources.
func (c *CompositeClient) Close() error {
	var firstErr error
	for _, closer := range c.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Daemon operations - delegate to daemon handler

func (c *CompositeClient) Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error) {
	return c.daemon.Load(ctx, spec, opts)
}

func (c *CompositeClient) Unload(ctx context.Context, kernelID uint32) error {
	return c.daemon.Unload(ctx, kernelID)
}

func (c *CompositeClient) List(ctx context.Context) ([]manager.ManagedProgram, error) {
	return c.daemon.List(ctx)
}

func (c *CompositeClient) Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error) {
	return c.daemon.Get(ctx, kernelID)
}

func (c *CompositeClient) AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (managed.LinkSummary, error) {
	return c.daemon.AttachTracepoint(ctx, programKernelID, group, name, linkPinPath)
}

func (c *CompositeClient) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error) {
	return c.daemon.AttachXDP(ctx, programKernelID, ifindex, ifname, linkPinPath)
}

func (c *CompositeClient) Detach(ctx context.Context, kernelLinkID uint32) error {
	return c.daemon.Detach(ctx, kernelLinkID)
}

func (c *CompositeClient) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	return c.daemon.ListLinks(ctx)
}

func (c *CompositeClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	return c.daemon.ListLinksByProgram(ctx, programKernelID)
}

func (c *CompositeClient) GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	return c.daemon.GetLink(ctx, kernelLinkID)
}

// Host operations - delegate to host handler (or return ErrNotSupported)

func (c *CompositeClient) PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error) {
	if c.host == nil {
		return manager.GCPlan{}, fmt.Errorf("PlanGC: %w", ErrNotSupported)
	}
	return c.host.PlanGC(ctx, cfg)
}

func (c *CompositeClient) ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error) {
	if c.host == nil {
		return manager.GCResult{}, fmt.Errorf("ApplyGC: %w", ErrNotSupported)
	}
	return c.host.ApplyGC(ctx, plan)
}

func (c *CompositeClient) Reconcile(ctx context.Context) error {
	if c.host == nil {
		return fmt.Errorf("Reconcile: %w", ErrNotSupported)
	}
	return c.host.Reconcile(ctx)
}

// Image operations - pull on host, load via daemon

func (c *CompositeClient) PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	if c.puller == nil {
		return interpreter.PulledImage{}, fmt.Errorf("PullImage: %w", ErrNotSupported)
	}
	return c.puller.Pull(ctx, ref)
}

func (c *CompositeClient) LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []managed.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error) {
	// Step 1: Pull image on host
	pulled, err := c.PullImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	// Step 2: Load each program via daemon ops
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

		loaded, err := c.daemon.Load(ctx, spec, loadOpts)
		if err != nil {
			// Return partial results on failure
			return results, fmt.Errorf("load program %s: %w", spec.ProgramName, err)
		}
		results = append(results, loaded)
	}

	return results, nil
}
