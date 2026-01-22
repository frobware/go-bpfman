package client

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
)

// RemoteClient wraps a gRPC client to provide remote BPF operations.
// It implements the Client interface by translating between domain
// types and protobuf messages.
//
// For image operations, the pull happens locally and the load is sent
// to the remote daemon.
type RemoteClient struct {
	client pb.BpfmanClient
	conn   *grpc.ClientConn
	puller interpreter.ImagePuller
	logger *slog.Logger
}

// NewRemote creates a new RemoteClient connected to the specified address.
// The address can be:
//   - "host:port" for TCP connections
//   - "unix:///path/to/socket" for Unix socket connections
//
// The returned client must be closed when no longer needed.
func NewRemote(address string, logger *slog.Logger) (*RemoteClient, error) {
	target := ParseAddress(address)

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", target, err)
	}

	return &RemoteClient{
		client: pb.NewBpfmanClient(conn),
		conn:   conn,
		logger: logger,
	}, nil
}

// ParseAddress normalises an address for gRPC.
// Handles Unix socket paths (unix:// prefix or absolute paths starting with /)
// and TCP addresses (host:port).
func ParseAddress(address string) string {
	if strings.HasPrefix(address, "unix://") {
		return address
	}
	if strings.HasPrefix(address, "/") {
		return "unix://" + address
	}
	return address
}

// Close releases the gRPC connection.
func (c *RemoteClient) Close() error {
	return c.conn.Close()
}

// Load loads a BPF program via gRPC.
func (c *RemoteClient) Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error) {
	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: spec.ObjectPath},
		},
		Metadata:   opts.UserMetadata,
		GlobalData: spec.GlobalData,
		Info: []*pb.LoadInfo{{
			Name:        spec.ProgramName,
			ProgramType: domainTypeToProto(spec.ProgramType),
		}},
	}

	resp, err := c.client.Load(ctx, req)
	if err != nil {
		return bpfman.ManagedProgram{}, translateGRPCError(err)
	}

	if len(resp.Programs) == 0 {
		return bpfman.ManagedProgram{}, fmt.Errorf("no programs returned from load")
	}

	return protoLoadResponseToManagedProgram(resp.Programs[0]), nil
}

// Unload removes a BPF program via gRPC.
func (c *RemoteClient) Unload(ctx context.Context, kernelID uint32) error {
	_, err := c.client.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	return translateGRPCError(err)
}

// List returns all managed programs via gRPC.
func (c *RemoteClient) List(ctx context.Context) ([]manager.ManagedProgram, error) {
	resp, err := c.client.List(ctx, &pb.ListRequest{})
	if err != nil {
		return nil, translateGRPCError(err)
	}

	return protoListResponseToPrograms(resp), nil
}

// Get retrieves a program by its kernel ID via gRPC.
func (c *RemoteClient) Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error) {
	resp, err := c.client.Get(ctx, &pb.GetRequest{Id: kernelID})
	if err != nil {
		return manager.ProgramInfo{}, translateGRPCError(err)
	}

	return protoGetResponseToInfo(resp, kernelID), nil
}

// AttachTracepoint attaches a program to a tracepoint via gRPC.
func (c *RemoteClient) AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (managed.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: programKernelID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: group + "/" + name,
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return managed.LinkSummary{}, translateGRPCError(err)
	}

	return managed.LinkSummary{
		LinkType:        managed.LinkTypeTracepoint,
		KernelProgramID: programKernelID,
		KernelLinkID:    resp.LinkId,
		PinPath:         linkPinPath,
	}, nil
}

// AttachXDP is not fully supported via gRPC.
// The proto exists but the server returns Unimplemented.
func (c *RemoteClient) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: programKernelID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface:    ifname,
					Priority: 50,
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return managed.LinkSummary{}, translateGRPCError(err)
	}

	return managed.LinkSummary{
		LinkType:        managed.LinkTypeXDP,
		KernelProgramID: programKernelID,
		KernelLinkID:    resp.LinkId,
		PinPath:         linkPinPath,
	}, nil
}

// Detach is not fully supported via gRPC.
// The proto uses link_id (uint32) which matches our kernel_link_id.
func (c *RemoteClient) Detach(ctx context.Context, kernelLinkID uint32) error {
	_, err := c.client.Detach(ctx, &pb.DetachRequest{LinkId: kernelLinkID})
	return translateGRPCError(err)
}

// ListLinks returns all managed links via gRPC.
func (c *RemoteClient) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	resp, err := c.client.ListLinks(ctx, &pb.ListLinksRequest{})
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return protoListLinksResponseToSummaries(resp), nil
}

// ListLinksByProgram returns all links for a given program via gRPC.
func (c *RemoteClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	resp, err := c.client.ListLinks(ctx, &pb.ListLinksRequest{ProgramId: &programKernelID})
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return protoListLinksResponseToSummaries(resp), nil
}

// GetLink retrieves a link by kernel link ID via gRPC.
func (c *RemoteClient) GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	resp, err := c.client.GetLink(ctx, &pb.GetLinkRequest{KernelLinkId: kernelLinkID})
	if err != nil {
		return managed.LinkSummary{}, nil, translateGRPCError(err)
	}
	summary := protoLinkSummaryToManaged(resp.Link.Summary)
	details := protoLinkDetailsToManaged(resp.Link.Details)
	return summary, details, nil
}

// PlanGC is a local-only operation.
func (c *RemoteClient) PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error) {
	return manager.GCPlan{}, fmt.Errorf("PlanGC: %w", ErrNotSupported)
}

// ApplyGC is a local-only operation.
func (c *RemoteClient) ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error) {
	return manager.GCResult{}, fmt.Errorf("ApplyGC: %w", ErrNotSupported)
}

// Reconcile is a local-only operation.
func (c *RemoteClient) Reconcile(ctx context.Context) error {
	return fmt.Errorf("Reconcile: %w", ErrNotSupported)
}

// SetImagePuller configures the image puller for OCI operations.
func (c *RemoteClient) SetImagePuller(p interpreter.ImagePuller) {
	c.puller = p
}

// PullImage pulls an OCI image and extracts the bytecode.
// Always executes locally, never forwarded to daemon.
func (c *RemoteClient) PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	if c.puller == nil {
		return interpreter.PulledImage{}, fmt.Errorf("PullImage: %w (no image puller configured)", ErrNotSupported)
	}
	return c.puller.Pull(ctx, ref)
}

// LoadImage pulls an OCI image and loads the specified programs.
// Pull happens locally, load is sent to the remote daemon.
func (c *RemoteClient) LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []managed.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error) {
	// Step 1: Pull image locally
	pulled, err := c.PullImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	// Step 2: Load each program via gRPC to remote daemon
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

		loaded, err := c.Load(ctx, spec, loadOpts)
		if err != nil {
			return results, fmt.Errorf("load program %s: %w", spec.ProgramName, err)
		}
		results = append(results, loaded)
	}

	return results, nil
}

// translateGRPCError converts gRPC errors to more user-friendly errors.
func translateGRPCError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.Unimplemented:
		return fmt.Errorf("%s: %w", st.Message(), ErrNotSupported)
	case codes.NotFound:
		return fmt.Errorf("not found: %s", st.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("invalid argument: %s", st.Message())
	default:
		return err
	}
}
