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

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
)

// RemoteClient wraps a gRPC client to provide remote BPF operations.
// It implements the Client interface by translating between domain
// types and protobuf messages.
type RemoteClient struct {
	client pb.BpfmanClient
	conn   *grpc.ClientConn
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
func (c *RemoteClient) Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (managed.Loaded, error) {
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
		return managed.Loaded{}, translateGRPCError(err)
	}

	if len(resp.Programs) == 0 {
		return managed.Loaded{}, fmt.Errorf("no programs returned from load")
	}

	return protoLoadResponseToLoaded(resp.Programs[0]), nil
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

// AttachTracepoint is not fully supported via gRPC.
// The proto exists but the server returns Unimplemented.
func (c *RemoteClient) AttachTracepoint(ctx context.Context, programKernelID uint32, progPinPath, group, name, linkPinPath string) (managed.LinkSummary, error) {
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

// ListLinks is not available via gRPC.
func (c *RemoteClient) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	return nil, fmt.Errorf("ListLinks: %w", ErrNotSupported)
}

// ListLinksByProgram is not available via gRPC.
func (c *RemoteClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	return nil, fmt.Errorf("ListLinksByProgram: %w", ErrNotSupported)
}

// GetLink is not available via gRPC.
func (c *RemoteClient) GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	return managed.LinkSummary{}, nil, fmt.Errorf("GetLink: %w", ErrNotSupported)
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
