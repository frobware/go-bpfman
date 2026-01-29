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

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/manager"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// remoteClient wraps a gRPC client to provide remote BPF operations.
// It implements the Client interface by translating between domain
// types and protobuf messages.
//
// For image operations, the pull happens locally and the load is sent
// to the remote daemon.
type remoteClient struct {
	client pb.BpfmanClient
	conn   *grpc.ClientConn
	puller interpreter.ImagePuller
	logger *slog.Logger
}

// newRemote creates a Client connected to the specified address.
func newRemote(address string, logger *slog.Logger) (Client, error) {
	target := parseAddress(address)

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", target, err)
	}

	return &remoteClient{
		client: pb.NewBpfmanClient(conn),
		conn:   conn,
		logger: logger,
	}, nil
}

// parseAddress normalises an address for gRPC.
// Handles Unix socket paths (unix:// prefix or absolute paths starting with /)
// and TCP addresses (host:port).
func parseAddress(address string) string {
	if strings.HasPrefix(address, "unix://") {
		return address
	}
	if strings.HasPrefix(address, "/") {
		return "unix://" + address
	}
	return address
}

// Close releases the gRPC connection.
func (c *remoteClient) Close() error {
	return c.conn.Close()
}

// Load loads a BPF program via gRPC.
func (c *remoteClient) Load(ctx context.Context, spec bpfman.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error) {
	protoType, err := domainTypeToProto(spec.ProgramType())
	if err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("convert program type: %w", err)
	}
	info := &pb.LoadInfo{
		Name:        spec.ProgramName(),
		ProgramType: protoType,
	}
	// Add ProgSpecificInfo for fentry/fexit which require attach function at load time
	if spec.ProgramType() == bpfman.ProgramTypeFentry {
		info.Info = &pb.ProgSpecificInfo{
			Info: &pb.ProgSpecificInfo_FentryLoadInfo{
				FentryLoadInfo: &pb.FentryLoadInfo{FnName: spec.AttachFunc()},
			},
		}
	} else if spec.ProgramType() == bpfman.ProgramTypeFexit {
		info.Info = &pb.ProgSpecificInfo{
			Info: &pb.ProgSpecificInfo_FexitLoadInfo{
				FexitLoadInfo: &pb.FexitLoadInfo{FnName: spec.AttachFunc()},
			},
		}
	}

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: spec.ObjectPath()},
		},
		Metadata:   opts.UserMetadata,
		GlobalData: spec.GlobalData(),
		Info:       []*pb.LoadInfo{info},
	}

	resp, err := c.client.Load(ctx, req)
	if err != nil {
		return bpfman.ManagedProgram{}, translateGRPCError(err)
	}

	if len(resp.Programs) == 0 {
		return bpfman.ManagedProgram{}, fmt.Errorf("no programs returned from load")
	}

	return protoLoadResponseToManagedProgram(resp.Programs[0])
}

// Unload removes a BPF program via gRPC.
func (c *remoteClient) Unload(ctx context.Context, kernelID uint32) error {
	_, err := c.client.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	return translateGRPCError(err)
}

// List returns all managed programs via gRPC.
func (c *remoteClient) List(ctx context.Context) ([]manager.ManagedProgram, error) {
	resp, err := c.client.List(ctx, &pb.ListRequest{})
	if err != nil {
		return nil, translateGRPCError(err)
	}

	return protoListResponseToPrograms(resp)
}

// Get retrieves a program by its kernel ID via gRPC.
func (c *remoteClient) Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error) {
	resp, err := c.client.Get(ctx, &pb.GetRequest{Id: kernelID})
	if err != nil {
		return manager.ProgramInfo{}, translateGRPCError(err)
	}

	return protoGetResponseToInfo(resp, kernelID)
}

// AttachTracepoint attaches a program to a tracepoint via gRPC.
func (c *remoteClient) AttachTracepoint(ctx context.Context, spec bpfman.TracepointAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: spec.Group() + "/" + spec.Name(),
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachXDP attaches an XDP program to a network interface via gRPC.
func (c *remoteClient) AttachXDP(ctx context.Context, spec bpfman.XDPAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface:    spec.Ifname(),
					Priority: 50,
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeXDP,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachTC attaches a TC program to a network interface via gRPC.
func (c *remoteClient) AttachTC(ctx context.Context, spec bpfman.TCAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     spec.Ifname(),
					Direction: spec.Direction(),
					Priority:  int32(spec.Priority()),
					ProceedOn: spec.ProceedOn(),
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTC,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachTCX attaches a TCX program to a network interface via gRPC.
func (c *remoteClient) AttachTCX(ctx context.Context, spec bpfman.TCXAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
					Iface:     spec.Ifname(),
					Direction: spec.Direction(),
					Priority:  int32(spec.Priority()),
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTCX,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachKprobe attaches a kprobe/kretprobe program to a kernel function via gRPC.
func (c *remoteClient) AttachKprobe(ctx context.Context, spec bpfman.KprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_KprobeAttachInfo{
				KprobeAttachInfo: &pb.KprobeAttachInfo{
					FnName: spec.FnName(),
					Offset: spec.Offset(),
				},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeKprobe,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachUprobe attaches a uprobe/uretprobe program to a user-space function via gRPC.
func (c *remoteClient) AttachUprobe(ctx context.Context, spec bpfman.UprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	fnName := spec.FnName()
	uprobeInfo := &pb.UprobeAttachInfo{
		Target: spec.Target(),
		FnName: &fnName,
		Offset: spec.Offset(),
	}
	if containerPid := spec.ContainerPid(); containerPid > 0 {
		uprobeInfo.ContainerPid = &containerPid
	}
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_UprobeAttachInfo{
				UprobeAttachInfo: uprobeInfo,
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeUprobe,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachFentry attaches a fentry program via gRPC.
func (c *remoteClient) AttachFentry(ctx context.Context, spec bpfman.FentryAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_FentryAttachInfo{
				FentryAttachInfo: &pb.FentryAttachInfo{},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeFentry,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// AttachFexit attaches a fexit program via gRPC.
func (c *remoteClient) AttachFexit(ctx context.Context, spec bpfman.FexitAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	req := &pb.AttachRequest{
		Id: spec.ProgramID(),
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_FexitAttachInfo{
				FexitAttachInfo: &pb.FexitAttachInfo{},
			},
		},
	}

	resp, err := c.client.Attach(ctx, req)
	if err != nil {
		return bpfman.LinkSummary{}, translateGRPCError(err)
	}

	return bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeFexit,
		KernelProgramID: spec.ProgramID(),
		KernelLinkID:    resp.LinkId,
		PinPath:         opts.LinkPinPath,
	}, nil
}

// Detach removes a link via gRPC.
// The proto uses link_id (uint32) which matches our kernel_link_id.
func (c *remoteClient) Detach(ctx context.Context, kernelLinkID uint32) error {
	_, err := c.client.Detach(ctx, &pb.DetachRequest{LinkId: kernelLinkID})
	return translateGRPCError(err)
}

// ListLinks returns all managed links via gRPC.
func (c *remoteClient) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	resp, err := c.client.ListLinks(ctx, &pb.ListLinksRequest{})
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return protoListLinksResponseToSummaries(resp), nil
}

// ListLinksByProgram returns all links for a given program via gRPC.
func (c *remoteClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error) {
	resp, err := c.client.ListLinks(ctx, &pb.ListLinksRequest{ProgramId: &programKernelID})
	if err != nil {
		return nil, translateGRPCError(err)
	}
	return protoListLinksResponseToSummaries(resp), nil
}

// GetLink retrieves a link by kernel link ID via gRPC.
func (c *remoteClient) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	resp, err := c.client.GetLink(ctx, &pb.GetLinkRequest{KernelLinkId: kernelLinkID})
	if err != nil {
		return bpfman.LinkSummary{}, nil, translateGRPCError(err)
	}
	summary := protoLinkSummaryToManaged(resp.Link.Summary)
	details := protoLinkDetailsToManaged(resp.Link.Details)
	return summary, details, nil
}

// GC is a local-only operation.
func (c *remoteClient) GC(ctx context.Context) (manager.GCResult, error) {
	return manager.GCResult{}, fmt.Errorf("GC: %w", ErrNotSupported)
}

// GCWithRules is a local-only operation.
func (c *remoteClient) GCWithRules(ctx context.Context, rules []string) (manager.GCResult, error) {
	return manager.GCResult{}, fmt.Errorf("GCWithRules: %w", ErrNotSupported)
}

// Doctor is a local-only operation.
func (c *remoteClient) Doctor(ctx context.Context) (manager.DoctorReport, error) {
	return manager.DoctorReport{}, fmt.Errorf("Doctor: %w", ErrNotSupported)
}

// SetImagePuller configures the image puller for OCI operations.
func (c *remoteClient) SetImagePuller(p interpreter.ImagePuller) {
	c.puller = p
}

// PullImage pulls an OCI image and extracts the bytecode.
// Always executes locally, never forwarded to daemon.
func (c *remoteClient) PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	if c.puller == nil {
		return interpreter.PulledImage{}, fmt.Errorf("PullImage: %w (no image puller configured)", ErrNotSupported)
	}
	return c.puller.Pull(ctx, ref)
}

// LoadImage loads programs from an OCI image via gRPC.
// The server handles pulling and caching the image.
func (c *remoteClient) LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []ImageProgramSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error) {
	// Build LoadInfo for each program
	loadInfo := make([]*pb.LoadInfo, 0, len(programs))

	// Start with request-level global data, per-program specs can override
	globalData := opts.GlobalData

	// Copy user metadata and add type hints for kretprobe/uretprobe
	// since the proto enum doesn't distinguish them from kprobe/uprobe.
	metadata := make(map[string]string)
	for k, v := range opts.UserMetadata {
		metadata[k] = v
	}

	for _, spec := range programs {
		protoType, err := domainTypeToProto(spec.ProgramType)
		if err != nil {
			return nil, fmt.Errorf("convert program type for %s: %w", spec.ProgramName, err)
		}
		info := &pb.LoadInfo{
			Name:        spec.ProgramName,
			ProgramType: protoType,
		}
		// Add ProgSpecificInfo for fentry/fexit which require attach function at load time
		switch spec.ProgramType {
		case bpfman.ProgramTypeFentry:
			info.Info = &pb.ProgSpecificInfo{
				Info: &pb.ProgSpecificInfo_FentryLoadInfo{
					FentryLoadInfo: &pb.FentryLoadInfo{FnName: spec.AttachFunc},
				},
			}
		case bpfman.ProgramTypeFexit:
			info.Info = &pb.ProgSpecificInfo{
				Info: &pb.ProgSpecificInfo_FexitLoadInfo{
					FexitLoadInfo: &pb.FexitLoadInfo{FnName: spec.AttachFunc},
				},
			}
		}
		loadInfo = append(loadInfo, info)
		if spec.GlobalData != nil {
			globalData = spec.GlobalData
		}
		// Add metadata to preserve kretprobe/uretprobe distinction
		if NeedsTypeMetadata(spec.ProgramType) {
			metadata[ActualTypeMetadataKey(spec.ProgramName)] = spec.ProgramType.String()
		}
	}

	// Build BytecodeImage with credentials
	var username, password *string
	if ref.Auth != nil {
		username = &ref.Auth.Username
		password = &ref.Auth.Password
	}

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_Image{
				Image: &pb.BytecodeImage{
					Url:             ref.URL,
					ImagePullPolicy: int32(ref.PullPolicy),
					Username:        username,
					Password:        password,
				},
			},
		},
		Metadata:   metadata,
		GlobalData: globalData,
		Info:       loadInfo,
	}

	resp, err := c.client.Load(ctx, req)
	if err != nil {
		return nil, translateGRPCError(err)
	}

	// Convert response to ManagedPrograms
	results := make([]bpfman.ManagedProgram, 0, len(resp.Programs))
	for _, p := range resp.Programs {
		mp, err := protoLoadResponseToManagedProgram(p)
		if err != nil {
			return nil, err
		}
		results = append(results, mp)
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
