// Package client provides a unified interface for BPF program management.
//
// Use Dial to connect to a running bpfman daemon:
//
//	c, err := client.Dial(client.DefaultSocketPath())
//	c, err := client.Dial("localhost:50051")
//
// Use Open for local BPF program management:
//
//	c, err := client.Open(ctx)
//	c, err := client.Open(ctx, client.WithRuntimeDir("/tmp/mybpfman"))
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

// ImageProgramSpec describes a program to load from an OCI image.
// Unlike LoadSpec, this doesn't require objectPath/pinPath since those are
// determined by the server after pulling the image.
type ImageProgramSpec struct {
	ProgramName string
	ProgramType bpfman.ProgramType
	AttachFunc  string            // Required for fentry/fexit
	GlobalData  map[string][]byte // Per-program overrides (optional)
	MapOwnerID  uint32            // Share maps with another program (optional)
}

// NewImageProgramSpec creates an ImageProgramSpec for non-fentry/fexit programs.
func NewImageProgramSpec(programName string, programType bpfman.ProgramType) (ImageProgramSpec, error) {
	if programName == "" {
		return ImageProgramSpec{}, errors.New("programName is required")
	}
	if !programType.Valid() {
		return ImageProgramSpec{}, errors.New("invalid program type")
	}
	if programType.RequiresAttachFunc() {
		return ImageProgramSpec{}, errors.New("use NewImageProgramSpecWithAttach for fentry/fexit")
	}
	return ImageProgramSpec{
		ProgramName: programName,
		ProgramType: programType,
	}, nil
}

// NewImageProgramSpecWithAttach creates an ImageProgramSpec for fentry/fexit programs.
func NewImageProgramSpecWithAttach(programName string, programType bpfman.ProgramType, attachFunc string) (ImageProgramSpec, error) {
	if programName == "" {
		return ImageProgramSpec{}, errors.New("programName is required")
	}
	if !programType.Valid() {
		return ImageProgramSpec{}, errors.New("invalid program type")
	}
	if !programType.RequiresAttachFunc() {
		return ImageProgramSpec{}, errors.New("use NewImageProgramSpec for non-fentry/fexit")
	}
	if attachFunc == "" {
		return ImageProgramSpec{}, errors.New("attachFunc is required for fentry/fexit")
	}
	return ImageProgramSpec{
		ProgramName: programName,
		ProgramType: programType,
		AttachFunc:  attachFunc,
	}, nil
}

// WithGlobalData returns a copy with global data set.
func (s ImageProgramSpec) WithGlobalData(data map[string][]byte) ImageProgramSpec {
	s.GlobalData = data
	return s
}

// WithMapOwnerID returns a copy with map owner ID set.
func (s ImageProgramSpec) WithMapOwnerID(id uint32) ImageProgramSpec {
	s.MapOwnerID = id
	return s
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
	AttachTracepoint(ctx context.Context, spec bpfman.TracepointAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachXDP(ctx context.Context, spec bpfman.XDPAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachTC(ctx context.Context, spec bpfman.TCAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachTCX(ctx context.Context, spec bpfman.TCXAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachKprobe(ctx context.Context, spec bpfman.KprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachUprobe(ctx context.Context, spec bpfman.UprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachFentry(ctx context.Context, spec bpfman.FentryAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	AttachFexit(ctx context.Context, spec bpfman.FexitAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkRecord, error)
	Detach(ctx context.Context, kernelLinkID uint32) error

	// Link operations
	ListLinks(ctx context.Context) ([]bpfman.LinkRecord, error)
	ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkRecord, error)
	GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkRecord, bpfman.LinkDetails, error)

	// Host-only operations (local execution required)
	GC(ctx context.Context) (manager.GCResult, error)
	GCWithRules(ctx context.Context, rules []string) (manager.GCResult, error)
	Doctor(ctx context.Context) (manager.DoctorReport, error)

	// Image operations
	PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error)
	LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []ImageProgramSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error)
}
