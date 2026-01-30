package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/manager"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// mockBpfmanClient records requests for verification.
type mockBpfmanClient struct {
	pb.BpfmanClient
	lastLoadRequest   *pb.LoadRequest
	lastAttachRequest *pb.AttachRequest
}

func (m *mockBpfmanClient) Load(ctx context.Context, req *pb.LoadRequest, opts ...grpc.CallOption) (*pb.LoadResponse, error) {
	m.lastLoadRequest = req
	// Return a minimal valid response
	return &pb.LoadResponse{
		Programs: []*pb.LoadResponseInfo{
			{
				KernelInfo: &pb.KernelProgramInfo{
					Id:          123,
					Name:        "test",
					ProgramType: uint32(bpfman.ProgramTypeXDP),
				},
				Info: &pb.ProgramInfo{
					Name:       "test",
					MapPinPath: "/run/bpfman/fs/maps/123",
				},
			},
		},
	}, nil
}

func (m *mockBpfmanClient) Attach(ctx context.Context, req *pb.AttachRequest, opts ...grpc.CallOption) (*pb.AttachResponse, error) {
	m.lastAttachRequest = req
	return &pb.AttachResponse{
		LinkId: 456,
	}, nil
}

// TestLoadImage_PassesGlobalDataToRequest verifies that LoadImageOpts.GlobalData
// is correctly passed to the pb.LoadRequest.
func TestLoadImage_PassesGlobalDataToRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	globalData := map[string][]byte{
		"GLOBAL_u8":  {0x42},
		"GLOBAL_u32": {0xDE, 0xAD, 0xBE, 0xEF},
	}

	_, err := client.LoadImage(context.Background(),
		interpreter.ImageRef{URL: "test-image:latest"},
		[]ImageProgramSpec{
			{ProgramName: "test", ProgramType: bpfman.ProgramTypeXDP},
		},
		LoadImageOpts{
			GlobalData: globalData,
		},
	)
	require.NoError(t, err)

	// Verify the request was built with global data
	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, globalData, mock.lastLoadRequest.GlobalData,
		"LoadRequest.GlobalData should match LoadImageOpts.GlobalData")
}

// TestLoadImage_PassesUserMetadataToRequest verifies that LoadImageOpts.UserMetadata
// is correctly passed to the pb.LoadRequest.
func TestLoadImage_PassesUserMetadataToRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	metadata := map[string]string{
		"owner":       "test-team",
		"environment": "testing",
	}

	_, err := client.LoadImage(context.Background(),
		interpreter.ImageRef{URL: "test-image:latest"},
		[]ImageProgramSpec{
			{ProgramName: "test", ProgramType: bpfman.ProgramTypeXDP},
		},
		LoadImageOpts{
			UserMetadata: metadata,
		},
	)
	require.NoError(t, err)

	// Verify the request was built with metadata
	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, "test-team", mock.lastLoadRequest.Metadata["owner"],
		"LoadRequest.Metadata should contain owner")
	assert.Equal(t, "testing", mock.lastLoadRequest.Metadata["environment"],
		"LoadRequest.Metadata should contain environment")
}

// TestLoadImage_PassesBothMetadataAndGlobalData verifies that both metadata
// and global data are correctly passed when both are provided.
func TestLoadImage_PassesBothMetadataAndGlobalData(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	metadata := map[string]string{
		"app": "test-app",
	}
	globalData := map[string][]byte{
		"config": {0x01, 0x02, 0x03},
	}

	_, err := client.LoadImage(context.Background(),
		interpreter.ImageRef{URL: "test-image:latest"},
		[]ImageProgramSpec{
			{ProgramName: "test", ProgramType: bpfman.ProgramTypeXDP},
		},
		LoadImageOpts{
			UserMetadata: metadata,
			GlobalData:   globalData,
		},
	)
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, "test-app", mock.lastLoadRequest.Metadata["app"],
		"LoadRequest.Metadata should contain app")
	assert.Equal(t, globalData, mock.lastLoadRequest.GlobalData,
		"LoadRequest.GlobalData should match")
}

// TestLoadImage_PerProgramGlobalDataOverridesOpts verifies that per-program
// GlobalData takes precedence over LoadImageOpts.GlobalData.
func TestLoadImage_PerProgramGlobalDataOverridesOpts(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	optsGlobalData := map[string][]byte{
		"config": {0x01},
	}
	perProgramGlobalData := map[string][]byte{
		"config": {0x02}, // Should override
	}

	_, err := client.LoadImage(context.Background(),
		interpreter.ImageRef{URL: "test-image:latest"},
		[]ImageProgramSpec{
			{
				ProgramName: "test",
				ProgramType: bpfman.ProgramTypeXDP,
				GlobalData:  perProgramGlobalData,
			},
		},
		LoadImageOpts{
			GlobalData: optsGlobalData,
		},
	)
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, perProgramGlobalData, mock.lastLoadRequest.GlobalData,
		"Per-program GlobalData should override opts GlobalData")
}

// TestLoad_PassesGlobalDataFromSpec verifies that LoadSpec.GlobalData()
// is correctly passed to the pb.LoadRequest.
func TestLoad_PassesGlobalDataFromSpec(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	globalData := map[string][]byte{
		"GLOBAL_u8":  {0x42},
		"GLOBAL_u32": {0xDE, 0xAD, 0xBE, 0xEF},
	}

	spec, err := bpfman.NewLoadSpec("/path/to/prog.o", "test_prog", bpfman.ProgramTypeXDP)
	require.NoError(t, err)
	spec = spec.WithGlobalData(globalData)

	_, err = client.Load(context.Background(), spec, manager.LoadOpts{})
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, globalData, mock.lastLoadRequest.GlobalData,
		"LoadRequest.GlobalData should match LoadSpec.GlobalData()")
}

// TestLoad_PassesUserMetadataFromOpts verifies that LoadOpts.UserMetadata
// is correctly passed to the pb.LoadRequest.
func TestLoad_PassesUserMetadataFromOpts(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	metadata := map[string]string{
		"owner":       "test-team",
		"environment": "testing",
	}

	spec, err := bpfman.NewLoadSpec("/path/to/prog.o", "test_prog", bpfman.ProgramTypeXDP)
	require.NoError(t, err)

	_, err = client.Load(context.Background(), spec, manager.LoadOpts{
		UserMetadata: metadata,
	})
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, metadata, mock.lastLoadRequest.Metadata,
		"LoadRequest.Metadata should match LoadOpts.UserMetadata")
}

// TestLoad_PassesBothMetadataAndGlobalData verifies that both metadata
// and global data are correctly passed when both are provided.
func TestLoad_PassesBothMetadataAndGlobalData(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	metadata := map[string]string{
		"app": "test-app",
	}
	globalData := map[string][]byte{
		"config": {0x01, 0x02, 0x03},
	}

	spec, err := bpfman.NewLoadSpec("/path/to/prog.o", "test_prog", bpfman.ProgramTypeTracepoint)
	require.NoError(t, err)
	spec = spec.WithGlobalData(globalData)

	_, err = client.Load(context.Background(), spec, manager.LoadOpts{
		UserMetadata: metadata,
	})
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	assert.Equal(t, metadata, mock.lastLoadRequest.Metadata,
		"LoadRequest.Metadata should match")
	assert.Equal(t, globalData, mock.lastLoadRequest.GlobalData,
		"LoadRequest.GlobalData should match")
}

// TestLoad_PassesProgramInfo verifies that LoadSpec fields are correctly
// mapped to the pb.LoadRequest.
func TestLoad_PassesProgramInfo(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	spec, err := bpfman.NewLoadSpec("/path/to/my_prog.o", "my_xdp_func", bpfman.ProgramTypeXDP)
	require.NoError(t, err)

	_, err = client.Load(context.Background(), spec, manager.LoadOpts{})
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")

	// Verify bytecode location
	require.NotNil(t, mock.lastLoadRequest.Bytecode)
	file, ok := mock.lastLoadRequest.Bytecode.Location.(*pb.BytecodeLocation_File)
	require.True(t, ok, "expected BytecodeLocation_File")
	assert.Equal(t, "/path/to/my_prog.o", file.File, "object path should match")

	// Verify program info
	require.Len(t, mock.lastLoadRequest.Info, 1)
	assert.Equal(t, "my_xdp_func", mock.lastLoadRequest.Info[0].Name, "program name should match")
	assert.Equal(t, pb.BpfmanProgramType_XDP, mock.lastLoadRequest.Info[0].ProgramType, "program type should match")
}

// TestLoad_FentryIncludesAttachFunc verifies that fentry programs include
// the attach function in the request.
func TestLoad_FentryIncludesAttachFunc(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	spec, err := bpfman.NewAttachLoadSpec("/path/to/prog.o", "test_fentry", bpfman.ProgramTypeFentry, "do_unlinkat")
	require.NoError(t, err)

	_, err = client.Load(context.Background(), spec, manager.LoadOpts{})
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	require.Len(t, mock.lastLoadRequest.Info, 1)

	info := mock.lastLoadRequest.Info[0]
	assert.Equal(t, pb.BpfmanProgramType_FENTRY, info.ProgramType)
	require.NotNil(t, info.Info, "fentry should have ProgSpecificInfo")

	fentryInfo, ok := info.Info.Info.(*pb.ProgSpecificInfo_FentryLoadInfo)
	require.True(t, ok, "expected FentryLoadInfo")
	assert.Equal(t, "do_unlinkat", fentryInfo.FentryLoadInfo.FnName, "attach function should match")
}

// TestLoad_FexitIncludesAttachFunc verifies that fexit programs include
// the attach function in the request.
func TestLoad_FexitIncludesAttachFunc(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{
		client: mock,
	}

	spec, err := bpfman.NewAttachLoadSpec("/path/to/prog.o", "test_fexit", bpfman.ProgramTypeFexit, "do_unlinkat")
	require.NoError(t, err)

	_, err = client.Load(context.Background(), spec, manager.LoadOpts{})
	require.NoError(t, err)

	require.NotNil(t, mock.lastLoadRequest, "Load should have been called")
	require.Len(t, mock.lastLoadRequest.Info, 1)

	info := mock.lastLoadRequest.Info[0]
	assert.Equal(t, pb.BpfmanProgramType_FEXIT, info.ProgramType)
	require.NotNil(t, info.Info, "fexit should have ProgSpecificInfo")

	fexitInfo, ok := info.Info.Info.(*pb.ProgSpecificInfo_FexitLoadInfo)
	require.True(t, ok, "expected FexitLoadInfo")
	assert.Equal(t, "do_unlinkat", fexitInfo.FexitLoadInfo.FnName, "attach function should match")
}

// --- Attach method tests ---

// TestAttachTracepoint_BuildsCorrectRequest verifies that AttachTracepoint
// correctly builds the proto request from the spec.
func TestAttachTracepoint_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewTracepointAttachSpec(123, "syscalls", "sys_enter_kill")
	require.NoError(t, err)

	summary, err := client.AttachTracepoint(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id, "program ID should match")

	tpInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_TracepointAttachInfo)
	require.True(t, ok, "expected TracepointAttachInfo")
	assert.Equal(t, "syscalls/sys_enter_kill", tpInfo.TracepointAttachInfo.Tracepoint,
		"tracepoint should be group/name format")

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindTracepoint, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachXDP_BuildsCorrectRequest verifies that AttachXDP
// correctly builds the proto request from the spec.
func TestAttachXDP_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewXDPAttachSpec(123, "eth0", 50)
	require.NoError(t, err)

	summary, err := client.AttachXDP(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	xdpInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_XdpAttachInfo)
	require.True(t, ok, "expected XdpAttachInfo")
	assert.Equal(t, "eth0", xdpInfo.XdpAttachInfo.Iface)
	assert.Equal(t, int32(50), xdpInfo.XdpAttachInfo.Priority)

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindXDP, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachTC_BuildsCorrectRequest verifies that AttachTC
// correctly builds the proto request from the spec.
func TestAttachTC_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewTCAttachSpec(123, "eth0", 1, "ingress")
	require.NoError(t, err)
	spec = spec.WithPriority(100).WithProceedOn([]int32{0, 2})

	summary, err := client.AttachTC(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	tcInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_TcAttachInfo)
	require.True(t, ok, "expected TcAttachInfo")
	assert.Equal(t, "eth0", tcInfo.TcAttachInfo.Iface)
	assert.Equal(t, "ingress", tcInfo.TcAttachInfo.Direction)
	assert.Equal(t, int32(100), tcInfo.TcAttachInfo.Priority)
	assert.Equal(t, []int32{0, 2}, tcInfo.TcAttachInfo.ProceedOn)

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindTC, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachTCX_BuildsCorrectRequest verifies that AttachTCX
// correctly builds the proto request from the spec.
func TestAttachTCX_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewTCXAttachSpec(123, "eth0", 1, "egress")
	require.NoError(t, err)
	spec = spec.WithPriority(75)

	summary, err := client.AttachTCX(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	tcxInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_TcxAttachInfo)
	require.True(t, ok, "expected TcxAttachInfo")
	assert.Equal(t, "eth0", tcxInfo.TcxAttachInfo.Iface)
	assert.Equal(t, "egress", tcxInfo.TcxAttachInfo.Direction)
	assert.Equal(t, int32(75), tcxInfo.TcxAttachInfo.Priority)

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindTCX, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachKprobe_BuildsCorrectRequest verifies that AttachKprobe
// correctly builds the proto request from the spec.
func TestAttachKprobe_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewKprobeAttachSpec(123, "do_sys_open")
	require.NoError(t, err)

	summary, err := client.AttachKprobe(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	kprobeInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_KprobeAttachInfo)
	require.True(t, ok, "expected KprobeAttachInfo")
	assert.Equal(t, "do_sys_open", kprobeInfo.KprobeAttachInfo.FnName)
	assert.Equal(t, uint64(0), kprobeInfo.KprobeAttachInfo.Offset)

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindKprobe, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachKprobe_WithOffset verifies that AttachKprobe includes the offset.
func TestAttachKprobe_WithOffset(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewKprobeAttachSpec(123, "do_sys_open")
	require.NoError(t, err)
	spec = spec.WithOffset(0x10)

	_, err = client.AttachKprobe(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	kprobeInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_KprobeAttachInfo)
	require.True(t, ok)
	assert.Equal(t, uint64(0x10), kprobeInfo.KprobeAttachInfo.Offset)
}

// TestAttachUprobe_BuildsCorrectRequest verifies that AttachUprobe
// correctly builds the proto request from the spec.
func TestAttachUprobe_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewUprobeAttachSpec(123, "/usr/lib/libc.so.6")
	require.NoError(t, err)
	spec = spec.WithFnName("malloc")

	summary, err := client.AttachUprobe(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	uprobeInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_UprobeAttachInfo)
	require.True(t, ok, "expected UprobeAttachInfo")
	assert.Equal(t, "/usr/lib/libc.so.6", uprobeInfo.UprobeAttachInfo.Target)
	assert.Equal(t, "malloc", *uprobeInfo.UprobeAttachInfo.FnName)
	assert.Equal(t, uint64(0), uprobeInfo.UprobeAttachInfo.Offset)

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindUprobe, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachFentry_BuildsCorrectRequest verifies that AttachFentry
// correctly builds the proto request from the spec.
func TestAttachFentry_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewFentryAttachSpec(123)
	require.NoError(t, err)

	summary, err := client.AttachFentry(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	fentryInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_FentryAttachInfo)
	require.True(t, ok, "expected FentryAttachInfo")
	_ = fentryInfo // Fentry attach info is empty - function is specified at load time

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindFentry, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttachFexit_BuildsCorrectRequest verifies that AttachFexit
// correctly builds the proto request from the spec.
func TestAttachFexit_BuildsCorrectRequest(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewFexitAttachSpec(123)
	require.NoError(t, err)

	summary, err := client.AttachFexit(context.Background(), spec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Verify request
	require.NotNil(t, mock.lastAttachRequest)
	assert.Equal(t, uint32(123), mock.lastAttachRequest.Id)

	fexitInfo, ok := mock.lastAttachRequest.Attach.Info.(*pb.AttachInfo_FexitAttachInfo)
	require.True(t, ok, "expected FexitAttachInfo")
	_ = fexitInfo // Fexit attach info is empty - function is specified at load time

	// Verify response mapping
	assert.Equal(t, bpfman.LinkKindFexit, summary.Kind)
	assert.Equal(t, bpfman.LinkID(456), summary.ID)
}

// TestAttach_LinkPinPathFromOpts verifies that AttachOpts.LinkPinPath
// is correctly returned in the LinkSummary.
func TestAttach_LinkPinPathFromOpts(t *testing.T) {
	mock := &mockBpfmanClient{}
	client := &remoteClient{client: mock}

	spec, err := bpfman.NewXDPAttachSpec(123, "eth0", 50)
	require.NoError(t, err)

	summary, err := client.AttachXDP(context.Background(), spec, bpfman.AttachOpts{
		LinkPinPath: "/run/bpfman/links/my-link",
	})
	require.NoError(t, err)

	assert.Equal(t, "/run/bpfman/links/my-link", summary.PinPath,
		"LinkPinPath from opts should be in summary")
}
