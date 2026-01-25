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

// mockBpfmanClient records the LoadRequest for verification.
type mockBpfmanClient struct {
	pb.BpfmanClient
	lastLoadRequest *pb.LoadRequest
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
