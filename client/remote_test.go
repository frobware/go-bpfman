package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter"
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
