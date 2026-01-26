package server_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/frobware/go-bpfman/server/pb"
)

// =============================================================================
// Link Listing Tests
// =============================================================================
//
// These tests verify the ListLinks and GetLink operations.

// TestListLinks_ReturnsAllLinks verifies that:
//
//	Given multiple attached links,
//	When I list links,
//	Then all links are returned.
func TestListLinks_ReturnsAllLinks(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "list-links-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach multiple times to different tracepoints
	tracepoints := []string{
		"syscalls/sys_enter_open",
		"syscalls/sys_enter_close",
		"syscalls/sys_enter_read",
	}

	var linkIDs []uint32
	for _, tp := range tracepoints {
		attachReq := &pb.AttachRequest{
			Id: programID,
			Attach: &pb.AttachInfo{
				Info: &pb.AttachInfo_TracepointAttachInfo{
					TracepointAttachInfo: &pb.TracepointAttachInfo{
						Tracepoint: tp,
					},
				},
			},
		}
		attachResp, err := fix.Server.Attach(ctx, attachReq)
		require.NoError(t, err, "Attach to %s should succeed", tp)
		linkIDs = append(linkIDs, attachResp.LinkId)
	}

	// List all links
	listResp, err := fix.Server.ListLinks(ctx, &pb.ListLinksRequest{})
	require.NoError(t, err, "ListLinks should succeed")
	assert.Len(t, listResp.Links, 3, "should have 3 links")

	// Verify all link IDs are present
	returnedIDs := make(map[uint32]bool)
	for _, link := range listResp.Links {
		returnedIDs[link.Summary.KernelLinkId] = true
	}
	for _, expectedID := range linkIDs {
		assert.True(t, returnedIDs[expectedID], "link ID %d should be in response", expectedID)
	}
}

// TestListLinks_EmptyWhenNoLinks verifies that:
//
//	Given no attached links,
//	When I list links,
//	Then an empty list is returned.
func TestListLinks_EmptyWhenNoLinks(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// List links without any attachments
	listResp, err := fix.Server.ListLinks(ctx, &pb.ListLinksRequest{})
	require.NoError(t, err, "ListLinks should succeed")
	assert.Empty(t, listResp.Links, "should have 0 links")
}

// TestGetLink_ReturnsLinkDetails verifies that:
//
//	Given an attached link,
//	When I get link details,
//	Then the correct details are returned.
func TestGetLink_ReturnsLinkDetails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load and attach a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "get-link-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_open",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId

	// Get link details
	getResp, err := fix.Server.GetLink(ctx, &pb.GetLinkRequest{KernelLinkId: linkID})
	require.NoError(t, err, "GetLink should succeed")
	assert.Equal(t, linkID, getResp.Link.Summary.KernelLinkId, "link ID should match")
	assert.Equal(t, pb.BpfmanLinkType_LINK_TYPE_TRACEPOINT, getResp.Link.Summary.LinkType, "link type should be tracepoint")
}

// TestGetLink_NonExistentLink_ReturnsNotFound verifies that:
//
//	Given no attached links,
//	When I try to get a non-existent link,
//	Then NotFound is returned.
func TestGetLink_NonExistentLink_ReturnsNotFound(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Try to get non-existent link
	_, err := fix.Server.GetLink(ctx, &pb.GetLinkRequest{KernelLinkId: 99999})
	require.Error(t, err, "GetLink should fail for non-existent link")

	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status")
	assert.Equal(t, codes.NotFound, st.Code(), "should return NotFound")
}
