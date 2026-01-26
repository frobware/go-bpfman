package server_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/frobware/go-bpfman/server/pb"
)

// =============================================================================
// TC Dispatcher Lifecycle Tests
// =============================================================================
//
// These tests verify the TC dispatcher lifecycle using the fake network
// interface resolver.

// TestTC_FirstAttachCreatesLink verifies that:
//
//	Given a loaded TC program,
//	When I attach it to an interface,
//	Then a link is created.
func TestTC_FirstAttachCreatesLink(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TC program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tc.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tc_pass", ProgramType: pb.BpfmanProgramType_TC},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tc-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach to interface with ingress direction
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "eth0",
					Direction: "ingress",
					Priority:  50,
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachTC should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestTC_IngressAndEgressDirections verifies that:
//
//	Given a loaded TC program,
//	When I attach it with both ingress and egress directions,
//	Then both attachments succeed.
func TestTC_IngressAndEgressDirections(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TC program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tc.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tc_pass", ProgramType: pb.BpfmanProgramType_TC},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tc-direction-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach ingress
	ingressReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "eth0",
					Direction: "ingress",
				},
			},
		},
	}

	ingressResp, err := fix.Server.Attach(ctx, ingressReq)
	require.NoError(t, err, "Ingress attach should succeed")

	// Attach egress
	egressReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "eth0",
					Direction: "egress",
				},
			},
		},
	}

	egressResp, err := fix.Server.Attach(ctx, egressReq)
	require.NoError(t, err, "Egress attach should succeed")

	// Verify both links exist
	assert.Equal(t, 2, fix.Kernel.LinkCount(), "should have 2 links")
	assert.NotEqual(t, ingressResp.LinkId, egressResp.LinkId, "link IDs should differ")
}

// TestTC_InvalidDirection verifies that:
//
//	Given a loaded TC program,
//	When I try to attach with an invalid direction,
//	Then the operation fails.
func TestTC_InvalidDirection(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TC program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tc.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tc_pass", ProgramType: pb.BpfmanProgramType_TC},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tc-invalid-direction-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt attach with invalid direction
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "eth0",
					Direction: "sideways",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach with invalid direction should fail")
	assert.Contains(t, err.Error(), "direction", "error should mention direction")
}

// TestTC_AttachToNonExistentInterface verifies that:
//
//	Given a loaded TC program,
//	When I try to attach it to a non-existent interface,
//	Then the operation fails with an appropriate error.
func TestTC_AttachToNonExistentInterface(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TC program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tc.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tc_pass", ProgramType: pb.BpfmanProgramType_TC},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tc-nonexistent-iface-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt to attach to non-existent interface
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "nonexistent0",
					Direction: "ingress",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach to non-existent interface should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention interface not found")

	// No links should exist
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "no links should exist")
}

// TestTC_FullLifecycle verifies the complete TC lifecycle:
//
//  1. Load TC program
//  2. Attach to ingress and egress
//  3. Detach all links
//  4. Unload program
//  5. Verify clean state
func TestTC_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load TC program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tc.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tc_pass", ProgramType: pb.BpfmanProgramType_TC},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tc-lifecycle-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id
	t.Logf("Step 1: Loaded program ID %d", programID)

	// Step 2: Attach to ingress and egress on multiple interfaces
	var linkIDs []uint32
	for _, iface := range []string{"lo", "eth0"} {
		for _, direction := range []string{"ingress", "egress"} {
			attachReq := &pb.AttachRequest{
				Id: programID,
				Attach: &pb.AttachInfo{
					Info: &pb.AttachInfo_TcAttachInfo{
						TcAttachInfo: &pb.TCAttachInfo{
							Iface:     iface,
							Direction: direction,
						},
					},
				},
			}
			attachResp, err := fix.Server.Attach(ctx, attachReq)
			require.NoError(t, err, "Attach %s/%s should succeed", iface, direction)
			linkIDs = append(linkIDs, attachResp.LinkId)
			t.Logf("Step 2: Attached %s/%s (link ID %d)", iface, direction, attachResp.LinkId)
		}
	}

	// Verify state after attachments (4 links: 2 interfaces x 2 directions)
	// 5 programs: 1 user TC program + 4 TC dispatchers (2 interfaces x 2 directions)
	assert.Equal(t, 5, fix.Kernel.ProgramCount(), "should have 5 programs (user + 4 dispatchers)")
	assert.Equal(t, 4, fix.Kernel.LinkCount(), "should have 4 links")

	// Step 3: Detach all links
	for i, linkID := range linkIDs {
		_, err := fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
		require.NoError(t, err, "Detach link %d should succeed", linkID)
		t.Logf("Step 3: Detached link %d, remaining: %d", linkID, fix.Kernel.LinkCount())
		assert.Equal(t, 4-i-1, fix.Kernel.LinkCount(), "link count should decrement")
	}

	// Step 4: Unload program
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: programID})
	require.NoError(t, err, "Unload should succeed")
	t.Logf("Step 4: Unloaded program %d", programID)

	// Step 5: Verify clean state
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "should have 0 programs")
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links")
	t.Log("Step 5: Verified clean state - test passed")
}
