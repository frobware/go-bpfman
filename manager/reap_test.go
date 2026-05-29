package manager_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/manager"
	"github.com/frobware/go-bpfman/platform"
)

// TestReapDeadProgramRecords proves the Load-path reap removes store
// records whose kernel program is gone, preserves still-live programs,
// and -- the crux -- deletes a dead map owner only after its dead
// dependent.
//
// The fixture's store is a real in-memory SQLite with foreign keys on,
// so the map_owner_id ON DELETE RESTRICT constraint is genuinely
// enforced: a reap that deleted the owner before its dependent would be
// rejected by the kernel of the database and leave the owner behind.
// The owner-absent assertion is therefore a real test of the
// dependents-first ordering, not of a mock.
func TestReapDeadProgramRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	discoverer := newFakeDiscoverer()
	f := newTestFixtureWithDiscoverer(t, discoverer)

	// Two shared-map programs: with ShareMaps the second auto-shares
	// the first's maps, so its map_owner_id points at the owner -- the
	// FK that makes deletion order matter.
	sharedObj := f.BytecodeFile("shared.o")
	discoverer.SetPrograms(sharedObj, []platform.DiscoveredProgram{
		{Name: "owner", SectionName: "xdp", Type: bpfman.ProgramTypeXDP},
		{Name: "dependent", SectionName: "xdp", Type: bpfman.ProgramTypeXDP},
	})
	shared, err := f.LoadDirect(ctx,
		manager.LoadSource{FilePath: sharedObj}, nil,
		manager.LoadOpts{ShareMaps: true})
	require.NoError(t, err)
	require.Len(t, shared, 2)
	ownerID := shared[0].Record.ProgramID
	dependentID := shared[1].Record.ProgramID

	// Guard: without a real map_owner_id FK the ordering assertion
	// below would be hollow (both rows independently deletable). Fail
	// loudly if ShareMaps did not wire the dependency.
	require.NotNil(t, shared[1].Record.Handles.MapOwnerID,
		"dependent must record a map owner; otherwise the test does not exercise the RESTRICT ordering")
	require.Equal(t, ownerID, *shared[1].Record.Handles.MapOwnerID)

	// A standalone program that stays live in the kernel.
	liveObj := f.BytecodeFile("live.o")
	discoverer.SetPrograms(liveObj, []platform.DiscoveredProgram{
		{Name: "live", SectionName: "xdp", Type: bpfman.ProgramTypeXDP},
	})
	live, err := f.LoadDirect(ctx,
		manager.LoadSource{FilePath: liveObj}, nil,
		manager.LoadOpts{})
	require.NoError(t, err)
	require.Len(t, live, 1)
	liveID := live[0].Record.ProgramID

	// The shared-map generation dies in the kernel while its store
	// records remain (daemon restart / external unload).
	f.Kernel.RemoveKernelProgram(ownerID)
	f.Kernel.RemoveKernelProgram(dependentID)

	require.NoError(t, f.Manager.ReapDeadProgramRecordsForTest(ctx))

	_, err = f.Store.Get(ctx, dependentID)
	assert.ErrorIs(t, err, platform.ErrRecordNotFound, "dead dependent should be reaped")

	_, err = f.Store.Get(ctx, ownerID)
	assert.ErrorIs(t, err, platform.ErrRecordNotFound, "dead map owner should be reaped after its dependent")

	_, err = f.Store.Get(ctx, liveID)
	assert.NoError(t, err, "live program must be preserved")
}
