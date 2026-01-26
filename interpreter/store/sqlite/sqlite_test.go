package sqlite_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter/store/sqlite"
)

// testLogger returns a logger for tests. By default it discards all output.
// Set BPFMAN_TEST_VERBOSE=1 to enable logging.
func testLogger() *slog.Logger {
	if os.Getenv("BPFMAN_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testProgram returns a valid Program for testing.
func testProgram() bpfman.Program {
	return bpfman.Program{
		ProgramName: "test_program",
		ProgramType: bpfman.ProgramTypeTracepoint,
		ObjectPath:  "/test/path/program.o",
		PinPath:     "/sys/fs/bpf/test",
		CreatedAt:   time.Now(),
	}
}

func TestForeignKey_LinkRequiresProgram(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Attempt to create a link referencing a non-existent program.
	summary := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 999, // does not exist
		KernelLinkID:    1,
		CreatedAt:       time.Now(),
	}
	details := bpfman.TracepointDetails{
		Group: "syscalls",
		Name:  "sys_enter_openat",
	}

	err = store.SaveTracepointLink(ctx, summary, details)
	require.Error(t, err, "expected FK constraint violation")
	assert.True(t, strings.Contains(err.Error(), "FOREIGN KEY constraint failed"), "expected FK constraint error, got: %v", err)
}

func TestForeignKey_CascadeDeleteRemovesLinks(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program directly.
	kernelID := uint32(42)
	prog := testProgram()

	require.NoError(t, store.Save(ctx, kernelID, prog), "Save failed")

	// Create two links for that program.
	for i := 0; i < 2; i++ {
		summary := bpfman.LinkSummary{
			LinkType:        bpfman.LinkTypeKprobe,
			KernelProgramID: kernelID,
			KernelLinkID:    uint32(100 + i),
			CreatedAt:       time.Now(),
		}
		details := bpfman.KprobeDetails{
			FnName:   "test_fn",
			Offset:   0,
			Retprobe: false,
		}
		require.NoError(t, store.SaveKprobeLink(ctx, summary, details), "SaveKprobeLink failed")
	}

	// Verify links exist.
	links, err := store.ListLinksByProgram(ctx, kernelID)
	require.NoError(t, err, "ListLinksByProgram failed")
	require.Len(t, links, 2, "expected 2 links")

	// Delete the program.
	require.NoError(t, store.Delete(ctx, kernelID), "Delete failed")

	// Verify CASCADE removed the links.
	links, err = store.ListLinksByProgram(ctx, kernelID)
	require.NoError(t, err, "ListLinksByProgram after delete failed")
	assert.Empty(t, links, "expected 0 links after CASCADE delete")
}

func TestForeignKey_CascadeDeleteRemovesMetadataIndex(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program with metadata.
	kernelID := uint32(42)
	prog := testProgram()
	prog.UserMetadata = map[string]string{
		"app":     "test",
		"version": "1.0",
	}

	require.NoError(t, store.Save(ctx, kernelID, prog), "Save failed")

	// Verify we can find by metadata.
	found, foundID, err := store.FindProgramByMetadata(ctx, "app", "test")
	require.NoError(t, err, "FindProgramByMetadata failed")
	assert.Equal(t, kernelID, foundID, "kernel_id mismatch")
	assert.Equal(t, "test", found.UserMetadata["app"], "metadata mismatch")

	// Delete the program.
	require.NoError(t, store.Delete(ctx, kernelID), "Delete failed")

	// Verify CASCADE removed the metadata index entries.
	_, _, err = store.FindProgramByMetadata(ctx, "app", "test")
	assert.Error(t, err, "expected error after CASCADE delete")
}

func TestProgramName_DuplicatesAllowed(t *testing.T) {
	// Multiple programs can share the same bpfman.io/ProgramName, e.g., when
	// loading multiple BPF programs from a single OCI image via the operator.
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create first program with a name.
	prog1 := testProgram()
	prog1.UserMetadata = map[string]string{
		"bpfman.io/ProgramName": "my-program",
	}

	require.NoError(t, store.Save(ctx, 100, prog1), "Save prog1 failed")

	// Create second program with the same name - this should succeed.
	prog2 := testProgram()
	prog2.UserMetadata = map[string]string{
		"bpfman.io/ProgramName": "my-program", // same name, allowed
	}

	err = store.Save(ctx, 200, prog2)
	require.NoError(t, err, "duplicate program names should be allowed")
}

func TestUniqueIndex_DifferentNamesAllowed(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create two programs with different names.
	for i, name := range []string{"program-a", "program-b"} {
		prog := testProgram()
		prog.UserMetadata = map[string]string{
			"bpfman.io/ProgramName": name,
		}

		require.NoError(t, store.Save(ctx, uint32(100+i), prog), "Save %s failed", name)
	}

	// Verify both exist.
	programs, err := store.List(ctx)
	require.NoError(t, err, "List failed")
	assert.Len(t, programs, 2, "expected 2 programs")
}

func TestUniqueIndex_NameCanBeReusedAfterDelete(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program with a name.
	prog := testProgram()
	prog.UserMetadata = map[string]string{
		"bpfman.io/ProgramName": "reusable-name",
	}

	require.NoError(t, store.Save(ctx, 100, prog), "Save failed")

	// Delete it.
	require.NoError(t, store.Delete(ctx, 100), "Delete failed")

	// Create a new program with the same name.
	prog2 := testProgram()
	prog2.UserMetadata = map[string]string{
		"bpfman.io/ProgramName": "reusable-name", // same name, should work
	}

	require.NoError(t, store.Save(ctx, 200, prog2), "Save prog2 failed")

	// Verify it exists.
	found, kernelID, err := store.FindProgramByMetadata(ctx, "bpfman.io/ProgramName", "reusable-name")
	require.NoError(t, err, "FindProgramByMetadata failed")
	assert.Equal(t, uint32(200), kernelID, "kernel_id mismatch")
	assert.Equal(t, "reusable-name", found.UserMetadata["bpfman.io/ProgramName"], "name mismatch")
}

func TestLinkRegistry_TracepointRoundTrip(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program first
	prog := testProgram()
	require.NoError(t, store.Save(ctx, 42, prog), "Save failed")

	// Create a tracepoint link
	kernelLinkID := uint32(100)
	summary := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 42,
		KernelLinkID:    kernelLinkID,
		PinPath:         "/sys/fs/bpf/bpfman/test/link",
		CreatedAt:       time.Now(),
	}
	details := bpfman.TracepointDetails{
		Group: "syscalls",
		Name:  "sys_enter_openat",
	}

	require.NoError(t, store.SaveTracepointLink(ctx, summary, details), "SaveTracepointLink failed")

	// Retrieve and verify
	gotSummary, gotDetails, err := store.GetLink(ctx, kernelLinkID)
	require.NoError(t, err, "GetLink failed")

	assert.Equal(t, summary.LinkType, gotSummary.LinkType)
	assert.Equal(t, summary.KernelProgramID, gotSummary.KernelProgramID)
	assert.Equal(t, summary.KernelLinkID, gotSummary.KernelLinkID)
	assert.Equal(t, summary.PinPath, gotSummary.PinPath)

	tpDetails, ok := gotDetails.(bpfman.TracepointDetails)
	require.True(t, ok, "expected TracepointDetails")
	assert.Equal(t, details.Group, tpDetails.Group)
	assert.Equal(t, details.Name, tpDetails.Name)
}

func TestLinkRegistry_KernelLinkIDUniqueness(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program first
	prog := testProgram()
	require.NoError(t, store.Save(ctx, 42, prog), "Save failed")

	// Create first link
	kernelLinkID := uint32(100)
	summary := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 42,
		KernelLinkID:    kernelLinkID,
		CreatedAt:       time.Now(),
	}
	details := bpfman.TracepointDetails{Group: "syscalls", Name: "sys_enter_openat"}

	require.NoError(t, store.SaveTracepointLink(ctx, summary, details), "first SaveTracepointLink failed")

	// Try to create another link with same kernel_link_id
	summary2 := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeKprobe,
		KernelProgramID: 42,
		KernelLinkID:    kernelLinkID, // same kernel_link_id
		CreatedAt:       time.Now(),
	}
	kprobeDetails := bpfman.KprobeDetails{FnName: "test_fn"}

	err = store.SaveKprobeLink(ctx, summary2, kprobeDetails)
	require.Error(t, err, "expected kernel_link_id uniqueness violation")
	assert.True(t, strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY"),
		"expected uniqueness error, got: %v", err)
}

func TestLinkRegistry_CascadeDeleteFromRegistry(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program first
	prog := testProgram()
	require.NoError(t, store.Save(ctx, 42, prog), "Save failed")

	// Create a tracepoint link
	kernelLinkID := uint32(100)
	summary := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 42,
		KernelLinkID:    kernelLinkID,
		CreatedAt:       time.Now(),
	}
	details := bpfman.TracepointDetails{Group: "syscalls", Name: "sys_enter_openat"}

	require.NoError(t, store.SaveTracepointLink(ctx, summary, details), "SaveTracepointLink failed")

	// Delete the link via registry
	require.NoError(t, store.DeleteLink(ctx, kernelLinkID), "DeleteLink failed")

	// Verify link is gone
	_, _, err = store.GetLink(ctx, kernelLinkID)
	require.Error(t, err, "expected link to be deleted")
}

// ----------------------------------------------------------------------------
// Dispatcher Store Tests
// ----------------------------------------------------------------------------

func TestDispatcherStore_SaveAndGet(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a dispatcher
	state := dispatcher.State{
		Type:          dispatcher.DispatcherTypeXDP,
		Nsid:          4026531840,
		Ifindex:       1,
		Revision:      1,
		KernelID:      100,
		LinkID:        101,
		LinkPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link",
		ProgPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher",
		NumExtensions: 0,
	}

	require.NoError(t, store.SaveDispatcher(ctx, state), "SaveDispatcher failed")

	// Retrieve and verify
	got, err := store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "GetDispatcher failed")

	assert.Equal(t, state.Type, got.Type)
	assert.Equal(t, state.Nsid, got.Nsid)
	assert.Equal(t, state.Ifindex, got.Ifindex)
	assert.Equal(t, state.Revision, got.Revision)
	assert.Equal(t, state.KernelID, got.KernelID)
	assert.Equal(t, state.LinkID, got.LinkID)
	assert.Equal(t, state.LinkPinPath, got.LinkPinPath)
	assert.Equal(t, state.ProgPinPath, got.ProgPinPath)
	assert.Equal(t, state.NumExtensions, got.NumExtensions)
}

func TestDispatcherStore_Update(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a dispatcher
	state := dispatcher.State{
		Type:          dispatcher.DispatcherTypeXDP,
		Nsid:          4026531840,
		Ifindex:       1,
		Revision:      1,
		KernelID:      100,
		LinkID:        101,
		LinkPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link",
		ProgPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher",
		NumExtensions: 0,
	}

	require.NoError(t, store.SaveDispatcher(ctx, state), "SaveDispatcher failed")

	// Update it
	state.NumExtensions = 3
	state.Revision = 2
	state.ProgPinPath = "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_2/dispatcher"

	require.NoError(t, store.SaveDispatcher(ctx, state), "SaveDispatcher (update) failed")

	// Verify the update
	got, err := store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "GetDispatcher failed")

	assert.Equal(t, uint8(3), got.NumExtensions)
	assert.Equal(t, uint32(2), got.Revision)
	assert.Equal(t, "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_2/dispatcher", got.ProgPinPath)
}

func TestDispatcherStore_Delete(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a dispatcher
	state := dispatcher.State{
		Type:          dispatcher.DispatcherTypeXDP,
		Nsid:          4026531840,
		Ifindex:       1,
		Revision:      1,
		KernelID:      100,
		LinkID:        101,
		LinkPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link",
		ProgPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher",
		NumExtensions: 0,
	}

	require.NoError(t, store.SaveDispatcher(ctx, state), "SaveDispatcher failed")

	// Delete it
	require.NoError(t, store.DeleteDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1), "DeleteDispatcher failed")

	// Verify it's gone
	_, err = store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.Error(t, err, "expected dispatcher to be deleted")
}

func TestDispatcherStore_DeleteNonExistent(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Try to delete a non-existent dispatcher
	err = store.DeleteDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 99)
	require.Error(t, err, "expected error for non-existent dispatcher")
}

func TestDispatcherStore_IncrementRevision(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a dispatcher with revision 1
	state := dispatcher.State{
		Type:          dispatcher.DispatcherTypeXDP,
		Nsid:          4026531840,
		Ifindex:       1,
		Revision:      1,
		KernelID:      100,
		LinkID:        101,
		LinkPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link",
		ProgPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher",
		NumExtensions: 0,
	}

	require.NoError(t, store.SaveDispatcher(ctx, state), "SaveDispatcher failed")

	// Increment revision
	newRev, err := store.IncrementRevision(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "IncrementRevision failed")
	assert.Equal(t, uint32(2), newRev, "expected revision 2")

	// Increment again
	newRev, err = store.IncrementRevision(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "IncrementRevision (2nd) failed")
	assert.Equal(t, uint32(3), newRev, "expected revision 3")

	// Verify via Get
	got, err := store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "GetDispatcher failed")
	assert.Equal(t, uint32(3), got.Revision, "revision mismatch")
}

func TestDispatcherStore_UniqueConstraint(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create an XDP dispatcher
	xdpState := dispatcher.State{
		Type:          dispatcher.DispatcherTypeXDP,
		Nsid:          4026531840,
		Ifindex:       1,
		Revision:      1,
		KernelID:      100,
		LinkID:        101,
		LinkPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link",
		ProgPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher",
		NumExtensions: 0,
	}

	require.NoError(t, store.SaveDispatcher(ctx, xdpState), "SaveDispatcher (xdp) failed")

	// Create a TC-ingress dispatcher on same nsid/ifindex - should work (different type)
	tcState := dispatcher.State{
		Type:          dispatcher.DispatcherTypeTCIngress,
		Nsid:          4026531840,
		Ifindex:       1,
		Revision:      1,
		KernelID:      200,
		LinkID:        201,
		LinkPinPath:   "/sys/fs/bpf/bpfman/tc-ingress/dispatcher_4026531840_1_link",
		ProgPinPath:   "/sys/fs/bpf/bpfman/tc-ingress/dispatcher_4026531840_1_1/dispatcher",
		NumExtensions: 0,
	}

	require.NoError(t, store.SaveDispatcher(ctx, tcState), "SaveDispatcher (tc-ingress) failed")

	// Verify both exist
	_, err = store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "GetDispatcher (xdp) failed")

	_, err = store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeTCIngress), 4026531840, 1)
	require.NoError(t, err, "GetDispatcher (tc-ingress) failed")
}

func TestDispatcherStore_DifferentInterfaces(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create dispatchers for ifindex 1 and 2
	for ifindex := uint32(1); ifindex <= 2; ifindex++ {
		state := dispatcher.State{
			Type:          dispatcher.DispatcherTypeXDP,
			Nsid:          4026531840,
			Ifindex:       ifindex,
			Revision:      1,
			KernelID:      100 + ifindex,
			LinkID:        200 + ifindex,
			LinkPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_" + string(rune('0'+ifindex)) + "_link",
			ProgPinPath:   "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_" + string(rune('0'+ifindex)) + "_1/dispatcher",
			NumExtensions: 0,
		}
		require.NoError(t, store.SaveDispatcher(ctx, state), "SaveDispatcher (ifindex %d) failed", ifindex)
	}

	// Verify both exist independently
	got1, err := store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 1)
	require.NoError(t, err, "GetDispatcher (ifindex 1) failed")
	assert.Equal(t, uint32(101), got1.KernelID)

	got2, err := store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), 4026531840, 2)
	require.NoError(t, err, "GetDispatcher (ifindex 2) failed")
	assert.Equal(t, uint32(102), got2.KernelID)
}

// ----------------------------------------------------------------------------
// Map Ownership Tests
// ----------------------------------------------------------------------------

func TestMapOwnership_CountDependentPrograms(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create the owner program (first program from an image).
	ownerID := uint32(100)
	ownerProg := testProgram()
	ownerProg.ProgramName = "kprobe_counter"
	ownerProg.MapPinPath = "/sys/fs/bpf/bpfman/100"
	require.NoError(t, store.Save(ctx, ownerID, ownerProg), "Save owner failed")

	// Initially no dependents.
	count, err := store.CountDependentPrograms(ctx, ownerID)
	require.NoError(t, err, "CountDependentPrograms failed")
	assert.Equal(t, 0, count, "expected 0 dependents initially")

	// Create dependent programs that share the owner's maps.
	for i := uint32(1); i <= 3; i++ {
		depProg := testProgram()
		depProg.ProgramName = "dependent_" + string(rune('0'+i))
		depProg.MapOwnerID = ownerID
		depProg.MapPinPath = "/sys/fs/bpf/bpfman/100" // Same as owner
		require.NoError(t, store.Save(ctx, 100+i, depProg), "Save dependent %d failed", i)
	}

	// Now we should have 3 dependents.
	count, err = store.CountDependentPrograms(ctx, ownerID)
	require.NoError(t, err, "CountDependentPrograms failed")
	assert.Equal(t, 3, count, "expected 3 dependents")

	// Delete one dependent.
	require.NoError(t, store.Delete(ctx, 101), "Delete dependent failed")

	// Now we should have 2 dependents.
	count, err = store.CountDependentPrograms(ctx, ownerID)
	require.NoError(t, err, "CountDependentPrograms failed")
	assert.Equal(t, 2, count, "expected 2 dependents after delete")
}

func TestMapOwnership_ForeignKeyPreventsDeletingOwner(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create the owner program.
	ownerID := uint32(100)
	ownerProg := testProgram()
	ownerProg.ProgramName = "owner"
	ownerProg.MapPinPath = "/sys/fs/bpf/bpfman/100"
	require.NoError(t, store.Save(ctx, ownerID, ownerProg), "Save owner failed")

	// Create a dependent program.
	depProg := testProgram()
	depProg.ProgramName = "dependent"
	depProg.MapOwnerID = ownerID
	depProg.MapPinPath = "/sys/fs/bpf/bpfman/100"
	require.NoError(t, store.Save(ctx, 101, depProg), "Save dependent failed")

	// Attempt to delete the owner while dependent exists - should fail due to FK.
	err = store.Delete(ctx, ownerID)
	require.Error(t, err, "expected FK constraint violation when deleting owner")
	assert.Contains(t, err.Error(), "FOREIGN KEY constraint failed",
		"expected FK constraint error, got: %v", err)

	// Delete the dependent first.
	require.NoError(t, store.Delete(ctx, 101), "Delete dependent failed")

	// Now we can delete the owner.
	require.NoError(t, store.Delete(ctx, ownerID), "Delete owner failed after dependents removed")
}

func TestMapOwnership_MapPinPathPersisted(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program with MapPinPath set.
	kernelID := uint32(42)
	prog := testProgram()
	prog.MapPinPath = "/sys/fs/bpf/bpfman/42"

	require.NoError(t, store.Save(ctx, kernelID, prog), "Save failed")

	// Retrieve and verify MapPinPath is persisted.
	got, err := store.Get(ctx, kernelID)
	require.NoError(t, err, "Get failed")
	assert.Equal(t, "/sys/fs/bpf/bpfman/42", got.MapPinPath, "MapPinPath mismatch")
}

func TestMapOwnership_MapOwnerIDPersisted(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create the owner program first.
	ownerID := uint32(100)
	ownerProg := testProgram()
	ownerProg.ProgramName = "owner"
	require.NoError(t, store.Save(ctx, ownerID, ownerProg), "Save owner failed")

	// Create a dependent program with MapOwnerID set.
	depID := uint32(101)
	depProg := testProgram()
	depProg.ProgramName = "dependent"
	depProg.MapOwnerID = ownerID
	depProg.MapPinPath = "/sys/fs/bpf/bpfman/100"

	require.NoError(t, store.Save(ctx, depID, depProg), "Save dependent failed")

	// Retrieve and verify MapOwnerID is persisted.
	got, err := store.Get(ctx, depID)
	require.NoError(t, err, "Get failed")
	assert.Equal(t, ownerID, got.MapOwnerID, "MapOwnerID mismatch")
}

func TestMapOwnership_ListIncludesMapFields(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create owner.
	ownerID := uint32(100)
	ownerProg := testProgram()
	ownerProg.ProgramName = "owner"
	ownerProg.MapPinPath = "/sys/fs/bpf/bpfman/100"
	require.NoError(t, store.Save(ctx, ownerID, ownerProg), "Save owner failed")

	// Create dependent.
	depID := uint32(101)
	depProg := testProgram()
	depProg.ProgramName = "dependent"
	depProg.MapOwnerID = ownerID
	depProg.MapPinPath = "/sys/fs/bpf/bpfman/100"
	require.NoError(t, store.Save(ctx, depID, depProg), "Save dependent failed")

	// List all programs.
	programs, err := store.List(ctx)
	require.NoError(t, err, "List failed")
	require.Len(t, programs, 2, "expected 2 programs")

	// Verify owner has MapPinPath but no MapOwnerID.
	owner := programs[ownerID]
	assert.Equal(t, "/sys/fs/bpf/bpfman/100", owner.MapPinPath, "owner MapPinPath mismatch")
	assert.Equal(t, uint32(0), owner.MapOwnerID, "owner should have no MapOwnerID")

	// Verify dependent has both fields.
	dep := programs[depID]
	assert.Equal(t, "/sys/fs/bpf/bpfman/100", dep.MapPinPath, "dependent MapPinPath mismatch")
	assert.Equal(t, ownerID, dep.MapOwnerID, "dependent MapOwnerID mismatch")
}

// TestListTCXLinksByInterface_OrderByPriority verifies that TCX links are
// returned in priority order (ascending), which is critical for correctly
// computing attach order when inserting new TCX programs.
func TestListTCXLinksByInterface_OrderByPriority(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program for the links to reference.
	progID := uint32(100)
	prog := testProgram()
	prog.ProgramType = bpfman.ProgramTypeTCX
	require.NoError(t, store.Save(ctx, progID, prog), "Save program failed")

	// Create TCX links with varying priorities (insert out of order).
	const (
		nsid      = uint64(4026531840)
		ifindex   = uint32(2)
		direction = "ingress"
	)

	// Insert links with priorities: 300, 100, 500, 200 (intentionally unordered)
	linksToCreate := []struct {
		linkID   uint32
		priority int32
	}{
		{linkID: 1001, priority: 300},
		{linkID: 1002, priority: 100},
		{linkID: 1003, priority: 500},
		{linkID: 1004, priority: 200},
	}

	for _, link := range linksToCreate {
		summary := bpfman.LinkSummary{
			KernelLinkID:    link.linkID,
			LinkType:        bpfman.LinkTypeTCX,
			KernelProgramID: progID,
			PinPath:         "/sys/fs/bpf/link_" + string(rune(link.linkID)),
			CreatedAt:       time.Now(),
		}
		details := bpfman.TCXDetails{
			Interface: "eth0",
			Ifindex:   ifindex,
			Direction: direction,
			Priority:  link.priority,
			Nsid:      nsid,
		}
		require.NoError(t, store.SaveTCXLink(ctx, summary, details),
			"SaveTCXLink failed for link %d", link.linkID)
	}

	// Query links - they should be ordered by priority ASC.
	links, err := store.ListTCXLinksByInterface(ctx, nsid, ifindex, direction)
	require.NoError(t, err, "ListTCXLinksByInterface failed")
	require.Len(t, links, 4, "expected 4 links")

	// Verify order: priorities should be 100, 200, 300, 500
	expectedPriorities := []int32{100, 200, 300, 500}
	for i, link := range links {
		assert.Equal(t, expectedPriorities[i], link.Priority,
			"link at position %d has wrong priority", i)
	}

	// Verify the correct link IDs are in order
	expectedLinkIDs := []uint32{1002, 1004, 1001, 1003}
	for i, link := range links {
		assert.Equal(t, expectedLinkIDs[i], link.KernelLinkID,
			"link at position %d has wrong kernel_link_id", i)
	}
}

// TestListTCXLinksByInterface_FiltersByInterfaceAndDirection verifies that
// only links matching the specified nsid, ifindex, and direction are returned.
func TestListTCXLinksByInterface_FiltersByInterfaceAndDirection(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program for the links to reference.
	progID := uint32(100)
	prog := testProgram()
	prog.ProgramType = bpfman.ProgramTypeTCX
	require.NoError(t, store.Save(ctx, progID, prog), "Save program failed")

	const nsid = uint64(4026531840)

	// Create links on different interfaces and directions.
	testLinks := []struct {
		linkID    uint32
		ifindex   uint32
		direction string
		priority  int32
	}{
		{linkID: 1001, ifindex: 2, direction: "ingress", priority: 100},
		{linkID: 1002, ifindex: 2, direction: "ingress", priority: 200},
		{linkID: 1003, ifindex: 2, direction: "egress", priority: 100},  // different direction
		{linkID: 1004, ifindex: 3, direction: "ingress", priority: 100}, // different interface
	}

	for _, link := range testLinks {
		summary := bpfman.LinkSummary{
			KernelLinkID:    link.linkID,
			LinkType:        bpfman.LinkTypeTCX,
			KernelProgramID: progID,
			CreatedAt:       time.Now(),
		}
		details := bpfman.TCXDetails{
			Interface: "eth0",
			Ifindex:   link.ifindex,
			Direction: link.direction,
			Priority:  link.priority,
			Nsid:      nsid,
		}
		require.NoError(t, store.SaveTCXLink(ctx, summary, details),
			"SaveTCXLink failed for link %d", link.linkID)
	}

	// Query for ifindex=2, ingress - should return only 2 links.
	links, err := store.ListTCXLinksByInterface(ctx, nsid, 2, "ingress")
	require.NoError(t, err)
	require.Len(t, links, 2, "expected 2 links for ifindex=2, ingress")
	assert.Equal(t, uint32(1001), links[0].KernelLinkID)
	assert.Equal(t, uint32(1002), links[1].KernelLinkID)

	// Query for ifindex=2, egress - should return only 1 link.
	links, err = store.ListTCXLinksByInterface(ctx, nsid, 2, "egress")
	require.NoError(t, err)
	require.Len(t, links, 1, "expected 1 link for ifindex=2, egress")
	assert.Equal(t, uint32(1003), links[0].KernelLinkID)

	// Query for ifindex=3, ingress - should return only 1 link.
	links, err = store.ListTCXLinksByInterface(ctx, nsid, 3, "ingress")
	require.NoError(t, err)
	require.Len(t, links, 1, "expected 1 link for ifindex=3, ingress")
	assert.Equal(t, uint32(1004), links[0].KernelLinkID)

	// Query for non-existent interface - should return empty.
	links, err = store.ListTCXLinksByInterface(ctx, nsid, 99, "ingress")
	require.NoError(t, err)
	require.Len(t, links, 0, "expected 0 links for non-existent interface")
}

// TestListTCXLinksByInterface_EmptyResult verifies that querying for
// an interface with no TCX links returns an empty slice, not nil.
func TestListTCXLinksByInterface_EmptyResult(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	links, err := store.ListTCXLinksByInterface(ctx, 4026531840, 2, "ingress")
	require.NoError(t, err, "ListTCXLinksByInterface should not error for empty result")
	assert.NotNil(t, links, "result should not be nil")
	assert.Empty(t, links, "result should be empty")
}

// -----------------------------------------------------------------------------
// GC Tests
// -----------------------------------------------------------------------------

func TestGC_EmptyStore(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// GC with empty kernel state on empty store
	result, err := store.GC(ctx, map[uint32]bool{}, map[uint32]bool{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ProgramsRemoved)
	assert.Equal(t, 0, result.DispatchersRemoved)
	assert.Equal(t, 0, result.LinksRemoved)
}

func TestGC_AllProgramsInKernel(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Save a program
	prog := testProgram()
	err = store.Save(ctx, 100, prog)
	require.NoError(t, err)

	// GC with program ID in kernel - nothing should be removed
	result, err := store.GC(ctx, map[uint32]bool{100: true}, map[uint32]bool{})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ProgramsRemoved)

	// Verify program still exists
	_, err = store.Get(ctx, 100)
	require.NoError(t, err, "program should still exist")
}

func TestGC_StalePrograms(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Save multiple programs
	prog := testProgram()
	err = store.Save(ctx, 100, prog)
	require.NoError(t, err)
	err = store.Save(ctx, 101, prog)
	require.NoError(t, err)
	err = store.Save(ctx, 102, prog)
	require.NoError(t, err)

	// GC with only program 100 in kernel - 101 and 102 should be removed
	result, err := store.GC(ctx, map[uint32]bool{100: true}, map[uint32]bool{})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ProgramsRemoved)

	// Verify 100 still exists, 101 and 102 are gone
	_, err = store.Get(ctx, 100)
	require.NoError(t, err, "program 100 should still exist")
	_, err = store.Get(ctx, 101)
	require.Error(t, err, "program 101 should be deleted")
	_, err = store.Get(ctx, 102)
	require.Error(t, err, "program 102 should be deleted")
}

func TestGC_MapOwnerOrdering(t *testing.T) {
	// Test that GC correctly handles map_owner_id FK constraint.
	// Programs with MapOwnerID (dependents) must be deleted before
	// the programs they reference (owners).
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create owner first (must exist for FK)
	owner := testProgram()
	owner.ProgramName = "owner"
	err = store.Save(ctx, 100, owner)
	require.NoError(t, err)

	// Create dependents that reference the owner
	dep1 := testProgram()
	dep1.ProgramName = "dep1"
	dep1.MapOwnerID = 100
	err = store.Save(ctx, 101, dep1)
	require.NoError(t, err)

	dep2 := testProgram()
	dep2.ProgramName = "dep2"
	dep2.MapOwnerID = 100
	err = store.Save(ctx, 102, dep2)
	require.NoError(t, err)

	// GC with empty kernel state - all should be removed
	// If ordering is wrong, FK constraint will fail
	result, err := store.GC(ctx, map[uint32]bool{}, map[uint32]bool{})
	require.NoError(t, err, "GC should handle FK ordering correctly")
	assert.Equal(t, 3, result.ProgramsRemoved)

	// Verify all are gone
	_, err = store.Get(ctx, 100)
	require.Error(t, err)
	_, err = store.Get(ctx, 101)
	require.Error(t, err)
	_, err = store.Get(ctx, 102)
	require.Error(t, err)
}

func TestGC_StaleDispatchers(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create dispatchers referencing different program IDs
	disp1 := dispatcher.State{
		Type:        dispatcher.DispatcherTypeXDP,
		Nsid:        4026531840,
		Ifindex:     2,
		Revision:    1,
		KernelID:    100,
		LinkID:      200,
		LinkPinPath: "/sys/fs/bpf/link",
		ProgPinPath: "/sys/fs/bpf/prog",
	}
	err = store.SaveDispatcher(ctx, disp1)
	require.NoError(t, err)

	disp2 := dispatcher.State{
		Type:        dispatcher.DispatcherTypeTCIngress,
		Nsid:        4026531840,
		Ifindex:     3,
		Revision:    1,
		KernelID:    101,
		LinkID:      201,
		LinkPinPath: "/sys/fs/bpf/link2",
		ProgPinPath: "/sys/fs/bpf/prog2",
	}
	err = store.SaveDispatcher(ctx, disp2)
	require.NoError(t, err)

	// GC with only program 100 in kernel - dispatcher for 101 should be removed
	result, err := store.GC(ctx, map[uint32]bool{100: true}, map[uint32]bool{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.DispatchersRemoved)

	// Verify disp1 still exists, disp2 is gone
	_, err = store.GetDispatcher(ctx, "xdp", 4026531840, 2)
	require.NoError(t, err, "dispatcher for program 100 should exist")
	_, err = store.GetDispatcher(ctx, "tc-ingress", 4026531840, 3)
	require.Error(t, err, "dispatcher for program 101 should be deleted")
}

func TestGC_StaleLinks(t *testing.T) {
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create a program first (FK requirement)
	prog := testProgram()
	err = store.Save(ctx, 100, prog)
	require.NoError(t, err)

	// Create links
	summary1 := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 100,
		KernelLinkID:    200,
		CreatedAt:       time.Now(),
	}
	details1 := bpfman.TracepointDetails{Group: "syscalls", Name: "sys_enter_openat"}
	err = store.SaveTracepointLink(ctx, summary1, details1)
	require.NoError(t, err)

	summary2 := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 100,
		KernelLinkID:    201,
		CreatedAt:       time.Now(),
	}
	details2 := bpfman.TracepointDetails{Group: "syscalls", Name: "sys_exit_openat"}
	err = store.SaveTracepointLink(ctx, summary2, details2)
	require.NoError(t, err)

	// GC with program in kernel but only link 200 in kernel
	result, err := store.GC(ctx, map[uint32]bool{100: true}, map[uint32]bool{200: true})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ProgramsRemoved)
	assert.Equal(t, 1, result.LinksRemoved)

	// Verify link 200 exists, link 201 is gone
	links, err := store.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, uint32(200), links[0].KernelLinkID)
}

func TestGC_Comprehensive(t *testing.T) {
	// Test GC with mixed stale entries across all types
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create programs: 100 (alive), 101 (stale owner), 102 (stale dependent)
	prog := testProgram()
	err = store.Save(ctx, 100, prog)
	require.NoError(t, err)

	ownerProg := testProgram()
	ownerProg.ProgramName = "stale_owner"
	err = store.Save(ctx, 101, ownerProg)
	require.NoError(t, err)

	depProg := testProgram()
	depProg.ProgramName = "stale_dep"
	depProg.MapOwnerID = 101
	err = store.Save(ctx, 102, depProg)
	require.NoError(t, err)

	// Create dispatchers: one for alive program, one for stale
	aliveDisp := dispatcher.State{
		Type:        dispatcher.DispatcherTypeXDP,
		Nsid:        4026531840,
		Ifindex:     2,
		Revision:    1,
		KernelID:    100,
		LinkID:      300,
		LinkPinPath: "/sys/fs/bpf/link",
		ProgPinPath: "/sys/fs/bpf/prog",
	}
	err = store.SaveDispatcher(ctx, aliveDisp)
	require.NoError(t, err)

	staleDisp := dispatcher.State{
		Type:        dispatcher.DispatcherTypeTCIngress,
		Nsid:        4026531840,
		Ifindex:     3,
		Revision:    1,
		KernelID:    101,
		LinkID:      301,
		LinkPinPath: "/sys/fs/bpf/link2",
		ProgPinPath: "/sys/fs/bpf/prog2",
	}
	err = store.SaveDispatcher(ctx, staleDisp)
	require.NoError(t, err)

	// Create links: one alive, one stale
	aliveLink := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 100,
		KernelLinkID:    400,
		CreatedAt:       time.Now(),
	}
	err = store.SaveTracepointLink(ctx, aliveLink, bpfman.TracepointDetails{Group: "syscalls", Name: "test"})
	require.NoError(t, err)

	staleLink := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeTracepoint,
		KernelProgramID: 100,
		KernelLinkID:    401,
		CreatedAt:       time.Now(),
	}
	err = store.SaveTracepointLink(ctx, staleLink, bpfman.TracepointDetails{Group: "syscalls", Name: "test2"})
	require.NoError(t, err)

	// GC with only program 100 and link 400 in kernel
	result, err := store.GC(ctx,
		map[uint32]bool{100: true},
		map[uint32]bool{400: true})
	require.NoError(t, err)

	// Should remove: 2 programs (101, 102), 1 dispatcher, 1 link
	assert.Equal(t, 2, result.ProgramsRemoved, "should remove 2 stale programs")
	assert.Equal(t, 1, result.DispatchersRemoved, "should remove 1 stale dispatcher")
	assert.Equal(t, 1, result.LinksRemoved, "should remove 1 stale link")

	// Verify remaining state
	programs, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, programs, 1, "should have 1 program remaining")
	_, exists := programs[100]
	assert.True(t, exists, "program 100 should exist")

	dispatchers, err := store.ListDispatchers(ctx)
	require.NoError(t, err)
	assert.Len(t, dispatchers, 1, "should have 1 dispatcher remaining")
	assert.Equal(t, uint32(100), dispatchers[0].KernelID)

	links, err := store.ListLinks(ctx)
	require.NoError(t, err)
	assert.Len(t, links, 1, "should have 1 link remaining")
	assert.Equal(t, uint32(400), links[0].KernelLinkID)
}

func TestGC_SyntheticLinkIDsSkipped(t *testing.T) {
	// Test that GC skips links with synthetic IDs (>= 0x80000000).
	// These are used for perf_event-based links (e.g., container uprobes)
	// that cannot be enumerated via the kernel's link iterator.
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create a program first (FK requirement)
	prog := testProgram()
	err = store.Save(ctx, 100, prog)
	require.NoError(t, err)

	// Create a real kernel link (ID 200)
	realLink := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeUprobe,
		KernelProgramID: 100,
		KernelLinkID:    200,
		CreatedAt:       time.Now(),
	}
	realDetails := bpfman.UprobeDetails{Target: "/usr/bin/test", FnName: "main"}
	err = store.SaveUprobeLink(ctx, realLink, realDetails)
	require.NoError(t, err)

	// Create a synthetic link (ID >= 0x80000000)
	// This simulates a container uprobe with perf_event-based link
	syntheticID := uint32(bpfman.SyntheticLinkIDBase | 0x12345678)
	syntheticLink := bpfman.LinkSummary{
		LinkType:        bpfman.LinkTypeUprobe,
		KernelProgramID: 100,
		KernelLinkID:    syntheticID,
		CreatedAt:       time.Now(),
	}
	syntheticDetails := bpfman.UprobeDetails{Target: "/app/binary", FnName: "handler", ContainerPid: 12345}
	err = store.SaveUprobeLink(ctx, syntheticLink, syntheticDetails)
	require.NoError(t, err)

	// Verify both links exist
	links, err := store.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, links, 2)

	// GC with program in kernel but only real link 200 in kernel
	// (synthetic link cannot be in kernelLinkIDs since it's not a real kernel ID)
	result, err := store.GC(ctx, map[uint32]bool{100: true}, map[uint32]bool{200: true})
	require.NoError(t, err)

	// Should NOT remove synthetic link even though it's not in kernelLinkIDs
	assert.Equal(t, 0, result.ProgramsRemoved, "should not remove any programs")
	assert.Equal(t, 0, result.LinksRemoved, "should not remove any links (synthetic should be skipped)")

	// Verify both links still exist
	links, err = store.ListLinks(ctx)
	require.NoError(t, err)
	assert.Len(t, links, 2, "both links should remain")

	// Find both links by ID
	var foundReal, foundSynthetic bool
	for _, link := range links {
		if link.KernelLinkID == 200 {
			foundReal = true
		}
		if link.KernelLinkID == syntheticID {
			foundSynthetic = true
		}
	}
	assert.True(t, foundReal, "real link should exist")
	assert.True(t, foundSynthetic, "synthetic link should exist")
}
