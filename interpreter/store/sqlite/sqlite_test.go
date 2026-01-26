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
