package sqlite

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

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// testLogger returns a logger for tests. By default it discards all output.
// Set BPFMAN_TEST_VERBOSE=1 to enable logging.
func testLogger() *slog.Logger {
	if os.Getenv("BPFMAN_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestForeignKey_LinkRequiresProgram(t *testing.T) {
	store, err := NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Attempt to create a link referencing a non-existent program.
	link := managed.Link{
		UUID:        "orphan-link",
		ProgramID:   999, // does not exist
		ProgramUUID: "fake-uuid",
		Type:        managed.LinkTypeXDP,
		AttachSpec:  managed.AttachSpec{Type: managed.LinkTypeXDP},
		CreatedAt:   time.Now(),
	}

	err = store.SaveLink(ctx, link)
	require.Error(t, err, "expected FK constraint violation")
	assert.True(t, strings.Contains(err.Error(), "FOREIGN KEY constraint failed"), "expected FK constraint error, got: %v", err)
}

func TestForeignKey_CascadeDeleteRemovesLinks(t *testing.T) {
	store, err := NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program via reservation flow.
	uuid := "test-program"
	prog := managed.Program{
		UUID:      uuid,
		CreatedAt: time.Now(),
	}

	require.NoError(t, store.Reserve(ctx, uuid, prog), "Reserve failed")

	kernelID := uint32(42)
	require.NoError(t, store.CommitReservation(ctx, uuid, kernelID), "CommitReservation failed")

	// Create two links for that program.
	for i, linkUUID := range []string{"link-1", "link-2"} {
		link := managed.Link{
			UUID:        linkUUID,
			ProgramID:   kernelID,
			ProgramUUID: uuid,
			Type:        managed.LinkTypeKprobe,
			AttachSpec: managed.AttachSpec{
				Type:   managed.LinkTypeKprobe,
				FnName: "test_fn",
			},
			ID:        uint32(100 + i),
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveLink(ctx, link), "SaveLink(%s) failed", linkUUID)
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
	store, err := NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program with metadata.
	uuid := "test-program"
	prog := managed.Program{
		UUID:      uuid,
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"app":     "test",
			"version": "1.0",
		},
	}

	require.NoError(t, store.Reserve(ctx, uuid, prog), "Reserve failed")

	kernelID := uint32(42)
	require.NoError(t, store.CommitReservation(ctx, uuid, kernelID), "CommitReservation failed")

	// Verify we can find by metadata.
	found, foundID, err := store.FindProgramByMetadata(ctx, "app", "test")
	require.NoError(t, err, "FindProgramByMetadata failed")
	assert.Equal(t, kernelID, foundID, "kernel_id mismatch")
	assert.Equal(t, uuid, found.UUID, "UUID mismatch")

	// Delete the program.
	require.NoError(t, store.Delete(ctx, kernelID), "Delete failed")

	// Verify CASCADE removed the metadata index entries.
	_, _, err = store.FindProgramByMetadata(ctx, "app", "test")
	assert.Error(t, err, "expected error after CASCADE delete")
}

func TestUniqueIndex_ProgramNameEnforcesUniqueness(t *testing.T) {
	store, err := NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create first program with a name.
	prog1 := managed.Program{
		UUID:      "prog-1",
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "my-program",
		},
	}

	require.NoError(t, store.Reserve(ctx, prog1.UUID, prog1), "Reserve prog1 failed")
	require.NoError(t, store.CommitReservation(ctx, prog1.UUID, 100), "CommitReservation prog1 failed")

	// Attempt to create second program with the same name.
	prog2 := managed.Program{
		UUID:      "prog-2",
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "my-program", // duplicate
		},
	}

	require.NoError(t, store.Reserve(ctx, prog2.UUID, prog2), "Reserve prog2 failed")

	err = store.CommitReservation(ctx, prog2.UUID, 200)
	require.Error(t, err, "expected unique constraint violation")
	assert.True(t, strings.Contains(err.Error(), "UNIQUE constraint failed"), "expected UNIQUE constraint error, got: %v", err)
}

func TestUniqueIndex_DifferentNamesAllowed(t *testing.T) {
	store, err := NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create two programs with different names.
	for i, name := range []string{"program-a", "program-b"} {
		prog := managed.Program{
			UUID:      name,
			CreatedAt: time.Now(),
			UserMetadata: map[string]string{
				"bpfman.io/ProgramName": name,
			},
		}

		require.NoError(t, store.Reserve(ctx, prog.UUID, prog), "Reserve %s failed", name)
		require.NoError(t, store.CommitReservation(ctx, prog.UUID, uint32(100+i)), "CommitReservation %s failed", name)
	}

	// Verify both exist.
	programs, err := store.List(ctx)
	require.NoError(t, err, "List failed")
	assert.Len(t, programs, 2, "expected 2 programs")
}

func TestUniqueIndex_NameCanBeReusedAfterDelete(t *testing.T) {
	store, err := NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	defer store.Close()

	ctx := context.Background()

	// Create a program with a name.
	prog := managed.Program{
		UUID:      "prog-1",
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name",
		},
	}

	require.NoError(t, store.Reserve(ctx, prog.UUID, prog), "Reserve failed")
	require.NoError(t, store.CommitReservation(ctx, prog.UUID, 100), "CommitReservation failed")

	// Delete it.
	require.NoError(t, store.Delete(ctx, 100), "Delete failed")

	// Create a new program with the same name.
	prog2 := managed.Program{
		UUID:      "prog-2",
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name", // same name, should work
		},
	}

	require.NoError(t, store.Reserve(ctx, prog2.UUID, prog2), "Reserve prog2 failed")
	require.NoError(t, store.CommitReservation(ctx, prog2.UUID, 200), "CommitReservation prog2 failed")

	// Verify it exists.
	found, kernelID, err := store.FindProgramByMetadata(ctx, "bpfman.io/ProgramName", "reusable-name")
	require.NoError(t, err, "FindProgramByMetadata failed")
	assert.Equal(t, uint32(200), kernelID, "kernel_id mismatch")
	assert.Equal(t, "prog-2", found.UUID, "UUID mismatch")
}
