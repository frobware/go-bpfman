package sqlite

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

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
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
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
	if err == nil {
		t.Fatal("expected FK constraint violation, got nil")
	}

	// SQLite FK violations contain "FOREIGN KEY constraint failed"
	if !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		t.Errorf("expected FK constraint error, got: %v", err)
	}
}

func TestForeignKey_CascadeDeleteRemovesLinks(t *testing.T) {
	store, err := NewInMemory(testLogger())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create a program via reservation flow.
	uuid := "test-program"
	prog := managed.Program{
		UUID:      uuid,
		CreatedAt: time.Now(),
	}

	if err := store.Reserve(ctx, uuid, prog); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}

	kernelID := uint32(42)
	if err := store.CommitReservation(ctx, uuid, kernelID); err != nil {
		t.Fatalf("CommitReservation failed: %v", err)
	}

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
		if err := store.SaveLink(ctx, link); err != nil {
			t.Fatalf("SaveLink(%s) failed: %v", linkUUID, err)
		}
	}

	// Verify links exist.
	links, err := store.ListLinksByProgram(ctx, kernelID)
	if err != nil {
		t.Fatalf("ListLinksByProgram failed: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}

	// Delete the program.
	if err := store.Delete(ctx, kernelID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify CASCADE removed the links.
	links, err = store.ListLinksByProgram(ctx, kernelID)
	if err != nil {
		t.Fatalf("ListLinksByProgram after delete failed: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected 0 links after CASCADE delete, got %d", len(links))
	}
}

func TestForeignKey_CascadeDeleteRemovesMetadataIndex(t *testing.T) {
	store, err := NewInMemory(testLogger())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
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

	if err := store.Reserve(ctx, uuid, prog); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}

	kernelID := uint32(42)
	if err := store.CommitReservation(ctx, uuid, kernelID); err != nil {
		t.Fatalf("CommitReservation failed: %v", err)
	}

	// Verify we can find by metadata.
	found, foundID, err := store.FindProgramByMetadata(ctx, "app", "test")
	if err != nil {
		t.Fatalf("FindProgramByMetadata failed: %v", err)
	}
	if foundID != kernelID {
		t.Errorf("expected kernel_id %d, got %d", kernelID, foundID)
	}
	if found.UUID != uuid {
		t.Errorf("expected UUID %s, got %s", uuid, found.UUID)
	}

	// Delete the program.
	if err := store.Delete(ctx, kernelID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify CASCADE removed the metadata index entries.
	_, _, err = store.FindProgramByMetadata(ctx, "app", "test")
	if err == nil {
		t.Error("expected error after CASCADE delete, got nil")
	}
}

func TestUniqueIndex_ProgramNameEnforcesUniqueness(t *testing.T) {
	store, err := NewInMemory(testLogger())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
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

	if err := store.Reserve(ctx, prog1.UUID, prog1); err != nil {
		t.Fatalf("Reserve prog1 failed: %v", err)
	}
	if err := store.CommitReservation(ctx, prog1.UUID, 100); err != nil {
		t.Fatalf("CommitReservation prog1 failed: %v", err)
	}

	// Attempt to create second program with the same name.
	prog2 := managed.Program{
		UUID:      "prog-2",
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "my-program", // duplicate
		},
	}

	if err := store.Reserve(ctx, prog2.UUID, prog2); err != nil {
		t.Fatalf("Reserve prog2 failed: %v", err)
	}

	err = store.CommitReservation(ctx, prog2.UUID, 200)
	if err == nil {
		t.Fatal("expected unique constraint violation, got nil")
	}

	// SQLite unique violations contain "UNIQUE constraint failed"
	if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Errorf("expected UNIQUE constraint error, got: %v", err)
	}
}

func TestUniqueIndex_DifferentNamesAllowed(t *testing.T) {
	store, err := NewInMemory(testLogger())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
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

		if err := store.Reserve(ctx, prog.UUID, prog); err != nil {
			t.Fatalf("Reserve %s failed: %v", name, err)
		}
		if err := store.CommitReservation(ctx, prog.UUID, uint32(100+i)); err != nil {
			t.Fatalf("CommitReservation %s failed: %v", name, err)
		}
	}

	// Verify both exist.
	programs, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(programs) != 2 {
		t.Errorf("expected 2 programs, got %d", len(programs))
	}
}

func TestUniqueIndex_NameCanBeReusedAfterDelete(t *testing.T) {
	store, err := NewInMemory(testLogger())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
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

	if err := store.Reserve(ctx, prog.UUID, prog); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}
	if err := store.CommitReservation(ctx, prog.UUID, 100); err != nil {
		t.Fatalf("CommitReservation failed: %v", err)
	}

	// Delete it.
	if err := store.Delete(ctx, 100); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Create a new program with the same name.
	prog2 := managed.Program{
		UUID:      "prog-2",
		CreatedAt: time.Now(),
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name", // same name, should work
		},
	}

	if err := store.Reserve(ctx, prog2.UUID, prog2); err != nil {
		t.Fatalf("Reserve prog2 failed: %v", err)
	}
	if err := store.CommitReservation(ctx, prog2.UUID, 200); err != nil {
		t.Fatalf("CommitReservation prog2 failed: %v", err)
	}

	// Verify it exists.
	found, kernelID, err := store.FindProgramByMetadata(ctx, "bpfman.io/ProgramName", "reusable-name")
	if err != nil {
		t.Fatalf("FindProgramByMetadata failed: %v", err)
	}
	if kernelID != 200 {
		t.Errorf("expected kernel_id 200, got %d", kernelID)
	}
	if found.UUID != "prog-2" {
		t.Errorf("expected UUID prog-2, got %s", found.UUID)
	}
}
