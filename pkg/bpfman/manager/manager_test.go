package manager

import (
	"context"
	"iter"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// fakeKernel implements interpreter.KernelOperations for testing.
// It simulates kernel BPF operations without actually touching the kernel.
type fakeKernel struct {
	nextID   atomic.Uint32
	programs map[uint32]managed.Loaded // tracks "loaded" programs
	links    map[uint32]*bpfman.AttachedLink
}

func newFakeKernel() *fakeKernel {
	fk := &fakeKernel{
		programs: make(map[uint32]managed.Loaded),
		links:    make(map[uint32]*bpfman.AttachedLink),
	}
	fk.nextID.Store(100) // start at 100 to make IDs obvious in tests
	return fk
}

func (f *fakeKernel) Load(_ context.Context, spec managed.LoadSpec) (managed.Loaded, error) {
	id := f.nextID.Add(1)
	loaded := managed.Loaded{
		ID:          id,
		Name:        spec.ProgramName,
		ProgramType: spec.ProgramType,
		PinPath:     spec.PinPath + "/" + spec.ProgramName,
		PinDir:      spec.PinPath,
	}
	f.programs[id] = loaded
	return loaded, nil
}

func (f *fakeKernel) Unload(_ context.Context, pinPath string) error {
	// Find and remove the program with this pin path
	for id, p := range f.programs {
		if p.PinDir == pinPath {
			delete(f.programs, id)
			return nil
		}
	}
	return nil
}

func (f *fakeKernel) Programs(_ context.Context) iter.Seq2[kernel.Program, error] {
	return func(yield func(kernel.Program, error) bool) {
		for id, p := range f.programs {
			kp := kernel.Program{
				ID:          id,
				Name:        p.Name,
				ProgramType: p.ProgramType.String(),
			}
			if !yield(kp, nil) {
				return
			}
		}
	}
}

func (f *fakeKernel) Maps(_ context.Context) iter.Seq2[kernel.Map, error] {
	return func(yield func(kernel.Map, error) bool) {}
}

func (f *fakeKernel) Links(_ context.Context) iter.Seq2[kernel.Link, error] {
	return func(yield func(kernel.Link, error) bool) {}
}

func (f *fakeKernel) ListPinDir(pinDir string, includeMaps bool) (*kernel.PinDirContents, error) {
	return &kernel.PinDirContents{}, nil
}

func (f *fakeKernel) GetPinned(pinPath string) (*kernel.PinnedProgram, error) {
	return nil, nil
}

func (f *fakeKernel) AttachTracepoint(progPinPath, group, name, linkPinPath string) (*bpfman.AttachedLink, error) {
	id := f.nextID.Add(1)
	link := &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachTracepoint,
	}
	f.links[id] = link
	return link, nil
}

func TestLoad_Success(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	spec := managed.LoadSpec{
		ObjectPath:  "/path/to/prog.o",
		ProgramName: "my_prog",
		ProgramType: bpfman.ProgramTypeTracepoint,
		PinPath:     "/sys/fs/bpf/test",
	}

	opts := LoadOpts{
		UUID: "test-uuid-1",
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "my-program",
		},
	}

	loaded, err := mgr.Load(ctx, spec, opts)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Name != "my_prog" {
		t.Errorf("expected name 'my_prog', got %q", loaded.Name)
	}
	if loaded.UUID != "test-uuid-1" {
		t.Errorf("expected UUID 'test-uuid-1', got %q", loaded.UUID)
	}

	// Verify program is in store
	stored, err := mgr.Get(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if stored.UUID != "test-uuid-1" {
		t.Errorf("stored UUID mismatch: got %q", stored.UUID)
	}
}

func TestLoad_DuplicateName_Rejected(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	spec := managed.LoadSpec{
		ObjectPath:  "/path/to/prog.o",
		ProgramName: "my_prog",
		ProgramType: bpfman.ProgramTypeTracepoint,
		PinPath:     "/sys/fs/bpf/test1",
	}

	// Load first program with a name
	opts1 := LoadOpts{
		UUID: "uuid-1",
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name",
		},
	}

	_, err = mgr.Load(ctx, spec, opts1)
	if err != nil {
		t.Fatalf("first Load failed: %v", err)
	}

	// Attempt to load second program with same name
	spec.PinPath = "/sys/fs/bpf/test2" // different pin path
	opts2 := LoadOpts{
		UUID: "uuid-2",
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name", // same name - should fail
		},
	}

	_, err = mgr.Load(ctx, spec, opts2)
	if err == nil {
		t.Fatal("expected duplicate name to be rejected, got nil error")
	}

	if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Errorf("expected UNIQUE constraint error, got: %v", err)
	}
}

func TestLoad_DifferentNames_Allowed(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	// Load two programs with different names
	for i, name := range []string{"program-a", "program-b"} {
		spec := managed.LoadSpec{
			ObjectPath:  "/path/to/prog.o",
			ProgramName: "prog",
			ProgramType: bpfman.ProgramTypeTracepoint,
			PinPath:     "/sys/fs/bpf/test" + name,
		}
		opts := LoadOpts{
			UUID: name,
			UserMetadata: map[string]string{
				"bpfman.io/ProgramName": name,
			},
		}

		_, err := mgr.Load(ctx, spec, opts)
		if err != nil {
			t.Fatalf("Load %d (%s) failed: %v", i, name, err)
		}
	}

	// Verify both exist
	programs, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	managed := FilterManaged(programs)
	if len(managed) != 2 {
		t.Errorf("expected 2 managed programs, got %d", len(managed))
	}
}

func TestUnload_Success(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	// Load a program
	spec := managed.LoadSpec{
		ObjectPath:  "/path/to/prog.o",
		ProgramName: "my_prog",
		ProgramType: bpfman.ProgramTypeTracepoint,
		PinPath:     "/sys/fs/bpf/test",
	}
	opts := LoadOpts{
		UUID: "test-uuid",
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "my-program",
		},
	}

	loaded, err := mgr.Load(ctx, spec, opts)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify it's in the store
	_, err = mgr.Get(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("Get after load failed: %v", err)
	}

	// Unload it
	err = mgr.Unload(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("Unload failed: %v", err)
	}

	// Verify it's gone from store
	_, err = mgr.Get(ctx, loaded.ID)
	if err == nil {
		t.Error("expected Get after unload to fail, got nil")
	}
}

func TestUnload_CascadesLinks(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	// Load a program
	spec := managed.LoadSpec{
		ObjectPath:  "/path/to/prog.o",
		ProgramName: "my_prog",
		ProgramType: bpfman.ProgramTypeTracepoint,
		PinPath:     "/sys/fs/bpf/test",
	}
	opts := LoadOpts{
		UUID: "test-uuid",
	}

	loaded, err := mgr.Load(ctx, spec, opts)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Attach to a tracepoint
	_, err = mgr.AttachTracepoint(ctx, loaded.ID, loaded.PinPath, "syscalls", "sys_enter_read", "/sys/fs/bpf/test/link")
	if err != nil {
		t.Fatalf("AttachTracepoint failed: %v", err)
	}

	// Verify link exists
	links, err := mgr.ListLinksByProgram(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("ListLinksByProgram failed: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}

	// Unload the program
	err = mgr.Unload(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("Unload failed: %v", err)
	}

	// Verify link was cascade deleted
	links, err = mgr.ListLinksByProgram(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("ListLinksByProgram after unload failed: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected 0 links after cascade delete, got %d", len(links))
	}
}

func TestAttach_RequiresLoadedProgram(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	// Try to attach to a non-existent program
	_, err = mgr.AttachTracepoint(ctx, 999, "/fake/path", "syscalls", "sys_enter_read", "/fake/link")
	if err == nil {
		t.Fatal("expected error when attaching to non-existent program, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestLoad_NameReusableAfterUnload(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	fk := newFakeKernel()
	mgr := New(store, fk, nil)
	ctx := context.Background()

	spec := managed.LoadSpec{
		ObjectPath:  "/path/to/prog.o",
		ProgramName: "my_prog",
		ProgramType: bpfman.ProgramTypeTracepoint,
		PinPath:     "/sys/fs/bpf/test1",
	}

	// Load with a name
	opts := LoadOpts{
		UUID: "uuid-1",
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name",
		},
	}

	loaded, err := mgr.Load(ctx, spec, opts)
	if err != nil {
		t.Fatalf("first Load failed: %v", err)
	}

	// Unload it
	err = mgr.Unload(ctx, loaded.ID)
	if err != nil {
		t.Fatalf("Unload failed: %v", err)
	}

	// Load again with the same name (different UUID and pin path)
	spec.PinPath = "/sys/fs/bpf/test2"
	opts = LoadOpts{
		UUID: "uuid-2",
		UserMetadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name", // same name should work now
		},
	}

	loaded2, err := mgr.Load(ctx, spec, opts)
	if err != nil {
		t.Fatalf("second Load with reused name failed: %v", err)
	}

	if loaded2.UUID != "uuid-2" {
		t.Errorf("expected UUID 'uuid-2', got %q", loaded2.UUID)
	}
}
