// Package server tests use Behaviour-Driven Development (BDD) style.
//
// Each test follows the Given/When/Then structure:
//   - Given: Initial state and context (the fixture)
//   - When: The action being tested
//   - Then: The expected outcome
//
// This makes tests readable as specifications of behaviour. When adding
// new tests, follow this pattern and use descriptive test names that
// explain the scenario being tested.
//
// The tests use a fake kernel implementation that simulates BPF operations
// without syscalls, combined with a real in-memory SQLite database. This
// enables fast, reliable testing of the full request path through gRPC.
package server

import (
	"context"
	"io"
	"iter"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
)

// testLogger returns a logger for tests. By default it discards all output.
// Set BPFMAN_TEST_VERBOSE=1 to enable logging.
func testLogger() *slog.Logger {
	if os.Getenv("BPFMAN_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeKernel implements interpreter.KernelOperations for testing.
// It simulates kernel BPF operations without actual syscalls.
type fakeKernel struct {
	nextID   atomic.Uint32
	programs map[uint32]managed.Loaded
	links    map[uint32]*bpfman.AttachedLink
}

func newFakeKernel() *fakeKernel {
	fk := &fakeKernel{
		programs: make(map[uint32]managed.Loaded),
		links:    make(map[uint32]*bpfman.AttachedLink),
	}
	fk.nextID.Store(100)
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

// newTestServer creates a server with fake kernel and real in-memory SQLite.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := sqlite.NewInMemory(testLogger())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return NewForTest(store, newFakeKernel(), testLogger())
}

// TestLoadProgram_WithValidRequest_Succeeds verifies that:
//
//	Given an empty server with no programs loaded,
//	When I load a program with valid bytecode and metadata,
//	Then the load succeeds and the program is retrievable via Get.
func TestLoadProgram_WithValidRequest_Succeeds(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("test-uuid-1"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "my-program",
		},
	}
	resp, err := srv.Load(ctx, req)

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(resp.Programs) != 1 {
		t.Fatalf("expected 1 program, got %d", len(resp.Programs))
	}
	if resp.Programs[0].KernelInfo.Name != "my_prog" {
		t.Errorf("expected name 'my_prog', got %q", resp.Programs[0].KernelInfo.Name)
	}

	getResp, err := srv.Get(ctx, &pb.GetRequest{Id: resp.Programs[0].KernelInfo.Id})
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if getResp.Info.Name != "my_prog" {
		t.Errorf("Get returned wrong name: %q", getResp.Info.Name)
	}
}

// TestLoadProgram_WithDuplicateName_IsRejected verifies that:
//
//	Given a server with one program already loaded using a name,
//	When I attempt to load another program with the same name,
//	Then the load fails with a unique constraint error.
func TestLoadProgram_WithDuplicateName_IsRejected(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	firstReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("uuid-1"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name",
		},
	}
	_, err := srv.Load(ctx, firstReq)
	if err != nil {
		t.Fatalf("setup: first Load failed: %v", err)
	}

	secondReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("uuid-2"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name",
		},
	}
	_, err = srv.Load(ctx, secondReq)

	if err == nil {
		t.Fatal("expected duplicate name to be rejected, got nil error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

// TestLoadProgram_WithDifferentNames_BothSucceed verifies that:
//
//	Given an empty server,
//	When I load two programs with different names,
//	Then both programs exist and are listed.
func TestLoadProgram_WithDifferentNames_BothSucceed(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	for _, name := range []string{"program-a", "program-b"} {
		req := &pb.LoadRequest{
			Bytecode: &pb.BytecodeLocation{
				Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
			},
			Info: []*pb.LoadInfo{
				{Name: "prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
			},
			Uuid: strPtr(name),
			Metadata: map[string]string{
				"bpfman.io/ProgramName": name,
			},
		}
		_, err := srv.Load(ctx, req)
		if err != nil {
			t.Fatalf("Load %s failed: %v", name, err)
		}
	}

	listResp, err := srv.List(ctx, &pb.ListRequest{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listResp.Results) != 2 {
		t.Errorf("expected 2 programs, got %d", len(listResp.Results))
	}
}

// TestUnloadProgram_WhenProgramExists_RemovesIt verifies that:
//
//	Given a server with one program loaded,
//	When I unload the program,
//	Then the unload succeeds and the program is no longer retrievable.
func TestUnloadProgram_WhenProgramExists_RemovesIt(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("test-uuid"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "my-program",
		},
	}
	loadResp, err := srv.Load(ctx, loadReq)
	if err != nil {
		t.Fatalf("setup: Load failed: %v", err)
	}
	kernelID := loadResp.Programs[0].KernelInfo.Id

	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	if err != nil {
		t.Fatalf("Unload failed: %v", err)
	}

	_, err = srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	if err == nil {
		t.Error("expected Get after unload to fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

// TestUnloadProgram_WhenProgramDoesNotExist_IsIdempotent verifies that:
//
//	Given an empty server with no programs,
//	When I try to unload a non-existent program,
//	Then the operation succeeds (idempotent behaviour).
func TestUnloadProgram_WhenProgramDoesNotExist_IsIdempotent(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.Unload(ctx, &pb.UnloadRequest{Id: 999})
	if err != nil {
		t.Errorf("Unload of non-existent program should succeed, got: %v", err)
	}
}

// TestLoadProgram_AfterUnload_NameBecomesAvailable verifies that:
//
//	Given a program was loaded and then unloaded,
//	When I load a new program with the same name,
//	Then the load succeeds because the name was freed.
func TestLoadProgram_AfterUnload_NameBecomesAvailable(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	firstReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("uuid-1"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name",
		},
	}
	loadResp, err := srv.Load(ctx, firstReq)
	if err != nil {
		t.Fatalf("setup: first Load failed: %v", err)
	}
	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: loadResp.Programs[0].KernelInfo.Id})
	if err != nil {
		t.Fatalf("setup: Unload failed: %v", err)
	}

	secondReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("uuid-2"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name",
		},
	}
	_, err = srv.Load(ctx, secondReq)
	if err != nil {
		t.Fatalf("second Load with reused name failed: %v", err)
	}
}

// TestListPrograms_WithMetadataFilter_ReturnsOnlyMatching verifies that:
//
//	Given two programs with different app metadata,
//	When I list programs filtering by app=frontend,
//	Then only the frontend program is returned.
func TestListPrograms_WithMetadataFilter_ReturnsOnlyMatching(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	for _, app := range []string{"frontend", "backend"} {
		req := &pb.LoadRequest{
			Bytecode: &pb.BytecodeLocation{
				Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
			},
			Info: []*pb.LoadInfo{
				{Name: "prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
			},
			Uuid: strPtr(app),
			Metadata: map[string]string{
				"bpfman.io/ProgramName": app,
				"app":                   app,
			},
		}
		_, err := srv.Load(ctx, req)
		if err != nil {
			t.Fatalf("setup: Load %s failed: %v", app, err)
		}
	}

	filteredResp, err := srv.List(ctx, &pb.ListRequest{
		MatchMetadata: map[string]string{"app": "frontend"},
	})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(filteredResp.Results) != 1 {
		t.Fatalf("expected 1 filtered program, got %d", len(filteredResp.Results))
	}
	if filteredResp.Results[0].Info.Metadata["app"] != "frontend" {
		t.Errorf("wrong program returned: %v", filteredResp.Results[0].Info.Metadata)
	}
}

func strPtr(s string) *string {
	return &s
}
