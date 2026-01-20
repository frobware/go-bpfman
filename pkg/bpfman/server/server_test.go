package server

import (
	"context"
	"iter"
	"strings"
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

// fakeKernel implements interpreter.KernelOperations for testing.
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

func TestLoad_Success(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
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

	prog := resp.Programs[0]
	if prog.KernelInfo.Name != "my_prog" {
		t.Errorf("expected name 'my_prog', got %q", prog.KernelInfo.Name)
	}

	// Verify program is retrievable via Get
	getResp, err := srv.Get(ctx, &pb.GetRequest{Id: prog.KernelInfo.Id})
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if getResp.Info.Name != "my_prog" {
		t.Errorf("Get returned wrong name: %q", getResp.Info.Name)
	}
}

func TestLoad_DuplicateName_Rejected(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
	ctx := context.Background()

	// Load first program with a name
	req1 := &pb.LoadRequest{
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

	_, err = srv.Load(ctx, req1)
	if err != nil {
		t.Fatalf("first Load failed: %v", err)
	}

	// Attempt to load second program with same name
	req2 := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("uuid-2"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name", // duplicate
		},
	}

	_, err = srv.Load(ctx, req2)
	if err == nil {
		t.Fatal("expected duplicate name to be rejected, got nil error")
	}

	// Should be an Internal error with UNIQUE constraint message
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
	if !strings.Contains(st.Message(), "UNIQUE constraint failed") {
		t.Errorf("expected UNIQUE constraint error, got: %v", st.Message())
	}
}

func TestLoad_DifferentNames_Allowed(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
	ctx := context.Background()

	// Load two programs with different names
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

	// Verify both exist via List
	listResp, err := srv.List(ctx, &pb.ListRequest{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listResp.Results) != 2 {
		t.Errorf("expected 2 programs, got %d", len(listResp.Results))
	}
}

func TestUnload_Success(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
	ctx := context.Background()

	// Load a program
	req := &pb.LoadRequest{
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

	loadResp, err := srv.Load(ctx, req)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Verify it exists
	_, err = srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	if err != nil {
		t.Fatalf("Get after load failed: %v", err)
	}

	// Unload it
	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	if err != nil {
		t.Fatalf("Unload failed: %v", err)
	}

	// Verify it's gone
	_, err = srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	if err == nil {
		t.Error("expected Get after unload to fail, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

func TestUnload_NotFound(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
	ctx := context.Background()

	// Try to unload non-existent program
	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: 999})
	// Unload of non-existent program is not an error (idempotent)
	if err != nil {
		t.Errorf("Unload of non-existent program should succeed, got: %v", err)
	}
}

func TestLoad_NameReusableAfterUnload(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
	ctx := context.Background()

	// Load with a name
	req1 := &pb.LoadRequest{
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

	loadResp, err := srv.Load(ctx, req1)
	if err != nil {
		t.Fatalf("first Load failed: %v", err)
	}

	// Unload it
	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: loadResp.Programs[0].KernelInfo.Id})
	if err != nil {
		t.Fatalf("Unload failed: %v", err)
	}

	// Load again with the same name
	req2 := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Uuid: strPtr("uuid-2"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "reusable-name", // same name should work
		},
	}

	_, err = srv.Load(ctx, req2)
	if err != nil {
		t.Fatalf("second Load with reused name failed: %v", err)
	}
}

func TestList_FilterByMetadata(t *testing.T) {
	store, err := sqlite.NewInMemory(nil)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	srv := NewForTest(store, newFakeKernel(), nil)
	ctx := context.Background()

	// Load two programs with different metadata
	for i, app := range []string{"frontend", "backend"} {
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
				"version":               string(rune('1' + i)),
			},
		}
		_, err := srv.Load(ctx, req)
		if err != nil {
			t.Fatalf("Load %s failed: %v", app, err)
		}
	}

	// List all
	allResp, err := srv.List(ctx, &pb.ListRequest{})
	if err != nil {
		t.Fatalf("List all failed: %v", err)
	}
	if len(allResp.Results) != 2 {
		t.Errorf("expected 2 programs, got %d", len(allResp.Results))
	}

	// Filter by app=frontend
	filteredResp, err := srv.List(ctx, &pb.ListRequest{
		MatchMetadata: map[string]string{"app": "frontend"},
	})
	if err != nil {
		t.Fatalf("List filtered failed: %v", err)
	}
	if len(filteredResp.Results) != 1 {
		t.Errorf("expected 1 filtered program, got %d", len(filteredResp.Results))
	}
	if filteredResp.Results[0].Info.Metadata["app"] != "frontend" {
		t.Errorf("wrong program returned: %v", filteredResp.Results[0].Info.Metadata)
	}
}

func strPtr(s string) *string {
	return &s
}
