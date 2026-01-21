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
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
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

func (f *fakeKernel) GetProgramByID(_ context.Context, id uint32) (kernel.Program, error) {
	p, ok := f.programs[id]
	if !ok {
		return kernel.Program{}, fmt.Errorf("program %d not found", id)
	}
	return kernel.Program{
		ID:          id,
		Name:        p.Name,
		ProgramType: p.ProgramType.String(),
	}, nil
}

func (f *fakeKernel) GetLinkByID(_ context.Context, id uint32) (kernel.Link, error) {
	link, ok := f.links[id]
	if !ok {
		return kernel.Link{}, fmt.Errorf("link %d not found", id)
	}
	return kernel.Link{
		ID:        id,
		LinkType:  string(link.Type),
		ProgramID: 0, // fakeKernel doesn't track program association
	}, nil
}

func (f *fakeKernel) GetMapByID(_ context.Context, id uint32) (kernel.Map, error) {
	// fakeKernel doesn't track maps, return a minimal stub
	return kernel.Map{ID: id}, nil
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

func (f *fakeKernel) AttachXDP(progPinPath string, ifindex int, linkPinPath string) (*bpfman.AttachedLink, error) {
	id := f.nextID.Add(1)
	link := &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachXDP,
	}
	f.links[id] = link
	return link, nil
}

func (f *fakeKernel) DetachLink(linkPinPath string) error {
	for id, link := range f.links {
		if link.PinPath == linkPinPath {
			delete(f.links, id)
			return nil
		}
	}
	return nil
}

func (f *fakeKernel) AttachXDPDispatcher(ifindex int, pinDir string, numProgs int, proceedOn uint32) (*interpreter.XDPDispatcherResult, error) {
	dispatcherID := f.nextID.Add(1)
	linkID := f.nextID.Add(1)
	return &interpreter.XDPDispatcherResult{
		DispatcherID:  dispatcherID,
		LinkID:        linkID,
		DispatcherPin: pinDir + "/xdp_dispatcher",
		LinkPin:       pinDir + "/link",
	}, nil
}

func (f *fakeKernel) AttachXDPExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath string) (*bpfman.AttachedLink, error) {
	id := f.nextID.Add(1)
	link := &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachXDP,
	}
	f.links[id] = link
	return link, nil
}

// newTestServer creates a server with fake kernel and real in-memory SQLite.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	t.Cleanup(func() { store.Close() })
	return NewForTest(store, newFakeKernel(), testLogger())
}

// TestLoadProgram_WithValidRequest_Succeeds verifies that:
//
//	Given an empty server with no programs loaded,
//	When I load a program with valid bytecode and metadata,
//	Then the load succeeds with all fields correctly populated.
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
			"app":                   "test-app",
		},
	}

	resp, err := srv.Load(ctx, req)
	require.NoError(t, err, "Load failed")
	require.Len(t, resp.Programs, 1, "expected 1 program")

	prog := resp.Programs[0]

	// Verify ProgramInfo fields
	assert.Equal(t, "my_prog", prog.Info.Name, "Info.Name")
	require.NotNil(t, prog.Info.Bytecode, "Info.Bytecode")
	file, ok := prog.Info.Bytecode.Location.(*pb.BytecodeLocation_File)
	require.True(t, ok, "expected BytecodeLocation_File")
	assert.Equal(t, "/path/to/prog.o", file.File, "Info.Bytecode.File")
	assert.Equal(t, "my-program", prog.Info.Metadata["bpfman.io/ProgramName"], "Info.Metadata[bpfman.io/ProgramName]")
	assert.Equal(t, "test-app", prog.Info.Metadata["app"], "Info.Metadata[app]")
	assert.NotEmpty(t, prog.Info.MapPinPath, "Info.MapPinPath")

	// Verify KernelProgramInfo fields
	assert.NotZero(t, prog.KernelInfo.Id, "KernelInfo.Id")
	assert.Equal(t, "my_prog", prog.KernelInfo.Name, "KernelInfo.Name")
	assert.Equal(t, uint32(bpfman.ProgramTypeTracepoint), prog.KernelInfo.ProgramType, "KernelInfo.ProgramType")
}

// TestGetProgram_ReturnsAllFields verifies that:
//
//	Given a program loaded with specific metadata,
//	When I retrieve it via Get,
//	Then all fields match what was provided at load time.
func TestGetProgram_ReturnsAllFields(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "get_test_prog", ProgramType: pb.BpfmanProgramType_KPROBE},
		},
		Uuid: strPtr("get-test-uuid"),
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "get-test-program",
			"environment":           "testing",
			"version":               "1.0.0",
		},
	}

	loadResp, err := srv.Load(ctx, req)
	require.NoError(t, err, "Load failed")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	getResp, err := srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	require.NoError(t, err, "Get failed")

	// Verify ProgramInfo fields
	assert.Equal(t, "get_test_prog", getResp.Info.Name, "Info.Name")
	require.NotNil(t, getResp.Info.Bytecode, "Info.Bytecode")
	file, ok := getResp.Info.Bytecode.Location.(*pb.BytecodeLocation_File)
	require.True(t, ok, "expected BytecodeLocation_File")
	assert.Equal(t, "/path/to/prog.o", file.File, "Info.Bytecode.File")
	assert.Equal(t, "get-test-program", getResp.Info.Metadata["bpfman.io/ProgramName"], "Info.Metadata[bpfman.io/ProgramName]")
	assert.Equal(t, "testing", getResp.Info.Metadata["environment"], "Info.Metadata[environment]")
	assert.Equal(t, "1.0.0", getResp.Info.Metadata["version"], "Info.Metadata[version]")
	assert.NotEmpty(t, getResp.Info.MapPinPath, "Info.MapPinPath")

	// Verify KernelProgramInfo fields
	assert.Equal(t, kernelID, getResp.KernelInfo.Id, "KernelInfo.Id")
	assert.Equal(t, "get_test_prog", getResp.KernelInfo.Name, "KernelInfo.Name")
	assert.Equal(t, uint32(bpfman.ProgramTypeKprobe), getResp.KernelInfo.ProgramType, "KernelInfo.ProgramType")
}

// TestListPrograms_ReturnsAllFields verifies that:
//
//	Given multiple programs loaded with different metadata,
//	When I list all programs,
//	Then each result contains correctly populated Info and KernelInfo.
func TestListPrograms_ReturnsAllFields(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	// Load two programs with distinct metadata
	programs := []struct {
		name        string
		programName string
		programType pb.BpfmanProgramType
		uuid        string
		app         string
	}{
		{"prog_one", "program-one", pb.BpfmanProgramType_TRACEPOINT, "uuid-1", "frontend"},
		{"prog_two", "program-two", pb.BpfmanProgramType_XDP, "uuid-2", "backend"},
	}

	expectedIDs := make(map[string]uint32)
	for _, p := range programs {
		req := &pb.LoadRequest{
			Bytecode: &pb.BytecodeLocation{
				Location: &pb.BytecodeLocation_File{File: "/path/to/" + p.name + ".o"},
			},
			Info: []*pb.LoadInfo{
				{Name: p.name, ProgramType: p.programType},
			},
			Uuid: strPtr(p.uuid),
			Metadata: map[string]string{
				"bpfman.io/ProgramName": p.programName,
				"app":                   p.app,
			},
		}
		resp, err := srv.Load(ctx, req)
		require.NoError(t, err, "Load %s failed", p.name)
		expectedIDs[p.programName] = resp.Programs[0].KernelInfo.Id
	}

	listResp, err := srv.List(ctx, &pb.ListRequest{})
	require.NoError(t, err, "List failed")
	require.Len(t, listResp.Results, 2, "expected 2 results")

	// Build a map for easier lookup
	resultsByName := make(map[string]*pb.ListResponse_ListResult)
	for _, r := range listResp.Results {
		resultsByName[r.Info.Metadata["bpfman.io/ProgramName"]] = r
	}

	// Verify program-one
	r1, ok := resultsByName["program-one"]
	require.True(t, ok, "program-one not found in list results")
	assert.Equal(t, "prog_one", r1.Info.Name, "program-one Info.Name")
	assert.Equal(t, "frontend", r1.Info.Metadata["app"], "program-one Info.Metadata[app]")
	assert.Equal(t, expectedIDs["program-one"], r1.KernelInfo.Id, "program-one KernelInfo.Id")
	assert.Equal(t, uint32(bpfman.ProgramTypeTracepoint), r1.KernelInfo.ProgramType, "program-one KernelInfo.ProgramType")

	// Verify program-two
	r2, ok := resultsByName["program-two"]
	require.True(t, ok, "program-two not found in list results")
	assert.Equal(t, "prog_two", r2.Info.Name, "program-two Info.Name")
	assert.Equal(t, "backend", r2.Info.Metadata["app"], "program-two Info.Metadata[app]")
	assert.Equal(t, expectedIDs["program-two"], r2.KernelInfo.Id, "program-two KernelInfo.Id")
	assert.Equal(t, uint32(bpfman.ProgramTypeXDP), r2.KernelInfo.ProgramType, "program-two KernelInfo.ProgramType")
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
	require.NoError(t, err, "first Load failed")

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

	require.Error(t, err, "expected duplicate name to be rejected")
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error")
	assert.Equal(t, codes.Internal, st.Code(), "expected Internal code")
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
		require.NoError(t, err, "Load %s failed", name)
	}

	listResp, err := srv.List(ctx, &pb.ListRequest{})
	require.NoError(t, err, "List failed")
	assert.Len(t, listResp.Results, 2, "expected 2 programs")
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
	require.NoError(t, err, "Load failed")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	require.NoError(t, err, "Unload failed")

	_, err = srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	require.Error(t, err, "expected Get after unload to fail")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code(), "expected NotFound")
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
	assert.NoError(t, err, "Unload of non-existent program should succeed")
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
	require.NoError(t, err, "first Load failed")

	_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: loadResp.Programs[0].KernelInfo.Id})
	require.NoError(t, err, "Unload failed")

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
	assert.NoError(t, err, "second Load with reused name should succeed")
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
		require.NoError(t, err, "Load %s failed", app)
	}

	filteredResp, err := srv.List(ctx, &pb.ListRequest{
		MatchMetadata: map[string]string{"app": "frontend"},
	})
	require.NoError(t, err, "List failed")
	require.Len(t, filteredResp.Results, 1, "expected 1 filtered program")
	assert.Equal(t, "frontend", filteredResp.Results[0].Info.Metadata["app"], "wrong program returned")
}

func strPtr(s string) *string {
	return &s
}
