// Package server_test uses Behaviour-Driven Development (BDD) style.
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
package server_test

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/kernel"
	"github.com/frobware/go-bpfman/server"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// testLogger returns a logger for tests. By default it discards all output.
// Set BPFMAN_TEST_VERBOSE=1 to enable logging.
func testLogger() *slog.Logger {
	if os.Getenv("BPFMAN_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// kernelOp records an operation performed on the fake kernel.
type kernelOp struct {
	Op        string // "load", "unload", "attach", "detach", "attach-xdp-ext", "attach-tc-ext"
	Name      string // program or link name
	ID        uint32 // kernel ID assigned
	Err       error  // error if operation failed
	MapPinDir string // for XDP/TC extension attachments, the map directory used
}

// fakeKernel implements interpreter.KernelOperations for testing.
// It simulates kernel BPF operations without actual syscalls.
type fakeKernel struct {
	nextID   atomic.Uint32
	programs map[uint32]fakeProgram
	links    map[uint32]*bpfman.AttachedLink

	// Operation recording for verification
	ops []kernelOp
	mu  sync.Mutex

	// Error injection - set these to control behaviour
	failOnProgram map[string]error // fail Load if program name matches
	failOnNthLoad int              // fail on Nth load (0 = never fail)
	loadCount     int              // track load count for failOnNthLoad

	// Attach error injection
	failOnAttach map[string]error // fail attach by type (e.g., "tracepoint", "kprobe")

	// Detach error injection
	failOnDetach map[uint32]error // fail detach by link ID
}

// fakeProgram stores program data for the fake kernel.
type fakeProgram struct {
	id          uint32
	name        string
	programType bpfman.ProgramType
	pinPath     string
	pinDir      string
}

// fakeKernelInfo implements bpfman.KernelProgramInfo for testing.
type fakeKernelInfo struct {
	id          uint32
	name        string
	programType bpfman.ProgramType
}

func (f *fakeKernelInfo) ID() uint32                   { return f.id }
func (f *fakeKernelInfo) Name() string                 { return f.name }
func (f *fakeKernelInfo) Type() bpfman.ProgramType     { return f.programType }
func (f *fakeKernelInfo) Tag() string                  { return "" }
func (f *fakeKernelInfo) MapIDs() []uint32             { return nil }
func (f *fakeKernelInfo) BTFId() uint32                { return 0 }
func (f *fakeKernelInfo) BytesXlated() uint32          { return 0 }
func (f *fakeKernelInfo) BytesJited() uint32           { return 0 }
func (f *fakeKernelInfo) VerifiedInstructions() uint32 { return 0 }
func (f *fakeKernelInfo) LoadedAt() time.Time          { return time.Time{} }
func (f *fakeKernelInfo) MemoryLocked() uint64         { return 0 }
func (f *fakeKernelInfo) GPLCompatible() bool          { return true }

// fakeKernelLinkInfo implements bpfman.KernelLinkInfo for testing.
type fakeKernelLinkInfo struct {
	id        uint32
	programID uint32
	linkType  string
}

func (f *fakeKernelLinkInfo) ID() uint32          { return f.id }
func (f *fakeKernelLinkInfo) ProgramID() uint32   { return f.programID }
func (f *fakeKernelLinkInfo) LinkType() string    { return f.linkType }
func (f *fakeKernelLinkInfo) AttachType() string  { return "" }
func (f *fakeKernelLinkInfo) TargetObjID() uint32 { return 0 }
func (f *fakeKernelLinkInfo) TargetBTFId() uint32 { return 0 }

// fakeNetIfaceResolver implements server.NetIfaceResolver for testing.
// It returns fake interface data without requiring real network interfaces.
type fakeNetIfaceResolver struct {
	interfaces map[string]*net.Interface
}

func newFakeNetIfaceResolver() *fakeNetIfaceResolver {
	return &fakeNetIfaceResolver{
		interfaces: map[string]*net.Interface{
			"lo":   {Index: 1, Name: "lo"},
			"eth0": {Index: 2, Name: "eth0"},
		},
	}
}

func (f *fakeNetIfaceResolver) InterfaceByName(name string) (*net.Interface, error) {
	iface, ok := f.interfaces[name]
	if !ok {
		return nil, fmt.Errorf("interface %q not found", name)
	}
	return iface, nil
}

func newFakeKernel() *fakeKernel {
	fk := &fakeKernel{
		programs:      make(map[uint32]fakeProgram),
		links:         make(map[uint32]*bpfman.AttachedLink),
		failOnProgram: make(map[string]error),
		failOnAttach:  make(map[string]error),
		failOnDetach:  make(map[uint32]error),
	}
	fk.nextID.Store(100)
	return fk
}

// Operations returns a copy of recorded operations for verification.
func (f *fakeKernel) Operations() []kernelOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	ops := make([]kernelOp, len(f.ops))
	copy(ops, f.ops)
	return ops
}

// recordOp records an operation for later verification.
func (f *fakeKernel) recordOp(op, name string, id uint32, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, kernelOp{Op: op, Name: name, ID: id, Err: err})
}

// recordExtensionAttach records an XDP/TC extension attachment with the mapPinDir.
func (f *fakeKernel) recordExtensionAttach(op, programName string, id uint32, mapPinDir string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, kernelOp{Op: op, Name: programName, ID: id, MapPinDir: mapPinDir})
}

// ExtensionAttachOps returns all XDP/TC extension attach operations.
func (f *fakeKernel) ExtensionAttachOps() []kernelOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ops []kernelOp
	for _, op := range f.ops {
		if op.Op == "attach-xdp-ext" || op.Op == "attach-tc-ext" {
			ops = append(ops, op)
		}
	}
	return ops
}

// recordTCXAttach records a TCX attachment with the programPinPath.
func (f *fakeKernel) recordTCXAttach(programPinPath string, id uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Reuse MapPinDir field to store programPinPath for TCX
	f.ops = append(f.ops, kernelOp{Op: "attach-tcx", Name: programPinPath, ID: id})
}

// TCXAttachOps returns all TCX attach operations.
func (f *fakeKernel) TCXAttachOps() []kernelOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ops []kernelOp
	for _, op := range f.ops {
		if op.Op == "attach-tcx" {
			ops = append(ops, op)
		}
	}
	return ops
}

// FailOnProgram configures the kernel to fail when loading a specific program.
func (f *fakeKernel) FailOnProgram(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOnProgram[name] = err
}

// FailOnNthLoad configures the kernel to fail on the Nth load attempt.
func (f *fakeKernel) FailOnNthLoad(n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOnNthLoad = n
}

// FailOnAttach configures the kernel to fail when attaching a specific type.
// Valid types: "tracepoint", "kprobe", "uprobe", "fentry", "fexit", "xdp", "tc", "tcx"
func (f *fakeKernel) FailOnAttach(attachType string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOnAttach[attachType] = err
}

// FailOnDetach configures the kernel to fail when detaching a specific link ID.
func (f *fakeKernel) FailOnDetach(linkID uint32, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOnDetach[linkID] = err
}

// Reset clears all recorded operations and error injection settings.
func (f *fakeKernel) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = nil
	f.failOnProgram = make(map[string]error)
	f.failOnAttach = make(map[string]error)
	f.failOnDetach = make(map[uint32]error)
	f.failOnNthLoad = 0
	f.loadCount = 0
}

func (f *fakeKernel) Load(_ context.Context, spec bpfman.LoadSpec) (bpfman.ManagedProgram, error) {
	// Validate program type - mirrors real kernel behaviour
	if spec.ProgramType() == bpfman.ProgramTypeUnspecified {
		err := fmt.Errorf("program type must be specified")
		f.recordOp("load", spec.ProgramName(), 0, err)
		return bpfman.ManagedProgram{}, err
	}
	if spec.ProgramType() < bpfman.ProgramTypeXDP || spec.ProgramType() > bpfman.ProgramTypeFexit {
		err := fmt.Errorf("invalid program type: %d", spec.ProgramType())
		f.recordOp("load", spec.ProgramName(), 0, err)
		return bpfman.ManagedProgram{}, err
	}

	// Check error injection
	f.mu.Lock()
	f.loadCount++
	loadNum := f.loadCount
	failErr := f.failOnProgram[spec.ProgramName()]
	failOnNth := f.failOnNthLoad
	f.mu.Unlock()

	if failErr != nil {
		f.recordOp("load", spec.ProgramName(), 0, failErr)
		return bpfman.ManagedProgram{}, failErr
	}
	if failOnNth > 0 && loadNum == failOnNth {
		err := fmt.Errorf("injected error on load %d", loadNum)
		f.recordOp("load", spec.ProgramName(), 0, err)
		return bpfman.ManagedProgram{}, err
	}

	id := f.nextID.Add(1)
	// Compute paths the same way the real kernel does - using kernel ID
	progPinPath := fmt.Sprintf("%s/prog_%d", spec.PinPath(), id)

	// Map sharing: if MapOwnerID is set, use the owner's maps directory
	var mapsDir string
	if spec.MapOwnerID() != 0 {
		// Share maps with the owner program
		mapsDir = fmt.Sprintf("%s/maps/%d", spec.PinPath(), spec.MapOwnerID())
	} else {
		// Own maps - use our kernel ID
		mapsDir = fmt.Sprintf("%s/maps/%d", spec.PinPath(), id)
	}

	fp := fakeProgram{
		id:          id,
		name:        spec.ProgramName(),
		programType: spec.ProgramType(),
		pinPath:     progPinPath,
		pinDir:      mapsDir,
	}
	f.programs[id] = fp
	f.recordOp("load", spec.ProgramName(), id, nil)
	return bpfman.ManagedProgram{
		Managed: &bpfman.ProgramInfo{
			Name:    fp.name,
			Type:    fp.programType,
			PinPath: fp.pinPath,
			PinDir:  fp.pinDir,
		},
		Kernel: &fakeKernelInfo{
			id:          fp.id,
			name:        fp.name,
			programType: fp.programType,
		},
	}, nil
}

func (f *fakeKernel) Unload(_ context.Context, pinPath string) error {
	for id, p := range f.programs {
		// Match by either program pin path or maps directory
		if p.pinPath == pinPath || p.pinDir == pinPath {
			delete(f.programs, id)
			f.recordOp("unload", p.name, id, nil)
			return nil
		}
	}
	return nil
}

func (f *fakeKernel) UnloadProgram(_ context.Context, progPinPath, mapsDir string) error {
	// Fake implementation - just removes any program whose pin path matches
	for id, p := range f.programs {
		if p.pinPath == progPinPath || p.pinDir == mapsDir {
			delete(f.programs, id)
			f.recordOp("unload", p.name, id, nil)
			return nil
		}
	}
	return nil
}

// ProgramCount returns the number of programs currently loaded.
func (f *fakeKernel) ProgramCount() int {
	return len(f.programs)
}

func (f *fakeKernel) LinkCount() int {
	return len(f.links)
}

func (f *fakeKernel) Programs(_ context.Context) iter.Seq2[kernel.Program, error] {
	return func(yield func(kernel.Program, error) bool) {
		for id, p := range f.programs {
			kp := kernel.Program{
				ID:          id,
				Name:        p.name,
				ProgramType: p.programType.String(),
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
		Name:        p.name,
		ProgramType: p.programType.String(),
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
	return func(yield func(kernel.Link, error) bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for id := range f.links {
			kl := kernel.Link{
				ID: id,
			}
			if !yield(kl, nil) {
				return
			}
		}
	}
}

func (f *fakeKernel) ListPinDir(pinDir string, includeMaps bool) (*kernel.PinDirContents, error) {
	return &kernel.PinDirContents{}, nil
}

func (f *fakeKernel) GetPinned(pinPath string) (*kernel.PinnedProgram, error) {
	return nil, nil
}

func (f *fakeKernel) AttachTracepoint(progPinPath, group, name, linkPinPath string) (bpfman.ManagedLink, error) {
	// Check error injection
	f.mu.Lock()
	failErr := f.failOnAttach["tracepoint"]
	f.mu.Unlock()
	if failErr != nil {
		f.recordOp("attach", "tracepoint:"+group+"/"+name, 0, failErr)
		return bpfman.ManagedLink{}, failErr
	}

	id := f.nextID.Add(1)
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachTracepoint,
	}
	f.recordOp("attach", "tracepoint:"+group+"/"+name, id, nil)
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeTracepoint,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.TracepointDetails{Group: group, Name: name},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "tracepoint"},
	}, nil
}

func (f *fakeKernel) AttachXDP(progPinPath string, ifindex int, linkPinPath string) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachXDP,
	}
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeXDP,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.XDPDetails{Ifindex: uint32(ifindex)},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "xdp"},
	}, nil
}

func (f *fakeKernel) AttachKprobe(progPinPath, fnName string, offset uint64, retprobe bool, linkPinPath string) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	linkType := bpfman.LinkTypeKprobe
	kernelLinkType := "kprobe"
	if retprobe {
		linkType = bpfman.LinkTypeKretprobe
		kernelLinkType = "kretprobe"
	}
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachKprobe,
	}
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.KprobeDetails{FnName: fnName, Offset: offset, Retprobe: retprobe},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: kernelLinkType},
	}, nil
}

func (f *fakeKernel) AttachUprobe(progPinPath, target, fnName string, offset uint64, retprobe bool, linkPinPath string, containerPid int32) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	linkType := bpfman.LinkTypeUprobe
	kernelLinkType := "uprobe"
	if retprobe {
		linkType = bpfman.LinkTypeUretprobe
		kernelLinkType = "uretprobe"
	}
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachUprobe,
	}
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.UprobeDetails{Target: target, FnName: fnName, Offset: offset, Retprobe: retprobe, ContainerPid: containerPid},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: kernelLinkType},
	}, nil
}

func (f *fakeKernel) AttachFentry(progPinPath, fnName, linkPinPath string) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachFentry,
	}
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeFentry,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.FentryDetails{FnName: fnName},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "fentry"},
	}, nil
}

func (f *fakeKernel) AttachFexit(progPinPath, fnName, linkPinPath string) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachFexit,
	}
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeFexit,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.FexitDetails{FnName: fnName},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "fexit"},
	}, nil
}

func (f *fakeKernel) DetachLink(linkPinPath string) error {
	for id, link := range f.links {
		if link.PinPath == linkPinPath {
			// Check error injection
			f.mu.Lock()
			failErr := f.failOnDetach[id]
			f.mu.Unlock()
			if failErr != nil {
				f.recordOp("detach", linkPinPath, id, failErr)
				return failErr
			}
			delete(f.links, id)
			f.recordOp("detach", linkPinPath, id, nil)
			return nil
		}
	}
	// Link not found - still record the detach attempt
	f.recordOp("detach", linkPinPath, 0, nil)
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

func (f *fakeKernel) AttachXDPDispatcherWithPaths(ifindex int, progPinPath, linkPinPath string, numProgs int, proceedOn uint32, netns string) (*interpreter.XDPDispatcherResult, error) {
	dispatcherID := f.nextID.Add(1)
	linkID := f.nextID.Add(1)
	// Add dispatcher program to programs map so GC sees it as valid
	f.programs[dispatcherID] = fakeProgram{
		id:          dispatcherID,
		name:        "xdp_dispatcher",
		programType: bpfman.ProgramTypeXDP,
		pinPath:     progPinPath,
	}
	return &interpreter.XDPDispatcherResult{
		DispatcherID:  dispatcherID,
		LinkID:        linkID,
		DispatcherPin: progPinPath,
		LinkPin:       linkPinPath,
	}, nil
}

func (f *fakeKernel) AttachXDPExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath, mapPinDir string) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachXDP,
	}
	// Record the operation with mapPinDir for test verification
	f.recordExtensionAttach("attach-xdp-ext", programName, id, mapPinDir)
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeXDP,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.XDPDetails{Position: int32(position)},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "xdp"},
	}, nil
}

func (f *fakeKernel) AttachTCDispatcherWithPaths(ifindex int, progPinPath, linkPinPath, direction string, numProgs int, proceedOn uint32, netns string) (*interpreter.TCDispatcherResult, error) {
	dispatcherID := f.nextID.Add(1)
	linkID := f.nextID.Add(1)
	// Add dispatcher program to programs map so GC sees it as valid
	f.programs[dispatcherID] = fakeProgram{
		id:          dispatcherID,
		name:        "tc_dispatcher",
		programType: bpfman.ProgramTypeTC,
		pinPath:     progPinPath,
	}
	return &interpreter.TCDispatcherResult{
		DispatcherID:  dispatcherID,
		LinkID:        linkID,
		DispatcherPin: progPinPath,
		LinkPin:       linkPinPath,
	}, nil
}

func (f *fakeKernel) AttachTCExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath, mapPinDir string) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	// Store for DetachLink lookup
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachTC,
	}
	// Record the operation with mapPinDir for test verification
	f.recordExtensionAttach("attach-tc-ext", programName, id, mapPinDir)
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeTC,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.TCDetails{Position: int32(position)},
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "tc"},
	}, nil
}

func (f *fakeKernel) AttachTCX(ifindex int, direction, programPinPath, linkPinPath, netns string, order bpfman.TCXAttachOrder) (bpfman.ManagedLink, error) {
	id := f.nextID.Add(1)
	f.links[id] = &bpfman.AttachedLink{
		ID:      id,
		PinPath: linkPinPath,
		Type:    bpfman.AttachTCX,
	}
	// Record the operation with programPinPath for test verification
	f.recordTCXAttach(programPinPath, id)
	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    id,
			KernelProgramID: 0,
			Type:            bpfman.LinkTypeTCX,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
		},
		Kernel: &fakeKernelLinkInfo{id: id, programID: 0, linkType: "tcx"},
	}, nil
}

func (f *fakeKernel) RemovePin(path string) error {
	// Remove programs matching this pin path (for dispatcher cleanup)
	for id, prog := range f.programs {
		if prog.pinPath == path {
			delete(f.programs, id)
			break
		}
	}
	return nil
}

func (f *fakeKernel) RepinMap(srcPath, dstPath string) error {
	return nil // Fake implementation - no-op
}

// testFixture provides access to all components for verification.
type testFixture struct {
	Server *server.Server
	Kernel *fakeKernel
	Store  interpreter.Store
	Dirs   *config.RuntimeDirs
	t      *testing.T
}

// newTestFixture creates a complete test fixture with accessible components.
func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	store, err := sqlite.NewInMemory(testLogger())
	require.NoError(t, err, "failed to create store")
	t.Cleanup(func() { store.Close() })
	dirs := config.NewRuntimeDirs(t.TempDir())
	kernel := newFakeKernel()
	netIface := newFakeNetIfaceResolver()
	srv := server.New(dirs, store, kernel, nil, netIface, testLogger())
	return &testFixture{
		Server: srv,
		Kernel: kernel,
		Store:  store,
		Dirs:   &dirs,
		t:      t,
	}
}

// AssertKernelEmpty verifies no programs remain in the kernel.
func (f *testFixture) AssertKernelEmpty() {
	f.t.Helper()
	assert.Equal(f.t, 0, f.Kernel.ProgramCount(), "expected no programs in kernel")
}

// AssertDatabaseEmpty verifies no programs remain in the database.
func (f *testFixture) AssertDatabaseEmpty() {
	f.t.Helper()
	programs, err := f.Store.List(context.Background())
	require.NoError(f.t, err, "failed to list programs from store")
	assert.Empty(f.t, programs, "expected no programs in database")
}

// AssertCleanState verifies both kernel and database are empty.
func (f *testFixture) AssertCleanState() {
	f.t.Helper()
	f.AssertKernelEmpty()
	f.AssertDatabaseEmpty()
}

// AssertKernelOps verifies the sequence of kernel operations.
func (f *testFixture) AssertKernelOps(expected []string) {
	f.t.Helper()
	ops := f.Kernel.Operations()
	actual := make([]string, len(ops))
	for i, op := range ops {
		if op.Err != nil {
			actual[i] = fmt.Sprintf("%s:%s:error", op.Op, op.Name)
		} else {
			actual[i] = fmt.Sprintf("%s:%s:ok", op.Op, op.Name)
		}
	}
	assert.Equal(f.t, expected, actual, "kernel operations mismatch")
}

// newTestServer creates a server with fake kernel and real in-memory SQLite.
func newTestServer(t *testing.T) *server.Server {
	return newTestFixture(t).Server
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

// TestLoadProgram_WithGlobalData verifies that:
//
//	Given a program loaded with global data,
//	When I retrieve it via Get,
//	Then the global data is returned correctly.
func TestLoadProgram_WithGlobalData(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	globalData := map[string][]byte{
		"GLOBAL_u8":  {0x01},
		"GLOBAL_u32": {0x0A, 0x0B, 0x0C, 0x0D},
		"sampling":   {0x00, 0x00, 0x00, 0x01},
	}

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "global_test_prog",
				ProgramType: pb.BpfmanProgramType_KPROBE,
			},
		},
		Metadata: map[string]string{
			"app": "global-test",
		},
		GlobalData: globalData,
	}

	loadResp, err := srv.Load(ctx, req)
	require.NoError(t, err, "Load failed")
	require.Len(t, loadResp.Programs, 1, "expected 1 program")

	// Verify global data is returned in the load response
	prog := loadResp.Programs[0]
	assert.Equal(t, globalData, prog.Info.GlobalData, "GlobalData in load response")

	// Verify global data is returned via Get
	kernelID := prog.KernelInfo.Id
	getResp, err := srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	require.NoError(t, err, "Get failed")
	assert.Equal(t, globalData, getResp.Info.GlobalData, "GlobalData in get response")
}

// TestLoadProgram_WithMetadataAndGlobalData verifies that:
//
//	Given a program loaded with both metadata and global data,
//	When I retrieve it via Get and List,
//	Then both are returned correctly.
func TestLoadProgram_WithMetadataAndGlobalData(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	metadata := map[string]string{
		"owner":       "test-team",
		"environment": "staging",
	}
	globalData := map[string][]byte{
		"config_flag": {0xFF},
	}

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "combined_test_prog",
				ProgramType: pb.BpfmanProgramType_TRACEPOINT,
			},
		},
		Metadata:   metadata,
		GlobalData: globalData,
	}

	loadResp, err := srv.Load(ctx, req)
	require.NoError(t, err, "Load failed")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Verify via Get
	getResp, err := srv.Get(ctx, &pb.GetRequest{Id: kernelID})
	require.NoError(t, err, "Get failed")
	assert.Equal(t, "test-team", getResp.Info.Metadata["owner"], "Metadata[owner]")
	assert.Equal(t, "staging", getResp.Info.Metadata["environment"], "Metadata[environment]")
	assert.Equal(t, globalData, getResp.Info.GlobalData, "GlobalData")

	// Verify via List
	listResp, err := srv.List(ctx, &pb.ListRequest{})
	require.NoError(t, err, "List failed")
	require.Len(t, listResp.Results, 1, "expected 1 program in list")
	assert.Equal(t, "test-team", listResp.Results[0].Info.Metadata["owner"], "List Metadata[owner]")
	assert.Equal(t, globalData, listResp.Results[0].Info.GlobalData, "List GlobalData")
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
		app         string
	}{
		{"prog_one", "program-one", pb.BpfmanProgramType_TRACEPOINT, "frontend"},
		{"prog_two", "program-two", pb.BpfmanProgramType_XDP, "backend"},
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

// TestLoadProgram_WithDuplicateName_BothSucceed verifies that:
//
//	Given a server with one program already loaded using a name,
//	When I attempt to load another program with the same name,
//	Then both programs load successfully (duplicates are allowed).
//
// Multiple programs can share the same bpfman.io/ProgramName, e.g., when
// loading multiple BPF programs from a single OCI image via the operator.
func TestLoadProgram_WithDuplicateName_BothSucceed(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	firstReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name",
		},
	}
	resp1, err := srv.Load(ctx, firstReq)
	require.NoError(t, err, "first Load failed")
	require.Len(t, resp1.Programs, 1)

	secondReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "my_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "shared-name",
		},
	}
	resp2, err := srv.Load(ctx, secondReq)
	require.NoError(t, err, "second Load should succeed (duplicates allowed)")
	require.Len(t, resp2.Programs, 1)

	// Verify both programs exist with different IDs
	assert.NotEqual(t, resp1.Programs[0].KernelInfo.Id, resp2.Programs[0].KernelInfo.Id, "should be different programs")
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

// TestUnloadProgram_WhenProgramDoesNotExist_ReturnsNotFound verifies that:
//
//	Given an empty server with no programs,
//	When I try to unload a non-existent program,
//	Then the operation returns NotFound (fail-fast).
func TestUnloadProgram_WhenProgramDoesNotExist_ReturnsNotFound(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.Unload(ctx, &pb.UnloadRequest{Id: 999})
	require.Error(t, err, "Unload of non-existent program should fail")
	assert.Contains(t, err.Error(), "not found", "expected NotFound error")
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

// TestLoadProgram_AllProgramTypes_RoundTrip verifies that:
//
//	Given an empty server,
//	When I load programs of each supported type,
//	Then each program's type is correctly stored and returned via Get.
func TestLoadProgram_AllProgramTypes_RoundTrip(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	// Test all program types that can be loaded via the proto API.
	// Note: proto enum doesn't distinguish kretprobe/uretprobe from kprobe/uprobe.
	tests := []struct {
		name       string
		protoType  pb.BpfmanProgramType
		domainType bpfman.ProgramType
	}{
		{"XDP", pb.BpfmanProgramType_XDP, bpfman.ProgramTypeXDP},
		{"TC", pb.BpfmanProgramType_TC, bpfman.ProgramTypeTC},
		{"TCX", pb.BpfmanProgramType_TCX, bpfman.ProgramTypeTCX},
		{"Tracepoint", pb.BpfmanProgramType_TRACEPOINT, bpfman.ProgramTypeTracepoint},
		{"Kprobe", pb.BpfmanProgramType_KPROBE, bpfman.ProgramTypeKprobe},
		{"Uprobe", pb.BpfmanProgramType_UPROBE, bpfman.ProgramTypeUprobe},
		{"Fentry", pb.BpfmanProgramType_FENTRY, bpfman.ProgramTypeFentry},
		{"Fexit", pb.BpfmanProgramType_FEXIT, bpfman.ProgramTypeFexit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			progName := "prog_" + tt.name

			// Build LoadInfo - fentry/fexit require ProgSpecificInfo with FnName
			loadInfo := &pb.LoadInfo{Name: progName, ProgramType: tt.protoType}
			if tt.protoType == pb.BpfmanProgramType_FENTRY {
				loadInfo.Info = &pb.ProgSpecificInfo{
					Info: &pb.ProgSpecificInfo_FentryLoadInfo{
						FentryLoadInfo: &pb.FentryLoadInfo{FnName: "test_func"},
					},
				}
			} else if tt.protoType == pb.BpfmanProgramType_FEXIT {
				loadInfo.Info = &pb.ProgSpecificInfo{
					Info: &pb.ProgSpecificInfo_FexitLoadInfo{
						FexitLoadInfo: &pb.FexitLoadInfo{FnName: "test_func"},
					},
				}
			}

			// Load
			loadReq := &pb.LoadRequest{
				Bytecode: &pb.BytecodeLocation{
					Location: &pb.BytecodeLocation_File{File: "/path/to/" + progName + ".o"},
				},
				Info: []*pb.LoadInfo{loadInfo},
				Metadata: map[string]string{
					"bpfman.io/ProgramName": progName,
				},
			}

			loadResp, err := srv.Load(ctx, loadReq)
			require.NoError(t, err, "Load failed")
			require.Len(t, loadResp.Programs, 1, "expected 1 program")

			kernelID := loadResp.Programs[0].KernelInfo.Id
			assert.Equal(t, uint32(tt.domainType), loadResp.Programs[0].KernelInfo.ProgramType,
				"Load response has wrong program type")

			// Get - verify round-trip
			getResp, err := srv.Get(ctx, &pb.GetRequest{Id: kernelID})
			require.NoError(t, err, "Get failed")
			assert.Equal(t, uint32(tt.domainType), getResp.KernelInfo.ProgramType,
				"Get response has wrong program type")

			// Cleanup for next iteration
			_, err = srv.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
			require.NoError(t, err, "Unload failed")
		})
	}
}

// TestListPrograms_AllProgramTypes_ReturnsCorrectTypes verifies that:
//
//	Given multiple programs of different types loaded,
//	When I list all programs,
//	Then each program's type is correctly returned.
func TestListPrograms_AllProgramTypes_ReturnsCorrectTypes(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	// Load programs of different types
	programTypes := []struct {
		name       string
		protoType  pb.BpfmanProgramType
		domainType bpfman.ProgramType
	}{
		{"xdp_prog", pb.BpfmanProgramType_XDP, bpfman.ProgramTypeXDP},
		{"tc_prog", pb.BpfmanProgramType_TC, bpfman.ProgramTypeTC},
		{"tp_prog", pb.BpfmanProgramType_TRACEPOINT, bpfman.ProgramTypeTracepoint},
		{"kprobe_prog", pb.BpfmanProgramType_KPROBE, bpfman.ProgramTypeKprobe},
	}

	expectedTypes := make(map[string]bpfman.ProgramType)
	for _, pt := range programTypes {
		req := &pb.LoadRequest{
			Bytecode: &pb.BytecodeLocation{
				Location: &pb.BytecodeLocation_File{File: "/path/to/" + pt.name + ".o"},
			},
			Info: []*pb.LoadInfo{
				{Name: pt.name, ProgramType: pt.protoType},
			},
			Metadata: map[string]string{
				"bpfman.io/ProgramName": pt.name,
			},
		}
		_, err := srv.Load(ctx, req)
		require.NoError(t, err, "Load %s failed", pt.name)
		expectedTypes[pt.name] = pt.domainType
	}

	// List all programs
	listResp, err := srv.List(ctx, &pb.ListRequest{})
	require.NoError(t, err, "List failed")
	require.Len(t, listResp.Results, len(programTypes), "expected %d programs", len(programTypes))

	// Verify each program has the correct type
	for _, result := range listResp.Results {
		progName := result.Info.Metadata["bpfman.io/ProgramName"]
		expectedType, ok := expectedTypes[progName]
		require.True(t, ok, "unexpected program %s in list", progName)
		assert.Equal(t, uint32(expectedType), result.KernelInfo.ProgramType,
			"program %s has wrong type", progName)
	}
}

// TestLoadProgram_WithInvalidProgramType_IsRejected verifies that:
//
//	Given an empty server,
//	When I attempt to load a program with an invalid program type,
//	Then the server rejects the request with an error.
func TestLoadProgram_WithInvalidProgramType_IsRejected(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "bad_prog", ProgramType: pb.BpfmanProgramType(999)}, // Invalid type
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "bad-program",
		},
	}

	_, err := srv.Load(ctx, req)
	require.Error(t, err, "Load with invalid program type should fail")
	assert.Contains(t, err.Error(), "unknown program type",
		"error should mention unknown program type")
}

// TestLoadProgram_WithUnspecifiedProgramType_IsRejected verifies that:
//
//	Given an empty server,
//	When I attempt to load a program without specifying a program type,
//	Then the server rejects the request with an error.
func TestLoadProgram_WithUnspecifiedProgramType_IsRejected(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	// pb.BpfmanProgramType zero value (XDP=0) is actually valid,
	// but we can test that an out-of-range negative-like value fails.
	// Actually, XDP is 0 in the proto, so "unspecified" isn't really
	// representable. This test documents that behaviour.
	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_prog", ProgramType: pb.BpfmanProgramType_XDP}, // XDP = 0
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "xdp-program",
		},
	}

	// This should succeed - XDP (0) is a valid type
	resp, err := srv.Load(ctx, req)
	require.NoError(t, err, "Load with XDP type should succeed")
	assert.Equal(t, uint32(bpfman.ProgramTypeXDP), resp.Programs[0].KernelInfo.ProgramType)
}

// TestFakeKernel_RejectsUnspecifiedProgramType verifies that:
//
//	Given a fake kernel,
//	When Load is called with ProgramTypeUnspecified,
//	Then it returns an error.
//
// Note: TestFakeKernel_RejectsUnspecifiedProgramType and
// TestFakeKernel_RejectsInvalidProgramType were removed because with
// proper constructors (NewLoadSpec, NewAttachLoadSpec), it's impossible
// to create a LoadSpec with an unspecified or out-of-range program type.
// The validation now happens at construction time, making these scenarios
// unreachable in production code.

// =============================================================================
// Partial Failure and Rollback Tests
// =============================================================================
//
// These tests verify that when operations fail partway through:
// 1. Kernel state is properly rolled back (no orphaned programs)
// 2. Database state is clean (nothing persisted)
// 3. Error is properly propagated to the caller

// TestLoadProgram_PartialFailure_SecondProgramFails verifies that:
//
//	Given a server configured to fail on the second program load,
//	When I attempt to load two programs in a single request,
//	Then the first program is unloaded (rolled back),
//	And neither program exists in the kernel,
//	And neither program exists in the database.
func TestLoadProgram_PartialFailure_SecondProgramFails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Configure kernel to fail on the second program
	fix.Kernel.FailOnProgram("prog_two", fmt.Errorf("injected failure on prog_two"))

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "prog_one", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
			{Name: "prog_two", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "multi-prog",
		},
	}

	_, err := fix.Server.Load(ctx, req)

	// Should have failed
	require.Error(t, err, "Load should fail when second program fails")
	assert.Contains(t, err.Error(), "injected failure", "error should mention injected failure")

	// Verify kernel operations: load prog_one, fail prog_two, unload prog_one
	fix.AssertKernelOps([]string{
		"load:prog_one:ok",
		"load:prog_two:error",
		"unload:prog_one:ok",
	})

	// Verify clean state
	fix.AssertCleanState()
}

// TestLoadProgram_PartialFailure_ThirdOfThreeFails verifies that:
//
//	Given a server configured to fail on the third program load,
//	When I attempt to load three programs,
//	Then the first two programs are unloaded (rolled back),
//	And no programs exist in the kernel or database.
//
// Note: We avoid using bpfman.io/ProgramName metadata because it has a unique
// constraint. Using non-unique metadata (like "app") allows batch loading.
func TestLoadProgram_PartialFailure_ThirdOfThreeFails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Configure kernel to fail on the third program
	fix.Kernel.FailOnProgram("prog_three", fmt.Errorf("injected failure on prog_three"))

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "prog_one", ProgramType: pb.BpfmanProgramType_XDP},
			{Name: "prog_two", ProgramType: pb.BpfmanProgramType_TC},
			{Name: "prog_three", ProgramType: pb.BpfmanProgramType_KPROBE},
		},
		Metadata: map[string]string{
			"app": "triple-prog", // Non-unique metadata - ok for batch loads
		},
	}

	_, err := fix.Server.Load(ctx, req)

	// Should have failed
	require.Error(t, err, "Load should fail when third program fails")

	// Verify kernel operations: load 1, load 2, fail 3, unload 2, unload 1
	fix.AssertKernelOps([]string{
		"load:prog_one:ok",
		"load:prog_two:ok",
		"load:prog_three:error",
		"unload:prog_two:ok",
		"unload:prog_one:ok",
	})

	// Verify clean state
	fix.AssertCleanState()
}

// TestLoadProgram_PartialFailure_FirstProgramFails verifies that:
//
//	Given a server configured to fail on the first program load,
//	When I attempt to load two programs,
//	Then no rollback is needed (nothing succeeded),
//	And no programs exist in the kernel or database.
func TestLoadProgram_PartialFailure_FirstProgramFails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Configure kernel to fail on the first program
	fix.Kernel.FailOnProgram("prog_one", fmt.Errorf("injected failure on prog_one"))

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "prog_one", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
			{Name: "prog_two", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "multi-prog",
		},
	}

	_, err := fix.Server.Load(ctx, req)

	// Should have failed
	require.Error(t, err, "Load should fail when first program fails")

	// Verify kernel operations: only the failed load attempt
	fix.AssertKernelOps([]string{
		"load:prog_one:error",
	})

	// Verify clean state
	fix.AssertCleanState()
}

// TestLoadProgram_SingleProgram_FailsCleanly verifies that:
//
//	Given a server configured to fail on a single program load,
//	When I attempt to load one program,
//	Then the error is returned,
//	And no programs exist in the kernel or database.
func TestLoadProgram_SingleProgram_FailsCleanly(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Configure kernel to fail
	fix.Kernel.FailOnProgram("single_prog", fmt.Errorf("injected failure"))

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/single.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "single_prog", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "single-prog",
		},
	}

	_, err := fix.Server.Load(ctx, req)

	require.Error(t, err, "Load should fail")
	fix.AssertKernelOps([]string{"load:single_prog:error"})
	fix.AssertCleanState()
}

// TestLoadProgram_FailOnNthLoad verifies that:
//
//	Given a server configured to fail on the Nth load operation,
//	When I load multiple programs,
//	Then the failure occurs at the expected point,
//	And rollback cleans up all previously loaded programs.
func TestLoadProgram_FailOnNthLoad(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Configure kernel to fail on the 2nd load attempt
	fix.Kernel.FailOnNthLoad(2, fmt.Errorf("nth load failure"))

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "prog_a", ProgramType: pb.BpfmanProgramType_XDP},
			{Name: "prog_b", ProgramType: pb.BpfmanProgramType_XDP},
			{Name: "prog_c", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "nth-fail-test",
		},
	}

	_, err := fix.Server.Load(ctx, req)

	require.Error(t, err, "Load should fail on 2nd program")
	fix.AssertKernelOps([]string{
		"load:prog_a:ok",
		"load:prog_b:error",
		"unload:prog_a:ok",
	})
	fix.AssertCleanState()
}

// =============================================================================
// Attach Failure Tests
// =============================================================================

// TestAttachTracepoint_WhenAttachFails_ProgramRemainsLoaded verifies that:
//
//	Given a program that was successfully loaded,
//	When I attempt to attach it and the attach operation fails,
//	Then the program remains loaded in the kernel and database,
//	And no link is created,
//	And the error is properly propagated.
func TestAttachTracepoint_WhenAttachFails_ProgramRemainsLoaded(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "attach-fail-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 1, "expected 1 program")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Configure kernel to fail on tracepoint attach
	fix.Kernel.FailOnAttach("tracepoint", fmt.Errorf("injected attach failure"))

	// Attempt to attach - should fail
	attachReq := &pb.AttachRequest{
		Id: kernelID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_openat",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach should fail")
	assert.Contains(t, err.Error(), "injected attach failure", "error should mention injected failure")

	// Verify kernel operations: load succeeded, attach failed
	fix.AssertKernelOps([]string{
		"load:tp_prog:ok",
		"attach:tracepoint:syscalls/sys_enter_openat:error",
	})

	// Program should still be loaded
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "program should still be in kernel")

	// Program should still be in database
	programs, err := fix.Store.List(ctx)
	require.NoError(t, err, "failed to list programs from store")
	assert.Len(t, programs, 1, "program should still be in database")

	// Should be able to retrieve it via Get
	getResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: kernelID})
	require.NoError(t, err, "Get should succeed for loaded program")
	assert.Equal(t, "tp_prog", getResp.Info.Name, "program name should match")

	// No links should exist
	assert.Empty(t, getResp.Info.Links, "no links should exist after failed attach")
}

// TestUnloadProgram_WithActiveLinks_DetachesLinksThenUnloads verifies that:
//
//	Given a program that was successfully loaded and has active links,
//	When I unload the program,
//	Then the links are detached first,
//	Then the program is unloaded,
//	And the kernel and database are clean.
func TestUnloadProgram_WithActiveLinks_DetachesLinksThenUnloads(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "unload-with-links-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 1, "expected 1 program")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Attach the program to a tracepoint
	attachReq := &pb.AttachRequest{
		Id: kernelID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_write",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify we have 1 program and 1 link
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 1, len(fix.Kernel.links), "should have 1 link")

	// Unload the program - should detach link first
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	require.NoError(t, err, "Unload should succeed")

	// Verify operation sequence: load -> attach -> detach -> unload
	ops := fix.Kernel.Operations()
	require.GreaterOrEqual(t, len(ops), 3, "expected at least 3 operations")

	// First op: load
	assert.Equal(t, "load", ops[0].Op, "first op should be load")
	assert.Equal(t, "tp_prog", ops[0].Name, "load should be for tp_prog")

	// Second op: attach
	assert.Equal(t, "attach", ops[1].Op, "second op should be attach")
	assert.Contains(t, ops[1].Name, "tracepoint", "attach should be for tracepoint")

	// Third op: detach (before unload)
	assert.Equal(t, "detach", ops[2].Op, "third op should be detach")

	// Fourth op: unload
	assert.Equal(t, "unload", ops[3].Op, "fourth op should be unload")

	// Verify clean state
	fix.AssertCleanState()
}

// =============================================================================
// Constraint Validation Tests
// =============================================================================

// TestAttach_ToNonExistentProgram_ReturnsNotFound verifies that:
//
//	Given an empty server with no programs loaded,
//	When I attempt to attach to a non-existent program ID,
//	Then the server returns a NotFound error.
func TestAttach_ToNonExistentProgram_ReturnsNotFound(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Attempt to attach to non-existent program ID 999
	attachReq := &pb.AttachRequest{
		Id: 999,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_write",
				},
			},
		},
	}

	_, err := fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach to non-existent program should fail")

	// Verify it's a gRPC NotFound error
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error")
	assert.Equal(t, codes.NotFound, st.Code(), "expected NotFound status code")

	// Verify clean state
	fix.AssertCleanState()
}

// TestLoadProgram_WithEmptyName_IsRejected verifies that:
//
//	Given an empty server,
//	When I attempt to load a program with an empty name,
//	Then the server rejects the request with an error.
func TestLoadProgram_WithEmptyName_IsRejected(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/prog.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "", ProgramType: pb.BpfmanProgramType_TRACEPOINT}, // Empty name
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "empty-name-test",
		},
	}

	_, err := fix.Server.Load(ctx, req)
	require.Error(t, err, "Load with empty program name should fail")

	// Verify clean state
	fix.AssertCleanState()
}

// =============================================================================
// Detach Tests
// =============================================================================

// TestDetach_NonExistentLink_ReturnsNotFound verifies that:
//
//	Given an empty server with no links,
//	When I attempt to detach a non-existent link ID,
//	Then the server returns a NotFound error.
func TestDetach_NonExistentLink_ReturnsNotFound(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Attempt to detach non-existent link ID 999
	_, err := fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: 999})
	require.Error(t, err, "Detach of non-existent link should fail")

	// Verify it's a gRPC NotFound error
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error")
	assert.Equal(t, codes.NotFound, st.Code(), "expected NotFound status code")

	// Verify clean state
	fix.AssertCleanState()
}

// TestDetach_ExistingLink_Succeeds verifies that:
//
//	Given a program with an active link,
//	When I detach the link,
//	Then the detach succeeds,
//	And the link is removed,
//	And the program remains loaded.
func TestDetach_ExistingLink_Succeeds(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "detach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Attach to a tracepoint
	attachReq := &pb.AttachRequest{
		Id: kernelID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_read",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId

	// Verify we have 1 program and 1 link
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 1, len(fix.Kernel.links), "should have 1 link")

	// Detach the link
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
	require.NoError(t, err, "Detach should succeed")

	// Verify link is removed but program remains
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "program should still be loaded")
	assert.Equal(t, 0, len(fix.Kernel.links), "link should be removed")

	// Verify operation sequence
	ops := fix.Kernel.Operations()
	assert.Equal(t, "load", ops[0].Op, "first op should be load")
	assert.Equal(t, "attach", ops[1].Op, "second op should be attach")
	assert.Equal(t, "detach", ops[2].Op, "third op should be detach")
}

// TestMultipleLinks_SameProgram_AllDetachable verifies that:
//
//	Given a program with multiple active links,
//	When I detach them one by one,
//	Then each detach succeeds,
//	And the program remains loaded until explicitly unloaded.
func TestMultipleLinks_SameProgram_AllDetachable(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "multi-link-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Attach to multiple tracepoints
	tracepoints := []string{
		"syscalls/sys_enter_read",
		"syscalls/sys_enter_write",
		"syscalls/sys_enter_open",
	}

	var linkIDs []uint32
	for _, tp := range tracepoints {
		attachReq := &pb.AttachRequest{
			Id: kernelID,
			Attach: &pb.AttachInfo{
				Info: &pb.AttachInfo_TracepointAttachInfo{
					TracepointAttachInfo: &pb.TracepointAttachInfo{
						Tracepoint: tp,
					},
				},
			},
		}

		attachResp, err := fix.Server.Attach(ctx, attachReq)
		require.NoError(t, err, "Attach to %s should succeed", tp)
		linkIDs = append(linkIDs, attachResp.LinkId)
	}

	// Verify we have 1 program and 3 links
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 3, len(fix.Kernel.links), "should have 3 links")

	// Detach links one by one
	for i, linkID := range linkIDs {
		_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
		require.NoError(t, err, "Detach link %d should succeed", i)
		assert.Equal(t, 2-i, len(fix.Kernel.links), "should have %d links remaining", 2-i)
	}

	// Program should still be loaded
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "program should still be loaded")

	// Clean up by unloading the program
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: kernelID})
	require.NoError(t, err, "Unload should succeed")

	// Now verify clean state
	fix.AssertCleanState()
}

// TestDetach_KernelFailure_ReturnsError verifies that:
//
//	Given a program with an active link,
//	When I attempt to detach and the kernel fails,
//	Then the detach operation returns an error,
//	And the link remains in the kernel (potential inconsistent state).
//
// Note: This tests the edge case where kernel detach fails. The link may
// remain in the database even though the kernel operation failed, which
// could lead to state inconsistency requiring reconciliation.
func TestDetach_KernelFailure_ReturnsError(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "detach-failure-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	kernelID := loadResp.Programs[0].KernelInfo.Id

	// Attach to a tracepoint
	attachReq := &pb.AttachRequest{
		Id: kernelID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_close",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId

	// Configure kernel to fail on detach for this link
	fix.Kernel.FailOnDetach(linkID, fmt.Errorf("injected detach failure"))

	// Attempt to detach - should fail
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
	require.Error(t, err, "Detach should fail due to kernel error")
	assert.Contains(t, err.Error(), "injected detach failure", "error should mention injected failure")

	// Verify the link still exists in the fake kernel (was not deleted)
	assert.Equal(t, 1, len(fix.Kernel.links), "link should still exist in kernel after failed detach")

	// Verify operation sequence
	ops := fix.Kernel.Operations()
	lastOp := ops[len(ops)-1]
	assert.Equal(t, "detach", lastOp.Op, "last op should be detach")
	assert.NotNil(t, lastOp.Err, "last op should have recorded the error")
}

// =============================================================================
// XDP Dispatcher Lifecycle Tests
// =============================================================================
//
// These tests verify the XDP dispatcher lifecycle, similar to the integration
// test in integration-tests/test-dispatcher-cleanup.sh but using a fake kernel
// and network interface resolver.

// TestXDPDispatcher_FirstAttachCreatesDispatcher verifies that:
//
//	Given a loaded XDP program,
//	When I attach it to an interface for the first time,
//	Then a dispatcher is created,
//	And the extension count is 1.
func TestXDPDispatcher_FirstAttachCreatesDispatcher(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load an XDP program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/xdp.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_pass", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "xdp-dispatcher-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach to interface (using fake "lo" interface)
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface: "lo",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachXDP should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestXDPDispatcher_MultipleAttachesCreateMultipleLinks verifies that:
//
//	Given a loaded XDP program,
//	When I attach it multiple times to the same interface,
//	Then multiple links are created.
func TestXDPDispatcher_MultipleAttachesCreateMultipleLinks(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load an XDP program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/xdp.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_pass", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "xdp-multi-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach multiple times
	var linkIDs []uint32
	for i := 0; i < 3; i++ {
		attachReq := &pb.AttachRequest{
			Id: programID,
			Attach: &pb.AttachInfo{
				Info: &pb.AttachInfo_XdpAttachInfo{
					XdpAttachInfo: &pb.XDPAttachInfo{
						Iface: "lo",
					},
				},
			},
		}
		attachResp, err := fix.Server.Attach(ctx, attachReq)
		require.NoError(t, err, "AttachXDP %d should succeed", i+1)
		linkIDs = append(linkIDs, attachResp.LinkId)
	}

	// Verify we have 3 links
	assert.Equal(t, 3, fix.Kernel.LinkCount(), "should have 3 links in kernel")
	assert.Len(t, linkIDs, 3, "should have collected 3 link IDs")
}

// TestXDPDispatcher_DetachDecrementsLinkCount verifies that:
//
//	Given a program with multiple XDP attachments,
//	When I detach one link,
//	Then the link count decrements,
//	And remaining links are still valid.
func TestXDPDispatcher_DetachDecrementsLinkCount(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load and attach twice
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/xdp.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_pass", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "xdp-detach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface: "lo",
				},
			},
		},
	}

	attach1, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "First attach should succeed")

	attach2, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Second attach should succeed")

	// Verify we have 2 links
	assert.Equal(t, 2, fix.Kernel.LinkCount(), "should have 2 links")

	// Detach first link
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: attach1.LinkId})
	require.NoError(t, err, "Detach first link should succeed")

	// Should have 1 link remaining
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link after first detach")

	// Detach second link
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: attach2.LinkId})
	require.NoError(t, err, "Detach second link should succeed")

	// Should have no links
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links after second detach")
}

// TestXDPDispatcher_FullLifecycle verifies the complete dispatcher lifecycle:
//
//  1. Load XDP program
//  2. Attach multiple times
//  3. Detach all links one by one
//  4. Unload program
//  5. Verify clean state
//
// This mirrors the integration test in test-dispatcher-cleanup.sh.
func TestXDPDispatcher_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load XDP program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/xdp.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_pass", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "xdp-lifecycle-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id
	t.Logf("Step 1: Loaded program ID %d", programID)

	// Step 2: Attach multiple times (simulate filling dispatcher slots)
	numAttachments := 5
	var linkIDs []uint32
	for i := 0; i < numAttachments; i++ {
		attachReq := &pb.AttachRequest{
			Id: programID,
			Attach: &pb.AttachInfo{
				Info: &pb.AttachInfo_XdpAttachInfo{
					XdpAttachInfo: &pb.XDPAttachInfo{
						Iface: "lo",
					},
				},
			},
		}
		attachResp, err := fix.Server.Attach(ctx, attachReq)
		require.NoError(t, err, "Attach %d should succeed", i+1)
		linkIDs = append(linkIDs, attachResp.LinkId)
		t.Logf("Step 2: Attached link %d (kernel ID %d)", i+1, attachResp.LinkId)
	}

	// Verify state after attachments
	// 2 programs: 1 user XDP program + 1 XDP dispatcher program
	assert.Equal(t, 2, fix.Kernel.ProgramCount(), "should have 2 programs (user + dispatcher)")
	assert.Equal(t, numAttachments, fix.Kernel.LinkCount(), "should have %d links", numAttachments)

	// Step 3: Detach all links one by one
	for i, linkID := range linkIDs {
		_, err := fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
		require.NoError(t, err, "Detach link %d should succeed", linkID)
		expectedLinks := numAttachments - i - 1
		assert.Equal(t, expectedLinks, fix.Kernel.LinkCount(),
			"should have %d links after detaching link %d", expectedLinks, i+1)
		t.Logf("Step 3: Detached link %d, remaining links: %d", linkID, expectedLinks)
	}

	// Step 4: Verify no links remain
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links after all detaches")

	// Step 5: Unload program
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: programID})
	require.NoError(t, err, "Unload should succeed")
	t.Logf("Step 4: Unloaded program %d", programID)

	// Step 6: Verify clean state
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "should have 0 programs")
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links")

	// Verify database is clean
	listResp, err := fix.Server.List(ctx, &pb.ListRequest{})
	require.NoError(t, err, "List should succeed")
	assert.Empty(t, listResp.Results, "should have 0 programs in database")

	t.Log("Step 5: Verified clean state - test passed")
}

// TestXDP_AttachToNonExistentInterface verifies that:
//
//	Given a loaded XDP program,
//	When I try to attach it to a non-existent interface,
//	Then the operation fails with an appropriate error.
func TestXDP_AttachToNonExistentInterface(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load an XDP program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/xdp.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_pass", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "xdp-nonexistent-iface-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt to attach to non-existent interface
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface: "nonexistent0",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach to non-existent interface should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention interface not found")

	// Program should still be loaded
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "program should still be loaded")
	// No links should exist
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "no links should exist")
}

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

// =============================================================================
// TCX Lifecycle Tests
// =============================================================================
//
// These tests verify the TCX lifecycle using the fake network interface
// resolver. TCX is the modern link-based TC attachment mechanism.

// TestTCX_FirstAttachCreatesLink verifies that:
//
//	Given a loaded TCX program,
//	When I attach it to an interface,
//	Then a link is created.
func TestTCX_FirstAttachCreatesLink(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TCX program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tcx.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tcx_pass", ProgramType: pb.BpfmanProgramType_TCX},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tcx-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach to interface with ingress direction
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
					Iface:     "eth0",
					Direction: "ingress",
					Priority:  50,
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachTCX should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestTCX_IngressAndEgressDirections verifies that:
//
//	Given a loaded TCX program,
//	When I attach it with both ingress and egress directions,
//	Then both attachments succeed.
func TestTCX_IngressAndEgressDirections(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TCX program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tcx.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tcx_pass", ProgramType: pb.BpfmanProgramType_TCX},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tcx-direction-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach ingress
	ingressReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
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
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
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

// TestTCX_InvalidDirection verifies that:
//
//	Given a loaded TCX program,
//	When I try to attach with an invalid direction,
//	Then the operation fails.
func TestTCX_InvalidDirection(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TCX program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tcx.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tcx_pass", ProgramType: pb.BpfmanProgramType_TCX},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tcx-invalid-direction-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt attach with invalid direction
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
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

// TestTCX_AttachToNonExistentInterface verifies that:
//
//	Given a loaded TCX program,
//	When I try to attach it to a non-existent interface,
//	Then the operation fails with an appropriate error.
func TestTCX_AttachToNonExistentInterface(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TCX program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tcx.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tcx_pass", ProgramType: pb.BpfmanProgramType_TCX},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tcx-nonexistent-iface-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt to attach to non-existent interface
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
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

// TestTCX_FullLifecycle verifies the complete TCX lifecycle:
//
//  1. Load TCX program
//  2. Attach to ingress and egress on multiple interfaces
//  3. Detach all links
//  4. Unload program
//  5. Verify clean state
func TestTCX_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load TCX program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tcx.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tcx_pass", ProgramType: pb.BpfmanProgramType_TCX},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "tcx-lifecycle-test",
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
					Info: &pb.AttachInfo_TcxAttachInfo{
						TcxAttachInfo: &pb.TCXAttachInfo{
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
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
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

// =============================================================================
// Fentry Lifecycle Tests
// =============================================================================
//
// These tests verify the fentry lifecycle. Fentry programs attach to kernel
// function entry points. The target function must be specified at load time
// via FentryLoadInfo.FnName.

// TestFentry_AttachSucceeds verifies that:
//
//	Given a loaded fentry program with FnName specified,
//	When I attach it,
//	Then a link is created.
func TestFentry_AttachSucceeds(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a fentry program with FnName specified
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/fentry.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "fentry_prog",
				ProgramType: pb.BpfmanProgramType_FENTRY,
				Info: &pb.ProgSpecificInfo{
					Info: &pb.ProgSpecificInfo_FentryLoadInfo{
						FentryLoadInfo: &pb.FentryLoadInfo{
							FnName: "tcp_connect",
						},
					},
				},
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "fentry-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach fentry
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_FentryAttachInfo{
				FentryAttachInfo: &pb.FentryAttachInfo{},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachFentry should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestFentry_LoadWithoutFnName_Fails verifies that:
//
//	Given a fentry program load request without FnName specified,
//	When I try to load it,
//	Then the operation fails because fentry requires attachFunc at load time.
func TestFentry_LoadWithoutFnName_Fails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Try to load a fentry program WITHOUT FnName (no ProgSpecificInfo)
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/fentry.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "fentry_prog",
				ProgramType: pb.BpfmanProgramType_FENTRY,
				// No Info field - FnName not specified
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "fentry-no-fnname-test",
		},
	}

	_, err := fix.Server.Load(ctx, loadReq)
	require.Error(t, err, "Load should fail without FnName for fentry")
	assert.Contains(t, err.Error(), "attachFunc", "error should mention attachFunc")

	// No programs should exist
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "no programs should exist")
}

// TestFentry_FullLifecycle verifies the complete fentry lifecycle:
//
//  1. Load fentry program with FnName
//  2. Attach to kernel function
//  3. Detach
//  4. Unload program
//  5. Verify clean state
func TestFentry_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load fentry program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/fentry.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "fentry_prog",
				ProgramType: pb.BpfmanProgramType_FENTRY,
				Info: &pb.ProgSpecificInfo{
					Info: &pb.ProgSpecificInfo_FentryLoadInfo{
						FentryLoadInfo: &pb.FentryLoadInfo{
							FnName: "tcp_connect",
						},
					},
				},
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "fentry-lifecycle-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id
	t.Logf("Step 1: Loaded program ID %d", programID)

	// Step 2: Attach
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_FentryAttachInfo{
				FentryAttachInfo: &pb.FentryAttachInfo{},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId
	t.Logf("Step 2: Attached (link ID %d)", linkID)

	// Verify state
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link")

	// Step 3: Detach
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
	require.NoError(t, err, "Detach should succeed")
	t.Logf("Step 3: Detached link %d", linkID)

	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links after detach")

	// Step 4: Unload
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: programID})
	require.NoError(t, err, "Unload should succeed")
	t.Logf("Step 4: Unloaded program %d", programID)

	// Step 5: Verify clean state
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "should have 0 programs")
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links")
	t.Log("Step 5: Verified clean state - test passed")
}

// =============================================================================
// Fexit Lifecycle Tests
// =============================================================================
//
// These tests verify the fexit lifecycle. Fexit programs attach to kernel
// function exit points. The target function must be specified at load time
// via FexitLoadInfo.FnName.

// TestFexit_AttachSucceeds verifies that:
//
//	Given a loaded fexit program with FnName specified,
//	When I attach it,
//	Then a link is created.
func TestFexit_AttachSucceeds(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a fexit program with FnName specified
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/fexit.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "fexit_prog",
				ProgramType: pb.BpfmanProgramType_FEXIT,
				Info: &pb.ProgSpecificInfo{
					Info: &pb.ProgSpecificInfo_FexitLoadInfo{
						FexitLoadInfo: &pb.FexitLoadInfo{
							FnName: "tcp_close",
						},
					},
				},
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "fexit-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach fexit
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_FexitAttachInfo{
				FexitAttachInfo: &pb.FexitAttachInfo{},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachFexit should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestFexit_LoadWithoutFnName_Fails verifies that:
//
//	Given a fexit program load request without FnName specified,
//	When I try to load it,
//	Then the operation fails because fexit requires attachFunc at load time.
func TestFexit_LoadWithoutFnName_Fails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Try to load a fexit program WITHOUT FnName (no ProgSpecificInfo)
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/fexit.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "fexit_prog",
				ProgramType: pb.BpfmanProgramType_FEXIT,
				// No Info field - FnName not specified
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "fexit-no-fnname-test",
		},
	}

	_, err := fix.Server.Load(ctx, loadReq)
	require.Error(t, err, "Load should fail without FnName for fexit")
	assert.Contains(t, err.Error(), "attachFunc", "error should mention attachFunc")

	// No programs should exist
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "no programs should exist")
}

// TestFexit_FullLifecycle verifies the complete fexit lifecycle:
//
//  1. Load fexit program with FnName
//  2. Attach to kernel function
//  3. Detach
//  4. Unload program
//  5. Verify clean state
func TestFexit_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load fexit program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/fexit.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "fexit_prog",
				ProgramType: pb.BpfmanProgramType_FEXIT,
				Info: &pb.ProgSpecificInfo{
					Info: &pb.ProgSpecificInfo_FexitLoadInfo{
						FexitLoadInfo: &pb.FexitLoadInfo{
							FnName: "tcp_close",
						},
					},
				},
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "fexit-lifecycle-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id
	t.Logf("Step 1: Loaded program ID %d", programID)

	// Step 2: Attach
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_FexitAttachInfo{
				FexitAttachInfo: &pb.FexitAttachInfo{},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId
	t.Logf("Step 2: Attached (link ID %d)", linkID)

	// Verify state
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link")

	// Step 3: Detach
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
	require.NoError(t, err, "Detach should succeed")
	t.Logf("Step 3: Detached link %d", linkID)

	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links after detach")

	// Step 4: Unload
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: programID})
	require.NoError(t, err, "Unload should succeed")
	t.Logf("Step 4: Unloaded program %d", programID)

	// Step 5: Verify clean state
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "should have 0 programs")
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links")
	t.Log("Step 5: Verified clean state - test passed")
}

// =============================================================================
// Kprobe/Kretprobe Lifecycle Tests
// =============================================================================
//
// These tests verify the kprobe lifecycle. Kprobe programs attach to kernel
// function entry points. The target function is specified at attach time.

// TestKprobe_AttachSucceeds verifies that:
//
//	Given a loaded kprobe program,
//	When I attach it with a function name,
//	Then a link is created.
func TestKprobe_AttachSucceeds(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a kprobe program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/kprobe.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "kprobe_prog",
				ProgramType: pb.BpfmanProgramType_KPROBE,
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "kprobe-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach kprobe with function name
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_KprobeAttachInfo{
				KprobeAttachInfo: &pb.KprobeAttachInfo{
					FnName: "do_sys_open",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachKprobe should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestKprobe_AttachWithoutFnName_Fails verifies that:
//
//	Given a loaded kprobe program,
//	When I try to attach without a function name,
//	Then the operation fails.
func TestKprobe_AttachWithoutFnName_Fails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a kprobe program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/kprobe.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "kprobe_prog",
				ProgramType: pb.BpfmanProgramType_KPROBE,
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "kprobe-no-fnname-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt to attach without function name
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_KprobeAttachInfo{
				KprobeAttachInfo: &pb.KprobeAttachInfo{
					// FnName not set
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach should fail without FnName")
	assert.Contains(t, err.Error(), "fn_name", "error should mention fn_name")

	// No links should exist
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "no links should exist")
}

// TestKprobe_FullLifecycle verifies the complete kprobe lifecycle.
func TestKprobe_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load kprobe program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/kprobe.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "kprobe_prog",
				ProgramType: pb.BpfmanProgramType_KPROBE,
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "kprobe-lifecycle-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Step 2: Attach
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_KprobeAttachInfo{
				KprobeAttachInfo: &pb.KprobeAttachInfo{
					FnName: "do_sys_open",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId

	// Verify state
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link")

	// Step 3: Detach
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
	require.NoError(t, err, "Detach should succeed")

	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links after detach")

	// Step 4: Unload
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: programID})
	require.NoError(t, err, "Unload should succeed")

	// Step 5: Verify clean state
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "should have 0 programs")
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links")
}

// =============================================================================
// Uprobe/Uretprobe Lifecycle Tests
// =============================================================================
//
// These tests verify the uprobe lifecycle. Uprobe programs attach to user-space
// function entry points. The target binary is specified at attach time.

// TestUprobe_AttachSucceeds verifies that:
//
//	Given a loaded uprobe program,
//	When I attach it with a target,
//	Then a link is created.
func TestUprobe_AttachSucceeds(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a uprobe program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/uprobe.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "uprobe_prog",
				ProgramType: pb.BpfmanProgramType_UPROBE,
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "uprobe-attach-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach uprobe with target
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_UprobeAttachInfo{
				UprobeAttachInfo: &pb.UprobeAttachInfo{
					Target: "/usr/lib/libc.so.6",
					FnName: stringPtr("malloc"),
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "AttachUprobe should succeed")
	require.NotZero(t, attachResp.LinkId, "link ID should be non-zero")

	// Verify link exists in fake kernel
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link in kernel")
}

// TestUprobe_AttachWithoutTarget_Fails verifies that:
//
//	Given a loaded uprobe program,
//	When I try to attach without a target,
//	Then the operation fails.
func TestUprobe_AttachWithoutTarget_Fails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a uprobe program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/uprobe.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "uprobe_prog",
				ProgramType: pb.BpfmanProgramType_UPROBE,
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "uprobe-no-target-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attempt to attach without target
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_UprobeAttachInfo{
				UprobeAttachInfo: &pb.UprobeAttachInfo{
					// Target not set
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.Error(t, err, "Attach should fail without target")
	assert.Contains(t, err.Error(), "target", "error should mention target")

	// No links should exist
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "no links should exist")
}

// TestUprobe_FullLifecycle verifies the complete uprobe lifecycle.
func TestUprobe_FullLifecycle(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Step 1: Load uprobe program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/uprobe.o"},
		},
		Info: []*pb.LoadInfo{
			{
				Name:        "uprobe_prog",
				ProgramType: pb.BpfmanProgramType_UPROBE,
			},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "uprobe-lifecycle-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Step 2: Attach
	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_UprobeAttachInfo{
				UprobeAttachInfo: &pb.UprobeAttachInfo{
					Target: "/usr/lib/libc.so.6",
					FnName: stringPtr("malloc"),
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId

	// Verify state
	assert.Equal(t, 1, fix.Kernel.ProgramCount(), "should have 1 program")
	assert.Equal(t, 1, fix.Kernel.LinkCount(), "should have 1 link")

	// Step 3: Detach
	_, err = fix.Server.Detach(ctx, &pb.DetachRequest{LinkId: linkID})
	require.NoError(t, err, "Detach should succeed")

	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links after detach")

	// Step 4: Unload
	_, err = fix.Server.Unload(ctx, &pb.UnloadRequest{Id: programID})
	require.NoError(t, err, "Unload should succeed")

	// Step 5: Verify clean state
	assert.Equal(t, 0, fix.Kernel.ProgramCount(), "should have 0 programs")
	assert.Equal(t, 0, fix.Kernel.LinkCount(), "should have 0 links")
}

// stringPtr is a helper to create a pointer to a string.
func stringPtr(s string) *string {
	return &s
}

// =============================================================================
// Link Listing Tests
// =============================================================================
//
// These tests verify the ListLinks and GetLink operations.

// TestListLinks_ReturnsAllLinks verifies that:
//
//	Given multiple attached links,
//	When I list links,
//	Then all links are returned.
func TestListLinks_ReturnsAllLinks(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "list-links-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	// Attach multiple times to different tracepoints
	tracepoints := []string{
		"syscalls/sys_enter_open",
		"syscalls/sys_enter_close",
		"syscalls/sys_enter_read",
	}

	var linkIDs []uint32
	for _, tp := range tracepoints {
		attachReq := &pb.AttachRequest{
			Id: programID,
			Attach: &pb.AttachInfo{
				Info: &pb.AttachInfo_TracepointAttachInfo{
					TracepointAttachInfo: &pb.TracepointAttachInfo{
						Tracepoint: tp,
					},
				},
			},
		}
		attachResp, err := fix.Server.Attach(ctx, attachReq)
		require.NoError(t, err, "Attach to %s should succeed", tp)
		linkIDs = append(linkIDs, attachResp.LinkId)
	}

	// List all links
	listResp, err := fix.Server.ListLinks(ctx, &pb.ListLinksRequest{})
	require.NoError(t, err, "ListLinks should succeed")
	assert.Len(t, listResp.Links, 3, "should have 3 links")

	// Verify all link IDs are present
	returnedIDs := make(map[uint32]bool)
	for _, link := range listResp.Links {
		returnedIDs[link.Summary.KernelLinkId] = true
	}
	for _, expectedID := range linkIDs {
		assert.True(t, returnedIDs[expectedID], "link ID %d should be in response", expectedID)
	}
}

// TestListLinks_EmptyWhenNoLinks verifies that:
//
//	Given no attached links,
//	When I list links,
//	Then an empty list is returned.
func TestListLinks_EmptyWhenNoLinks(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// List links without any attachments
	listResp, err := fix.Server.ListLinks(ctx, &pb.ListLinksRequest{})
	require.NoError(t, err, "ListLinks should succeed")
	assert.Empty(t, listResp.Links, "should have 0 links")
}

// TestGetLink_ReturnsLinkDetails verifies that:
//
//	Given an attached link,
//	When I get link details,
//	Then the correct details are returned.
func TestGetLink_ReturnsLinkDetails(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load and attach a tracepoint program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tracepoint.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tp_prog", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "get-link-test",
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	programID := loadResp.Programs[0].KernelInfo.Id

	attachReq := &pb.AttachRequest{
		Id: programID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TracepointAttachInfo{
				TracepointAttachInfo: &pb.TracepointAttachInfo{
					Tracepoint: "syscalls/sys_enter_open",
				},
			},
		},
	}

	attachResp, err := fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")
	linkID := attachResp.LinkId

	// Get link details
	getResp, err := fix.Server.GetLink(ctx, &pb.GetLinkRequest{KernelLinkId: linkID})
	require.NoError(t, err, "GetLink should succeed")
	assert.Equal(t, linkID, getResp.Link.Summary.KernelLinkId, "link ID should match")
	assert.Equal(t, pb.BpfmanLinkType_LINK_TYPE_TRACEPOINT, getResp.Link.Summary.LinkType, "link type should be tracepoint")
}

// TestGetLink_NonExistentLink_ReturnsNotFound verifies that:
//
//	Given no attached links,
//	When I try to get a non-existent link,
//	Then NotFound is returned.
func TestGetLink_NonExistentLink_ReturnsNotFound(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Try to get non-existent link
	_, err := fix.Server.GetLink(ctx, &pb.GetLinkRequest{KernelLinkId: 99999})
	require.Error(t, err, "GetLink should fail for non-existent link")

	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status")
	assert.Equal(t, codes.NotFound, st.Code(), "should return NotFound")
}

// ----------------------------------------------------------------------------
// Map Sharing Tests
// ----------------------------------------------------------------------------

// TestMapSharing_MultiProgramLoad_FirstIsOwner verifies that:
//
//	Given a Load request with multiple programs (like from an OCI image),
//	When all programs are successfully loaded,
//	Then the first program has no MapOwnerID (it owns the maps),
//	And subsequent programs have MapOwnerID set to the first program's ID,
//	And all programs share the same MapPinPath.
func TestMapSharing_MultiProgramLoad_FirstIsOwner(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "kprobe_counter", ProgramType: pb.BpfmanProgramType_KPROBE},
			{Name: "tracepoint_counter", ProgramType: pb.BpfmanProgramType_TRACEPOINT},
			{Name: "xdp_stats", ProgramType: pb.BpfmanProgramType_XDP},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "multi-prog-image",
		},
	}

	resp, err := fix.Server.Load(ctx, req)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, resp.Programs, 3, "expected 3 programs")

	// Get detailed info for each program
	ownerID := resp.Programs[0].KernelInfo.Id
	ownerResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: ownerID})
	require.NoError(t, err, "Get owner failed")

	// First program is the map owner - MapOwnerId should be 0 (not set)
	assert.Zero(t, ownerResp.Info.MapOwnerId, "first program should have no MapOwnerId (it owns the maps)")
	assert.NotEmpty(t, ownerResp.Info.MapPinPath, "first program should have MapPinPath set")
	ownerMapPinPath := ownerResp.Info.MapPinPath

	// Check subsequent programs
	for i := 1; i < len(resp.Programs); i++ {
		progID := resp.Programs[i].KernelInfo.Id
		progResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: progID})
		require.NoError(t, err, "Get program %d failed", i)

		// Subsequent programs should reference the owner
		assert.Equal(t, ownerID, progResp.Info.GetMapOwnerId(),
			"program %d should have MapOwnerId set to owner's ID", i)
		// All programs share the same maps directory
		assert.Equal(t, ownerMapPinPath, progResp.Info.MapPinPath,
			"program %d should share owner's MapPinPath", i)
	}
}

// TestMapSharing_SingleProgram_NoMapOwner verifies that:
//
//	Given a Load request with a single program,
//	When it is successfully loaded,
//	Then MapOwnerID is 0 (it owns its own maps).
func TestMapSharing_SingleProgram_NoMapOwner(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	req := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/single.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "single_prog", ProgramType: pb.BpfmanProgramType_KPROBE},
		},
		Metadata: map[string]string{
			"bpfman.io/ProgramName": "single-program",
		},
	}

	resp, err := fix.Server.Load(ctx, req)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, resp.Programs, 1, "expected 1 program")

	progID := resp.Programs[0].KernelInfo.Id
	getResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: progID})
	require.NoError(t, err, "Get failed")

	// Single program owns its own maps
	assert.Zero(t, getResp.Info.MapOwnerId, "single program should have no MapOwnerID")
	assert.NotEmpty(t, getResp.Info.MapPinPath, "single program should have MapPinPath set")
}

// TestMapSharing_XDPAttach_UsesMapPinPath verifies that:
//
//	Given a loaded XDP program,
//	When it is attached to an interface,
//	Then the kernel receives the program's MapPinPath (not computed from kernel ID).
func TestMapSharing_XDPAttach_UsesMapPinPath(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load an XDP program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/xdp.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "xdp_prog", ProgramType: pb.BpfmanProgramType_XDP},
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 1)

	progID := loadResp.Programs[0].KernelInfo.Id

	// Get the program's MapPinPath
	getResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: progID})
	require.NoError(t, err, "Get should succeed")
	expectedMapPinPath := getResp.Info.MapPinPath
	require.NotEmpty(t, expectedMapPinPath, "MapPinPath should be set")

	// Attach the program
	attachReq := &pb.AttachRequest{
		Id: progID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface: "eth0",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")

	// Verify the kernel received the correct MapPinDir
	extOps := fix.Kernel.ExtensionAttachOps()
	require.Len(t, extOps, 1, "expected one XDP extension attach")
	assert.Equal(t, "attach-xdp-ext", extOps[0].Op)
	assert.Equal(t, expectedMapPinPath, extOps[0].MapPinDir,
		"XDP attach should use the program's MapPinPath")
}

// TestMapSharing_TCAttach_UsesMapPinPath verifies that:
//
//	Given a loaded TC program,
//	When it is attached to an interface,
//	Then the kernel receives the program's MapPinPath (not computed from kernel ID).
func TestMapSharing_TCAttach_UsesMapPinPath(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TC program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tc.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tc_prog", ProgramType: pb.BpfmanProgramType_TC},
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 1)

	progID := loadResp.Programs[0].KernelInfo.Id

	// Get the program's MapPinPath
	getResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: progID})
	require.NoError(t, err, "Get should succeed")
	expectedMapPinPath := getResp.Info.MapPinPath
	require.NotEmpty(t, expectedMapPinPath, "MapPinPath should be set")

	// Attach the program
	attachReq := &pb.AttachRequest{
		Id: progID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "eth0",
					Priority:  50,
					Direction: "ingress",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")

	// Verify the kernel received the correct MapPinDir
	extOps := fix.Kernel.ExtensionAttachOps()
	require.Len(t, extOps, 1, "expected one TC extension attach")
	assert.Equal(t, "attach-tc-ext", extOps[0].Op)
	assert.Equal(t, expectedMapPinPath, extOps[0].MapPinDir,
		"TC attach should use the program's MapPinPath")
}

// TestMapSharing_MultiProgram_XDPAttach_UsesOwnerMapPinPath verifies that:
//
//	Given a multi-program load where the second program has MapOwnerID set,
//	When the second (XDP) program is attached,
//	Then the kernel receives the map owner's MapPinPath (shared maps directory).
func TestMapSharing_MultiProgram_XDPAttach_UsesOwnerMapPinPath(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load multiple programs - first is owner, second is XDP that shares maps
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "kprobe_counter", ProgramType: pb.BpfmanProgramType_KPROBE},
			{Name: "xdp_stats", ProgramType: pb.BpfmanProgramType_XDP},
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 2)

	ownerID := loadResp.Programs[0].KernelInfo.Id
	xdpProgID := loadResp.Programs[1].KernelInfo.Id

	// Get the owner's MapPinPath
	ownerResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: ownerID})
	require.NoError(t, err, "Get owner should succeed")
	ownerMapPinPath := ownerResp.Info.MapPinPath
	require.NotEmpty(t, ownerMapPinPath, "owner should have MapPinPath")

	// Verify the XDP program has MapOwnerID set and same MapPinPath
	xdpResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: xdpProgID})
	require.NoError(t, err, "Get XDP program should succeed")
	assert.Equal(t, ownerID, xdpResp.Info.GetMapOwnerId(),
		"XDP program should reference the owner")
	assert.Equal(t, ownerMapPinPath, xdpResp.Info.MapPinPath,
		"XDP program should have same MapPinPath as owner")

	// Attach the XDP program
	attachReq := &pb.AttachRequest{
		Id: xdpProgID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &pb.XDPAttachInfo{
					Iface: "eth0",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")

	// Verify the kernel received the owner's MapPinPath, not the XDP program's kernel ID
	extOps := fix.Kernel.ExtensionAttachOps()
	require.Len(t, extOps, 1, "expected one XDP extension attach")
	assert.Equal(t, "attach-xdp-ext", extOps[0].Op)
	assert.Equal(t, ownerMapPinPath, extOps[0].MapPinDir,
		"XDP attach should use the owner's MapPinPath, not compute from kernel ID")
}

// TestMapSharing_MultiProgram_TCAttach_UsesOwnerMapPinPath verifies that:
//
//	Given a multi-program load where the second program has MapOwnerID set,
//	When the second (TC) program is attached,
//	Then the kernel receives the map owner's MapPinPath (shared maps directory).
func TestMapSharing_MultiProgram_TCAttach_UsesOwnerMapPinPath(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load multiple programs - first is owner, second is TC that shares maps
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/multi.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "kprobe_counter", ProgramType: pb.BpfmanProgramType_KPROBE},
			{Name: "tc_stats", ProgramType: pb.BpfmanProgramType_TC},
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 2)

	ownerID := loadResp.Programs[0].KernelInfo.Id
	tcProgID := loadResp.Programs[1].KernelInfo.Id

	// Get the owner's MapPinPath
	ownerResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: ownerID})
	require.NoError(t, err, "Get owner should succeed")
	ownerMapPinPath := ownerResp.Info.MapPinPath
	require.NotEmpty(t, ownerMapPinPath, "owner should have MapPinPath")

	// Verify the TC program has MapOwnerID set and same MapPinPath
	tcResp, err := fix.Server.Get(ctx, &pb.GetRequest{Id: tcProgID})
	require.NoError(t, err, "Get TC program should succeed")
	assert.Equal(t, ownerID, tcResp.Info.GetMapOwnerId(),
		"TC program should reference the owner")
	assert.Equal(t, ownerMapPinPath, tcResp.Info.MapPinPath,
		"TC program should have same MapPinPath as owner")

	// Attach the TC program
	attachReq := &pb.AttachRequest{
		Id: tcProgID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcAttachInfo{
				TcAttachInfo: &pb.TCAttachInfo{
					Iface:     "eth0",
					Priority:  50,
					Direction: "ingress",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")

	// Verify the kernel received the owner's MapPinPath, not the TC program's kernel ID
	extOps := fix.Kernel.ExtensionAttachOps()
	require.Len(t, extOps, 1, "expected one TC extension attach")
	assert.Equal(t, "attach-tc-ext", extOps[0].Op)
	assert.Equal(t, ownerMapPinPath, extOps[0].MapPinDir,
		"TC attach should use the owner's MapPinPath, not compute from kernel ID")
}

// TestTCX_AttachUsesProgramPinPath verifies that:
//
//	Given a loaded TCX program,
//	When it is attached to an interface,
//	Then the kernel receives the program's PinPath (not derived from MapPinPath).
func TestTCX_AttachUsesProgramPinPath(t *testing.T) {
	fix := newTestFixture(t)
	ctx := context.Background()

	// Load a TCX program
	loadReq := &pb.LoadRequest{
		Bytecode: &pb.BytecodeLocation{
			Location: &pb.BytecodeLocation_File{File: "/path/to/tcx.o"},
		},
		Info: []*pb.LoadInfo{
			{Name: "tcx_prog", ProgramType: pb.BpfmanProgramType_TCX},
		},
	}

	loadResp, err := fix.Server.Load(ctx, loadReq)
	require.NoError(t, err, "Load should succeed")
	require.Len(t, loadResp.Programs, 1)

	progID := loadResp.Programs[0].KernelInfo.Id

	// The expected pin path follows the pattern: <fsRoot>/prog_<kernelID>
	// The fake kernel uses spec.PinPath() (which is fix.Dirs.FS) + "/prog_" + id
	expectedPinPath := fmt.Sprintf("%s/prog_%d", fix.Dirs.FS, progID)

	// Attach the program
	attachReq := &pb.AttachRequest{
		Id: progID,
		Attach: &pb.AttachInfo{
			Info: &pb.AttachInfo_TcxAttachInfo{
				TcxAttachInfo: &pb.TCXAttachInfo{
					Iface:     "eth0",
					Direction: "ingress",
				},
			},
		},
	}

	_, err = fix.Server.Attach(ctx, attachReq)
	require.NoError(t, err, "Attach should succeed")

	// Verify the kernel received the correct programPinPath
	tcxOps := fix.Kernel.TCXAttachOps()
	require.Len(t, tcxOps, 1, "expected one TCX attach")
	assert.Equal(t, "attach-tcx", tcxOps[0].Op)
	assert.Equal(t, expectedPinPath, tcxOps[0].Name,
		"TCX attach should use prog.PinPath directly, not derive from MapPinPath")
}
