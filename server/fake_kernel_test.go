package server_test

import (
	"context"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/kernel"
)

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

func (f *fakeKernel) AttachTCDispatcherWithPaths(ifindex int, ifname, progPinPath, direction string, numProgs int, proceedOn uint32, netns string) (*interpreter.TCDispatcherResult, error) {
	dispatcherID := f.nextID.Add(1)
	handle := f.nextID.Add(1)
	// Add dispatcher program to programs map so GC sees it as valid
	f.programs[dispatcherID] = fakeProgram{
		id:          dispatcherID,
		name:        "tc_dispatcher",
		programType: bpfman.ProgramTypeTC,
		pinPath:     progPinPath,
	}
	return &interpreter.TCDispatcherResult{
		DispatcherID:  dispatcherID,
		DispatcherPin: progPinPath,
		Handle:        handle,
		Priority:      50,
	}, nil
}

func (f *fakeKernel) DetachTCFilter(ifindex int, ifname string, parent uint32, priority uint16, handle uint32) error {
	return nil
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
