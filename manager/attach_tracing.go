package manager

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
)

// AttachTracepoint attaches a pinned program to a tracepoint.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachTracepoint(ctx context.Context, spec bpfman.TracepointAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	group := spec.Group()
	name := spec.Name()
	linkPinPath := opts.LinkPinPath

	// FETCH: Verify program exists in store
	_, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := fmt.Sprintf("%s_%s", group, name)
		linksDir := m.dirs.LinkPinDir(programKernelID)
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel (returns ManagedLink with full info)
	link, err := m.kernel.AttachTracepoint(progPinPath, group, name, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach tracepoint %s/%s: %w", group, name, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachTracepointAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, group, name)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached tracepoint",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"tracepoint", group+"/"+name,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachTracepointAction is a pure function that builds the save action
// for a tracepoint attachment.
func computeAttachTracepointAction(programKernelID, kernelLinkID uint32, pinPath, group, name string) action.SaveTracepointLink {
	return action.SaveTracepointLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        bpfman.LinkTypeTracepoint,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.TracepointDetails{
			Group: group,
			Name:  name,
		},
	}
}

// AttachKprobe attaches a pinned program to a kernel function.
// retprobe is derived from the program type stored in the database.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachKprobe(ctx context.Context, spec bpfman.KprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	fnName := spec.FnName()
	offset := spec.Offset()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program to determine if it's a kretprobe
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Derive retprobe from program type
	retprobe := prog.ProgramType == bpfman.ProgramTypeKretprobe

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := fnName
		if retprobe {
			linkName = "ret_" + linkName
		}
		linksDir := m.dirs.LinkPinDir(programKernelID)
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel (returns ManagedLink with full info)
	link, err := m.kernel.AttachKprobe(progPinPath, fnName, offset, retprobe, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach kprobe %s: %w", fnName, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachKprobeAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, fnName, offset, retprobe)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	probeType := "kprobe"
	if retprobe {
		probeType = "kretprobe"
	}
	m.logger.Info("attached "+probeType,
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"fn_name", fnName,
		"offset", offset,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachKprobeAction is a pure function that builds the save action
// for a kprobe/kretprobe attachment.
func computeAttachKprobeAction(programKernelID, kernelLinkID uint32, pinPath, fnName string, offset uint64, retprobe bool) action.SaveKprobeLink {
	linkType := bpfman.LinkTypeKprobe
	if retprobe {
		linkType = bpfman.LinkTypeKretprobe
	}
	return action.SaveKprobeLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        linkType,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.KprobeDetails{
			FnName:   fnName,
			Offset:   offset,
			Retprobe: retprobe,
		},
	}
}

// AttachUprobe attaches a pinned program to a user-space function.
// retprobe is derived from the program type stored in the database.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachUprobe(ctx context.Context, spec bpfman.UprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	target := spec.Target()
	fnName := spec.FnName()
	offset := spec.Offset()
	containerPid := spec.ContainerPid()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program to determine if it's a uretprobe
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Derive retprobe from program type
	retprobe := prog.ProgramType == bpfman.ProgramTypeUretprobe

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := fnName
		if retprobe {
			linkName = "ret_" + linkName
		}
		linksDir := m.dirs.LinkPinDir(programKernelID)
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel (returns ManagedLink with full info)
	link, err := m.kernel.AttachUprobe(progPinPath, target, fnName, offset, retprobe, linkPinPath, containerPid)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach uprobe %s to %s: %w", fnName, target, err)
	}

	// Get kernel link ID (0 for perf_event-based links which have no kernel link)
	var kernelLinkID uint32
	if link.Kernel != nil {
		kernelLinkID = link.Kernel.ID()
	} else {
		kernelLinkID = link.Managed.KernelLinkID
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachUprobeAction(programKernelID, kernelLinkID, link.Managed.PinPath, target, fnName, offset, retprobe, containerPid)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	probeType := "uprobe"
	if retprobe {
		probeType = "uretprobe"
	}
	m.logger.Info("attached "+probeType,
		"kernel_link_id", kernelLinkID,
		"program_id", programKernelID,
		"target", target,
		"fn_name", fnName,
		"offset", offset,
		"container_pid", containerPid,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachUprobeAction is a pure function that builds the save action
// for a uprobe/uretprobe attachment.
func computeAttachUprobeAction(programKernelID, kernelLinkID uint32, pinPath, target, fnName string, offset uint64, retprobe bool, containerPid int32) action.SaveUprobeLink {
	linkType := bpfman.LinkTypeUprobe
	if retprobe {
		linkType = bpfman.LinkTypeUretprobe
	}
	return action.SaveUprobeLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        linkType,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.UprobeDetails{
			Target:       target,
			FnName:       fnName,
			Offset:       offset,
			Retprobe:     retprobe,
			ContainerPid: containerPid,
		},
	}
}

// AttachFentry attaches a pinned fentry program to its target kernel function.
// The target function was specified at load time and stored in the program's AttachFunc.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachFentry(ctx context.Context, spec bpfman.FentryAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to access AttachFunc
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	fnName := prog.AttachFunc
	if fnName == "" {
		return bpfman.LinkSummary{}, fmt.Errorf("program %d has no attach function (fentry requires attach function at load time)", programKernelID)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := "fentry_" + fnName
		linksDir := m.dirs.LinkPinDir(programKernelID)
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachFentry(progPinPath, fnName, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach fentry %s: %w", fnName, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachFentryAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, fnName)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached fentry",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"fn_name", fnName,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachFentryAction is a pure function that builds the save action
// for a fentry attachment.
func computeAttachFentryAction(programKernelID, kernelLinkID uint32, pinPath, fnName string) action.SaveFentryLink {
	return action.SaveFentryLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        bpfman.LinkTypeFentry,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.FentryDetails{
			FnName: fnName,
		},
	}
}

// AttachFexit attaches a pinned fexit program to its target kernel function.
// The target function was specified at load time and stored in the program's AttachFunc.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachFexit(ctx context.Context, spec bpfman.FexitAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to access AttachFunc
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	fnName := prog.AttachFunc
	if fnName == "" {
		return bpfman.LinkSummary{}, fmt.Errorf("program %d has no attach function (fexit requires attach function at load time)", programKernelID)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := "fexit_" + fnName
		linksDir := m.dirs.LinkPinDir(programKernelID)
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachFexit(progPinPath, fnName, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach fexit %s: %w", fnName, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachFexitAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, fnName)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached fexit",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"fn_name", fnName,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachFexitAction is a pure function that builds the save action
// for a fexit attachment.
func computeAttachFexitAction(programKernelID, kernelLinkID uint32, pinPath, fnName string) action.SaveFexitLink {
	return action.SaveFexitLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        bpfman.LinkTypeFexit,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.FexitDetails{
			FnName: fnName,
		},
	}
}
