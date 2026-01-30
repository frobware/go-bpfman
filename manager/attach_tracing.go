package manager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/lock"
)

// AttachTracepoint attaches a pinned program to a tracepoint.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachTracepoint(ctx context.Context, spec bpfman.TracepointAttachSpec, opts bpfman.AttachOpts) (bpfman.Link, error) {
	programKernelID := spec.ProgramID()
	group := spec.Group()
	name := spec.Name()

	// FETCH: Verify program exists in store
	_, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return bpfman.Link{}, bpfman.ErrProgramNotFound{ID: programKernelID}
		}
		return bpfman.Link{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := m.dirs.ProgPinPath(programKernelID)

	// COMPUTE: Calculate link pin path from conventions
	linkName := fmt.Sprintf("%s_%s", group, name)
	linksDir := m.dirs.LinkPinDir(programKernelID)
	linkPinPath := filepath.Join(linksDir, linkName)

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachTracepoint(ctx, progPinPath, group, name, linkPinPath)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach tracepoint %s/%s: %w", group, name, err)
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, linkPinPath)
	})

	// EXECUTE: Save link metadata directly to store
	// The link ID is populated by the kernel attach function (kernel-assigned for real links)
	// Set the program ID before saving (kernel adapter doesn't know it)
	link.Spec.ProgramID = programKernelID
	if err := m.store.SaveLink(ctx, link.Spec); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.Link{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.Link{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.InfoContext(ctx, "attached tracepoint",
		"link_id", link.Spec.ID,
		"program_id", programKernelID,
		"tracepoint", group+"/"+name,
		"pin_path", linkPinPath)

	return link, nil
}

// AttachKprobe attaches a pinned program to a kernel function.
// retprobe is derived from the program type stored in the database.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachKprobe(ctx context.Context, spec bpfman.KprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.Link, error) {
	programKernelID := spec.ProgramID()
	fnName := spec.FnName()
	offset := spec.Offset()

	// FETCH: Get program to determine if it's a kretprobe
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return bpfman.Link{}, bpfman.ErrProgramNotFound{ID: programKernelID}
		}
		return bpfman.Link{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Derive retprobe from program type
	retprobe := prog.Load.ProgramType == bpfman.ProgramTypeKretprobe

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := m.dirs.ProgPinPath(programKernelID)

	// COMPUTE: Calculate link pin path from conventions
	linkName := fnName
	if retprobe {
		linkName = "ret_" + linkName
	}
	linksDir := m.dirs.LinkPinDir(programKernelID)
	linkPinPath := filepath.Join(linksDir, linkName)

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachKprobe(ctx, progPinPath, fnName, offset, retprobe, linkPinPath)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach kprobe %s: %w", fnName, err)
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, linkPinPath)
	})

	// EXECUTE: Save link metadata directly to store
	// The link ID is populated by the kernel attach function (kernel-assigned for real links)
	// Set the program ID before saving (kernel adapter doesn't know it)
	link.Spec.ProgramID = programKernelID
	if err := m.store.SaveLink(ctx, link.Spec); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.Link{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.Link{}, fmt.Errorf("save link metadata: %w", err)
	}

	probeType := "kprobe"
	if retprobe {
		probeType = "kretprobe"
	}
	m.logger.InfoContext(ctx, "attached "+probeType,
		"link_id", link.Spec.ID,
		"program_id", programKernelID,
		"fn_name", fnName,
		"offset", offset,
		"pin_path", linkPinPath)

	return link, nil
}

// AttachUprobe attaches a pinned program to a user-space function.
// retprobe is derived from the program type stored in the database.
//
// The scope parameter is required for container uprobes (containerPid > 0)
// to pass the lock fd to the helper subprocess. For local uprobes, scope
// is not used but accepted for API uniformity.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachUprobe(ctx context.Context, scope lock.WriterScope, spec bpfman.UprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.Link, error) {
	programKernelID := spec.ProgramID()
	target := spec.Target()
	fnName := spec.FnName()
	offset := spec.Offset()
	containerPid := spec.ContainerPid()

	// FETCH: Get program to determine if it's a uretprobe
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return bpfman.Link{}, bpfman.ErrProgramNotFound{ID: programKernelID}
		}
		return bpfman.Link{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Derive retprobe from program type
	retprobe := prog.Load.ProgramType == bpfman.ProgramTypeUretprobe

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := m.dirs.ProgPinPath(programKernelID)

	// COMPUTE: Calculate link pin path from conventions
	linkName := fnName
	if retprobe {
		linkName = "ret_" + linkName
	}
	linksDir := m.dirs.LinkPinDir(programKernelID)
	linkPinPath := filepath.Join(linksDir, linkName)

	// KERNEL I/O: Choose local vs container method based on spec
	var link bpfman.Link
	if containerPid > 0 {
		// Container uprobe - scope required
		if scope == nil {
			return bpfman.Link{}, fmt.Errorf("container uprobe requires lock scope (containerPid=%d)", containerPid)
		}
		link, err = m.kernel.AttachUprobeContainer(ctx, scope, progPinPath, target, fnName, offset, retprobe, linkPinPath, containerPid)
	} else {
		// Local uprobe - no scope needed
		link, err = m.kernel.AttachUprobeLocal(ctx, progPinPath, target, fnName, offset, retprobe, linkPinPath)
	}
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach uprobe %s to %s: %w", fnName, target, err)
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, linkPinPath)
	})

	// EXECUTE: Save link metadata directly to store
	// The link ID is populated by the kernel attach function (kernel-assigned or synthetic)
	// Set the program ID before saving (kernel adapter doesn't know it)
	link.Spec.ProgramID = programKernelID
	if err := m.store.SaveLink(ctx, link.Spec); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.Link{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.Link{}, fmt.Errorf("save link metadata: %w", err)
	}

	probeType := "uprobe"
	if retprobe {
		probeType = "uretprobe"
	}
	m.logger.InfoContext(ctx, "attached "+probeType,
		"link_id", link.Spec.ID,
		"program_id", programKernelID,
		"target", target,
		"fn_name", fnName,
		"offset", offset,
		"container_pid", containerPid,
		"pin_path", linkPinPath)

	return link, nil
}

// AttachFentry attaches a pinned fentry program to its target kernel function.
// The target function was specified at load time and stored in the program's AttachFunc.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachFentry(ctx context.Context, spec bpfman.FentryAttachSpec, opts bpfman.AttachOpts) (bpfman.Link, error) {
	programKernelID := spec.ProgramID()

	// FETCH: Get program metadata to access AttachFunc
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return bpfman.Link{}, bpfman.ErrProgramNotFound{ID: programKernelID}
		}
		return bpfman.Link{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	fnName := prog.Load.AttachFunc
	if fnName == "" {
		return bpfman.Link{}, fmt.Errorf("program %d has no attach function (fentry requires attach function at load time)", programKernelID)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := m.dirs.ProgPinPath(programKernelID)

	// COMPUTE: Calculate link pin path from conventions
	linkName := "fentry_" + fnName
	linksDir := m.dirs.LinkPinDir(programKernelID)
	linkPinPath := filepath.Join(linksDir, linkName)

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachFentry(ctx, progPinPath, fnName, linkPinPath)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach fentry %s: %w", fnName, err)
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, linkPinPath)
	})

	// EXECUTE: Save link metadata directly to store
	// The link ID is populated by the kernel attach function (kernel-assigned for real links)
	// Set the program ID before saving (kernel adapter doesn't know it)
	link.Spec.ProgramID = programKernelID
	if err := m.store.SaveLink(ctx, link.Spec); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.Link{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.Link{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.InfoContext(ctx, "attached fentry",
		"link_id", link.Spec.ID,
		"program_id", programKernelID,
		"fn_name", fnName,
		"pin_path", linkPinPath)

	return link, nil
}

// AttachFexit attaches a pinned fexit program to its target kernel function.
// The target function was specified at load time and stored in the program's AttachFunc.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachFexit(ctx context.Context, spec bpfman.FexitAttachSpec, opts bpfman.AttachOpts) (bpfman.Link, error) {
	programKernelID := spec.ProgramID()

	// FETCH: Get program metadata to access AttachFunc
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return bpfman.Link{}, bpfman.ErrProgramNotFound{ID: programKernelID}
		}
		return bpfman.Link{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	fnName := prog.Load.AttachFunc
	if fnName == "" {
		return bpfman.Link{}, fmt.Errorf("program %d has no attach function (fexit requires attach function at load time)", programKernelID)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := m.dirs.ProgPinPath(programKernelID)

	// COMPUTE: Calculate link pin path from conventions
	linkName := "fexit_" + fnName
	linksDir := m.dirs.LinkPinDir(programKernelID)
	linkPinPath := filepath.Join(linksDir, linkName)

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachFexit(ctx, progPinPath, fnName, linkPinPath)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach fexit %s: %w", fnName, err)
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, linkPinPath)
	})

	// EXECUTE: Save link metadata directly to store
	// The link ID is populated by the kernel attach function (kernel-assigned for real links)
	// Set the program ID before saving (kernel adapter doesn't know it)
	link.Spec.ProgramID = programKernelID
	if err := m.store.SaveLink(ctx, link.Spec); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.Link{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.Link{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.InfoContext(ctx, "attached fexit",
		"link_id", link.Spec.ID,
		"program_id", programKernelID,
		"fn_name", fnName,
		"pin_path", linkPinPath)

	return link, nil
}
