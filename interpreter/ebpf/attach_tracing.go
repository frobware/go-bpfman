package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/frobware/go-bpfman"
)

// AttachTracepoint attaches a pinned program to a tracepoint.
func (k *kernelAdapter) AttachTracepoint(progPinPath, group, name, linkPinPath string) (bpfman.ManagedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	// Get program info to find kernel program ID
	progInfo, err := prog.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get program info: %w", err)
	}
	progID, _ := progInfo.ID()

	lnk, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach to tracepoint %s:%s: %w", group, name, err)
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get link info: %w", err)
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            bpfman.LinkTypeTracepoint,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.TracepointDetails{Group: group, Name: name},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachKprobe attaches a pinned program to a kernel function.
// If retprobe is true, attaches as a kretprobe instead of kprobe.
func (k *kernelAdapter) AttachKprobe(progPinPath, fnName string, offset uint64, retprobe bool, linkPinPath string) (bpfman.ManagedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	// Get program info to find kernel program ID
	progInfo, err := prog.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get program info: %w", err)
	}
	progID, _ := progInfo.ID()

	// Build kprobe options
	opts := &link.KprobeOptions{
		Offset: offset,
	}

	// Attach as kprobe or kretprobe
	var lnk link.Link
	if retprobe {
		lnk, err = link.Kretprobe(fnName, prog, opts)
	} else {
		lnk, err = link.Kprobe(fnName, prog, opts)
	}
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach kprobe to %s: %w", fnName, err)
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get link info: %w", err)
	}

	// Determine link type based on retprobe flag
	linkType := bpfman.LinkTypeKprobe
	if retprobe {
		linkType = bpfman.LinkTypeKretprobe
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.KprobeDetails{FnName: fnName, Offset: offset, Retprobe: retprobe},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachFentry attaches a pinned fentry program to a kernel function.
// The target function was specified at load time and is stored in the program.
func (k *kernelAdapter) AttachFentry(progPinPath, fnName, linkPinPath string) (bpfman.ManagedLink, error) {
	return k.attachTracing(progPinPath, fnName, linkPinPath, bpfman.LinkTypeFentry)
}

// AttachFexit attaches a pinned fexit program to a kernel function.
// The target function was specified at load time and is stored in the program.
func (k *kernelAdapter) AttachFexit(progPinPath, fnName, linkPinPath string) (bpfman.ManagedLink, error) {
	return k.attachTracing(progPinPath, fnName, linkPinPath, bpfman.LinkTypeFexit)
}

// attachTracing is the shared implementation for fentry and fexit attachment.
func (k *kernelAdapter) attachTracing(progPinPath, fnName, linkPinPath string, linkType bpfman.LinkType) (bpfman.ManagedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	// Get program info to find kernel program ID
	progInfo, err := prog.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get program info: %w", err)
	}
	progID, _ := progInfo.ID()

	// Attach using link.AttachTracing - the program already has the target
	// function and attach type set from load time (via ELF section name).
	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach tracing to %s: %w", fnName, err)
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get link info: %w", err)
	}

	// Build details based on link type
	var details bpfman.LinkDetails
	if linkType == bpfman.LinkTypeFentry {
		details = bpfman.FentryDetails{FnName: fnName}
	} else {
		details = bpfman.FexitDetails{FnName: fnName}
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         details,
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}
