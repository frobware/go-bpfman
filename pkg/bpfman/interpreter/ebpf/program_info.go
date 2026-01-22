package ebpf

import (
	"time"

	"github.com/cilium/ebpf"

	"github.com/frobware/go-bpfman/pkg/bpfman"
)

// ProgramInfo wraps cilium/ebpf's ProgramInfo to implement bpfman.KernelProgramInfo.
type ProgramInfo struct {
	raw *ebpf.ProgramInfo
}

// NewProgramInfo creates a KernelProgramInfo from a cilium/ebpf ProgramInfo.
func NewProgramInfo(info *ebpf.ProgramInfo) *ProgramInfo {
	return &ProgramInfo{raw: info}
}

func (p *ProgramInfo) ID() uint32 {
	id, _ := p.raw.ID()
	return uint32(id)
}

func (p *ProgramInfo) Name() string {
	return p.raw.Name
}

func (p *ProgramInfo) Type() bpfman.ProgramType {
	// Map cilium/ebpf ProgramType to our ProgramType
	switch p.raw.Type {
	case ebpf.XDP:
		return bpfman.ProgramTypeXDP
	case ebpf.SchedCLS:
		return bpfman.ProgramTypeTC
	case ebpf.Tracing:
		// Could be fentry/fexit, but we can't distinguish here
		return bpfman.ProgramTypeFentry
	case ebpf.TracePoint:
		return bpfman.ProgramTypeTracepoint
	case ebpf.Kprobe:
		return bpfman.ProgramTypeKprobe
	default:
		return bpfman.ProgramTypeUnspecified
	}
}

func (p *ProgramInfo) Tag() string {
	return p.raw.Tag
}

func (p *ProgramInfo) MapIDs() []uint32 {
	ids, ok := p.raw.MapIDs()
	if !ok {
		return nil
	}
	result := make([]uint32, len(ids))
	for i, id := range ids {
		result[i] = uint32(id)
	}
	return result
}

func (p *ProgramInfo) BTFId() uint32 {
	id, _ := p.raw.BTFID()
	return uint32(id)
}

func (p *ProgramInfo) BytesXlated() uint32 {
	size, _ := p.raw.TranslatedSize()
	return uint32(size)
}

func (p *ProgramInfo) BytesJited() uint32 {
	size, _ := p.raw.JitedSize()
	return size
}

func (p *ProgramInfo) VerifiedInstructions() uint32 {
	insns, _ := p.raw.VerifiedInstructions()
	return insns
}

func (p *ProgramInfo) LoadedAt() time.Time {
	// LoadTime returns duration since boot
	loadTime, ok := p.raw.LoadTime()
	if !ok {
		return time.Time{}
	}
	// Convert to wall clock time: boot time + load duration
	// Boot time = Now - system uptime, but we approximate using LoadTime
	// Since LoadTime is duration since boot, we calculate:
	// loaded_at = now - (uptime - load_time) = now - uptime + load_time
	// We don't have uptime directly, so we use a simpler approximation:
	// Just return current time minus the age of the program
	// This is approximate but usually accurate enough
	return bootTime().Add(loadTime)
}

func (p *ProgramInfo) MemoryLocked() uint64 {
	mem, _ := p.raw.Memlock()
	return mem
}

func (p *ProgramInfo) GPLCompatible() bool {
	// cilium/ebpf doesn't directly expose GPL compatibility
	// We'll return true as a default since most BPF programs are GPL
	// TODO: investigate if there's a way to get this from cilium/ebpf
	return true
}

// Verify interface compliance at compile time.
var _ bpfman.KernelProgramInfo = (*ProgramInfo)(nil)
