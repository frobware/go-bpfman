package ebpf

import (
	"time"

	"github.com/cilium/ebpf"

	"github.com/frobware/go-bpfman/pkg/bpfman"
)

// programInfo wraps cilium/ebpf's ProgramInfo to implement bpfman.KernelProgramInfo.
type programInfo struct {
	raw *ebpf.ProgramInfo
}

// NewProgramInfo creates a KernelProgramInfo from a cilium/ebpf ProgramInfo.
func NewProgramInfo(info *ebpf.ProgramInfo) bpfman.KernelProgramInfo {
	return &programInfo{raw: info}
}

func (p *programInfo) ID() uint32 {
	id, _ := p.raw.ID()
	return uint32(id)
}

func (p *programInfo) Name() string {
	return p.raw.Name
}

func (p *programInfo) Type() bpfman.ProgramType {
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

func (p *programInfo) Tag() string {
	return p.raw.Tag
}

func (p *programInfo) MapIDs() []uint32 {
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

func (p *programInfo) BTFId() uint32 {
	id, _ := p.raw.BTFID()
	return uint32(id)
}

func (p *programInfo) BytesXlated() uint32 {
	size, _ := p.raw.TranslatedSize()
	return uint32(size)
}

func (p *programInfo) BytesJited() uint32 {
	size, _ := p.raw.JitedSize()
	return size
}

func (p *programInfo) VerifiedInstructions() uint32 {
	insns, _ := p.raw.VerifiedInstructions()
	return insns
}

func (p *programInfo) LoadedAt() time.Time {
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

func (p *programInfo) MemoryLocked() uint64 {
	mem, _ := p.raw.Memlock()
	return mem
}

func (p *programInfo) GPLCompatible() bool {
	// cilium/ebpf doesn't directly expose GPL compatibility
	// We'll return true as a default since most BPF programs are GPL
	// TODO: investigate if there's a way to get this from cilium/ebpf
	return true
}

// Verify interface compliance at compile time.
var _ bpfman.KernelProgramInfo = (*programInfo)(nil)
