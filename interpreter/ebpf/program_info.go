package ebpf

import (
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/frobware/go-bpfman"
)

// bpfProgInfo mirrors the kernel's bpf_prog_info struct up to and including
// the gpl_compatible bitfield. We only need the fields up to that point.
type bpfProgInfo struct {
	Type            uint32
	ID              uint32
	Tag             [8]byte
	JitedProgLen    uint32
	XlatedProgLen   uint32
	JitedProgInsns  uint64
	XlatedProgInsns uint64
	LoadTime        uint64
	CreatedByUID    uint32
	NrMapIds        uint32
	MapIds          uint64
	Name            [16]byte
	Ifindex         uint32
	// This field contains gpl_compatible as bit 0
	Flags uint32
}

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
	id, ok := p.raw.ID()
	if !ok {
		return true // Default to true if we can't get the ID
	}
	return getGPLCompatible(uint32(id))
}

// getGPLCompatible queries the kernel for the GPL compatible flag of a BPF program.
// cilium/ebpf doesn't expose this field, so we make a direct syscall.
func getGPLCompatible(progID uint32) bool {
	// BPF_PROG_GET_FD_BY_ID to get a file descriptor for the program
	attr := struct {
		progID uint32
		nextID uint32
		flags  uint32
	}{
		progID: progID,
	}

	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(unix.BPF_PROG_GET_FD_BY_ID),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return true // Default to true on error
	}
	defer unix.Close(int(fd))

	// Query program info using BPF_OBJ_GET_INFO_BY_FD
	var info bpfProgInfo
	infoLen := uint32(unsafe.Sizeof(info))

	infoAttr := struct {
		fd      uint32
		infoLen uint32
		info    uint64
	}{
		fd:      uint32(fd),
		infoLen: infoLen,
		info:    uint64(uintptr(unsafe.Pointer(&info))),
	}

	_, _, errno = unix.Syscall(
		unix.SYS_BPF,
		uintptr(unix.BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&infoAttr)),
		unsafe.Sizeof(infoAttr),
	)
	if errno != 0 {
		return true // Default to true on error
	}

	// gpl_compatible is bit 0 of the Flags field
	return (info.Flags & 1) != 0
}

// Verify interface compliance at compile time.
var _ bpfman.KernelProgramInfo = (*programInfo)(nil)
