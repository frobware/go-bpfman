// Package bpf provides BPF program management using cilium/ebpf.
package bpf

// ProgramType represents the type of BPF program.
type ProgramType uint32

// Program types supported by bpfman.
const (
	ProgramTypeUnspec ProgramType = iota
	ProgramTypeSocketFilter
	ProgramTypeKprobe
	ProgramTypeSchedCls
	ProgramTypeSchedAct
	ProgramTypeTracepoint
	ProgramTypeXDP
	ProgramTypePerfEvent
	ProgramTypeCgroupSkb
	ProgramTypeCgroupSock
	ProgramTypeLwtIn
	ProgramTypeLwtOut
	ProgramTypeLwtXmit
	ProgramTypeSockOps
	ProgramTypeSkSkb
	ProgramTypeCgroupDevice
	ProgramTypeSkMsg
	ProgramTypeRawTracepoint
	ProgramTypeCgroupSockAddr
	ProgramTypeLwtSeg6local
	ProgramTypeLircMode2
	ProgramTypeSkReuseport
	ProgramTypeFlowDissector
	ProgramTypeCgroupSysctl
	ProgramTypeRawTracepointWritable
	ProgramTypeCgroupSockopt
	ProgramTypeTracing
	ProgramTypeStructOps
	ProgramTypeExt
	ProgramTypeLsm
	ProgramTypeSkLookup
	ProgramTypeSyscall
	ProgramTypeNetfilter
)

// MapType represents the type of BPF map.
type MapType uint32

// Program represents a loaded BPF program.
type Program struct {
	ID         uint32      `json:"id"`
	Name       string      `json:"name"`
	Type       ProgramType `json:"type"`
	PinnedPath string      `json:"pinned_path,omitempty"`
}

// Map represents a BPF map.
type Map struct {
	ID         uint32  `json:"id"`
	Name       string  `json:"name"`
	Type       MapType `json:"type"`
	KeySize    uint32  `json:"key_size"`
	ValueSize  uint32  `json:"value_size"`
	MaxEntries uint32  `json:"max_entries"`
	PinnedPath string  `json:"pinned_path,omitempty"`
}

// LoadResult contains the result of loading a BPF program.
type LoadResult struct {
	Program Program `json:"program"`
	Maps    []Map   `json:"maps"`
	PinDir  string  `json:"pin_dir"`
}
