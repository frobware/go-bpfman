package domain

// KernelMap represents a BPF map in the kernel.
type KernelMap struct {
	ID         uint32
	Name       string
	MapType    string
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	BTFId      uint32
	Memlock    *uint64 // nil if not available
	Frozen     bool
}

// KernelLink represents a BPF link in the kernel.
type KernelLink struct {
	ID          uint32
	ProgramID   uint32
	LinkType    string
	AttachType  string
	TargetIface string
	TargetObjID uint32
	TargetBTFId uint32
}
