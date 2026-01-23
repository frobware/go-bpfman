package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"

	"github.com/frobware/go-bpfman/pkg/bpfman"
)

// linkInfo wraps cilium/ebpf's link.Info to implement bpfman.KernelLinkInfo.
type linkInfo struct {
	raw *link.Info
}

// NewLinkInfo creates a KernelLinkInfo from a cilium/ebpf link.Info.
func NewLinkInfo(info *link.Info) bpfman.KernelLinkInfo {
	return &linkInfo{raw: info}
}

func (l *linkInfo) ID() uint32 {
	return uint32(l.raw.ID)
}

func (l *linkInfo) ProgramID() uint32 {
	return uint32(l.raw.Program)
}

func (l *linkInfo) LinkType() string {
	return linkTypeString(l.raw.Type)
}

func (l *linkInfo) AttachType() string {
	// Extract attach type from type-specific info
	if tracing := l.raw.Tracing(); tracing != nil {
		return fmt.Sprintf("%d", tracing.AttachType)
	}
	if tcx := l.raw.TCX(); tcx != nil {
		return fmt.Sprintf("%d", tcx.AttachType)
	}
	if cgroup := l.raw.Cgroup(); cgroup != nil {
		return fmt.Sprintf("%d", cgroup.AttachType)
	}
	if netns := l.raw.NetNs(); netns != nil {
		return fmt.Sprintf("%d", netns.AttachType)
	}
	if netkit := l.raw.Netkit(); netkit != nil {
		return fmt.Sprintf("%d", netkit.AttachType)
	}
	return ""
}

func (l *linkInfo) TargetObjID() uint32 {
	// Return the target object ID based on link type
	if xdp := l.raw.XDP(); xdp != nil {
		return xdp.Ifindex
	}
	if tcx := l.raw.TCX(); tcx != nil {
		return tcx.Ifindex
	}
	if netns := l.raw.NetNs(); netns != nil {
		return netns.NetnsIno
	}
	if netkit := l.raw.Netkit(); netkit != nil {
		return netkit.Ifindex
	}
	if tracing := l.raw.Tracing(); tracing != nil {
		return tracing.TargetObjId
	}
	return 0
}

func (l *linkInfo) TargetBTFId() uint32 {
	if tracing := l.raw.Tracing(); tracing != nil {
		return uint32(tracing.TargetBtfId)
	}
	return 0
}

// Verify interface compliance at compile time.
var _ bpfman.KernelLinkInfo = (*linkInfo)(nil)
