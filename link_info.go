package bpfman

import (
	"time"
)

// LinkInfo is the concrete implementation of ManagedLinkInfo.
// It holds what bpfman tracks about a link.
type LinkInfo struct {
	kernelLinkID    uint32
	kernelProgramID uint32
	linkType        LinkType
	pinPath         string
	createdAt       time.Time
	details         LinkDetails
}

// NewLinkInfo creates a new LinkInfo.
func NewLinkInfo(kernelLinkID, kernelProgramID uint32, linkType LinkType, pinPath string, createdAt time.Time, details LinkDetails) *LinkInfo {
	return &LinkInfo{
		kernelLinkID:    kernelLinkID,
		kernelProgramID: kernelProgramID,
		linkType:        linkType,
		pinPath:         pinPath,
		createdAt:       createdAt,
		details:         details,
	}
}

// NewLinkInfoFromSummary creates a LinkInfo from a LinkSummary and optional details.
func NewLinkInfoFromSummary(summary LinkSummary, details LinkDetails) *LinkInfo {
	return &LinkInfo{
		kernelLinkID:    summary.KernelLinkID,
		kernelProgramID: summary.KernelProgramID,
		linkType:        summary.LinkType,
		pinPath:         summary.PinPath,
		createdAt:       summary.CreatedAt,
		details:         details,
	}
}

func (l *LinkInfo) KernelLinkID() uint32    { return l.kernelLinkID }
func (l *LinkInfo) KernelProgramID() uint32 { return l.kernelProgramID }
func (l *LinkInfo) LinkType() string        { return string(l.linkType) }
func (l *LinkInfo) PinPath() string         { return l.pinPath }
func (l *LinkInfo) CreatedAt() time.Time    { return l.createdAt }
func (l *LinkInfo) Details() any {
	return l.details
}

// Verify interface compliance at compile time.
var _ ManagedLinkInfo = (*LinkInfo)(nil)
