package bpfman

import "time"

// LinkSummary contains the common fields from link_registry.
// This is the primary polymorphic type for links - most operations
// only need these fields without type-specific details.
// KernelLinkID is the primary identifier (kernel-assigned link ID).
type LinkSummary struct {
	KernelLinkID    uint32    `json:"kernel_link_id"`
	LinkType        LinkType  `json:"link_type"`
	KernelProgramID uint32    `json:"kernel_program_id"`
	PinPath         string    `json:"pin_path,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}
