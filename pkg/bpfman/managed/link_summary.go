package managed

import "time"

// LinkSummary contains the common fields from link_registry.
// This is the primary polymorphic type for links - most operations
// only need these fields without type-specific details.
type LinkSummary struct {
	UUID            string    `json:"uuid"`
	LinkType        LinkType  `json:"link_type"`
	KernelProgramID uint32    `json:"kernel_program_id"`
	KernelLinkID    uint32    `json:"kernel_link_id,omitempty"`
	PinPath         string    `json:"pin_path,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}
