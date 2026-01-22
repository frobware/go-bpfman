package managed

import (
	"slices"
	"time"
)

// Program contains metadata for programs managed by bpfman.
// This is what we store - the kernel is the source of truth for runtime state.
// A Program only exists in the store after successful load.
type Program struct {
	LoadSpec     LoadSpec          `json:"load_spec"`
	Tags         []string          `json:"tags,omitempty"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
	Description  string            `json:"description,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// WithTag returns a new Program with the tag added.
func (p Program) WithTag(tag string) Program {
	return Program{
		LoadSpec:     p.LoadSpec,
		Tags:         append(slices.Clone(p.Tags), tag),
		UserMetadata: cloneMap(p.UserMetadata),
		Description:  p.Description,
		Owner:        p.Owner,
		CreatedAt:    p.CreatedAt,
	}
}

// WithDescription returns a new Program with the description set.
func (p Program) WithDescription(desc string) Program {
	return Program{
		LoadSpec:     p.LoadSpec,
		Tags:         slices.Clone(p.Tags),
		UserMetadata: cloneMap(p.UserMetadata),
		Description:  desc,
		Owner:        p.Owner,
		CreatedAt:    p.CreatedAt,
	}
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}
	result := make(map[K]V, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
