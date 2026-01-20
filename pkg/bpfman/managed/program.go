package managed

import (
	"slices"
	"time"
)

// State represents the lifecycle state of a managed program.
type State string

const (
	// StateLoading indicates a load is in progress (reservation exists).
	StateLoading State = "loading"
	// StateLoaded indicates the program is fully loaded with pins and metadata.
	StateLoaded State = "loaded"
	// StateUnloading indicates an unload is in progress.
	StateUnloading State = "unloading"
	// StateError indicates a failed operation that could not be fully rolled back.
	StateError State = "error"
)

// Program contains metadata for programs managed by bpfman.
// This is what we store - the kernel is the source of truth for runtime state.
type Program struct {
	LoadSpec     LoadSpec          `json:"load_spec"`
	UUID         string            `json:"uuid"`
	Tags         []string          `json:"tags,omitempty"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
	Description  string            `json:"description,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	State        State             `json:"state"`
	ErrorMessage string            `json:"error_message,omitempty"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// WithTag returns a new Program with the tag added.
func (p Program) WithTag(tag string) Program {
	return Program{
		LoadSpec:     p.LoadSpec,
		UUID:         p.UUID,
		Tags:         append(slices.Clone(p.Tags), tag),
		UserMetadata: cloneMap(p.UserMetadata),
		Description:  p.Description,
		Owner:        p.Owner,
		CreatedAt:    p.CreatedAt,
		State:        p.State,
		ErrorMessage: p.ErrorMessage,
		UpdatedAt:    p.UpdatedAt,
	}
}

// WithDescription returns a new Program with the description set.
func (p Program) WithDescription(desc string) Program {
	return Program{
		LoadSpec:     p.LoadSpec,
		UUID:         p.UUID,
		Tags:         slices.Clone(p.Tags),
		UserMetadata: cloneMap(p.UserMetadata),
		Description:  desc,
		Owner:        p.Owner,
		CreatedAt:    p.CreatedAt,
		State:        p.State,
		ErrorMessage: p.ErrorMessage,
		UpdatedAt:    p.UpdatedAt,
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
