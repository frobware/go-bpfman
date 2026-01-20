package compute

import (
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// FilterPrograms returns programs matching the predicate.
// Pure function.
func FilterPrograms(
	programs []kernel.Program,
	predicate func(kernel.Program) bool,
) []kernel.Program {
	var result []kernel.Program
	for _, p := range programs {
		if predicate(p) {
			result = append(result, p)
		}
	}
	return result
}

// FilterByType returns programs of the specified type.
// Pure function.
func FilterByType(programs []kernel.Program, programType string) []kernel.Program {
	return FilterPrograms(programs, func(p kernel.Program) bool {
		return p.ProgramType == programType
	})
}

// FilterByName returns programs matching the name.
// Pure function.
func FilterByName(programs []kernel.Program, name string) []kernel.Program {
	return FilterPrograms(programs, func(p kernel.Program) bool {
		return p.Name == name
	})
}

// FilterMetadata returns metadata matching the predicate.
// Pure function.
func FilterMetadata(
	metadata map[uint32]managed.Program,
	predicate func(uint32, managed.Program) bool,
) map[uint32]managed.Program {
	result := make(map[uint32]managed.Program)
	for id, m := range metadata {
		if predicate(id, m) {
			result[id] = m
		}
	}
	return result
}

// FilterByTag returns metadata containing the specified tag.
// Pure function.
func FilterByTag(metadata map[uint32]managed.Program, tag string) map[uint32]managed.Program {
	return FilterMetadata(metadata, func(_ uint32, m managed.Program) bool {
		for _, t := range m.Tags {
			if t == tag {
				return true
			}
		}
		return false
	})
}

// FilterByOwner returns metadata for the specified owner.
// Pure function.
func FilterByOwner(metadata map[uint32]managed.Program, owner string) map[uint32]managed.Program {
	return FilterMetadata(metadata, func(_ uint32, m managed.Program) bool {
		return m.Owner == owner
	})
}
