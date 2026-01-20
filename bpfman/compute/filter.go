package compute

import "github.com/frobware/bpffs-csi-driver/bpfman/domain"

// FilterPrograms returns programs matching the predicate.
// Pure function.
func FilterPrograms(
	programs []domain.KernelProgram,
	predicate func(domain.KernelProgram) bool,
) []domain.KernelProgram {
	var result []domain.KernelProgram
	for _, p := range programs {
		if predicate(p) {
			result = append(result, p)
		}
	}
	return result
}

// FilterByType returns programs of the specified type.
// Pure function.
func FilterByType(programs []domain.KernelProgram, programType string) []domain.KernelProgram {
	return FilterPrograms(programs, func(p domain.KernelProgram) bool {
		return p.ProgramType == programType
	})
}

// FilterByName returns programs matching the name.
// Pure function.
func FilterByName(programs []domain.KernelProgram, name string) []domain.KernelProgram {
	return FilterPrograms(programs, func(p domain.KernelProgram) bool {
		return p.Name == name
	})
}

// FilterMetadata returns metadata matching the predicate.
// Pure function.
func FilterMetadata(
	metadata map[uint32]domain.ProgramMetadata,
	predicate func(uint32, domain.ProgramMetadata) bool,
) map[uint32]domain.ProgramMetadata {
	result := make(map[uint32]domain.ProgramMetadata)
	for id, m := range metadata {
		if predicate(id, m) {
			result[id] = m
		}
	}
	return result
}

// FilterByTag returns metadata containing the specified tag.
// Pure function.
func FilterByTag(metadata map[uint32]domain.ProgramMetadata, tag string) map[uint32]domain.ProgramMetadata {
	return FilterMetadata(metadata, func(_ uint32, m domain.ProgramMetadata) bool {
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
func FilterByOwner(metadata map[uint32]domain.ProgramMetadata, owner string) map[uint32]domain.ProgramMetadata {
	return FilterMetadata(metadata, func(_ uint32, m domain.ProgramMetadata) bool {
		return m.Owner == owner
	})
}
