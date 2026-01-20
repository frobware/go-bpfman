// Package memory provides an in-memory implementation of the program store.
// Useful for testing.
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// Store implements interpreter.ProgramStore in memory.
type Store struct {
	mu       sync.RWMutex
	programs map[uint32]managed.Program
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		programs: make(map[uint32]managed.Program),
	}
}

// Get retrieves program metadata by kernel ID.
// Returns store.ErrNotFound if the program does not exist.
func (s *Store) Get(_ context.Context, kernelID uint32) (managed.Program, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if m, ok := s.programs[kernelID]; ok {
		return m, nil
	}
	return managed.Program{}, fmt.Errorf("program %d: %w", kernelID, store.ErrNotFound)
}

// Save stores program metadata.
func (s *Store) Save(_ context.Context, kernelID uint32, metadata managed.Program) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.programs[kernelID] = metadata
	return nil
}

// Delete removes program metadata.
func (s *Store) Delete(_ context.Context, kernelID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.programs, kernelID)
	return nil
}

// List returns all program metadata.
func (s *Store) List(_ context.Context) (map[uint32]managed.Program, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[uint32]managed.Program, len(s.programs))
	for k, v := range s.programs {
		result[k] = v
	}
	return result, nil
}
