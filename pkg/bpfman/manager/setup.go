package manager

import (
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
)

// Setup creates a Manager with default implementations and returns
// a cleanup function to close the store.
func Setup(dbPath string) (*Manager, func(), error) {
	store, err := sqlite.New(dbPath)
	if err != nil {
		return nil, nil, err
	}

	kernel := ebpf.New()
	cleanup := func() { store.Close() }

	return New(store, kernel), cleanup, nil
}
