# bpfman Design

This document describes the architecture of bpfman, a minimal BPF program manager built with functional programming principles.

## Core Principles

### SANS-IO (Separate Application from Network/System I/O)

The core logic performs no I/O directly. All side effects are:
1. Described as data (reified effects)
2. Executed by an interpreter layer
3. Isolated at the edges of the system

This separation enables:
- Pure functions that are trivially testable without mocks
- Clear boundaries between business logic and infrastructure
- Easy substitution of I/O implementations (e.g., in-memory stores for testing)

### Fetch/Compute/Execute Pattern

Operations follow a three-phase pattern:

```
FETCH    -> Gather data from external sources (impure)
COMPUTE  -> Transform data, make decisions (pure)
EXECUTE  -> Apply effects to external systems (impure)
```

Example from reconciliation:
```go
// FETCH - gather data
stored, _ := store.List(ctx)
kernel := collectKernelPrograms(ctx)

// COMPUTE - pure logic, no I/O
actions := compute.ReconcileActions(stored, kernel)

// EXECUTE - apply effects
executor.ExecuteAll(ctx, actions)
```

### Reified Effects

Side effects are represented as data structures rather than executed immediately:

```go
// Instead of:
store.Delete(id)  // Immediate side effect

// We describe the intent:
action := action.DeleteProgram{KernelID: id}
// ...and execute it later
executor.Execute(ctx, action)
```

This enables:
- Batching and optimisation of effects
- Logging/auditing of intended operations
- Testing without actual I/O
- Transaction-like semantics (compute all changes, then apply)

## Package Structure

```
bpfman/
├── domain/           Pure data types (no I/O, no dependencies)
├── action/           Reified effects as data structures
├── compute/          Pure functions for business logic
├── interpreter/      I/O layer: interfaces and implementations
│   ├── store/        Store implementations (sqlite, memory)
│   └── kernel/       Kernel adapters (ebpf)
├── manager/          Orchestration using fetch/compute/execute
└── cmd/bpfman/       CLI entry point
```

### domain/

Pure data types with no external dependencies. These represent:

- **KernelProgram** - A BPF program as observed in the kernel
- **KernelMap** - A BPF map as observed in the kernel
- **ProgramMetadata** - Metadata we store about programs we manage
- **LoadSpec** - Specification for loading a program
- **Option[T]** - Explicit optionality (no nil pointers)

Key principle: domain types never perform I/O. They're pure data.

```go
// Pure data - just describes what something is
type KernelProgram struct {
    ID          uint32
    Name        string
    ProgramType string
    Tag         string
    MapIDs      []uint32
}
```

### action/

Reified effects - data structures describing what to do:

```go
type Action interface { isAction() }

type SaveProgram struct {
    KernelID uint32
    Metadata domain.ProgramMetadata
}

type DeleteProgram struct {
    KernelID uint32
}
```

Actions are inert - they describe intent but perform no I/O.

### compute/

Pure functions that transform data and make decisions:

```go
// Pure function - no I/O, deterministic, trivially testable
func ReconcileActions(
    stored map[uint32]domain.ProgramMetadata,
    kernel []domain.KernelProgram,
) []action.Action {
    var actions []action.Action
    for id := range stored {
        if !inKernel(id, kernel) {
            actions = append(actions, action.DeleteProgram{KernelID: id})
        }
    }
    return actions
}
```

Testing is trivial - no mocks needed:

```go
func TestReconcileActions(t *testing.T) {
    stored := map[uint32]domain.ProgramMetadata{1: {}, 2: {}}
    kernel := []domain.KernelProgram{{ID: 1}}

    actions := ReconcileActions(stored, kernel)

    // ID 2 should be deleted (in store but not kernel)
    assert.Len(t, actions, 1)
}
```

### interpreter/

The I/O layer. Contains:

1. **Interfaces** - Define capabilities needed by business logic
2. **Implementations** - Concrete adapters for external systems
3. **Executor** - Interprets and executes actions

#### Interfaces

Small, focused interfaces following the Interface Segregation Principle:

```go
type ProgramReader interface {
    Get(ctx context.Context, kernelID uint32) (domain.Option[domain.ProgramMetadata], error)
}

type ProgramWriter interface {
    Save(ctx context.Context, kernelID uint32, metadata domain.ProgramMetadata) error
    Delete(ctx context.Context, kernelID uint32) error
}

type KernelSource interface {
    Programs(ctx context.Context) iter.Seq2[domain.KernelProgram, error]
}
```

Interfaces are defined by consumers, not implementations.

#### Store Implementations

- **sqlite/** - Persistent storage using SQLite
- **memory/** - In-memory store for testing

Both implement the same interfaces, enabling easy substitution:

```go
// Production
store := sqlite.Open("/var/lib/bpfman/state.db")

// Testing
store := memory.New()
```

#### Kernel Adapter

The `kernel/ebpf/` package wraps cilium/ebpf:

```go
type Kernel struct{}

func (k *Kernel) Programs(ctx context.Context) iter.Seq2[domain.KernelProgram, error]
func (k *Kernel) Load(ctx context.Context, spec domain.LoadSpec) (domain.LoadedProgram, error)
func (k *Kernel) Unload(ctx context.Context, pinPath string) error
```

#### Executor

Interprets action types and performs the corresponding I/O:

```go
func (e *Executor) Execute(ctx context.Context, a action.Action) error {
    switch act := a.(type) {
    case action.SaveProgram:
        return e.store.Save(ctx, act.KernelID, act.Metadata)
    case action.DeleteProgram:
        return e.store.Delete(ctx, act.KernelID)
    }
}
```

### manager/

High-level orchestration using fetch/compute/execute:

```go
type Manager struct {
    store    interpreter.ProgramStore
    kernel   interpreter.KernelOperations
    executor *interpreter.Executor
}

func (m *Manager) Reconcile(ctx context.Context) error {
    // FETCH
    stored, _ := m.store.List(ctx)
    var kernelPrograms []domain.KernelProgram
    for kp, _ := range m.kernel.Programs(ctx) {
        kernelPrograms = append(kernelPrograms, kp)
    }

    // COMPUTE (pure)
    actions := compute.ReconcileActions(stored, kernelPrograms)

    // EXECUTE
    return m.executor.ExecuteAll(ctx, actions)
}
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI / gRPC                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         manager/                                │
│  Orchestrates fetch/compute/execute pattern                     │
└─────────────────────────────────────────────────────────────────┘
          │                   │                   │
          ▼                   ▼                   ▼
   ┌────────────┐     ┌─────────────┐     ┌─────────────┐
   │   FETCH    │     │   COMPUTE   │     │   EXECUTE   │
   │ (impure)   │     │   (pure)    │     │  (impure)   │
   └────────────┘     └─────────────┘     └─────────────┘
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐   ┌─────────────┐   ┌─────────────────┐
│  interpreter/   │   │  compute/   │   │  interpreter/   │
│  (kernel, store)│   │  (pure fns) │   │  (executor)     │
└─────────────────┘   └─────────────┘   └─────────────────┘
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐   ┌─────────────┐   ┌─────────────────┐
│  domain/        │   │  action/    │   │  domain/        │
│  (pure types)   │   │  (effects)  │   │  (pure types)   │
└─────────────────┘   └─────────────┘   └─────────────────┘
```

## Benefits

### Testability

Pure functions in `compute/` can be tested without any mocks:

```go
func TestOrphanedPrograms(t *testing.T) {
    stored := map[uint32]domain.ProgramMetadata{1: {}, 2: {}}
    kernel := []domain.KernelProgram{{ID: 1}}

    orphaned := OrphanedPrograms(stored, kernel)

    // Just check the result - no I/O involved
    assert.Equal(t, []uint32{2}, orphaned)
}
```

### Substitutability

Interfaces enable easy substitution:
- In-memory store for tests
- Mock kernel for unit tests
- Different storage backends

### Reasoning

With effects reified as data:
- You can inspect what will happen before it happens
- Logging becomes trivial
- Debugging is easier (print the action list)

### Modularity

Clear boundaries between:
- What we know (domain)
- What we want to do (action)
- How we decide (compute)
- How we do it (interpreter)

## Migration Status

Migration is complete. All code now uses the FP architecture:

- **CLI** (`cmd/bpfman/`) - Uses `interpreter/kernel/ebpf/` for BPF operations
- **gRPC server** (`internal/server/`) - Uses `interpreter/kernel/ebpf/` and `interpreter/store/sqlite/`

The legacy `internal/bpf/` and `internal/store/` packages have been removed.

### Internal Packages

The `internal/` directory contains only server-related code:

```
internal/
  server/
    server.go    # gRPC server implementation
    pb/          # Generated protobuf code (via make bpfman-proto)
```

The proto stubs are co-located with the server since they're tightly coupled. Generate them with `make bpfman-proto`.
