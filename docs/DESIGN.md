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
pkg/bpfman/
├── types.go              Shared types (ProgramType, AttachType, etc.)
├── kernel/               Kernel-observed BPF objects (read-only domain)
│   ├── program.go
│   ├── map.go
│   └── link.go
├── managed/              bpfman-managed metadata (what we store)
│   ├── program.go
│   ├── load.go
│   └── link.go
├── action/               Reified effects as data structures
├── compute/              Pure business logic functions
├── interpreter/          I/O layer
│   ├── interfaces.go
│   ├── executor.go
│   ├── ebpf/             cilium/ebpf adapter
│   └── store/            Store implementations
│       ├── sqlite/
│       └── memory/
├── manager/              Orchestration (fetch/compute/execute)
└── server/               gRPC server
    └── pb/               Generated protobuf code
```

## Dependency Inversion Principle

The package structure follows a strict dependency rule that keeps pure logic separate from I/O concerns.

**Dependency Flow:**
```
interpreter/ ──imports──> compute/ ──imports──> kernel/, managed/
```

The pure packages (`kernel/`, `managed/`, `compute/`) have no knowledge of the I/O layer. They work only with pure data types.

**Interfaces defined by consumers, not implementations:**
- Each consumer declares only what it needs (e.g., `ProgramReader` with one method)
- The SQLite store satisfies many small interfaces
- Testing only requires satisfying the few methods actually used

This inversion means:
- `compute/` defines what operations it needs via interfaces
- `interpreter/` provides implementations that satisfy those interfaces
- Pure packages never import `interpreter/`

### kernel/

Types representing what the kernel reports about BPF objects. These are observed, not created by us. Pure data with no I/O.

```go
// Observed from kernel - we don't create these, we discover them
type Program struct {
    ID          uint32
    Name        string
    ProgramType ProgramType
    Tag         string
    MapIDs      []uint32
}
```

### managed/

Metadata we persist about programs we manage. Includes LoadSpec for loading programs, Program state tracking, and Link tracking for attachments.

```go
// What we store about programs we manage
type Program struct {
    KernelID    uint32
    UUID        string
    ObjectPath  string
    ProgramName string
    State       ProgramState
}
```

### types.go

Shared types at the package root representing the capabilities of the bpfman package. These include `ProgramType`, `AttachType`, and other enumerations used across packages.

### action/

Reified effects - data structures describing what to do:

```go
type Action interface { isAction() }

type SaveProgram struct {
    Program managed.Program
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
    stored map[uint32]managed.Program,
    observed []kernel.Program,
) []action.Action {
    var actions []action.Action
    for id := range stored {
        if !inKernel(id, observed) {
            actions = append(actions, action.DeleteProgram{KernelID: id})
        }
    }
    return actions
}
```

Testing is trivial - no mocks needed:

```go
func TestReconcileActions(t *testing.T) {
    stored := map[uint32]managed.Program{1: {}, 2: {}}
    observed := []kernel.Program{{ID: 1}}

    actions := ReconcileActions(stored, observed)

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
    // Get returns store.ErrNotFound if the program does not exist.
    Get(ctx context.Context, kernelID uint32) (managed.Program, error)
}

type ProgramWriter interface {
    Save(ctx context.Context, program managed.Program) error
    Delete(ctx context.Context, kernelID uint32) error
}

type KernelSource interface {
    Programs(ctx context.Context) iter.Seq2[kernel.Program, error]
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

#### eBPF Adapter

The `interpreter/ebpf/` package wraps cilium/ebpf:

```go
type Kernel struct{}

func (k *Kernel) Programs(ctx context.Context) iter.Seq2[kernel.Program, error]
func (k *Kernel) Load(ctx context.Context, spec managed.LoadSpec) (managed.Program, error)
func (k *Kernel) Unload(ctx context.Context, pinPath string) error
```

#### Executor

Interprets action types and performs the corresponding I/O:

```go
func (e *Executor) Execute(ctx context.Context, a action.Action) error {
    switch act := a.(type) {
    case action.SaveProgram:
        return e.store.Save(ctx, act.Program)
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
    var observed []kernel.Program
    for kp, _ := range m.kernel.Programs(ctx) {
        observed = append(observed, kp)
    }

    // COMPUTE (pure)
    actions := compute.ReconcileActions(stored, observed)

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
│  (ebpf, store)  │   │  (pure fns) │   │  (executor)     │
└─────────────────┘   └─────────────┘   └─────────────────┘
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐   ┌─────────────┐   ┌─────────────────┐
│  kernel/        │   │  action/    │   │  managed/       │
│  managed/       │   │  (effects)  │   │  kernel/        │
│  (pure types)   │   │             │   │  (pure types)   │
└─────────────────┘   └─────────────┘   └─────────────────┘
```

## Benefits

### Testability

Pure functions in `compute/` can be tested without any mocks:

```go
func TestOrphanedPrograms(t *testing.T) {
    stored := map[uint32]managed.Program{1: {}, 2: {}}
    observed := []kernel.Program{{ID: 1}}

    orphaned := OrphanedPrograms(stored, observed)

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
- What the kernel tells us (kernel/)
- What we persist (managed/)
- What we want to do (action/)
- How we decide (compute/)
- How we do it (interpreter/)

## Testing Philosophy

The SANS-IO architecture enables a layered testing strategy. The principle is: **test at the level where the behaviour is defined**.

### Test Levels

**Server tests** (`pkg/bpfman/server/server_test.go`) - The primary test suite. These are behaviour specifications written in BDD style with Given/When/Then structure. They drive requests through the gRPC layer using a fake kernel and real in-memory SQLite, exercising the full request path without mocks.

```go
// TestLoadProgram_WithDuplicateName_IsRejected verifies that:
//
//     Given a server with one program already loaded using a name,
//     When I attempt to load another program with the same name,
//     Then the load fails with a unique constraint error.
func TestLoadProgram_WithDuplicateName_IsRejected(t *testing.T) {
    srv := newTestServer(t)
    // ...
}
```

**SQLite constraint tests** (`pkg/bpfman/interpreter/store/sqlite/sqlite_test.go`) - Verify schema correctness directly. Foreign key constraints and unique indexes are database-level guarantees; testing them at the store level provides clear failure messages when schema invariants are violated.

**Pure function tests** (`pkg/bpfman/compute/`) - Test pure logic in isolation. These are trivially testable with no setup, no state, just input/output verification.

### What We Don't Test

**Manager-level integration tests** - The server tests already exercise the manager through the gRPC layer. Adding tests at the manager level would duplicate coverage and couple tests to an internal interface.

**Mocked unit tests** - The SANS-IO architecture lets us test with real implementations (fake kernel + real SQLite). Mocking the store or kernel defeats the purpose of the architecture.

### Test Helpers

Tests use a `testLogger` helper that discards log output by default. Set `BPFMAN_TEST_VERBOSE=1` to enable structured logging during test runs for debugging.

```go
func testLogger() *slog.Logger {
    if os.Getenv("BPFMAN_TEST_VERBOSE") != "" {
        return slog.New(slog.NewTextHandler(os.Stderr, nil))
    }
    return slog.New(slog.NewTextHandler(io.Discard, nil))
}
```

## Migration Status

Migration is complete. All code now uses the FP architecture:

- **CLI** (`cmd/bpfman/`) - Uses `interpreter/ebpf/` for BPF operations
- **gRPC server** (`pkg/bpfman/server/`) - Uses `interpreter/ebpf/` and `interpreter/store/sqlite/`

The proto stubs are co-located with the server in `pkg/bpfman/server/pb/`. Generate them with `make bpfman-proto`.
