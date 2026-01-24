# Test Fixtures with Fake Kernel

This document describes the test fixture pattern used in `server/server_test.go` for comprehensive testing of the bpfman server without requiring actual BPF syscalls.

## Overview

The fake kernel approach enables:

- **Fast, deterministic tests** - No kernel interaction, runs in milliseconds
- **Error injection** - Simulate failures at specific points
- **Operation recording** - Verify exact sequence of kernel operations
- **State inspection** - Check kernel and database state at any point
- **Constraint validation** - Discover database schema issues through realistic scenarios

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Test Code                          │
├─────────────────────────────────────────────────────────┤
│                     testFixture                         │
│  ┌─────────┐  ┌─────────────┐  ┌───────────────────┐   │
│  │ Server  │  │ fakeKernel  │  │ SQLite (in-mem)   │   │
│  └────┬────┘  └──────┬──────┘  └─────────┬─────────┘   │
│       │              │                   │             │
│       │   Uses       │   Implements      │  Real DB    │
│       ▼              ▼                   ▼             │
│  ┌─────────┐  ┌─────────────┐  ┌───────────────────┐   │
│  │ Manager │  │ Kernel      │  │ Store interface   │   │
│  │         │──│ Operations  │  │                   │   │
│  └─────────┘  │ interface   │  └───────────────────┘   │
│               └─────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

The test fixture combines:
- **Real server** - Actual gRPC service implementation
- **Fake kernel** - Simulates BPF operations without syscalls
- **Real database** - In-memory SQLite with full schema

This combination catches bugs that mock-heavy approaches miss.

## Test Fixture

```go
type testFixture struct {
    Server *server.Server
    Kernel *fakeKernel
    Store  interpreter.Store
    t      *testing.T
}

func newTestFixture(t *testing.T) *testFixture
```

### Helper Methods

```go
// Verify kernel state
fix.AssertKernelEmpty()           // No programs in kernel
fix.Kernel.ProgramCount()         // Count loaded programs

// Verify database state
fix.AssertDatabaseEmpty()         // No programs in store

// Verify both
fix.AssertCleanState()            // Kernel AND database empty

// Verify operation sequence
fix.AssertKernelOps([]string{
    "load:prog_one:ok",
    "load:prog_two:error",
    "unload:prog_one:ok",
})
```

## Fake Kernel

The fake kernel implements `interpreter.KernelOperations` with additional testing capabilities.

### Operation Recording

Every kernel operation is recorded for later verification:

```go
type kernelOp struct {
    Op   string // "load", "unload", "attach", "detach"
    Name string // program or link name
    ID   uint32 // kernel ID assigned
    Err  error  // error if operation failed
}

// Get recorded operations
ops := fix.Kernel.Operations()
```

### Error Injection

**Fail on specific program:**
```go
fix.Kernel.FailOnProgram("prog_two", fmt.Errorf("simulated failure"))
```

**Fail on Nth load attempt:**
```go
fix.Kernel.FailOnNthLoad(3, fmt.Errorf("third load fails"))
```

**Reset between tests:**
```go
fix.Kernel.Reset()  // Clears ops, error injection, load count
```

### Path Conventions

The fake kernel computes paths identically to the real kernel:

```go
progPinPath := fmt.Sprintf("%s/prog_%d", spec.PinPath, kernelID)
mapsDir := fmt.Sprintf("%s/maps/%d", spec.PinPath, kernelID)
```

This ensures Unload operations match loaded programs correctly.

## Test Patterns

### 1. Verify Successful Operations

```go
func TestLoadProgram_Succeeds(t *testing.T) {
    fix := newTestFixture(t)

    // Load via gRPC
    resp, err := fix.Server.Load(ctx, req)
    require.NoError(t, err)

    // Verify kernel state
    assert.Equal(t, 1, fix.Kernel.ProgramCount())

    // Verify operations
    fix.AssertKernelOps([]string{"load:my_prog:ok"})
}
```

### 2. Verify Rollback on Failure

```go
func TestLoadProgram_RollsBackOnFailure(t *testing.T) {
    fix := newTestFixture(t)

    // Inject failure on second program
    fix.Kernel.FailOnProgram("prog_two", fmt.Errorf("injected"))

    // Attempt batch load
    _, err := fix.Server.Load(ctx, batchRequest)
    require.Error(t, err)

    // Verify rollback happened
    fix.AssertKernelOps([]string{
        "load:prog_one:ok",
        "load:prog_two:error",
        "unload:prog_one:ok",  // Rollback
    })

    // Verify clean state
    fix.AssertCleanState()
}
```

### 3. Verify Error Propagation

```go
func TestLoadProgram_PropagatesKernelError(t *testing.T) {
    fix := newTestFixture(t)

    fix.Kernel.FailOnProgram("my_prog", fmt.Errorf("BPF verifier failed"))

    _, err := fix.Server.Load(ctx, req)

    require.Error(t, err)
    assert.Contains(t, err.Error(), "BPF verifier failed")
}
```

### 4. Verify Database Constraints

```go
func TestLoadProgram_RejectsDuplicateName(t *testing.T) {
    fix := newTestFixture(t)

    // First load succeeds
    _, err := fix.Server.Load(ctx, reqWithName("my-app"))
    require.NoError(t, err)

    // Second load with same name fails
    _, err = fix.Server.Load(ctx, reqWithName("my-app"))
    require.Error(t, err)

    // First program still exists
    assert.Equal(t, 1, fix.Kernel.ProgramCount())
}
```

## Bugs Discovered Through This Pattern

### 1. Missing Rollback

**Symptom:** Partial failures left orphaned programs in kernel/database.

**Test:** Load multiple programs, fail the Nth one, verify all previous are cleaned up.

**Fix:** Track loaded kernel IDs, unload in reverse order on failure.

### 2. Path Mismatch in Fake Kernel

**Symptom:** Unload operations silently succeeded without removing programs.

**Test:** Rollback tests showed unload operations but programs remained.

**Fix:** Fake kernel must compute paths identically to real kernel (using kernel ID, not program name).

### 3. Database Constraint Violations

**Symptom:** Batch loads with shared metadata failed unexpectedly.

**Test:** Load multiple programs with same `bpfman.io/ProgramName`.

**Discovery:** The metadata index has a unique constraint - batch loads with shared ProgramName fail on the second program.

## Best Practices

### DO

- **Test error paths explicitly** - Inject errors at each stage
- **Verify operation sequences** - Order matters for rollback
- **Check both kernel AND database** - They can get out of sync
- **Use realistic data** - Discover constraint issues early
- **Reset state between sub-tests** - Use `fix.Kernel.Reset()`

### DON'T

- **Don't leak schema details into tests** - Test behaviour, not implementation
- **Don't assume silent success** - Verify operations actually happened
- **Don't share unique-constrained metadata** - Use distinct values per program
- **Don't ignore rollback errors** - Log them for debugging

## Adding New Error Injection Points

To test failures at new points:

1. Add error injection field to `fakeKernel`:
   ```go
   failOnAttach map[string]error
   ```

2. Check in the relevant method:
   ```go
   if err := f.failOnAttach[linkType]; err != nil {
       f.recordOp("attach", linkType, 0, err)
       return ..., err
   }
   ```

3. Add configuration method:
   ```go
   func (f *fakeKernel) FailOnAttach(linkType string, err error)
   ```

4. Write tests that exercise the new failure path.

## Related Files

- `server/server_test.go` - Test fixtures and tests
- `interpreter/interpreter.go` - KernelOperations interface
- `interpreter/ebpf/ebpf.go` - Real kernel implementation
- `interpreter/store/sqlite/sqlite.go` - Database schema
