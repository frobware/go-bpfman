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
┌─────────────────────────────────────────────────────────────┐
│                        Test Code                            │
├─────────────────────────────────────────────────────────────┤
│                       testFixture                           │
│  ┌─────────┐  ┌─────────────┐  ┌───────────────────────┐   │
│  │ Server  │  │ fakeKernel  │  │ SQLite (in-mem)       │   │
│  └────┬────┘  └──────┬──────┘  └─────────┬─────────────┘   │
│       │              │                   │                 │
│       │   Uses       │   Implements      │  Real DB        │
│       ▼              ▼                   ▼                 │
│  ┌─────────┐  ┌─────────────┐  ┌───────────────────────┐   │
│  │ Manager │──│ Kernel      │  │ Store interface       │   │
│  │         │  │ Operations  │  │                       │   │
│  └─────────┘  │ interface   │  └───────────────────────┘   │
│       │       └─────────────┘                              │
│       │                                                    │
│       ▼                                                    │
│  ┌─────────────────────┐                                   │
│  │ fakeNetIfaceResolver│  (for XDP/TC/TCX tests)          │
│  └─────────────────────┘                                   │
└─────────────────────────────────────────────────────────────┘
```

The test fixture combines:
- **Real server** - Actual gRPC service implementation
- **Fake kernel** - Simulates BPF operations without syscalls
- **Real database** - In-memory SQLite with full schema
- **Fake network resolver** - Mock network interfaces for XDP/TC/TCX tests

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

## Network Interface Resolver

For testing XDP, TC, and TCX attachment without real network interfaces, the server uses dependency injection via the `NetIfaceResolver` interface:

```go
// NetIfaceResolver resolves network interfaces by name.
type NetIfaceResolver interface {
    InterfaceByName(name string) (*net.Interface, error)
}

// Production code uses DefaultNetIfaceResolver
type DefaultNetIfaceResolver struct{}

func (DefaultNetIfaceResolver) InterfaceByName(name string) (*net.Interface, error) {
    return net.InterfaceByName(name)
}
```

### Fake Network Interface Resolver

Tests use `fakeNetIfaceResolver` which provides mock interfaces:

```go
type fakeNetIfaceResolver struct {
    interfaces map[string]*net.Interface
}

func newFakeNetIfaceResolver() *fakeNetIfaceResolver {
    return &fakeNetIfaceResolver{
        interfaces: map[string]*net.Interface{
            "lo":   {Index: 1, Name: "lo"},
            "eth0": {Index: 2, Name: "eth0"},
        },
    }
}

func (f *fakeNetIfaceResolver) InterfaceByName(name string) (*net.Interface, error) {
    iface, ok := f.interfaces[name]
    if !ok {
        return nil, fmt.Errorf("interface %q not found", name)
    }
    return iface, nil
}
```

This enables tests like `TestXDP_AttachToNonExistentInterface` to verify that attachment to unknown interfaces fails correctly.

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

## Test Scenarios

This section outlines the comprehensive set of scenarios to test using the fake kernel. Each scenario can be implemented by adding appropriate error injection and verification.

### Program Lifecycle - Success Paths

| Scenario | Operations | Verification |
|----------|------------|--------------|
| Load single program | Load | Program in kernel and DB |
| Load multiple programs (batch) | Load × N | All programs in kernel and DB |
| Load then unload | Load, Unload | Clean state |
| Load, attach, detach, unload | Full lifecycle | Clean state, correct op sequence |

### Program Lifecycle - Failure at Each Stage

| Scenario | Failure Point | Expected Behaviour |
|----------|---------------|-------------------|
| Load fails (verifier) | `kernel.Load` | Error returned, clean state |
| Load succeeds, DB save fails | `store.Save` | Kernel rollback, clean state |
| Batch load fails at position N | `kernel.Load` (Nth) | Rollback programs 1..N-1 |
| Batch load, DB fails at position N | `store.Save` (Nth) | Rollback all, clean state |

### Attach/Detach Failures

| Scenario | Failure Point | Expected Behaviour |
|----------|---------------|-------------------|
| Attach fails after load | `kernel.AttachX` | Program remains loaded, no link |
| Attach succeeds, link save fails | `store.SaveLink` | Kernel link detached, program intact |
| Detach non-existent link | `store.GetLink` | NotFound error |
| Detach fails at kernel | `kernel.DetachLink` | Link remains in DB (needs reconciliation) |

### Unload Failures

| Scenario | Failure Point | Expected Behaviour |
|----------|---------------|-------------------|
| Unload non-existent program | `store.Get` | NotFound error |
| Unload with active links | - | Links detached first, then unload |
| Unload kernel fails | `kernel.Unload` | DB entry remains (needs reconciliation) |
| Unload DB delete fails | `store.Delete` | Kernel cleaned, DB stale |

### Multi-Program Batch Scenarios

| Scenario | Setup | Expected Behaviour |
|----------|-------|-------------------|
| Batch load 2, fail 2nd | `FailOnProgram("prog_two")` | Rollback prog_one, clean state |
| Batch load 3, fail 3rd | `FailOnProgram("prog_three")` | Rollback prog_one and prog_two |
| Batch load 5, fail 3rd | `FailOnNthLoad(3)` | Rollback first 2 only |
| Batch load, DB unique constraint | Same ProgramName metadata | Fail on 2nd, rollback 1st |

### Dispatcher Scenarios (XDP/TC)

| Scenario | Setup | Expected Behaviour |
|----------|-------|-------------------|
| First XDP attach creates dispatcher | No existing dispatcher | Dispatcher created, extension attached |
| Second XDP attach reuses dispatcher | Existing dispatcher | Extension added to existing |
| XDP attach, dispatcher creation fails | `FailOnDispatcherCreate` | Error, no partial state |
| XDP attach, extension attach fails | `FailOnExtensionAttach` | Dispatcher exists, no extension |
| Last extension detach cleans dispatcher | Single extension | Dispatcher removed |
| Detach extension, dispatcher cleanup fails | `FailOnDispatcherCleanup` | Extension gone, dispatcher orphaned |

### Constraint Validation

| Scenario | Input | Expected Behaviour |
|----------|-------|-------------------|
| Duplicate program name | Same `bpfman.io/ProgramName` | Second load fails |
| Invalid program type | `ProgramType(999)` | Rejected before kernel load |
| Unspecified program type | `ProgramTypeUnspecified` | Rejected before kernel load |
| Attach to non-existent program | Invalid kernel ID | NotFound error |
| Load with empty program name | `Name: ""` | Validation error |

### State Consistency

| Scenario | Setup | Verification |
|----------|-------|--------------|
| Program in kernel, not in DB | Manual kernel injection | Reconciliation detects orphan |
| Program in DB, not in kernel | Manual DB injection | Reconciliation detects stale |
| Link in DB, program gone | Delete program directly | Link becomes orphaned |
| Dispatcher in DB, not in kernel | Manual DB injection | Reconciliation cleans up |

### Resource Limits

| Scenario | Setup | Expected Behaviour |
|----------|-------|-------------------|
| Max programs per dispatcher | Load MAX_PROGRAMS + 1 | Fails or creates new dispatcher |
| Simulated memory exhaustion | `FailOnNthLoad` with ENOMEM | Proper error propagation |

### Error Injection Methods

The fake kernel supports these error injection points:

```go
// Program load failures
FailOnProgram(name string, err error)    // Fail when loading specific program
FailOnNthLoad(n int, err error)          // Fail on Nth load attempt

// Attach failures
FailOnAttach(attachType string, err error)  // Fail specific attach type

// Detach failures
FailOnDetach(linkID uint32, err error)   // Fail when detaching specific link
```

### Implementation Status

**Implemented Tests:**

| Category | Test | Status |
|----------|------|--------|
| **Program Lifecycle** | | |
| Load single program | `TestLoadProgram_WithValidRequest_Succeeds` | Done |
| Load with duplicate name | `TestLoadProgram_WithDuplicateName_IsRejected` | Done |
| Load with empty name | `TestLoadProgram_WithEmptyName_IsRejected` | Done |
| Unload existing program | `TestUnloadProgram_WhenProgramExists_RemovesIt` | Done |
| Unload non-existent | `TestUnloadProgram_WhenProgramDoesNotExist_ReturnsNotFound` | Done |
| Unload with active links | `TestUnloadProgram_WithActiveLinks_DetachesLinksThenUnloads` | Done |
| **Batch Load Rollback** | | |
| Fail 2nd of 2 | `TestLoadProgram_PartialFailure_SecondProgramFails` | Done |
| Fail 3rd of 3 | `TestLoadProgram_PartialFailure_ThirdOfThreeFails` | Done |
| Fail 1st | `TestLoadProgram_PartialFailure_FirstProgramFails` | Done |
| Fail Nth | `TestLoadProgram_FailOnNthLoad` | Done |
| **Attach Failures** | | |
| Attach after load fails | `TestAttachTracepoint_WhenAttachFails_ProgramRemainsLoaded` | Done |
| Attach to non-existent program | `TestAttach_ToNonExistentProgram_ReturnsNotFound` | Done |
| **Detach** | | |
| Detach non-existent link | `TestDetach_NonExistentLink_ReturnsNotFound` | Done |
| Detach existing link | `TestDetach_ExistingLink_Succeeds` | Done |
| Multiple links same program | `TestMultipleLinks_SameProgram_AllDetachable` | Done |
| Detach kernel failure | `TestDetach_KernelFailure_ReturnsError` | Done |
| **XDP Lifecycle** | | |
| First attach | `TestXDPDispatcher_FirstAttachCreatesDispatcher` | Done |
| Multiple attaches | `TestXDPDispatcher_MultipleAttachesCreateMultipleLinks` | Done |
| Detach decrements | `TestXDPDispatcher_DetachDecrementsLinkCount` | Done |
| Full lifecycle | `TestXDPDispatcher_FullLifecycle` | Done |
| Non-existent interface | `TestXDP_AttachToNonExistentInterface` | Done |
| **TC Lifecycle** | | |
| First attach | `TestTC_FirstAttachCreatesLink` | Done |
| Ingress and egress | `TestTC_IngressAndEgressDirections` | Done |
| Invalid direction | `TestTC_InvalidDirection` | Done |
| Non-existent interface | `TestTC_AttachToNonExistentInterface` | Done |
| Full lifecycle | `TestTC_FullLifecycle` | Done |
| **TCX Lifecycle** | | |
| First attach | `TestTCX_FirstAttachCreatesLink` | Done |
| Ingress and egress | `TestTCX_IngressAndEgressDirections` | Done |
| Invalid direction | `TestTCX_InvalidDirection` | Done |
| Non-existent interface | `TestTCX_AttachToNonExistentInterface` | Done |
| Full lifecycle | `TestTCX_FullLifecycle` | Done |
| **Fentry Lifecycle** | | |
| Attach succeeds | `TestFentry_AttachSucceeds` | Done |
| Attach without FnName | `TestFentry_AttachWithoutFnName_Fails` | Done |
| Full lifecycle | `TestFentry_FullLifecycle` | Done |
| **Fexit Lifecycle** | | |
| Attach succeeds | `TestFexit_AttachSucceeds` | Done |
| Attach without FnName | `TestFexit_AttachWithoutFnName_Fails` | Done |
| Full lifecycle | `TestFexit_FullLifecycle` | Done |
| **Constraint Validation** | | |
| Invalid program type | `TestLoadProgram_WithInvalidProgramType_IsRejected` | Done |
| Unspecified program type | `TestLoadProgram_WithUnspecifiedProgramType_IsRejected` | Done |
| All program types round-trip | `TestLoadProgram_AllProgramTypes_RoundTrip` | Done |

**Remaining Scenarios:**

| Priority | Scenario | Status |
|----------|----------|--------|
| Medium | DB save failures with kernel rollback | Not implemented |
| Medium | Dispatcher creation/cleanup failures | Not implemented |
| Lower | State consistency / reconciliation | Not implemented |
| Lower | Resource limit scenarios | Not implemented |

## Related Files

- `server/server_test.go` - Test fixtures and tests
- `interpreter/interpreter.go` - KernelOperations interface
- `interpreter/ebpf/ebpf.go` - Real kernel implementation
- `interpreter/store/sqlite/sqlite.go` - Database schema
