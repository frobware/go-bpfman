# Check locking

## 1. Remove WriterScope as a data-passing mechanism from Attach

### Problem

`Manager.Attach` takes a `lock.WriterScope` parameter, but it uses
it for two conflated purposes: proving the lock is held, and
threading the lock fd to the container uprobe subprocess. The fd
threading is the only reason the parameter exists today -- no other
method takes it despite having the same locking requirement.

### Current flow

    CLI (RunWithLockValueAndScope)
      -> Manager.Attach(ctx, scope, spec)
        -> attachUprobe(ctx, scope, spec)
          -> action.AttachUprobeContainer{Scope: scope, ...}
            -> ActionExecutor runs nsenter with lock fd

Only the container uprobe path uses the fd. All other attach types
ignore it. Non-container uprobes use `AttachUprobeLocal` which has
no scope field.

### Fix

Separate the two concerns:

- **Lock proof:** all mutating methods take `lock.WriterScope` (see
  section 2).
- **Fd passing:** carry the scope in context for the action executor
  to retrieve when running `AttachUprobeContainer`. The server
  already does this via `contextWithScope`/`ScopeFromContext`; move
  those helpers to the `lock` package so the dependency direction is
  correct.

## 2. Compile-time lock enforcement for mutating manager methods

### Problem

Every caller of a mutating manager method (Load, Unload, Attach,
Detach, GC, DeleteDispatcherSnapshot) is individually responsible
for acquiring the cross-process writer lock before calling the
method. Nothing enforces this. A caller that forgets the lock
silently corrupts the serialisation guarantee. Hope is not a
strategy.

### Proposed approach: use WriterScope as a capability token

`lock.WriterScope` already exists, has an unexported marker method
preventing external implementation, and can only be obtained by
acquiring the lock via `lock.RunWithTiming`. It is already a
compile-time capability token -- we just need to require it
consistently.

### Manager API changes

Every mutating method gains a `lock.WriterScope` parameter:

```go
func (m *Manager) Load(ctx context.Context, scope lock.WriterScope, ...) ([]bpfman.Program, error)
func (m *Manager) Unload(ctx context.Context, scope lock.WriterScope, id ProgramID) error
func (m *Manager) Attach(ctx context.Context, scope lock.WriterScope, spec AttachSpec) (Link, error)
func (m *Manager) Detach(ctx context.Context, scope lock.WriterScope, id LinkID) error
func (m *Manager) GC(ctx context.Context, scope lock.WriterScope) (GCResult, error)
func (m *Manager) DeleteDispatcherSnapshot(ctx context.Context, scope lock.WriterScope, key Key) error
```

Read methods (`ListPrograms`, `Get`, `GetLink`, etc.) do not take
the token and remain callable without the lock.

### What changes per caller

- **CLI:** `RunWithLock` variants already call `RunWithTiming` which
  provides a `WriterScope`. The callback threads it to manager
  calls. `executeDeletePrograms`, `executeLoadFile`, `runAttach`,
  etc. pass `scope` through.

- **Server:** `handleMutating` already calls `RunWithTiming` and
  stores the scope in context. Handler methods already receive the
  scope and pass it to `Attach`; extend this to all mutating
  manager calls.

- **REPL:** calls `executeDeletePrograms` and `executeLoadFile`
  which handle their own locking -- no change needed in REPL
  dispatch code.

- **Tests:** test helpers that call mutating manager methods
  directly need a `WriterScope`. Export a test constructor
  (`lock.TestScope()`) in a `_test.go` file within the `lock`
  package, or have tests acquire a real lock against a temp file.

### What this does not change

- Lock granularity: callers still decide the scope (single
  operation or batch). The token is valid for the duration of the
  `RunWithTiming` callback.

- `beginOp`/`endOp`: these continue to handle GC coordination and
  re-entry detection. They are not the enforcement mechanism.
