# BPF Program Types Implementation Guide

This document tracks the implementation status of BPF program types in go-bpfman, referencing the Rust bpfman implementation as the source of truth.

## Reference Implementation

The Go implementation is based on the Rust bpfman project:

- **Rust source**: `~/src/github.com/bpfman/bpfman/worktrees/general`
- **Rust binary**: `~/rust-bpfman/bin/rust-bpfman`

Use the Rust binary to discover CLI flags and behaviour:
```bash
~/rust-bpfman/bin/rust-bpfman load file --help
~/rust-bpfman/bin/rust-bpfman load image --help
~/rust-bpfman/bin/rust-bpfman attach --help
~/rust-bpfman/bin/rust-bpfman attach 0 <type> --help
```

## Program Types Overview

| Type | Load | Attach | Dispatcher | Status |
|------|------|--------|------------|--------|
| tracepoint | Yes | Yes | No | Complete |
| xdp | Yes | Yes | Yes | Complete |
| tc | Yes | Yes | Yes | Complete |
| tcx | Yes | Yes | No | Complete |
| kprobe | Yes | Yes | No | Complete |
| kretprobe | Yes | Yes | No | Complete (shares kprobe implementation) |
| uprobe | Yes | Yes | No | Complete |
| uretprobe | Yes | Yes | No | Complete (shares uprobe implementation) |
| fentry | Yes | Yes | No | Complete |
| fexit | Yes | Yes | No | Complete (shares fentry implementation) |

### Kretprobe Usage

Kretprobe shares the kprobe implementation. The program type determines whether it attaches as entry or return probe:

```bash
# Load as kprobe (entry)
bpfman load image --programs kprobe:my_func --image-url ...

# Load as kretprobe (return)
bpfman load image --programs kretprobe:my_func --image-url ...

# Attach is the same for both - the retprobe flag is derived from program type
bpfman attach <id> kprobe --fn-name try_to_wake_up
```

The server looks up the program type and passes `retprobe=true` to the manager when the program was loaded as `kretprobe`.

### Uprobe / Uretprobe Usage

Uretprobe shares the uprobe implementation. The program type determines whether it attaches as entry or return probe:

```bash
# Load as uprobe (entry)
bpfman load image --programs uprobe:uprobe_counter --image-url quay.io/bpfman-bytecode/go-uprobe-counter:latest

# Load as uretprobe (return)
bpfman load image --programs uretprobe:uprobe_counter --image-url quay.io/bpfman-bytecode/go-uprobe-counter:latest

# Attach using the uprobe command - the retprobe flag is derived from program type
bpfman attach <id> uprobe --target /lib64/libc.so.6 --fn-name malloc
```

The server looks up the program type and passes `retprobe=true` to the manager when the program was loaded as `uretprobe`.

## Implementation Pattern

Each program type requires changes across multiple files. The pattern established by kprobe:

### 1. Action Definition (`action/action.go`)

Add a `Save<Type>Link` action:
```go
type SaveKprobeLink struct {
    Summary bpfman.LinkSummary
    Details bpfman.KprobeDetails
}
func (SaveKprobeLink) isAction() {}
```

### 2. Link Types (`link.go`)

Types and details are already defined for all program types:
- `LinkType` constants (e.g., `LinkTypeKprobe`)
- `<Type>Details` structs (e.g., `KprobeDetails`)

### 3. Interface (`interpreter/interfaces.go`)

Add method to `ProgramAttacher` interface:
```go
AttachKprobe(progPinPath, fnName string, offset uint64, retprobe bool, linkPinPath string) (bpfman.ManagedLink, error)
```

### 4. Kernel Implementation (`interpreter/ebpf/ebpf.go`)

Implement the attach method using cilium/ebpf:
```go
func (k *kernelAdapter) AttachKprobe(...) (bpfman.ManagedLink, error) {
    // Load pinned program
    // Attach using link.Kprobe() or link.Kretprobe()
    // Pin the link
    // Return ManagedLink with details
}
```

### 5. Executor (`interpreter/executor.go`)

Add case for the new action:
```go
case action.SaveKprobeLink:
    return e.store.SaveKprobeLink(ctx, a.Summary, a.Details)
```

### 6. Manager (`manager/manager.go`)

Implement the manager method following FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE pattern:
```go
func (m *Manager) AttachKprobe(ctx context.Context, programKernelID uint32, ...) (bpfman.LinkSummary, error)
func computeAttachKprobeAction(...) action.SaveKprobeLink
```

### 7. Server (`server/server.go`)

Add case to `Attach` RPC switch and implement handler:
```go
case *pb.AttachInfo_KprobeAttachInfo:
    return s.attachKprobe(ctx, req.Id, info.KprobeAttachInfo)
```

### 8. Client (`client/client.go`, `client/remote.go`, `client/ephemeral.go`)

Add method to Client interface and implement in both clients:
```go
AttachKprobe(ctx context.Context, programKernelID uint32, fnName string, offset uint64, linkPinPath string) (bpfman.LinkSummary, error)
```

### 9. CLI (`cmd/bpfman/cli/attach.go`)

Wire up the attach subcommand to call the client method.

### 10. Test Fake (`server/server_test.go`)

Add fake implementation of the attach method.

### 11. Integration Test (`integration-tests/`)

Create `test-<type>-load-attach.sh` following existing patterns.

## Source Code Locations

### Go Implementation

| Component | File |
|-----------|------|
| Core types | `program.go`, `link.go` |
| Actions | `action/action.go` |
| Interfaces | `interpreter/interfaces.go` |
| Kernel ops | `interpreter/ebpf/ebpf.go` |
| Executor | `interpreter/executor.go` |
| Store | `interpreter/store/sqlite/sqlite.go` |
| Schema | `interpreter/store/sqlite/schema.sql` |
| Manager | `manager/manager.go` |
| Server | `server/server.go` |
| Client | `client/client.go`, `client/remote.go`, `client/ephemeral.go` |
| CLI | `cmd/bpfman/cli/attach.go`, `cmd/bpfman/cli/types.go` |
| Proto | `proto/bpfman.proto` |

### Rust Implementation

| Component | File |
|-----------|------|
| Core types | `bpfman/src/types.rs` |
| Attach logic | `bpfman/src/lib.rs` |
| Examples | `examples/` |

### Fentry / Fexit Usage

**Key difference**: The attach function is specified at **load time**, not attach time.

```bash
# Load as fentry (entry)
bpfman load image --programs fentry:test_fentry:do_unlinkat --image-url quay.io/bpfman-bytecode/go-fentry-counter:latest

# Load as fexit (exit)
bpfman load image --programs fexit:test_fexit:do_unlinkat --image-url quay.io/bpfman-bytecode/go-fexit-counter:latest

# Attach - no function name needed, it was stored at load time
bpfman attach <id> fentry
bpfman attach <id> fexit
```

The server retrieves the attach function from the stored program metadata (`LoadSpec.AttachFunc`) when processing the attach request.

## Test Images

Available from quay.io/bpfman-bytecode/:

| Type | Image | BPF Function | Attach Target |
|------|-------|--------------|---------------|
| kprobe | go-kprobe-counter:latest | kprobe_counter | try_to_wake_up |
| tracepoint | go-tracepoint-counter:latest | tracepoint_kill_recorder | syscalls/sys_enter_kill |
| xdp | go-xdp-counter:latest | stats | interface |
| tc | go-tc-counter:latest | stats | interface |
| uprobe | go-uprobe-counter:latest | uprobe_counter | libc:malloc |
| uretprobe | go-uretprobe-counter:latest | uretprobe_counter | libc:malloc |

### Fentry / Fexit Test Bytecode

Fentry and fexit use local bytecode for integration tests since OCI images are not available:

| Type | Bytecode | BPF Function | Attach Target |
|------|----------|--------------|---------------|
| fentry | `integration-tests/bytecode/fentry.bpf.o` | test_fentry | do_unlinkat |
| fexit | `integration-tests/bytecode/fentry.bpf.o` | test_fexit | do_unlinkat |

The bytecode was compiled from the Rust bpfman test source (`tests/integration-test/bpf/fentry.bpf.c`).

Example configurations can be found in:
`~/src/github.com/bpfman/bpfman/worktrees/general/examples/config/`

## Database Schema

Link details tables already exist for all types (`interpreter/store/sqlite/schema.sql`):

- `tracepoint_link_details`
- `kprobe_link_details`
- `uprobe_link_details`
- `fentry_link_details`
- `fexit_link_details`
- `xdp_link_details`
- `tc_link_details`
- `tcx_link_details`

Store methods also exist (`interpreter/store/sqlite/sqlite.go`):
- `SaveTracepointLink`, `SaveKprobeLink`, `SaveUprobeLink`, etc.
- `GetLink` handles all types via the `link_registry` + type-specific details join

## Dispatcher Types

XDP and TC use dispatchers for multi-program chaining. Other types are single-attach.

| Type | Dispatcher | Notes |
|------|------------|-------|
| xdp | Yes | `dispatcher/xdp_dispatcher.c` |
| tc | Yes | `dispatcher/tc_dispatcher.c` |
| tcx | No | Native kernel multi-prog support |
| Others | No | Single-attach |
