# E2E Test Comparison: go-bpfman vs upstream bpfman

This document compares the go-bpfman e2e tests (`e2e/e2e_test.go`) with
the upstream bpfman basic integration tests
(`tests/integration-test/src/tests/basic.rs`).

## Architecture

### Upstream (Rust/bpfman)

Tests call bpfman library functions directly (`add_programs`,
`attach_program`, `remove_program`, `list_programs`). Setup is a single
`setup()` call returning a `Config` and a `sled::Db`. Tests share
process state and are not parallelised.

### go-bpfman (Go)

Tests go through a `client.Client` abstraction that wraps an embedded
gRPC server. Each test gets a fully isolated `TestEnv` with unique temp
directories, SQLite database, and bpffs mount. Tests run with
`t.Parallel()`.

## Lifecycle Model

### Upstream

Load and attach are combined into a single operation (`add_xdp`,
`add_tc`, etc. call `add_programs` then `attach_program` internally).
Cleanup uses `verify_and_delete_programs` which lists, deletes, and
verifies removal in one pass. The concept of "links" does not exist;
programs are loaded-and-attached as one unit.

### go-bpfman

Load and attach are explicitly separate steps: `LoadImage` / `Load`
returns a loaded program, then `AttachTracepoint` / `AttachKprobe` /
etc. creates a link. Detach and unload are also separate. The lifecycle
is Load -> Attach -> Detach -> Unload, with each step independently
verified via round-trip assertions (Get, GetLink, List, ListLinks).

## Program Type Coverage

| Type | Upstream basic.rs | go-bpfman e2e |
|------|-------------------|---------------|
| XDP | Yes (10 progs, file+image) | Yes (1 prog, image only) |
| TC | Yes (10 progs, file+image) | Yes (1 prog, image only) |
| TCX | No | Yes (kernel 6.6+ gated) |
| Tracepoint | Yes | Yes |
| Kprobe | Yes | Yes |
| Kretprobe | Yes | Yes |
| Uprobe | Yes | Yes |
| Uretprobe | Yes | Yes |
| Fentry | Yes | Yes (file only) |
| Fexit | Yes | Yes (file only) |
| Map sharing | Yes (`test_map_sharing_load_unload_xdp`) | No |
| Metadata/list filtering | Yes (`test_list_with_metadata`) | Yes (`TestLoadWithMetadataAndGlobalData`) |
| Pull bytecode | Yes (`test_pull_bytecode`) | No |
| Cosign disabled | Yes (`test_load_unload_cosign_disabled`) | No (disabled in config by default) |

## Key Differences

### Multi-program scale testing

Upstream loads 10 XDP and 10 TC programs per test (5 from file, 5 from
image), verifying multi-program dispatcher behaviour. go-bpfman loads 1
program per test and does not test multi-program scenarios on a single
interface.

### File vs image sources

Upstream tests both file and OCI image locations for every program type.
go-bpfman primarily uses OCI images; only fentry/fexit use local files
(because no OCI images exist for them).

### Globals

Upstream sets global variables (`GLOBAL_U8`, `GLOBAL_U32`) on nearly
every program. go-bpfman only tests globals in the dedicated
`TestLoadWithMetadataAndGlobalData` test.

### Link introspection

go-bpfman tests are significantly more thorough on round-trip
verification: every test checks Get, GetLink, List, ListLinks, and
verifies type-specific link details (e.g., `KprobeDetails.FnName`,
`TCDetails.Interface`, `XDPDetails.DispatcherID`). Upstream does not
inspect link details at all -- it only checks program IDs via
`list_programs`.

### Map sharing

Upstream has a dedicated test (`test_map_sharing_load_unload_xdp`) that
loads two XDP programs sharing maps and verifies `maps_used_by`,
`map_owner_id`, and `map_pin_path`. go-bpfman has no equivalent.

### Network namespace setup

Upstream creates a veth pair in a network namespace with IP addressing
and a ping process for XDP/TC tests. go-bpfman uses the `lo` interface,
avoiding the namespace complexity entirely.

### Cleanup strategy

Upstream uses `verify_and_delete_programs` with retry logic (5 retries
with 1-second sleeps). go-bpfman uses `t.Cleanup()` callbacks, relying
on Go's testing framework for ordering.

### Retprobe distinction

go-bpfman explicitly tests that kretprobe/uretprobe links report the
correct `Retprobe=true` field and authoritative link types from the
server. Upstream does not verify retprobe-specific semantics.

### Prerequisites

go-bpfman has explicit guards (`RequireRoot`, `RequireBTF`,
`RequireKernelFunction`, `RequireKernelVersion`, `RequireTracepoint`).
Upstream uses `TestMain` for root check but otherwise lets tests fail on
missing prerequisites.

## Gaps in go-bpfman

- Multi-program dispatcher stress testing (multiple programs on one
  interface)
- Map sharing between programs
- File-based bytecode loading for most program types
- `pull_bytecode` equivalent
- Network namespace with real traffic (veth + ping)
- `tc filter show` verification for TC programs

## Additions in go-bpfman Over Upstream

- TCX program type coverage
- Full link lifecycle testing (attach/detach as separate operations)
- Type-specific link detail verification
- Per-test isolation with parallel execution
- User metadata and global data round-trip testing
- Stale test directory cleanup
- Retprobe semantics verification
