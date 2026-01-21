# XDP and TC Dispatchers

This document describes the dispatcher implementation for multi-program
chaining on XDP and TC hooks.

## Overview

Dispatchers allow multiple BPF programs to be attached to a single
network interface. Rather than replacing each other, programs are
chained together and executed in sequence. Each program can decide
whether to continue to the next program based on its return value.

The dispatcher model matches upstream bpfman's behaviour, ensuring
drop-in compatibility.

## Limits

### Dispatchers Per Interface

You can have up to **3 dispatchers** per network interface (per namespace):

| Dispatcher Type | Hook Point |
|-----------------|------------|
| `xdp` | XDP (ingress only) |
| `tc-ingress` | TC ingress |
| `tc-egress` | TC egress |

This is enforced by the unique constraint `(type, nsid, ifindex)` in
the database schema.

### Programs Per Dispatcher

Each dispatcher can chain up to **10 programs** (positions 0-9).

This limit is defined by `MaxPrograms = 10` in `dispatcher.go` and
matches the upstream bpfman implementation.

### Total Capacity

Per interface, you can attach:
- 10 XDP programs
- 10 TC-ingress programs
- 10 TC-egress programs

The system-wide limit is bounded by the number of network namespaces
and interfaces, which are limited by kernel resources.

## Architecture

### Dispatcher Programs

The dispatcher is a BPF program with 10 stub functions (`prog0` through
`prog9`) that can be replaced at runtime using the kernel's freplace
mechanism. When a packet arrives:

1. The dispatcher calls each enabled stub function in order
2. After each call, it checks the return value against a "proceed-on" mask
3. If the return value matches the mask, it continues to the next program
4. Otherwise, it returns the value immediately

### BPF Extension (freplace)

User programs are attached to dispatcher slots using BPF extensions
(`BPF_PROG_TYPE_EXT`). This is a kernel mechanism that replaces a
function in one BPF program with another.

**Key insight**: The same ELF bytecode can be loaded as different
program types. For dispatcher attachment, we reload the program from
the original ELF file with:

- `Type = Extension` (not XDP)
- `AttachTarget = dispatcher program`
- `AttachTo = "prog0"` (or other slot name)

This is different from direct XDP attachment where the program is
loaded as `BPF_PROG_TYPE_XDP`.

## Pin Path Structure

Pin paths follow the Rust bpfman convention, using network namespace
ID (nsid) and interface index (ifindex) for unique identification:

```
/sys/fs/bpf/bpfman/
├── <uuid>/                              # User programs (unchanged)
│   ├── <program-name>
│   └── <map-names>
│
├── xdp/                                 # XDP dispatchers
│   ├── dispatcher_{nsid}_{ifindex}_link        # Stable XDP link
│   └── dispatcher_{nsid}_{ifindex}_{revision}/ # Revision directory
│       ├── dispatcher                          # Dispatcher program
│       ├── link_0                              # Extension link position 0
│       ├── link_1                              # Extension link position 1
│       └── ...
│
├── tc-ingress/                          # TC ingress dispatchers
│   ├── dispatcher_{nsid}_{ifindex}_link
│   └── dispatcher_{nsid}_{ifindex}_{revision}/
│       └── ...
│
└── tc-egress/                           # TC egress dispatchers
    ├── dispatcher_{nsid}_{ifindex}_link
    └── dispatcher_{nsid}_{ifindex}_{revision}/
        └── ...
```

### Path Components

| Component | Description |
|-----------|-------------|
| `nsid` | Network namespace inode number (e.g., `4026531840`) |
| `ifindex` | Network interface index (e.g., `1` for lo) |
| `revision` | Dispatcher revision, incremented on atomic updates |

### Example Paths

For XDP on loopback (ifindex=1) in the root namespace (nsid=4026531840):

```
/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link
/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher
/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_0
```

### Why This Structure?

1. **Stable link path**: The `_link` file is outside the revision
   directory, allowing atomic dispatcher replacement without
   re-attaching the XDP link.

2. **Namespace isolation**: Using nsid ensures dispatchers in
   different network namespaces don't collide.

3. **Revision-based updates**: New dispatcher configs are loaded into
   a new revision directory, then extension links are migrated
   atomically.

## Implementation

### Package Structure

```
pkg/bpfman/dispatcher/     # Dispatcher loading and config
  dispatcher.go            # Load functions, config structs
  paths.go                 # Path construction functions
  xdp_dispatcher_v2.bpf.o  # Embedded XDP dispatcher bytecode
  tc_dispatcher.bpf.o      # Embedded TC dispatcher bytecode

pkg/bpfman/netns/          # Network namespace utilities
  netns.go                 # GetCurrentNsid()

pkg/bpfman/managed/        # Data types
  dispatcher.go            # DispatcherState struct

dispatchers/               # BPF source files
  xdp_dispatcher_v2.bpf.c
  tc_dispatcher.bpf.c
  Makefile
```

### Path Construction

The `dispatcher` package provides functions to construct paths:

```go
// Stable link path (outside revision directory)
dispatcher.DispatcherLinkPath(DispatcherTypeXDP, nsid, ifindex)
// -> /sys/fs/bpf/bpfman/xdp/dispatcher_{nsid}_{ifindex}_link

// Revision directory
dispatcher.DispatcherRevisionDir(DispatcherTypeXDP, nsid, ifindex, revision)
// -> /sys/fs/bpf/bpfman/xdp/dispatcher_{nsid}_{ifindex}_{revision}

// Dispatcher program within revision
dispatcher.DispatcherProgPath(revisionDir)
// -> {revisionDir}/dispatcher

// Extension link within revision
dispatcher.ExtensionLinkPath(revisionDir, position)
// -> {revisionDir}/link_{position}
```

### Config Injection

The dispatcher config is a C struct embedded in the `.rodata` section:

```c
struct xdp_dispatcher_conf {
    __u8 magic;
    __u8 dispatcher_version;
    __u8 num_progs_enabled;
    __u8 is_xdp_frags;
    __u32 chain_call_actions[10];
    __u32 run_prios[10];
    __u32 program_flags[10];
};

static volatile const struct xdp_dispatcher_conf conf = {};
```

Because the variable is `static`, it's not exported as a global symbol.
We inject the config by directly modifying the `.rodata` map contents
before loading:

```go
rodata := spec.Maps[".rodata"]
rodata.Contents = []ebpf.MapKV{
    {Key: uint32(0), Value: configBytes},
}
```

Note: `RewriteConstants` and the Variables API don't work for static
variables in cilium/ebpf.

### Dispatcher State

Dispatcher state is persisted in SQLite:

```sql
CREATE TABLE dispatchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,           -- 'xdp', 'tc-ingress', 'tc-egress'
    nsid INTEGER NOT NULL,        -- Network namespace inode
    ifindex INTEGER NOT NULL,     -- Interface index
    revision INTEGER NOT NULL,    -- Current revision
    kernel_id INTEGER NOT NULL,   -- Dispatcher program kernel ID
    link_id INTEGER NOT NULL,     -- XDP/TC link kernel ID
    link_pin_path TEXT NOT NULL,  -- Stable link path
    prog_pin_path TEXT NOT NULL,  -- Current dispatcher program path
    num_extensions INTEGER NOT NULL,
    UNIQUE (type, nsid, ifindex)
);
```

### Attachment Flow

1. **Load program** (via `bpfman load`):
   - Program loaded as XDP type
   - Pinned at `/sys/fs/bpf/bpfman/<uuid>/<name>`
   - ObjectPath stored in database

2. **Attach XDP** (via `bpfman attach xdp`):
   - Get current network namespace ID
   - Look up dispatcher by `(xdp, nsid, ifindex)` in store
   - If not found, create new dispatcher with revision=1
   - Compute extension link path: `{revision_dir}/link_{position}`
   - Reload program from ObjectPath as Extension type
   - Set AttachTarget to dispatcher, AttachTo to slot name
   - Create freplace link and pin to extension link path
   - Update dispatcher extension count in store

3. **Detach** (via `bpfman detach`):
   - Remove extension link pin
   - Dispatcher remains attached (for reuse)

## Current Limitations

### Single Slot (Position 0)

Currently all programs are attached to position 0. Position tracking
based on priority is not yet implemented.

### Hardcoded Proceed-On

Currently hardcoded to proceed on XDP_PASS only:

```go
xdpProceedOnPass = 1 << 2  // Continue on XDP_PASS
```

The CLI doesn't expose proceed-on configuration. Future work: add
`--proceed-on` flag to `attach xdp` command.

### No Atomic Revision Updates

Revision-based atomic updates are not yet implemented. The revision
field exists in the schema but is not used for atomic replacement.

### TC Dispatcher Untested

The TC dispatcher implementation exists but is untested.

## XDP vs Extension Program Types

A common confusion: why can't we just attach an already-loaded XDP
program to the dispatcher?

The kernel's freplace mechanism requires `BPF_PROG_TYPE_EXT`. When you
load a program, the kernel assigns it a type that cannot be changed.
An XDP program (type 6) cannot be used for freplace.

cilium/ebpf enforces this:

```go
// link/tracing.go
if prog.Type() != ebpf.Extension {
    return nil, fmt.Errorf("eBPF program type %s is not an Extension", prog.Type())
}
```

The solution is to reload the same bytecode with different load
parameters. The ELF file doesn't mandate a specific program type - it
contains the instructions which are valid for both XDP and Extension
contexts when the target is an XDP function.

## Testing

Manual test flow:

```bash
# Load a program
bpfman load image --program=xdp:pass quay.io/bpfman-bytecode/xdp_pass:latest

# Attach using dispatcher (program ID from load output)
bpfman attach xdp --program-id=<id> lo

# Verify new path structure
ls /sys/fs/bpf/bpfman/xdp/
# Should show: dispatcher_{nsid}_{ifindex}_link
#              dispatcher_{nsid}_{ifindex}_1/

ls /sys/fs/bpf/bpfman/xdp/dispatcher_*_1/
# Should show: dispatcher, link_0

ip link show lo                    # Shows xdpgeneric
bpfman list links                  # Shows extension link

# Detach
bpfman detach <link-uuid>
```

## Future Work

1. **Position tracking**: Allocate slots based on priority, track
   occupied positions per interface

2. **Dispatcher lifecycle**: Remove dispatcher when last extension is
   detached

3. **Proceed-on configuration**: CLI flag to configure which return
   values continue the chain

4. **Atomic revision updates**: Load new dispatcher config into new
   revision, migrate extensions, clean up old revision

5. **TC dispatcher testing**: Verify TC dispatchers work correctly

6. **Multi-program testing**: Verify multiple programs can be attached
   to different slots on the same interface
