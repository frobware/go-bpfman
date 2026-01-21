# BPF Program Lifecycle

This document explains how BPF programs are loaded, attached, and managed
by bpfman, and what makes a program "managed" versus just loaded in the
kernel.

## Kernel Reference Counting

BPF objects (programs, maps, links) are reference-counted by the kernel.
An object stays alive while at least one reference exists:

| Reference Type | Description |
|----------------|-------------|
| File descriptor | Userspace process holds an open fd |
| Pin | Filesystem entry in bpffs |
| Attachment | Link connecting program to a hook |
| Map reference | Program using a map |

When all references are gone, the kernel frees the object.

### The Problem with File Descriptors

If a process loads a BPF program and holds it via fd, the program
disappears when the process exits. This is unsuitable for system services
that should survive daemon restarts.

### Pinning as Persistent Reference

bpffs (`/sys/fs/bpf`) provides a filesystem interface to BPF objects.
Pinning creates a filesystem entry that holds a reference:

```
Program loaded → fd held by process → process exits → program gone
Program loaded → pinned to bpffs → process exits → program persists
```

This decouples object lifetime from process lifetime.

## The Two-Phase Model: Load and Attach

BPF programs go through two distinct phases:

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOAD PHASE                              │
│                                                                 │
│  ELF file ──→ Kernel verification ──→ Program object created   │
│                                                                 │
│  Result: Program is resident in kernel memory                   │
│          Program is NOT receiving any events                    │
│          Maps are allocated but possibly empty                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACH PHASE                             │
│                                                                 │
│  Program ──→ Link created ──→ Connected to hook                 │
│                                                                 │
│  Result: Program receives events from the hook                  │
│          (tracepoint fires, packets arrive, etc.)               │
└─────────────────────────────────────────────────────────────────┘
```

### Why Separate Phases?

1. **Multiple attachments**: One program can attach to many hooks
2. **Deferred attachment**: Load now, attach later
3. **Graceful transitions**: Detach without unloading, then reattach
4. **Resource sharing**: Multiple links share the same program and maps

## What bpfman Manages

bpfman tracks metadata about BPF objects it has loaded. This is what makes
them "managed" rather than just existing in the kernel.

### Managed Program

When bpfman loads a program:

```
Kernel state:
  - Program object (kernel_id=123)
  - Maps referenced by program

bpffs pins:
  /sys/fs/bpf/bpfman/<uuid>/
  ├── <program-name>     # pinned program
  ├── <map-name-1>       # pinned map
  └── <map-name-2>       # pinned map

SQLite (managed_programs):
  - uuid: unique identifier we assigned
  - kernel_id: kernel's program ID
  - state: loaded | loading | error | unloading
  - load_spec: how to reload (object path, program name, etc.)
  - user_metadata: labels for discovery (e.g., application=stats)
  - owner: who loaded it
  - created_at, updated_at
```

### Managed Link

When bpfman attaches a program:

```
Kernel state:
  - Link object (link_id=456)
  - Connection: program 123 ←→ tracepoint syscalls/sys_enter_openat

bpffs pins:
  /sys/fs/bpf/bpfman/links/<link-uuid>    # pinned link

SQLite (managed_links):
  - uuid: unique identifier we assigned
  - kernel_link_id: kernel's link ID
  - program_kernel_id: which program this attaches
  - program_uuid: our UUID for the program
  - link_type: tracepoint | kprobe | xdp | etc.
  - pin_path: where we pinned it
  - attach_spec: parameters (group, name, interface, etc.)
  - created_at
```

## Example: One Program, Two Links

A syscall tracer attached to multiple tracepoints:

```bash
# Load the program once
$ bpfman load file --name=syscall_stats \
    --program-name=trace_syscall \
    /opt/bpf/syscall_tracer.o

Program loaded:
  uuid: abc-111
  kernel_id: 100
  pin_path: /sys/fs/bpf/bpfman/abc-111/trace_syscall
```

State after load:

```
┌──────────────────────────────────────────────────────────┐
│ Kernel                                                   │
│   Program 100: trace_syscall (not attached to anything)  │
│   Map 200: syscall_counts                                │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ bpffs                                                    │
│   /sys/fs/bpf/bpfman/abc-111/                            │
│   ├── trace_syscall  (prog 100)                          │
│   └── syscall_counts (map 200)                           │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ SQLite                                                   │
│   managed_programs: uuid=abc-111, kernel_id=100          │
│   managed_links: (empty)                                 │
└──────────────────────────────────────────────────────────┘
```

```bash
# Attach to openat tracepoint
$ bpfman attach tracepoint --program-id=100 \
    /sys/fs/bpf/bpfman/abc-111/trace_syscall \
    syscalls sys_enter_openat \
    --link-pin-path=/sys/fs/bpf/bpfman/links/link-001

# Attach to read tracepoint (same program)
$ bpfman attach tracepoint --program-id=100 \
    /sys/fs/bpf/bpfman/abc-111/trace_syscall \
    syscalls sys_enter_read \
    --link-pin-path=/sys/fs/bpf/bpfman/links/link-002
```

State after both attachments:

```
┌──────────────────────────────────────────────────────────┐
│ Kernel                                                   │
│   Program 100: trace_syscall                             │
│   Map 200: syscall_counts                                │
│   Link 300: prog 100 → syscalls/sys_enter_openat         │
│   Link 301: prog 100 → syscalls/sys_enter_read           │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ bpffs                                                    │
│   /sys/fs/bpf/bpfman/abc-111/                            │
│   ├── trace_syscall                                      │
│   └── syscall_counts                                     │
│   /sys/fs/bpf/bpfman/links/                              │
│   ├── link-001  (link 300)                               │
│   └── link-002  (link 301)                               │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ SQLite                                                   │
│   managed_programs: uuid=abc-111, kernel_id=100          │
│   managed_links:                                         │
│     uuid=link-001, kernel_id=300, program_id=100         │
│     uuid=link-002, kernel_id=301, program_id=100         │
└──────────────────────────────────────────────────────────┘
```

Both tracepoints now fire into the same program, incrementing counters
in the shared `syscall_counts` map.

## Detach vs Unload

### Detach (remove a link)

```bash
$ bpfman detach link-001
```

- Removes the link pin from bpffs
- Kernel releases the link (no more references)
- Program stops receiving events from that hook
- Program remains loaded (still pinned, still has link-002)
- Map data preserved

### Unload (remove the program)

```bash
$ bpfman unload 100
```

- Removes all link pins for this program
- Removes the program pin from bpffs
- Removes map pins from bpffs
- Kernel releases everything (no more references)
- Map data lost

## Orphans and Reconciliation

State can become inconsistent:

| Scenario | Cause | Detection | Resolution |
|----------|-------|-----------|------------|
| Store entry, no kernel object | System reboot, external unload | kernel_id lookup fails | Delete from store |
| Pin exists, no store entry | Crash during load, external load | Scan bpffs, check store | Remove pin |
| Link in store, pin gone | External detach, crash | pin_path doesn't exist | Delete from store |
| Program in `loading` state | Crash during load | State query | Clean up reservation |

The `bpfman gc` command reconciles these states:

```bash
$ bpfman gc
Reconciled 2 orphaned store entries
Removed 1 stale pin
```

## CSI Integration

The CSI driver exposes maps to pods without giving them access to the
program or full bpffs:

```
Canonical pins (managed by bpfman):
  /sys/fs/bpf/bpfman/<uuid>/<map>

Per-pod view (created by CSI driver):
  /var/lib/kubelet/pods/<pod>/volumes/.../<map>
```

The CSI driver:
1. Queries bpfman for programs matching pod's selector
2. Creates a per-pod bpffs mount
3. Re-pins maps from canonical location to pod's volume
4. Pod accesses maps at its mount path

When the pod terminates, the per-pod mount is cleaned up. The canonical
pins (and thus the program and maps) remain.

## Summary

| Concept | Kernel Object | bpffs Pin | SQLite Row |
|---------|---------------|-----------|------------|
| Loaded program | Program ID | `/sys/fs/bpf/bpfman/<uuid>/<name>` | managed_programs |
| Program's map | Map ID | `/sys/fs/bpf/bpfman/<uuid>/<map>` | (via program) |
| Attachment | Link ID | `/sys/fs/bpf/bpfman/links/<uuid>` | managed_links |

A program is "managed" when bpfman has:
1. Pinned it to a known location
2. Recorded metadata in SQLite
3. Taken responsibility for its lifecycle

This enables discovery (query by metadata), persistence (survives daemon
restart), and coordination (CSI can find and expose maps to pods).
