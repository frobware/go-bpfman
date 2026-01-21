# Managed Programs

This document explains what bpfman stores for each program type and why.
The guiding principle is: **only store what cannot be queried from the
kernel**.

## Program Types

bpfman supports eight program types, divided into two categories based on
their attachment model:

### Single-Attach Programs

These attach directly to a hook point. One link per attachment.

| Type | Hook Point | Use Case |
|------|------------|----------|
| Tracepoint | Kernel tracepoint | `syscalls/sys_enter_openat` |
| Kprobe | Kernel function entry | `do_sys_open` |
| Kretprobe | Kernel function return | `do_sys_open` return |
| Uprobe | Userspace function entry | `/usr/bin/bash:readline` |
| Uretprobe | Userspace function return | `/usr/bin/bash:readline` return |
| Fentry | Kernel function entry (BTF) | `tcp_connect` |
| Fexit | Kernel function exit (BTF) | `tcp_connect` exit |

### Multi-Attach Programs (Dispatcher-Based)

These use a dispatcher to multiplex multiple programs through a single
kernel attachment point.

| Type | Hook Point | Use Case |
|------|------------|----------|
| XDP | Network interface (ingress) | Packet filtering, DDoS mitigation |
| TC | Traffic control (ingress/egress) | Traffic shaping, policy |
| TCX | Traffic control extended | Modern TC replacement (kernel 6.6+) |

## The Dispatcher Model

The kernel only allows one XDP program per interface. To support multiple
programs, bpfman uses a **dispatcher**:

```
What the kernel sees:

    eth0
      │
      ▼
    dispatcher (single XDP program)


What bpfman manages:

    eth0
      │
      ▼
    dispatcher
      │
      ├─► Program A (priority=10, position=0)
      │        │
      │        ▼ (proceed_on: PASS, DROP)
      │
      ├─► Program B (priority=20, position=1)
      │        │
      │        ▼ (proceed_on: PASS)
      │
      └─► Program C (priority=30, position=2)
               │
               ▼
           final verdict
```

The dispatcher:
1. Calls each program in position order (0-9 slots available)
2. Uses `proceed_on` masks to determine flow between programs
3. Returns the final verdict to the kernel

This abstraction exists **only in bpfman** - the kernel knows nothing about
the individual programs or their ordering.

## What the Kernel Knows

The kernel exposes information through `bpf_prog_info` and `bpf_link_info`:

**Program info (queryable):**
- Program ID, name, type
- Map IDs used by the program
- BTF ID, load time, tag
- JIT info, verified instructions

**Link info (queryable):**
- Link ID, type, program ID
- Target info (tracepoint name, kprobe function, interface index)

**Map info (queryable):**
- Map ID, name, type
- Key/value sizes, max entries

## What Must Be Stored

### For All Programs

| Field | Why store it |
|-------|--------------|
| UUID | Our identifier, kernel doesn't know it |
| User metadata | Labels for discovery (e.g., `application=stats`) |
| Load spec | Bytecode source, program name, global data |
| Owner | Who loaded it |
| Pin path | Convention-derivable, but stored for efficiency |

### For Single-Attach Links

Most attach parameters are queryable from kernel link info, but we store:

| Field | Why store it |
|-------|--------------|
| Link UUID | Our identifier |
| Pin path | Where we pinned it |

The kernel link info already contains:
- Tracepoint: group and name
- Kprobe/Kretprobe: function name, offset, return probe flag
- Uprobe/Uretprobe: binary path, offset, PID, return probe flag
- Fentry/Fexit: function name, BTF ID

### For XDP/TC Links (Dispatcher-Based)

These fields **cannot** be queried from the kernel:

| Field | Why store it |
|-------|--------------|
| Priority | User-specified ordering, determines position |
| Position | Slot (0-9) in dispatcher chain |
| Proceed-on masks | Flow control between programs |
| Interface | Which network interface |
| Direction | Ingress/egress (TC only) |
| Network namespace | nsid for namespace-aware attachments |
| Dispatcher ID | Which dispatcher this belongs to |

### For TCX Links

TCX is simpler than XDP/TC - no dispatcher needed, but still multi-attach:

| Field | Why store it |
|-------|--------------|
| Priority | Ordering among TCX programs |
| Interface | Which network interface |
| Direction | Ingress/egress |
| Network namespace | nsid |

### Dispatcher State

Each dispatcher (per interface + direction) requires:

| Field | Why store it |
|-------|--------------|
| Revision | Version number, incremented on changes |
| Interface index | Kernel ifindex |
| Interface name | Human-readable name |
| Mode | XDP mode (driver/skb) |
| Extension count | Number of attached programs |
| Namespace ID | Network namespace |

## Schema Design

Based on the above, our SQLite schema needs:

```sql
-- Core program metadata (all types)
CREATE TABLE managed_programs (
    kernel_id INTEGER PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    program_type TEXT NOT NULL,
    load_spec TEXT NOT NULL,      -- JSON: object_path, program_name, global_data
    user_metadata TEXT,           -- JSON: key/value pairs
    owner TEXT,
    pin_path TEXT NOT NULL,
    state TEXT NOT NULL,          -- loading, loaded, error, unloading
    created_at TEXT NOT NULL
);

-- Fast metadata lookups for CSI
CREATE TABLE program_metadata_index (
    kernel_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (kernel_id, key),
    FOREIGN KEY (kernel_id) REFERENCES managed_programs(kernel_id) ON DELETE CASCADE
);

-- Links for all attachment types
CREATE TABLE managed_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    kernel_link_id INTEGER,
    program_kernel_id INTEGER NOT NULL,
    link_type TEXT NOT NULL,
    pin_path TEXT,

    -- Single-attach fields (tracepoint, kprobe, etc.)
    -- Stored for convenience, but mostly queryable from kernel
    attach_target TEXT,           -- function name, tracepoint, binary path
    attach_offset INTEGER,
    attach_retprobe INTEGER,
    attach_pid INTEGER,

    -- Multi-attach fields (XDP, TC, TCX)
    interface TEXT,
    direction TEXT,               -- ingress/egress
    priority INTEGER,
    position INTEGER,             -- 0-9 for dispatcher slot
    proceed_on TEXT,              -- JSON array of action masks
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER,

    created_at TEXT NOT NULL,
    FOREIGN KEY (program_kernel_id) REFERENCES managed_programs(kernel_id) ON DELETE CASCADE
);

-- Dispatcher state (XDP/TC only)
CREATE TABLE dispatchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dispatcher_type TEXT NOT NULL,  -- xdp, tc
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT,                 -- NULL for XDP, ingress/egress for TC
    mode TEXT,                      -- driver/skb for XDP
    revision INTEGER NOT NULL,
    extension_count INTEGER NOT NULL,
    netns TEXT,
    nsid INTEGER,
    pin_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (dispatcher_type, ifindex, direction, nsid)
);
```

## Storage Decision Tree

```
Is it queryable from kernel?
    │
    ├─► YES: Don't store (or store only for performance)
    │         - Program ID, name, type, map IDs
    │         - Link target info (tracepoint name, kprobe fn)
    │         - Map details
    │
    └─► NO: Must store
              │
              ├─► Our identifiers: UUID
              ├─► Our metadata: labels, owner, load spec
              ├─► Our abstractions: dispatcher state, priority, position
              └─► Pin paths (convention-derivable but stored for efficiency)
```

## Reconciliation

When bpfman starts, it must reconcile stored state with kernel reality:

| Scenario | Detection | Action |
|----------|-----------|--------|
| Program in store, not in kernel | Kernel ID lookup fails | Delete from store |
| Program in kernel, not in store | Scan bpffs for our pins | Add to store or remove pin |
| Dispatcher in store, not in kernel | Link lookup fails | Rebuild or delete |
| Link in store, pin gone | Pin path doesn't exist | Delete from store |

For dispatchers, reconciliation is more complex:
1. Check if dispatcher program still attached
2. Verify extension programs match stored positions
3. Rebuild dispatcher if inconsistent

## Example: XDP Attachment Flow

```bash
# User attaches program to eth0 with priority 100
bpfman attach xdp --priority=100 --iface=eth0 <program-id>
```

**Steps:**

1. Check if dispatcher exists for eth0
   - No: Create dispatcher, attach to interface
   - Yes: Use existing dispatcher

2. Calculate position from priority
   - Sort all programs by priority
   - Assign positions 0, 1, 2, ...

3. Load user program as BPF_PROG_TYPE_EXT
   - Extension programs attach to dispatcher

4. Update dispatcher map
   - Write program fd to position slot
   - Configure proceed_on masks

5. Store in database
   - Link: priority, position, proceed_on, interface
   - Dispatcher: revision++, extension_count++

6. Pin link to bpffs

**Kernel state after attachment:**
- One XDP program (dispatcher) attached to eth0
- Dispatcher internally calls extensions by position

**bpfman state after attachment:**
- `managed_links`: records priority=100, position=0, interface=eth0
- `dispatchers`: revision=1, extension_count=1

## Summary

| Program Type | Attachment Model | Storage Requirements |
|--------------|------------------|---------------------|
| Tracepoint | Single-attach | Minimal (UUID, pin path) |
| Kprobe | Single-attach | Minimal |
| Uprobe | Single-attach | Minimal |
| Fentry | Single-attach | Minimal |
| Fexit | Single-attach | Minimal |
| XDP | Dispatcher | Full (priority, position, proceed_on, dispatcher) |
| TC | Dispatcher | Full |
| TCX | Multi-attach | Medium (priority, interface, direction) |

The dispatcher model is the key complexity. Without it, most link state
would be queryable from the kernel. With it, bpfman must store the
abstraction layer that maps user intent (priorities) to kernel reality
(single dispatcher program).
