# Switch from UUIDs to Kernel IDs

## Implementation Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Filesystem Structure (`prog_{id}`, `links/{id}`, etc.) | Not started |
| Phase 2 | Protocol Extensions (ListLinks, GetLink RPCs) | Not started |
| Phase 3 | Schema Migration (kernel_id as PK, drop UUID columns) | **Complete** |
| Phase 4 | CLI Cleanup (remove LinkUUID, detach uses link_id) | **Complete** |

### What's been done

- Schema uses `kernel_id` as PRIMARY KEY for programs (no UUID column)
- Schema uses `kernel_link_id` as PRIMARY KEY for links (no UUID column)
- Removed `managed.Program.UUID`, `State`, `ErrorMessage`, `UpdatedAt` fields
- Removed `managed.LinkSummary.UUID` field
- Removed `managed.Loaded.UUID` field
- Removed reservation pattern (`Reserve`, `CommitReservation`, `MarkError`)
- Simplified to atomic load model (kernel first, DB persist on success)
- CLI `detach` command uses `link-id` (uint32) instead of UUID
- CLI `get link` command uses `link-id` (uint32) instead of UUID
- GC simplified to orphan detection only (no state-based cleanup)

### What remains

- Filesystem paths still use timestamps, not `prog_{kernel_id}` naming
- Root path is configurable RuntimeDirs, not fixed `/run/bpfman/fs/`
- Protocol doesn't have ListLinks/GetLink RPCs (remote client returns ErrNotSupported)
- Map paths don't follow `/run/bpfman/fs/maps/{prog_id}/{map_name}` convention

## Overview

This document captures the plan to align bpfman's internal model with the
upstream Rust bpfman implementation, using kernel-assigned IDs as primary
identifiers rather than bpfman-generated UUIDs.

## Current State (go-bpfman)

We currently use UUIDs in paths and as primary identifiers:

```
/sys/fs/bpf/bpfman/
└── {uuid}/
    ├── {program_name}
    ├── {map_name}
    └── link
```

## Target State (align with upstream)

Upstream Rust bpfman uses kernel IDs throughout with a managed bpffs mount:

```
/run/bpfman/
├── fs/                                    # Managed bpffs mount
│   ├── prog_{kernel_id}                   # Program pins
│   ├── links/
│   │   └── {link_id}                      # Link pins (single-attach)
│   ├── maps/
│   │   └── {program_id}/
│   │       └── {map_name}                 # Map pins
│   ├── xdp/
│   │   ├── dispatcher_{nsid}_{ifindex}_link
│   │   └── dispatcher_{nsid}_{ifindex}_{revision}/
│   │       └── link_{id}                  # Dispatcher extension links
│   ├── tc-ingress/
│   │   └── dispatcher_{nsid}_{ifindex}_{revision}/
│   │       └── link_{id}
│   └── tc-egress/
│       └── dispatcher_{nsid}_{ifindex}_{revision}/
│           └── link_{id}
├── csi/
│   ├── csi.sock                           # CSI socket
│   └── fs/
│       └── {volume_id}/                   # Per-pod bpffs mount
│           └── {map_name}                 # Re-pinned maps (flat)
└── db/                                    # SQLite database
```

## Upstream Path Constants

```go
const (
    RTDIR                = "/run/bpfman"
    RTDIR_FS             = "/run/bpfman/fs"
    RTDIR_FS_LINKS       = "/run/bpfman/fs/links"
    RTDIR_FS_MAPS        = "/run/bpfman/fs/maps"
    RTDIR_FS_XDP         = "/run/bpfman/fs/xdp"
    RTDIR_FS_TC_INGRESS  = "/run/bpfman/fs/tc-ingress"
    RTDIR_FS_TC_EGRESS   = "/run/bpfman/fs/tc-egress"
    RTDIR_CSI_SOCKET     = "/run/bpfman/csi/csi.sock"
    RTDIR_CSI_FS         = "/run/bpfman/csi/fs"
    RTDIR_DB             = "/run/bpfman/db"
)
```

## Upstream Naming Patterns

| Entity | Pattern | Example |
|--------|---------|---------|
| Program | `prog_{kernel_id}` | `/run/bpfman/fs/prog_42` |
| Link (single-attach) | `{link_id}` | `/run/bpfman/fs/links/123` |
| Link (dispatcher) | `link_{id}` | `/run/bpfman/fs/xdp/dispatcher_0_2_1/link_456` |
| Map | `{map_name}` | `/run/bpfman/fs/maps/42/packet_count` |
| XDP dispatcher link | `dispatcher_{nsid}_{ifindex}_link` | `/run/bpfman/fs/xdp/dispatcher_0_2_link` |
| XDP dispatcher dir | `dispatcher_{nsid}_{ifindex}_{rev}/` | `/run/bpfman/fs/xdp/dispatcher_0_2_1/` |
| CSI per-pod | `{volume_id}/` | `/run/bpfman/csi/fs/vol-abc123/` |

## Upstream CSI Re-pinning Flow

Upstream uses re-pinning with per-pod bpffs mounts:

```
1. Source maps at:     /run/bpfman/fs/maps/{program_id}/{map_name}
                                    │
                                    ▼ MapData::from_pin()
2. Re-pin to pod:      /run/bpfman/csi/fs/{volume_id}/{map_name}
                                    │
                                    ▼ bind mount
3. Container sees:     {target_path}/{map_name}
```

Key implementation details from `storage.rs`:

```rust
const RTDIR_BPFMAN_CSI_FS: &str = "/run/bpfman/csi/fs";

// Get source map path
let core_map_path = prog_data.get_data().get_map_pin_path()?;
// Returns: /run/bpfman/fs/maps/{kernel_program_id}

// Create per-pod bpffs
let path = &Path::new(RTDIR_BPFMAN_CSI_FS).join(volume_id);
create_bpffs(path)?;

// Re-pin each requested map
maps.iter().try_for_each(|m| {
    let map = MapData::from_pin(core_map_path.join(m));  // Load from source
    map.pin(path.join(m))                                 // Re-pin to pod
})?;

// Bind mount to container
mount(path, target_path, MS_BIND)?;
```

## Benefits of Alignment

1. **No UUIDs** - Kernel IDs are the only identifiers
2. **Protocol alignment** - CLI commands map directly to gRPC RPCs
3. **Upstream compatibility** - Matches Rust bpfman conventions
4. **Simpler model** - One identifier per entity
5. **Interoperability** - bpfman-operator works unchanged

## Current vs Target Comparison

| Aspect | Current (go-bpfman) | Target (upstream) |
|--------|---------------------|-------------------|
| Root | `/sys/fs/bpf/bpfman/` | `/run/bpfman/fs/` |
| Program path | `/{uuid}/{prog_name}` | `/prog_{kernel_id}` |
| Link path | `/{uuid}/link` | `/links/{link_id}` |
| Map path | `/{uuid}/{map_name}` | `/maps/{prog_id}/{map_name}` |
| CSI per-pod | `/run/bpfman/csi/fs/{vol}/` | `/run/bpfman/csi/fs/{vol}/` |
| Identifier | UUID (string) | kernel ID (uint32) |

## Protocol Extensions

Add missing link operations for full remote support:

```protobuf
service Bpfman {
    // Existing RPCs (unchanged)
    rpc Load (LoadRequest) returns (LoadResponse);
    rpc Unload (UnloadRequest) returns (UnloadResponse);
    rpc List (ListRequest) returns (ListResponse);
    rpc Get (GetRequest) returns (GetResponse);
    rpc Attach (AttachRequest) returns (AttachResponse);
    rpc Detach (DetachRequest) returns (DetachResponse);
    rpc PullBytecode (PullBytecodeRequest) returns (PullBytecodeResponse);

    // New link operations
    rpc ListLinks (ListLinksRequest) returns (ListLinksResponse);
    rpc GetLink (GetLinkRequest) returns (GetLinkResponse);
}

message ListLinksRequest {
    optional uint32 program_id = 1;
}

message ListLinksResponse {
    repeated LinkInfo links = 1;
}

message GetLinkRequest {
    uint32 link_id = 1;
}

message GetLinkResponse {
    LinkInfo link = 1;
}

message LinkInfo {
    uint32 link_id = 1;
    uint32 program_id = 2;
    LinkType link_type = 3;
    string pin_path = 4;
    oneof details {
        TracepointLinkInfo tracepoint = 10;
        XDPLinkInfo xdp = 11;
        TCLinkInfo tc = 12;
        KprobeLinkInfo kprobe = 13;
    }
}
```

## Schema Changes

### Programs Table

Current:
```sql
CREATE TABLE programs (
    uuid TEXT PRIMARY KEY,
    kernel_id INTEGER,
    ...
);
```

Target:
```sql
CREATE TABLE programs (
    kernel_id INTEGER PRIMARY KEY,
    ...
);
```

### Links Table

Current:
```sql
CREATE TABLE link_registry (
    uuid TEXT PRIMARY KEY,
    kernel_link_id INTEGER,
    kernel_program_id INTEGER,
    ...
);
```

Target:
```sql
CREATE TABLE links (
    link_id INTEGER PRIMARY KEY,
    program_id INTEGER NOT NULL,
    ...
    FOREIGN KEY (program_id) REFERENCES programs(kernel_id)
);
```

## CLI Changes

Commands switch from UUIDs to kernel IDs:

| Before | After |
|--------|-------|
| `bpfman detach <uuid>` | `bpfman detach <link-id>` |
| `bpfman get link <uuid>` | `bpfman get link <link-id>` |

Program commands already use kernel IDs (unchanged).

## Local vs Remote

With kernel IDs and protocol extensions, local and remote modes become
functionally equivalent:

| Operation | Local | Remote | Notes |
|-----------|-------|--------|-------|
| List programs | Yes | Yes | Existing RPC |
| Get program | Yes | Yes | Existing RPC |
| Load | Yes | Yes | Existing RPC |
| Unload | Yes | Yes | Existing RPC |
| Attach | Yes | Yes | Existing RPC |
| Detach | Yes | Yes | Uses link_id |
| List links | Yes | Yes | New RPC |
| Get link | Yes | Yes | New RPC |
| GC | Yes | No | Local-only |
| Reconcile | Yes | No | Local-only |

## Migration Path

### Phase 1: Filesystem Structure

1. Change root from `/sys/fs/bpf/bpfman/` to `/run/bpfman/fs/`
2. Mount bpffs at `/run/bpfman/fs/`
3. Adopt `prog_{id}`, `links/{id}`, `maps/{id}/` naming
4. Update CSI to use `/run/bpfman/csi/fs/`

### Phase 2: Protocol Extensions

1. Add ListLinks and GetLink RPCs to proto
2. Implement server handlers
3. Update RemoteClient to use new RPCs

### Phase 3: Schema Migration

1. Create migration to switch primary keys to kernel IDs
2. Drop UUID columns
3. Update store interface and implementations

### Phase 4: CLI Cleanup

1. Remove LinkUUID type from CLI
2. Change detach to accept link_id
3. Remove UUID-related code

## Upstream Initialization

Upstream bpfman handles `/run/bpfman/` setup **programmatically** at daemon
startup, not via systemd or init containers.

### bpffs Mount

Upstream bpfman uses a single bpffs mount at `/run/bpfman/fs/` for all its
managed objects. It does **not** use `/sys/fs/bpf` for any of its own data.

The bpfman source code contains zero references to `/sys/fs/bpf`. All path
constants are under `/run/bpfman/`:

```rust
pub(crate) const RTDIR: &str = "/run/bpfman";
pub(crate) const RTDIR_FS: &str = "/run/bpfman/fs";
pub(crate) const RTDIR_FS_MAPS: &str = "/run/bpfman/fs/maps";
pub(crate) const RTDIR_FS_LINKS: &str = "/run/bpfman/fs/links";
// etc.
```

### Daemon Startup Sequence

The `initialize_bpfman()` function in `utils.rs` runs at startup:

```rust
pub(crate) fn initialize_bpfman() -> anyhow::Result<()> {
    // Check capabilities
    has_cap(caps::CapSet::Effective, caps::Capability::CAP_BPF);
    has_cap(caps::CapSet::Effective, caps::Capability::CAP_SYS_ADMIN);

    // Set resource limits
    setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY)?;

    // Create directories
    create_dir_all(RTDIR)?;      // /run/bpfman
    create_dir_all(RTDIR_FS)?;   // /run/bpfman/fs

    // Mount bpffs if not already mounted
    if !is_bpffs_mounted()? {
        create_bpffs(RTDIR_FS)?;
    }

    // Create subdirectories (on the now-mounted bpffs)
    create_dir_all(RTDIR_FS_XDP)?;
    create_dir_all(RTDIR_FS_TC_INGRESS)?;
    create_dir_all(RTDIR_FS_TC_EGRESS)?;
    create_dir_all(RTDIR_FS_MAPS)?;
    create_dir_all(RTDIR_FS_LINKS)?;

    Ok(())
}
```

The bpffs mount function:

```rust
pub fn create_bpffs(directory: &str) -> anyhow::Result<()> {
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME;
    mount::<str, str, str, str>(None, directory, Some("bpf"), flags, None)
}
```

The mount check reads `/proc/mounts` looking for a bpffs mount containing
"bpfman" in the path.

### Kubernetes Deployment

In the bpfman-operator daemonset:

**Init container** mounts `/sys/fs/bpf` for aya/libbpf compatibility (see note
below):

```yaml
initContainers:
- name: mount-bpffs
  image: quay.io/fedora/fedora-minimal:39
  command:
  - /bin/sh
  - -xc
  - |
    if ! /usr/bin/findmnt --noheadings --types bpf /sys/fs/bpf >/dev/null 2>&1; then
      /bin/mount bpffs /sys/fs/bpf -t bpf
    fi
  securityContext:
    privileged: true
  volumeMounts:
  - mountPath: /sys/fs/bpf
    name: default-bpf-fs
    mountPropagation: Bidirectional
```

**Main container** (bpfman daemon) creates `/run/bpfman/fs/` and mounts its
own bpffs at startup via `initialize_bpfman()`.

**Key volumes** in the daemonset:

| Volume | Host Path | Container Path | Purpose |
|--------|-----------|----------------|---------|
| `default-bpf-fs` | `/sys/fs/bpf` | `/sys/fs/bpf` | For aya `PIN_BY_NAME` |
| `runtime` | `/run/bpfman` | `/run/bpfman` | bpfman runtime directory |
| `socket-dir` | `/var/lib/kubelet/plugins/csi-bpfman` | ... | CSI registration |

**Mount propagation**: Bidirectional for `/sys/fs/bpf` and `/run/bpfman` so
that mounts made by the container (like per-pod bpffs for CSI) are visible to
the host and other containers.

### Map Sharing Mechanisms

bpfman supports two independent mechanisms for sharing maps between programs:

#### 1. `--map-owner-id` (bpfman-managed)

The CLI provides explicit map sharing via the `--map-owner-id` argument:

```bash
# Load first program
bpfman load image quay.io/example/prog:latest --programs xdp:counter
# Returns kernel_id, e.g., 63178

# Load second program, sharing maps with first
bpfman load image quay.io/example/other:latest \
    --programs xdp:reader \
    --map-owner-id 63178
```

This mechanism:
- Is explicit and controlled via CLI/API
- Uses the owner program's kernel ID
- Shares maps via bpfman's managed path: `/run/bpfman/fs/maps/{owner_id}/`
- Works entirely within bpfman's managed bpffs

#### 2. `LIBBPF_PIN_BY_NAME` (libbpf/aya convention)

BPF programs can declare maps with automatic sharing by name:

```c
// Program A
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} shared_counters SEC(".maps");

// Program B (separate bytecode, same map name)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} shared_counters SEC(".maps");  // Same name = shared map
```

This mechanism:
- Is implicit, defined in BPF program source code
- Uses map name for sharing (programs with same map name share it)
- Pins to `/sys/fs/bpf/{map_name}` by default (libbpf convention)
- Is handled by aya during program loading

When aya loads a program with `PIN_BY_NAME` maps, it calls
`create_pinned_by_name()` which first tries to open an existing pin at
`/sys/fs/bpf/{map_name}`. If found, it reuses that map; otherwise it creates
and pins a new one. bpfman does not override this behaviour (it doesn't call
`.map_pin_path()` on the aya loader).

### Why `/sys/fs/bpf` is Mounted

The operator mounts `/sys/fs/bpf` to support programs using `LIBBPF_PIN_BY_NAME`.
Without this mount, aya would fail when trying to pin maps to the default path.

The daemonset comments (misleadingly) describe this as a "hack for kind", but
it's actually required for any program using `LIBBPF_PIN_BY_NAME` maps:

> "Hack for kind to allow LIBBPF_PIN_BY_NAME to work when it results in the
> maps being pinned to /sys/fs/bpf."

> "Needed for the aya PIN_BY_NAME feature to function correctly"

**Summary**:
- bpfman's own data → `/run/bpfman/fs/`
- `--map-owner-id` sharing → `/run/bpfman/fs/maps/{owner_id}/`
- `LIBBPF_PIN_BY_NAME` sharing → `/sys/fs/bpf/{map_name}` (via aya)

## Open Questions

1. ~~**bpffs mount management**~~: Resolved. The daemon mounts its own bpffs at
   `/run/bpfman/fs/` programmatically at startup. The `/sys/fs/bpf` mount in
   the operator daemonset is for aya's `LIBBPF_PIN_BY_NAME` compatibility.

2. **CSI integration**: Verify our CSI driver aligns with upstream patterns.

3. **Dispatcher state**: Our dispatcher implementation needs review against
   upstream path conventions.

4. ~~**PIN_BY_NAME support**~~: Resolved. bpfman supports two map sharing
   mechanisms: `--map-owner-id` (explicit, bpfman-managed) and
   `LIBBPF_PIN_BY_NAME` (implicit, libbpf convention). The latter requires
   `/sys/fs/bpf` to be mounted. If we want to support programs that use
   `LIBBPF_PIN_BY_NAME`, we must mount `/sys/fs/bpf` in our deployment.
