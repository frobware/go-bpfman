# Data coherency in bpfman

All coherency rules are comparisons between sources; no rule
inspects a single source in isolation. This document enumerates all
divergence scenarios currently recognised by bpfman.

bpfman maintains state across three independent sources of truth:

1. **Kernel** — BPF programs, links, and maps loaded into the kernel,
   plus TC filters attached via netlink.
2. **Filesystem** — Pin files on bpffs that keep kernel objects alive
   and addressable by path.
3. **Database** — SQLite store recording program metadata, link
   details, and dispatcher state.

These three sources can diverge. A daemon crash, a restart, a failed
attach, or incomplete test teardown can leave one source inconsistent
with the others. When they disagree, the daemon may fail to attach
(EBUSY), leak kernel resources, or report stale data.

## Divergence scenarios

### Kernel has state the database does not

This happens when the daemon attaches a program or dispatcher, then
crashes before persisting to the database, or when the database is
deleted and the daemon restarts. The kernel still holds the BPF
program and link, but the daemon has no record of it.

Consequences: the daemon tries to create a new dispatcher on the same
interface and gets `EBUSY`. Programs and links accumulate in the
kernel with no owner.

### Database has state the kernel does not

This happens when a BPF program is removed from the kernel externally
(e.g. by another tool, or by the kernel reclaiming resources), but the
database still references it.

Consequences: the daemon believes links and dispatchers exist that the
kernel has already removed. Detach operations may silently fail or
produce confusing errors.

### Filesystem has pins the database does not reference

This happens when the daemon creates pin files, then crashes before
recording them in the database, or when a previous daemon instance
used a different database.

Consequences: orphan pin files keep kernel objects alive
unnecessarily, preventing resource reclamation.

### Database references pins that do not exist

This happens when pin files are removed externally or by a partial
cleanup. The database still records pin paths, but the files are gone.

Consequences: detach operations that attempt to remove pins fail with
ENOENT. Dispatcher cleanup may leave partial state behind.

## Coherency checks

`bpfman doctor` cross-references all three sources and reports
discrepancies. Each check compares two sources and reports rows that
appear in one but not the other.

### Database vs kernel

| Check | Description |
|-------|-------------|
| Program in DB, not in kernel | DB records a kernel program ID that no longer exists. The program was unloaded externally or the kernel reclaimed it. |
| Link in DB, not in kernel | DB records a kernel link ID that no longer exists. The link was detached externally. |
| Dispatcher in DB, kernel program gone | Dispatcher references a kernel program ID that no longer exists. The dispatcher program was unloaded but the DB row persists. |
| Dispatcher in DB, kernel link gone (XDP) | XDP dispatcher references a link ID that no longer exists in the kernel. The dispatcher link was detached externally. |
| TC filter expected, not found via netlink | TC dispatcher exists in the DB with a known priority, but no matching filter exists on the interface. |

### Database vs filesystem

| Check | Description |
|-------|-------------|
| Program in DB, pin missing | DB records a program pin path, but no file exists at that path. The pin was removed externally. |
| Link in DB, pin missing | DB records a link pin path, but no file exists at that path. |
| Dispatcher prog pin missing | Dispatcher exists in DB. The expected program pin (derived from revision and bpffs convention) does not exist on the filesystem. |
| Dispatcher link pin missing (XDP) | XDP dispatcher exists in DB. The expected link pin does not exist on the filesystem. |
| Extension link pin missing | Extension link exists in DB. The expected pin under the dispatcher revision directory does not exist. |

### Filesystem vs database

| Check | Description |
|-------|-------------|
| Orphan program pin | A program pin file exists under the bpffs programs directory but no DB row references it. |
| Orphan link pin | A link pin file exists under the bpffs links directory but no DB row references it. |
| Orphan dispatcher directory | A dispatcher revision directory exists on the filesystem but no matching dispatcher row exists in the DB. |

### Derived state consistency

| Check | Description |
|-------|-------------|
| Extension count mismatch | `CountDispatcherLinks` from the DB disagrees with the number of extension link pin files in the dispatcher's revision directory. |

## Pin path conventions

All dispatcher pin paths are derived from `(bpffsRoot, type, nsid,
ifindex, revision)` using functions in `dispatcher/paths.go`:

- **Dispatcher program pin**: `{bpffsRoot}/{type}/dispatcher_{nsid}_{ifindex}_{revision}/dispatcher`
- **Dispatcher link pin (XDP)**: `{bpffsRoot}/{type}/dispatcher_{nsid}_{ifindex}_link`
- **Extension link pin**: `{bpffsRoot}/{type}/dispatcher_{nsid}_{ifindex}_{revision}/link_{position}`
- **Revision directory**: `{bpffsRoot}/{type}/dispatcher_{nsid}_{ifindex}_{revision}`

Program and link pins for non-dispatcher objects use `RuntimeDirs`:

- **Program pin**: `{bpffsRoot}/prog_{kernelID}`
- **Link pin**: `{bpffsRoot}/links/link_{kernelLinkID}`

## Implementation

`bpfman doctor` collects data from all three sources, then runs each
check. It reports findings grouped by severity:

- **Error** — state that will cause operations to fail (e.g. EBUSY on
  attach, missing pin for detach).
- **Warning** — state that wastes resources but does not block
  operations (e.g. orphan pins, leaked kernel objects).
- **OK** — sources agree.

The command is read-only. It does not modify the kernel, filesystem, or
database. Remediation is left to `bpfman gc` or manual intervention.
