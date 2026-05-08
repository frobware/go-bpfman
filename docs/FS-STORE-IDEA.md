# Filesystem Store: Exploration and Tradeoffs

This document captures the exploration of implementing a filesystem-based
alternative to SQLite for go-bpfman's program/link/dispatcher state store.

**Conclusion**: SQLite is the right choice for this codebase. However, the
exploration yielded a valuable insight: **staged pins in bpffs** eliminate
the worst crash window regardless of which store backend is used.

## Context

The store abstraction (`interpreter.Store`) manages:

- **Programs**: metadata for loaded BPF programs (keyed by `kernel_id`)
- **Links**: attachment records (keyed by `kernel_link_id`)
- **Dispatchers**: XDP/TC multi-program dispatcher state (keyed by `type, nsid, ifindex`)

The question: could we replace SQLite with plain files on disk, matching
the mental model of bpffs pins?

## When a Filesystem Store Might Fit

An FS-only store is reasonable if:

- You only need lookup by kernel_id (and maybe one or two other keys)
- You're happy with directory scans as your "list" operation
- You can tolerate GC by walking the tree and cross-checking kernel state
- You're fine implementing atomic multi-step updates with `rename(2)` / temp files
- You don't need cross-object constraints (foreign keys, cascades) beyond code

## What SQLite Gives You

SQLite provides these capabilities that an FS store must reimplement:

1. **Fast queries by metadata** (CSI lookup via key/value index)
2. **Joins / polymorphism** (link registry + detail tables)
3. **Uniqueness constraints** (positions per ifindex+nsid, etc.)
4. **Referential integrity** (map owner can't be deleted while dependents exist)
5. **Single-transaction updates** across program + tags + metadata index
6. **Stable "list all"** without bespoke on-disk indexing

## The Kernel ID Reuse Problem

This is the killer constraint for FS stores.

The kernel aggressively reuses program and link IDs. If bpfman crashes and
restarts, the kernel may have reused an ID that the store still has recorded.
With FS files keyed by kernel ID, you get collisions.

SQLite handles this cleanly:

- Store a second discriminator (pin_path, created_at, program_tag)
- On conflict, decide: same object, or ID reuse / stale record?
- Use `INSERT ... ON CONFLICT` for upsert semantics

Without a database, "INSERT is fatal" becomes "a random reboot bricks the
daemon until GC runs perfectly".

## FS Store Design Explored

### Simple Layout (No Transactions)

```
/var/lib/bpfman/store/
├── locks/
│   └── global.lock              # flock for store-wide ops
├── programs/
│   └── <kernel_id>.json         # program + tags + metadata embedded
├── links/
│   └── tcx/<nsid>/<ifindex>/<direction>/<kernel_link_id>.json
├── dispatchers/
│   └── <type>-<nsid>-<ifindex>.json
└── indexes/                     # optional cache for fast lookups
    └── metadata/<key>/<value>/<kernel_id>
```

### Locking

Use fd-based advisory locks, NOT "lock file exists":

```go
// Lock is held for as long as the fd is open.
// Kernel releases automatically on process crash.
f, _ := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
unix.Flock(int(f.Fd()), unix.LOCK_EX)
defer f.Close()
```

The lock file can exist forever; its existence is not the lock.

### Atomic Writes

Every file write must be crash-safe:

```go
func atomicWriteJSON(path string, v any) error {
    tmp, _ := os.CreateTemp(filepath.Dir(path), ".tmp-*")
    json.NewEncoder(tmp).Encode(v)
    tmp.Sync()              // fsync file
    tmp.Close()
    os.Rename(tmp.Name(), path)  // atomic

    // fsync parent directory (ensures rename is durable)
    d, _ := os.Open(filepath.Dir(path))
    d.Sync()
    d.Close()
}
```

### Generational Snapshots (Nix-style)

For true multi-object atomicity, you need:

```
/var/lib/bpfman/store/
├── state/
│   └── current -> ../gens/<genid>    # atomic symlink flip
├── gens/
│   └── <genid>/
│       ├── programs/...
│       ├── dispatchers/...
│       └── links/...
└── tx/
    └── <txid>/                       # staging for in-progress transaction
```

Commit sequence:
1. Create new generation directory
2. Copy forward unchanged files (hardlinks for efficiency)
3. Write changed files
4. Atomic symlink swap: `current -> new-gen`

### What This Requires You to Build

To match SQLite semantics with an FS store, you end up building:

- A staging area in bpffs
- Per-resource locks + lock ordering
- Crash recovery logic
- Typed on-disk formats and versioning
- Deterministic ordering rules
- GC/doctor as a first-class reconciliation loop
- A journal or pointer-flip generations for atomicity

**This is essentially a small database with fewer battle-tested guarantees.**

## The "Staged Reads" Problem

Inside a transaction, reads must see both committed state AND staged writes:

```go
func (tx *TxStore) CountDispatcherLinks(dispatcherID uint32) (int, error) {
    committed := tx.gen0.countLinks(dispatcherID)
    staged := 0
    for _, link := range tx.stagedLinks {
        if link.DispatcherID == dispatcherID {
            staged++
        }
    }
    return committed + staged, nil
}
```

This adds complexity to every read operation that might be affected by
in-flight writes.

## Expensive Operations in FS Store

| Operation | SQLite | FS Store |
|-----------|--------|----------|
| `FindProgramByMetadata(key, value)` | Index lookup | Scan all programs OR maintain index |
| `ListTCXLinksByInterface` sorted by priority | Indexed query | Scan + sort OR per-interface layout |
| `CountDependentPrograms` | FK count | Scan all programs |
| `CountDispatcherLinks` | Indexed count | Scan all links for dispatcher |

## TCX vs XDP Recovery Differences

| Aspect | XDP | TCX |
|--------|-----|-----|
| Position | Encoded in pin path (`link_{position}`) | Not in path |
| Priority | Stored but not critical (position is truth) | Critical for ordering |
| Dispatcher | Yes, can reconstruct from pin | N/A (native kernel) |
| Recovery policy | Reconstruct (safe) | Detach (ordering unknown) |

For TCX orphans without store records: **detach on sight** because priority
(which determines ordering) cannot be recovered from the pin path.

## The Key Insight: Staged Pins

The most valuable outcome of this exploration: **pin to a staging directory
first, then promote after store commit**.

This works with ANY store backend and eliminates the worst crash window.

### Current Problem

```
1. kernel.AttachXDPExtension(finalPinPath)   # Kernel committed
   ═══════════════════════════════════════
   CRASH WINDOW: kernel has link, store doesn't
   ═══════════════════════════════════════
2. store.SaveXDPLink(...)                     # Store committed
```

### With Staged Pins

```
1. kernel.AttachXDPExtension(stagingPinPath)  # Kernel committed to staging
2. store.SaveXDPLink(..., finalPinPath)       # Store committed (records final path)
3. os.Rename(stagingPinPath, finalPinPath)    # Promote pin
```

Crash behaviour:

| Crash Point | Staging Pin | Store | Final Pin | Recovery |
|-------------|-------------|-------|-----------|----------|
| After 1 | exists | no | no | GC deletes `.staging/*` |
| After 2 | exists | yes | no | Doctor promotes pin |
| After 3 | no | yes | yes | Clean |

### Implementation

```go
// staging.go
func (m *Manager) stagingDir(txid string) string {
    return filepath.Join(m.bpffsRoot, ".staging", txid)
}

func stagingNameForFinal(finalPath string) string {
    sum := sha256.Sum256([]byte(finalPath))
    return hex.EncodeToString(sum[:8])
}

func promotePins(promotions map[string]string) error {
    for staging, final := range promotions {
        os.MkdirAll(filepath.Dir(final), 0755)
        if err := os.Rename(staging, final); err != nil {
            return err
        }
    }
    return nil
}
```

### Doctor Rules

```go
func (d *Doctor) ValidateLinks(ctx context.Context) error {
    links, _ := d.store.ListLinks(ctx)

    for _, link := range links {
        // Pin exists at recorded path?
        if _, err := os.Stat(link.PinPath); err == nil {
            // Verify kernel ID matches
            continue
        }

        // Check staging
        staged := d.findInStaging(link.PinPath)
        if staged != "" {
            os.Rename(staged, link.PinPath)  // Promote
            continue
        }

        // Stale record
        if d.repair {
            d.store.DeleteLink(ctx, link.KernelLinkID)
        }
    }
    return nil
}
```

## Pin Path Conventions

The existing pin path conventions are valuable for recovery:

### XDP/TC (Dispatcher Model)

```
{bpffsRoot}/{type}/dispatcher_{nsid}_{ifindex}_link           # dispatcher link
{bpffsRoot}/{type}/dispatcher_{nsid}_{ifindex}_{revision}/    # revision dir
    dispatcher                                                 # dispatcher prog
    link_{position}                                            # extension link
```

### TCX (Native Multi-attach)

```
{bpffsRoot}/tcx-{direction}/link_{nsid}_{ifindex}_{programKernelID}
```

These paths encode enough information to reconstruct store state for XDP
(position is in the path), but NOT for TCX (priority is not in the path).

## Parsing Helpers

```go
var (
    dispatcherLinkRE = regexp.MustCompile(`^dispatcher_(\d+)_(\d+)_link$`)
    revisionDirRE    = regexp.MustCompile(`^dispatcher_(\d+)_(\d+)_(\d+)$`)
    extensionLinkRE  = regexp.MustCompile(`^link_(\d+)$`)
    tcxLinkRE        = regexp.MustCompile(`^link_(\d+)_(\d+)_(\d+)$`)
)

func ParseExtensionLinkPath(path string) (ParsedExtensionLink, error) {
    // Extract: type, nsid, ifindex, revision, position
}

func ParseTCXLinkPath(path string) (ParsedTCXLink, error) {
    // Extract: direction, nsid, ifindex, programKernelID
    // NOTE: priority is NOT recoverable
}
```

## Recommendations

### 1. Keep SQLite

SQLite wins for this use case:

- Real transactions across multiple rows/tables
- Durability with WAL
- Unique constraints and FKs as invariants
- Indexes for fast queries
- Simpler GC: diff kernel↔db without debugging partial FS state

### 2. Add Staged Pins

Regardless of store backend, stage pins before commit:

```go
func (m *Manager) AttachXDP(...) {
    txid := uuid.NewString()
    stagingDir := m.stagingDir(txid)
    os.MkdirAll(stagingDir, 0755)
    defer os.RemoveAll(stagingDir)  // cleanup on failure

    // Kernel attaches to staging paths
    kernel.AttachXDPDispatcher(stagingProgPath, stagingLinkPath)
    kernel.AttachXDPExtension(stagingExtPath)

    // Store commits with final paths
    store.RunInTransaction(func(tx) {
        tx.SaveDispatcher(...)
        tx.SaveXDPLink(..., finalExtPath)
    })

    // Promote pins after commit
    promotePins(promotions)
}
```

### 3. Doctor Invariants

On startup:

1. Delete everything under `.staging/*` (always safe)
2. For each store record, verify pin exists at recorded path
3. If missing, check staging and promote
4. If still missing, record is stale → delete or warn

### 4. GC for Orphan Pins

For pins that exist but have no store record:

- **XDP**: Can reconstruct from pin path (position encoded)
- **TCX**: Detach on sight (priority not recoverable, ordering is semantic)

## Future Consideration: FS Store for Debugging

If an FS store is ever implemented for comparison or debugging:

- Make it a **weak store** (lock + atomic files + reconcile)
- NO attempt at multi-object atomicity beyond the lock
- Accept that recovery = "clear staging + reconcile against kernel"
- Use it for experiments or export format, not as source of truth

## Summary

The FS store exploration revealed:

1. **SQLite is worth it**: The complexity of building crash-safe multi-object
   atomicity in a filesystem store approaches building a database.

2. **Pin paths are gold**: The existing conventions encode enough to reconstruct
   XDP state, detect ID reuse, and make doctor/GC deterministic.

3. **Staged pins are the key insight**: Pin to `.staging/<txid>/...` first,
   commit store, then promote. This eliminates the worst crash window with
   minimal code changes.

4. **Kernel ID reuse is the killer constraint**: Without a database to enforce
   discriminators and handle conflicts, ID reuse turns minor crashes into
   major recovery problems.
