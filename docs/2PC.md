# Two-Phase Commit for Kernel/Store Consistency

## The Problem

Every attach flow in go-bpfman performs two non-atomic operations:

1. **Kernel I/O** — load a program, create a link, pin to bpffs
2. **Store write** — persist the record to SQLite

Between these two steps there is a crash window. If the process dies
after the kernel operation succeeds but before the store commits, the
kernel holds state that the store knows nothing about. On restart, the
daemon cannot reliably distinguish these orphaned objects from objects
legitimately managed by another process or from kernel ID reuse.

bpffs pins are the only durable handle we control. Staging pins allow us
to explicitly mark *prepared-but-not-committed* kernel state, making the
boundary between "in flight" and "committed" visible and inspectable on
the filesystem.

The problem is most acute for dispatcher-based flows (XDP, TC), where
multiple kernel objects — dispatcher program, dispatcher link, extension
link — are created in sequence, with a single store write only at the
end.

## Two-Phase Commit Protocol

The protocol eliminates the *primary* crash window — **final pins
existing without a corresponding store record** — by splitting each
attach flow into two phases.

It does not eliminate all crash windows, but it ensures that every
remaining failure mode is deterministic and recoverable.

### Phase A: Prepare (Kernel)

Perform all kernel operations, but pin objects into a staging directory
rather than their final bpffs paths. Collect sufficient in-memory state
to undo the operation if needed (kernel IDs, pin paths).

```
/sys/fs/bpf/bpfman/.staging/<txid>/
    disp_prog
    disp_link
    ext_link_0
    ...
```

The staging directory is keyed by a UUID transaction ID. Pin names use
stable, human-readable prefixes rather than mirroring the final path
hierarchy (e.g. `disp_prog`, `disp_link`, `ext_link_<position>`,
`tcx_link_<nsid>_<ifindex>_<prog>`). This keeps staging inspectable and
predictable without requiring a hash-to-path mapping.

If any kernel operation fails during Phase A, the staging directory is
removed and all partially created kernel objects are cleaned up. Nothing
is written to the store.

### Phase B: Commit (Store + Promote)

1. Begin a SQLite transaction.
2. Write all rows (dispatcher, link, program metadata), recording the
   **final** pin paths — never the staging paths.
3. Commit the SQLite transaction. **This is the commit point.**

   Before this moment, the operation has not happened. After this
   moment, the operation is committed, even if pin promotion has not yet
   completed.
4. Promote pins: `rename(staging-path, final-path)` for each pin.
   Promotion is post-commit finalisation, not part of the transaction.
5. Remove the staging directory.

## Rollback Scenarios

The two-phase protocol has two distinct cleanup paths:

* **Immediate cleanup** performed by the attach flow itself on any error
* **Crash recovery** performed by doctor and GC on startup

| Failure Point                                   | Staging Pins | Store Record | Final Pins | Who Cleans Up | When                        |
| ----------------------------------------------- | ------------ | ------------ | ---------- | ------------- | --------------------------- |
| Kernel fails during Phase A                     | partial      | none         | none       | Attach path   | Immediately (defer cleanup) |
| SQLite transaction fails (FK, constraint, etc.) | exists       | none         | none       | Attach path   | Immediately (defer cleanup) |
| Process killed before SQLite commit             | exists       | none         | none       | GC            | After doctor on restart     |
| Process killed during pin promotion             | exists       | yes          | partial    | Doctor        | On next startup             |
| Process killed after promotion                  | none         | yes          | yes        | —             | Clean state                 |

### Key rules

* **Any failure before the SQLite commit is handled synchronously by the
  attach path.** Staging pins are removed and kernel objects are detached
  best-effort.
* **Any failure after the SQLite commit is handled asynchronously by
  doctor/GC.**

The SQLite commit is the **linearisation point**. Before it commits, the
operation has not happened. After it commits, the operation must be made
durable, even if pin promotion was interrupted.

## Staging Invariants

The following invariants are critical to correctness:

1. **No store record ever references a staging path.**
   Store records always contain the *final* bpffs pin path.

2. **Staging pins exist only for uncommitted or partially committed
   work.** They are never considered authoritative state.

3. **Staging pins may be deleted iff no committed store record depends on
   them.** Determining that dependency is the doctor's job.

> If there is no committed store record corresponding to an operation,
> its staging directory contains only uncommitted kernel state and is
> safe to delete.

This defines *safety*, not *timing*. Who deletes staging and when is
specified by the doctor and GC integration below.

## The `staging.go` Helper

`manager/staging.go` encapsulates the protocol mechanics:

* `newStagingTx(bpffsRoot)` — create `.staging/<txid>/` and return a
  `stagingTx`.
* `stx.stage(finalPath)` — register a final-to-staging mapping and return
  the staging path for kernel pinning.
* `stx.promote()` — rename all staged pins to their final locations.
* `stx.cleanup()` — remove the staging directory. Safe to call
  unconditionally via `defer`.

## Per-Flow Application

### Simple Flows (Tracepoint, Kprobe, Uprobe, Fentry, Fexit)

These flows create a single kernel link and a single store record. The
crash window is small but real.

```
stx := newStagingTx(bpffsRoot)
defer stx.cleanup()

stagingPin := stx.stage(finalLinkPinPath)
kernel.AttachTracepoint(progPinPath, stagingPin)

store.RunInTransaction(func(tx) {
    tx.SaveTracepointLink(..., finalLinkPinPath)
})

stx.promote()
```

### XDP Flow (Dispatcher-Based)

XDP may create up to three kernel objects:

1. Dispatcher program
2. Dispatcher link
3. Extension link

All pins land in staging; all store writes occur in a single transaction.

```
stx := newStagingTx(bpffsRoot)
defer stx.cleanup()

stagingDispProg := stx.stage(finalDispProgPath)
stagingDispLink := stx.stage(finalDispLinkPath)
kernel.AttachXDPDispatcher(stagingDispProg, stagingDispLink)

stagingExtLink := stx.stage(finalExtLinkPath)
kernel.AttachXDPExtension(stagingExtLink)

store.RunInTransaction(func(tx) {
    tx.SaveDispatcher(...)
    tx.SaveXDPLink(..., finalExtLinkPath)
})

stx.promote()
```

The dispatcher record is no longer written independently. This removes
the window where a dispatcher exists in the store without its extension
links.

### TC Flow (Dispatcher-Based, Netlink)

TC mirrors XDP but includes a netlink filter, which cannot be staged.

```
stx := newStagingTx(bpffsRoot)
defer stx.cleanup()

stagingDispProg := stx.stage(finalDispProgPath)
kernel.AttachTCDispatcher(stagingDispProg)
// netlink filter created here

stagingExtLink := stx.stage(finalExtLinkPath)
kernel.AttachTCExtension(stagingExtLink)

store.RunInTransaction(func(tx) {
    tx.SaveDispatcher(...)
    tx.SaveTCLink(..., finalExtLinkPath)
})

stx.promote()
```

If Phase B fails, the netlink filter must be explicitly removed.

### TCX Flow (Native Kernel Multi-Attach)

TCX has no dispatcher; a single link is created with priority-derived
ordering.

```
stx := newStagingTx(bpffsRoot)
defer stx.cleanup()

stagingLinkPin := stx.stage(finalLinkPinPath)
kernel.AttachTCX(ifindex, direction, progPinPath, stagingLinkPin, order)

store.RunInTransaction(func(tx) {
    tx.SaveTCXLink(..., finalLinkPinPath)
})

stx.promote()
```

**TCX policy:** priority is not encoded in the pin path. Orphan TCX links
cannot be reconstructed safely and must be detached.

## Doctor and GC Integration

Doctor and GC have **non-overlapping responsibilities** and must run in
order.

```
doctor → gc
```

### Doctor: Repair and Verification (Must Run First)

Doctor is responsible for **completing interrupted commits** and
verifying invariants. It must **not** delete staging directories until
promotion opportunities are exhausted.

On startup, doctor performs:

1. **Verify final pins for all store records**

   For each persisted dispatcher or link record:

   * Check that the recorded `pin_path` exists.
   * If it exists:

     * Verify the pinned object matches the expected kernel ID.
     * If it does not, report a coherency error (possible kernel ID reuse
       or external interference).

2. **Promote staged pins when final pins are missing**

   If a store record exists but its final pin path does not:

   * Search `.staging/*/` for a staged pin corresponding to that final
     path.
   * If found:

     * Atomically promote it via `rename(staged, final)`.
     * This completes a previously interrupted commit.
   * If not found:

     * The store record is stale (kernel object removed or never fully
       created).
     * Flag or delete the record according to policy.

3. **Leave `.staging/` intact**

   Doctor must not remove staging directories wholesale. They are
   required input for repair.

**Invariant after doctor completes:**

> Any remaining entry in `.staging/` has no corresponding committed
> store record and is therefore unreachable.

### GC: Cleanup of Unreachable State (Runs After Doctor)

GC is purely destructive and assumes doctor has already repaired all
recoverable states.

GC performs:

1. **Remove leftover staging directories**

   After doctor finishes, any remaining `.staging/*` directories
   represent incomplete operations with no committed intent:

   ```
   rm -rf /sys/fs/bpf/bpfman/.staging/*
   ```

2. **Detect orphaned final pins**

   Enumerate all managed bpffs pins:

   * For each pin, read the kernel object ID.
   * Check whether the store has a record for that ID.

   If no store record exists:

   * **XDP / TC extension links**

     * Reconstruct if metadata is fully recoverable (position from path,
       program ID probeable, dispatcher probeable).
     * Otherwise detach.
   * **TCX links**

     * Detach immediately.
     * Priority/order is not encoded in the pin path and cannot be
       reconstructed safely.
   * **Dispatchers with no dependents**

     * Detach and remove.

3. **Optionally remove stale store records**

   Records whose kernel objects no longer exist (and cannot be recovered
   from staging) may be deleted or flagged depending on configuration.

## Locking

Concurrent attaches to the same hook point must be serialised using
advisory `flock(2)` locks:

```
locks/xdp-<nsid>-<ifindex>.lock
locks/tcx-<nsid>-<ifindex>-<direction>.lock
```

Locks are held across the entire 2PC sequence and are released
automatically on process death.

## Relationship to the Coherency Model

2PC reduces — but does not replace — the coherency model described in
`docs/COHERENCY-MODEL.md`. It eliminates the primary crash window while
leaving the coherency engine responsible for:

* Kernel ID reuse
* External pin removal
* Latent bugs

Doctor becomes verification-first, repair-second — no longer the primary
recovery mechanism.

## Mental Model

* **SQLite is the source of truth for intent.**
* **bpffs pins are the durable handle for kernel objects.**
* **Staging marks "kernel work done, intent not yet committed".**
* **SQLite commit is the moment the change becomes real.**
* **Doctor finishes anything that committed but did not fully materialise.**
* **GC deletes anything that never committed.**

## Summary

The two-phase commit protocol:

1. **Eliminates the primary crash window** by ensuring kernel pins reach
   their final paths only after the store commits.
2. **Makes recovery deterministic** by giving staging pins a single,
   unambiguous meaning.
3. **Batches store writes**, reducing sync overhead and consistency
   risk, especially for dispatcher-based flows.
