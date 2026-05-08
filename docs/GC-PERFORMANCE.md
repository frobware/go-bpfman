# GC Performance Analysis

This document captures the GC performance problems observed during
e2e testing, identifies their root causes, and outlines optimisation
strategies.

## Problem Statement

GC dominates the cost of mutating operations. In
`TestTC_DispatcherFillDrainRefill`, each TC Detach call takes
approximately 110ms, of which 37--40ms (70--80%) is spent in GC. The
actual detach work (dispatcher rebuild, filter swap, store persist)
costs only 8--18ms.

The problem compounds in loops. A drain of 6 TC extensions calls
Detach 6 times, accumulating ~240ms of GC overhead on operations
that produce no garbage.

## Observed Timing Breakdown

Measurements from instrumented `TestTC_DispatcherFillDrainRefill`
(6 extensions per dispatcher, 3 fill-drain-refill cycles):

### Per-Detach Cost

| Phase          | Time    | % of total |
|----------------|---------|------------|
| GC             | 37-40ms | 70-80%     |
| Preflight      | ~0.04ms | <1%        |
| Plan execution | 8-18ms  | 20-30%     |
| **Total**      | 45-56ms |            |

### Plan Execution Breakdown (dispatcher rebuild)

| Step              | Time      |
|-------------------|-----------|
| Load dispatcher   | ~0.5ms    |
| Attach extensions | 0.3-1.5ms |
| Filter swap       | 0.1-0.5ms |
| Store persist     | 6-16ms    |

### GC in Aggregate

Over a full e2e run (326s, 43 tests): 80 GC invocations, ~12-15ms
each, totalling ~1.04s. The per-call cost is lower when the system
has fewer managed objects; the 37-40ms figure applies to the
dispatcher tests which maintain several programs and links.

## Root Cause 1: GC Runs Too Often

Every mutating method (Load, Unload, Attach, Detach) calls
`gcIfNeeded` at entry. After each mutation completes, `defer
markMutated()` sets the dirty flag. This means that in any sequence
of mutations, every call after the first triggers a full GC cycle.

The server holds the cross-process flock for the duration of each
RPC. Within that flock scope, no external actor can modify kernel or
filesystem state. GC after the first call in a flock-held scope is
therefore redundant: the only mutations are our own, and they are
well-defined.

### Implication

When the manager is used under a flock (the server path), GC should
run once at entry and then be suppressed for the remainder of the
flock scope. The manager needs either:

- Internal variants of mutating methods that skip GC, or
- A mechanism to suppress GC for a scope (e.g., a context flag or
  an explicit "begin batch" / "end batch" API).

When the manager is used from the CLI (which also holds the flock),
the same pattern applies: a single GC at the start of the lock
scope is sufficient.

## Root Cause 2: GC Is Too Expensive Per Call

A single GC cycle performs far more I/O than necessary due to
redundant enumeration across `ComputeGC` and `evaluateCoherency`.

### Call Graph

```
gcIfNeeded
  GC
    GCWithOptions
      ComputeGC                          -- phase 1: store GC
        kernel.Programs(ctx)             [kernel syscall]
        store.List(ctx)                  [SQLite query]
        scanner.PathExists(pin) x N      [filesystem stat per program]
        kernel.Links(ctx)                [kernel syscall]
        store.ListDispatcherSummaries    [SQLite query]
        store.ListLinks(ctx)             [SQLite query]
        computeStoreGC(...)              [pure]
        evaluateCoherency                -- phase 2: coherency rules
          GatherState
            inspect.Snapshot             -- reads everything again
              kernel.Programs(ctx)       [DUPLICATE kernel syscall]
              kernel.Links(ctx)          [DUPLICATE kernel syscall]
              scanner.ProgPins(ctx)      [filesystem scan]
              scanner.LinkDirs(ctx)      [filesystem scan]
              scanner.MapDirs(ctx)       [filesystem scan]
              scanner.DispatcherDirs     [filesystem scan]
              scanner.DispatcherLinkPins [filesystem scan]
              store.List(ctx)            [DUPLICATE SQLite query]
              store.ListLinks(ctx)       [DUPLICATE SQLite query]
              store.ListDispatcherSummaries [DUPLICATE SQLite query]
              kernel.Links(ctx)          [THIRD kernel links enum]
            scanner.Scan(ctx)            [full bpffs scan]
            kops.FindTCFilterHandle x M  [netlink query per TC dispatcher]
            store.ListReferencedSharedMaps [SQLite query]
            layout.Bytecode().ScanProgramDirs [filesystem scan]
            layout.Bytecode().ScanStagingDirs [filesystem scan]
      ExecuteGC
        [execute store actions in transaction]
        evaluateCoherency               -- SECOND GatherState call
          GatherState                   [entire gather repeated]
```

### Redundancy Summary

| Resource                   | Enumerations per GC | Notes                          |
|----------------------------|---------------------|--------------------------------|
| Kernel programs            | 2                   | ComputeGC + Snapshot           |
| Kernel links               | 3                   | ComputeGC + Snapshot + Snapshot phase 3 |
| store.List (programs)      | 2                   | ComputeGC + Snapshot           |
| store.ListLinks            | 2                   | ComputeGC + Snapshot           |
| store.ListDispatcherSummaries | 2                | ComputeGC + Snapshot           |
| Full bpffs scan            | 1-2                 | Once in Snapshot iterators, once in scanner.Scan |
| GatherState overall        | 2 (worst case)      | Once in ComputeGC (dry-run), once in ExecuteGC (re-gather) |

When store actions exist, `evaluateCoherency` runs twice: once
inside a rolled-back transaction (dry-run in ComputeGC) and once
after execution (in ExecuteGC). Each call performs the full
GatherState I/O. This doubles all filesystem scanning, kernel
enumeration, store queries, and netlink probes.

### Why GatherState Runs Twice

`ComputeGC` applies store deletions inside a rolled-back transaction
so that coherency rules evaluate against the post-deletion state.
The plan records the resulting violations. `ExecuteGC` then performs
the actual store deletions and must re-gather state to see filesystem
artefacts orphaned by those deletions (the dry-run did not actually
remove anything from disk).

This design is correct but expensive. The re-gather in `ExecuteGC`
is needed because removing a store row may leave behind bpffs pins,
program directories, or dispatcher directories that become orphans
only after the deletion commits.

## Optimisation Strategies

### Strategy 1: Flock-Scoped GC Suppression

Run GC once at the start of a flock scope, then suppress it for all
subsequent mutations within that scope.

**Approach A: Context-based suppression.** Store a "GC already ran"
flag in context. `gcIfNeeded` checks this flag and skips GC when
set. The server interceptor or CLI wrapper sets the flag after the
first GC.

**Approach B: Explicit batch API.** Add `BeginBatch` / `EndBatch`
methods to the manager. `BeginBatch` runs GC and sets an internal
flag that suppresses `gcIfNeeded`. `EndBatch` clears the flag.

**Approach C: Internal non-GC methods.** Provide unexported variants
(e.g., `detachInternal`) that skip `gcIfNeeded`. The public methods
call GC then delegate. Batch operations call the internal variants
directly. This is the simplest change but requires care to ensure
internal methods are never called without a prior GC.

**Expected impact:** Eliminates ~240ms of redundant GC in a 6-detach
drain loop. More generally, reduces GC from O(N) to O(1) per
flock-held operation sequence.

### Strategy 2: Reduce GC I/O Cost

Even with flock-scoped suppression, GC still runs at least once per
RPC. The per-call cost should be reduced.

**2a: Unified state gathering.** Replace the two-phase approach
(ComputeGC gathers kernel+store, then GatherState gathers
everything again) with a single gather pass. ComputeGC should build
an `ObservedState` (or equivalent) once and use it for both store GC
and coherency evaluation.

**2b: Eliminate the double GatherState.** Instead of re-gathering
after store execution, pass the filesystem orphan information
forward from the compute phase. The only reason ExecuteGC re-gathers
is to discover filesystem artefacts that became orphans after store
deletion. If the compute phase records which store entries will be
deleted, the corresponding filesystem paths are known in advance.

**2c: Cache kernel enumeration.** Kernel program and link iteration
involves BPF syscalls that enumerate the entire kernel BPF state.
Within a single GC cycle, the kernel state does not change (we hold
the flock). Cache the results of `kernel.Programs` and
`kernel.Links` for the duration of a GC call.

**2d: Prepared statements for hot queries.** The store queries
(`List`, `ListLinks`, `ListDispatcherSummaries`) are called multiple
times. Ensuring they use prepared statements reduces per-query
overhead. (This may already be the case after recent prepared
statement work.)

**2e: Concurrent gathering.** Some I/O operations within
GatherState are independent and could run concurrently:

- Kernel enumeration (programs + links) vs store queries
- Filesystem scans (bpffs, program dirs, staging dirs) vs kernel
  enumeration
- TC filter netlink queries (per-dispatcher, independent of each
  other)

Fan-out would reduce wall-clock time for GC but adds complexity.
The redundancy elimination (2a, 2b, 2c) should be attempted first
as it reduces total work rather than just parallelising it.

### Strategy 3: Skip GC When No External Mutation Is Possible

The current `mutatedSinceGC` flag tracks whether any mutation
occurred since the last GC. But under a flock, the only mutations
are our own. If we know our own mutations are well-formed (no
orphans left behind), GC after our own operations is unnecessary.

The flag could distinguish between "self-mutation" (our own
successful operations) and "unknown mutation" (state that may have
changed externally, e.g., between flock acquisitions). Only unknown
mutations would trigger GC.

This is a more aggressive optimisation and depends on the invariant
that all manager operations clean up after themselves (including on
failure, via rollback). The existing rollback machinery makes this
plausible but would need careful verification.

## Baseline Measurements Needed

Before implementing optimisations, we need reproducible baselines:

1. **Per-GC cost by phase.** Instrument `ComputeGC` and `ExecuteGC`
   to report time spent in each I/O category: kernel enumeration,
   store queries, filesystem scans, netlink probes.

2. **GC invocation count per test.** Log how many times GC runs per
   e2e test, and how many of those runs find anything to clean up
   (non-empty GCPlan).

3. **Steady-state GC cost.** Measure GC cost when there is nothing
   to clean up (the common case in a drain loop). This isolates the
   overhead of gathering state from the overhead of executing
   actions.

4. **TestTC_DispatcherFillDrainRefill wall-clock time.** This test
   is the most GC-sensitive because it performs many sequential
   mutations. Track its total time as optimisations land.

5. **Full e2e suite comparison.** Compare against the Rust baseline
   (`/tmp/baseline.log`) to track overall progress. The Go
   implementation is already 15--27% faster on simple lifecycle
   tests; the goal is to close the gap on dispatcher-heavy tests
   where GC overhead dominates.

## Priority Order

1. **Flock-scoped GC suppression** (Strategy 1) -- highest impact,
   simplest change.
2. **Unified state gathering** (Strategy 2a) -- eliminates
   redundant enumeration within a single GC call.
3. **Eliminate double GatherState** (Strategy 2b) -- removes the
   second full I/O pass.
4. **Kernel enumeration caching** (Strategy 2c) -- quick win within
   a single GC cycle.
5. **Concurrent gathering** (Strategy 2e) -- diminishing returns
   after the above, but useful if per-call cost is still too high.
