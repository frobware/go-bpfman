# Dispatcher teardown as a lifecycle action

## What this is for

This is a design note for a small refactor under `manager/`: delete
the dispatcher teardown recipe builder from `manager/detach.go` and
make the dispatcher executor (in `manager/executor_dispatcher.go`)
own empty-dispatcher teardown directly. The motivation is a real
race bug we just fixed. The goal is to remove that bug class from
the manager's planning layer and confine dispatcher teardown
semantics to the dispatcher executor — the module boundary we want
to harden next. This is encapsulation, not type-level impossibility:
the unsafe primitives still exist inside the executor, but they are
no longer reachable from the planning layer that composes actions.

## What failed

`TestXDP_LoadAttachDetachUnload` failed reliably on ARM CI runners
and intermittently on x86 with the symptom: after `Detach()`
returned, exactly one ICMP echo (`1 × weight`) still hit the BPF
program's counter. The failure was the kind that exact-equality
e2e tests are built to surface — a single packet of leakage.

Root cause (commit `32024a9`): when a dispatcher's program count
went `1 → 0`, the empty-dispatcher cleanup builder
(`computeDispatcherCleanupActions` in `manager/detach.go`) was
emitting `action.RemovePin{Path: linkPinPath}` for the dispatcher's
*outer XDP link* — the one attached to the netdev.

`RemovePin` is `os.Remove` on a bpffs path. For a passive pin
(program file, map directory) that is the correct teardown: drop
the userland reference, kernel reclaims when refcount hits zero.

For a kernel-attached BPF link it is wrong. Removing the pin drops
*one* userland reference but the kernel detaches the link from the
netdev only after RCU grace periods and deferred work complete. In
the gap between `os.Remove` returning to userland and the kernel
finishing the detach, the netdev is still running the dispatcher
program. Packets in flight count.

The fix replaced `RemovePin` with `DetachLink`, which performs
`BPF_LINK_DETACH` synchronously before unpinning. After that
syscall returns, the link is detached from the attach point; later
bpffs cleanup no longer controls whether packets can reach the
program. ARM went green and `STRESS_COUNT=100` runs are clean.

## Why it was easy to write the bug

The action layer at the time exposed two path-shaped primitives
with different lifecycle semantics:

```go
action.RemovePin{Path: ...}    // os.Remove on a bpffs path
action.DetachLink{PinPath: ...} // BPF_LINK_DETACH, then unpin, then close
```

Their inputs looked identical (both took a string-shaped path).
Their kernel-side semantics did not. Choosing wrong was a
syntactic non-event: the compiler said nothing, the manager said
nothing, the linter said nothing. The caller had to remember:

> For a path that names a kernel-attached BPF link, you must call
> DetachLink. For everything else, RemovePin is fine.

That is kernel knowledge living in the manager's planning code,
where it does not belong.

But the type-safety gap is only the surface symptom. The deeper
smell is that the manager was *assembling a teardown recipe* at
all. Look at the function name: `computeDispatcherCleanupActions`.
It computed a list of low-level actions. For the XDP case, the
pre-fix shape (the shape that produced the bug) was:

```go
actions = []action.Action{
    action.RemovePin{Path: linkPin.String()},     // wrong for an XDP link
    action.RemovePin{Path: progPin.String()},
    action.RemoveDispatcherRevDir{Path: revDir},
    action.DeleteDispatcher{Type, Nsid, Ifindex},
}
```

The fix changed the first step from `RemovePin` to `DetachLink`
for the XDP branch. That closed the immediate race. But the
underlying recipe — four steps, an XDP-vs-TC branch, a known
ordering constraint (synchronous kernel detach before any
filesystem cleanup) — is unchanged in shape and still owned by the
manager.

The recipe is platform knowledge: which step, in which order,
against which kernel resource. The planning layer should not own
that knowledge. For dispatcher lifecycle, the rest of the code
already tends toward single domain-level actions that the executor
expands. The empty-dispatcher case is the exception.

The bug landed in the exception. It was not "the manager picked
the wrong action"; it was "the manager was picking actions at all
for a domain operation that should have been a single intent".

In Ousterhout's terms, this is a shallow interface: the call site
looks small, but the caller must carry a large amount of hidden
knowledge to use it correctly. A deeper interface would expose the
domain operation — remove this dispatcher — and hide the teardown
recipe behind it.

## What is already correct

`action.CleanupEmptyDispatcher{Key}` exists. It is the
right-shaped public interface: the manager passes a dispatcher key
and asks the executor to remove the empty dispatcher. The action
is wired and exercised on every empty-dispatcher path. There is no
"bypass path".

The leak is *inside* the implementation. `removeEmptyDispatcher`
in `manager/executor_dispatcher.go` looks like this:

```go
func (e *executor) removeEmptyDispatcher(ctx context.Context, snap platform.DispatcherSnapshot) error {
    // ...
    // Convert snapshot to dispatcher.State for
    // computeDispatcherCleanupActions (to be migrated later).
    state := dispatcher.State{ ... }
    // ...
    cleanupActions := computeDispatcherCleanupActions(e.bpffs, state, tcHandle)
    if err := e.ExecuteAll(ctx, cleanupActions); err != nil {
        return fmt.Errorf("execute dispatcher cleanup actions: %w", err)
    }
    // ...
}
```

The lifecycle-aware action exists; the executor's implementation
hollows it out by delegating back up to the recipe-builder. The
code itself flags this with a `(to be migrated later)` comment.

The boundary was sketched, not finished.

## What we plan

Two related changes on this branch.

The first is a boundary refactor: the recipe-builder leaves the
manager and the empty-dispatcher teardown sequence is owned by the
dispatcher executor.

The second makes the destructive-teardown failure contract
explicit. The kernel-detach step (XDP outer link or TC filter)
remains fail-fast. The bpffs and store cleanup steps that follow
run best-effort: failures join via `errors.Join` but later steps
still execute, because the kernel attachment is already gone and
re-creation is not a well-defined inverse for destructive
teardown. Coherency, doctor, and GC repair residual state. The
old action-list shape inherited `ExecuteAll`'s stop-on-first-error
semantics by accident, which for teardown was the worst of both
worlds: a transient bpffs failure could leave the store row
referencing a kernel attachment that no longer existed.

### A deliberate create/teardown asymmetry

The create and rebuild paths still use the action and operation
machinery. The empty-dispatcher teardown path no longer does. That
asymmetry is intentional and reflects the actual semantics of the
two sides.

Creation and rebuild are transactional-ish. Partial success has a
meaningful inverse: a newly-loaded dispatcher can be unpinned, a
just-attached extension link can be detached, a failed persist can
roll back the kernel objects that were created on its behalf. The
plan/operation interpreter expresses that compensation directly.

Destructive teardown is not transactional. Once the kernel
attachment is gone, "undo" is not a clean inverse: you would have
to prove the old snapshot is still valid, the pins still exist,
the attachment point has not moved, the store is not stale, and no
concurrent repair has intervened. That is a great deal of
machinery for a worse outcome than letting the dedicated repair
paths (coherency, doctor, GC) reconcile residue.

So the deletion-side contract is:

1. If kernel detach fails, abort: the dispatcher may still be live
   and packets may still reach it.
2. If kernel detach succeeds, do not compensate.
3. Continue bpffs and store cleanup best-effort.
4. Return joined residue errors.
5. Let coherency, doctor, and GC repair leftovers.

This is a substantive change from `ExecuteAll`. `ExecuteAll`
stops on the first error, which after a destructive point of no
return is the wrong policy: the kernel attachment is already
gone, and refusing to attempt the remaining cleanup steps only
leaves more residue.

The old action-list shape made create and delete look artificially
symmetric because both were lists of actions executed by the same
runner. Exposing the asymmetry — action machinery for construction,
explicit lifecycle code for destruction — is the point of the new
shape.

### Move dispatcher teardown behind the executor boundary

Mechanically, move the body of `computeDispatcherCleanupActions`
(in `manager/detach.go`) into `removeEmptyDispatcher` (in
`manager/executor_dispatcher.go`), or into a private helper method
on the `executor` type. Delete `computeDispatcherCleanupActions`.

The XDP-vs-TC type-switch happens once, in one place, owned by the
dispatcher executor. The bpffs path arithmetic
(`bpffs.DispatcherLinkPath(...)`,
`bpffs.DispatcherProgPath(...)`,
`bpffs.DispatcherRevisionDir(...)`) is a private detail of that
helper. The `dispatcher.State` -> `bpfman.LinkPath` /
`bpfman.ProgPinPath` / `bpfman.DispatcherRevDir` derivations are
internal.

The manager continues to submit one dispatcher-level intent:

```go
e.executor.Execute(ctx, action.RemoveDispatcher{Key: key})
```

Same call site shape. The implementation behind it stops
delegating back up.

### Rename `CleanupEmptyDispatcher` → `RemoveDispatcher`

Cleanup reads as a bag of incidental chores. This action is a
domain transition: the dispatcher is removed from kernel
attachment, bpffs, and the store. `RemoveDispatcher` says what it
does. The receiver of the action is the *dispatcher* (a domain
concept), not "everything around it that needs cleaning up".

The `Key` field stays. The action is identified by what it acts
on, not what it touches.

### Preserve the SANS-IO/action style

This is not a move toward RAII or handle-based lifecycle. The
action layer remains the right shape: intent as data, executor at
the boundary. We are not adding `lnk.Close()` or `dispatcher.Detach()`
methods on long-lived handles. We are reducing the number of
*shallow* actions exposed to the manager — replacing a four-action
recipe with a one-action intent — and pushing the recipe expansion
one layer down where the platform knowledge already lives.

## What this makes structurally hard

After the refactor:

- There is no manager-visible function that builds a
  dispatcher-teardown recipe. For nominal empty-dispatcher teardown,
  the only route is `action.RemoveDispatcher{Key}`. The manager cannot get the
  primitive ordering wrong because the manager does not see the
  primitives. (Coherency / doctor drift remediation may still use
  lower-level repair actions until a follow-up converts those
  paths too — see "What we deliberately do not do" below.)
- The XDP-vs-TC teardown branch lives in one place. Changing the
  kernel teardown contract for an existing dispatcher type is
  localised to the dispatcher executor instead of being split
  between planning and execution.
- The bug we just fixed (`RemovePin` where `DetachLink` was
  needed) becomes inexpressible at the manager planning layer.
  The executor still owns the unsafe details — `RemovePin` and
  `DetachLink` remain string-shaped primitives whose kernel
  semantics diverge — but there is now one place to audit and
  harden them. This refactor does not make incorrect XDP teardown
  untypeable inside the executor. It makes the executor the only
  place where that knowledge is required.

## What we deliberately do not do

### `RemoveProgram` analogue for unload

`unloadPlan` (in `manager/unload.go`) currently builds a 5–7 step
recipe for program unload: detach links, remove links dir, unload
program, remove maps pins, cleanup shared maps, delete program.
The same shape complaint applies: this is a recipe that the
manager probably should not be assembling.

We deliberately defer. Program unload has more legitimate
orchestration concerns than dispatcher teardown:

- Shared maps with reference-counted cleanup.
- Links of different lifecycles (perf-event-style vs BPF-link-style).
- Partial-failure compensation.
- Doctor / GC semantics that need to observe intermediate states.

Some of those concerns may collapse under a deeper boundary; some
may not. We prove the dispatcher case first and revisit unload as
a separate decision once we have working precedent.

### Path types collapsing into a sealed `Pinned` interface

A natural-looking next step is to make `LinkPath`, `ProgPinPath`,
`MapPinPath` etc. cases of a sealed `Pinned` interface, with one
`Remove(Pinned)` action that polymorphically dispatches. We do not
do this. The reason is the same as above — `Remove` still centres
the filesystem. The bug was not "wrong filesystem operation"; it
was "filesystem operations leaked above the layer where they
belonged". Collapsing the path types would tidy the `RemovePin` /
`RemoveProgPin` / `RemoveLinkDir` / `RemoveMapDir` family but
would not change the layering. The layering is what matters.

If a future iteration wants typed-pin polymorphism, that is fine
as long as the consumer is the platform layer, not the manager.

### Touching `manager/coherency`

GC and the doctor both currently emit `RemoveDispatcher*` actions
(prog pin, link pin, revision dir). Those call sites are
narrower in scope — coherency rules act on detected drift, not on
nominal operations — and the same refactor would change their
shape too. We leave them for a follow-up. The dispatcher executor
exposing a single intent makes that subsequent change easier, not
harder.

## Verification plan

This is mostly a boundary refactor, with one intentional
behavioural change in empty-dispatcher teardown: after kernel
detach succeeds, cleanup failures are joined and later cleanup
steps still run rather than aborting on the first error. The
verification is the existing test suite, rerun:

- `make test` — unit tests, including `manager/detach_test.go`
  and any executor tests that exercise the empty-dispatcher path.
- `make test-e2e STRESS_COUNT=50` — confirms the original ARM bug
  is still fixed (regression guard) and no new race is introduced.
  The default shared-runtime mode exercises the cleanup path under
  contention, which is where the empty-dispatcher case is most
  heavily hit; pass `ISOLATED_RUNTIME=1` to compare against the
  isolated-per-test mode if needed.
- `make ci-check-vet` and `make ci-check-fmt` — type discipline
  and formatting.
- The full CI matrix (8 cells of `test-e2e`, 2 cells of
  `test-e2e-parallel`) on the resulting PR.

A successful refactor leaves every test green, deletes the recipe
builder from `manager/detach.go`, and propagates the action rename
from `CleanupEmptyDispatcher` to `RemoveDispatcher` across call
sites.

### Empirical baseline

`make test-e2e STRESS_COUNT=1000` passed cleanly on commit
`2f8df46` ("ci: add parallel-mode e2e canary"), the commit this
branch was cut from, on both x86 and ARM. ARM is the architecture
where the original detach race (commit `32024a9`) manifested most
reliably; a clean run there is the strongest empirical signal that
the dispatcher-teardown path is currently race-free at the level
the test can observe. `TestTC_DispatcherFillDrainRefill` is the
heaviest single test in that path and was green on both
architectures at 1000.

That run is the reference baseline for the hardening-ladder work:
each subsequent step (2.5, 3, 4) should re-run at the same stress
count, on both architectures, and match. With a known-good floor
at 1000, divergence after a refactor can be treated as signal
rather than as suspected test flakiness, which is the regime in
which deep-module changes (typed teardown resources, narrowed
`RemovePin`, platform-level lifecycle helpers) pay off.

## Hardening ladder

The final ladder, in summary form:

1. Encapsulate dispatcher teardown at the action boundary.
2. Make destructive teardown explicit inside the executor.
2.5. Retire or narrow generic `RemovePin`.
3. Add typed dispatcher teardown resources.

No step 4. Keep the coherent teardown lifecycle in the executor
unless a future design can move the whole lifecycle without
splitting the contract.

This PR implements steps 1, 2, 2.5, and 3 as discrete commits.
There is no step 4 in the original "platform-level lifecycle"
sense: moving teardown into `platform` would split the lifecycle
contract rather than deepen the module. The reasoning is captured
below in its own section.

The original framing assumed each step would cost roughly an
order of magnitude more than the last. That held for steps 1 → 2
but broke at step 3, which turned out to be roughly the same size
as step 2.5b. The correct rule of thumb is: **audit before
deferring**. Cost estimates derived from a model of the codebase
drift out of sync with the codebase as incremental typing work
lands without anyone updating the model.

### Step 1 — Encapsulate dispatcher teardown (implemented here)

Delete `computeDispatcherCleanupActions`. Rename
`CleanupEmptyDispatcher` to `RemoveDispatcher`. Manager submits one
domain intent. The bug becomes inexpressible at the manager
planning layer; the executor still owns the unsafe primitives.

### Step 2 — Make destructive teardown semantics explicit (implemented here)

Replace `ExecuteAll([]action.Action)` inside `removeEmptyDispatcher`
with private lifecycle methods, and write the failure contract
that the action-list version was hiding.

```go
detachXDPOuterLink(ctx, ...)        // BPF_LINK_DETACH then unpin
detachTCDispatcherFilter(ctx, ...)  // RTM_DELTFILTER
removeDispatcherProgPin(ctx, ...)
removeDispatcherRevisionDir(ctx, ...)
deleteDispatcherSnapshot(ctx, key)
```

This is two changes wearing one coat.

**Naming.** The unit of review shifts from "is this action list
correct?" (which requires the reviewer to mentally evaluate kernel
semantics behind each generic `RemovePin` / `DetachLink`) to "is
this sequence of named lifecycle operations correct?" (which a
reviewer can answer). The lifecycle methods are private to the
executor, so nothing outside this file can compose them
differently.

**Failure contract.** Once teardown is written as a list of
actions, `ExecuteAll`'s stop-on-first-error becomes the implicit
teardown contract. For destructive lifecycle, that contract is
wrong:

1. Kernel detach (XDP link or TC filter) is the *point of no
   return*. If it fails, packets can still reach the dispatcher
   program; the function aborts and surfaces the error.

2. After kernel detach succeeds, the remaining bpffs/store steps
   run *best-effort*. Failures are joined via `errors.Join` but
   later steps still execute. Stopping at the first cleanup
   failure would only leave more residue without compensating
   value, since the kernel attachment is already gone and
   re-creation is not a well-defined inverse for destructive
   teardown. Coherency, doctor, and GC repair residual state.

The previous behaviour was the worst of both worlds: a transient
bpffs failure could leave the store row referencing a kernel
attachment that no longer existed.

Still not type-safe. Still much harder to review incorrectly, and
now correctly resilient to partial cleanup failure.

### Step 2.5 — Narrow `kernel.RemovePin` and delete `action.RemovePin` (implemented here)

The audit done while the e2e ran showed the generic-pin-removal
problem had two layers, and the design note's original
description conflated them.

The action wrapper `action.RemovePin{Path: string}` had zero
production constructions on this branch after step 2: the
dispatcher teardown recipe was its only caller, and step 1 + step 2
removed it. The wrapper survived only in test machinery and an
exhaustiveness table.

The real loaded gun was one layer deeper: every actual pin
removal in production goes through `platform.PinRemover.RemovePin(ctx, path string)`,
which accepted any string. The action wrapper just forwarded.
Closing the action layer alone would have been theatre.

This step does both:

1. Narrow `platform.PinRemover.RemovePin` to take
   `bpfman.ProgPinPath` instead of `string`. Every production
   caller already passed a `bpfman.ProgPinPath` rendered through
   `.String()`; the typed signature encodes that contract in the
   type system. Feeding a `bpfman.LinkPath`, a `bpfman.MapPinPath`,
   or a raw string is now a compile error. This mirrors the shape
   already used by `kernel.DetachLink(ctx, bpfman.LinkPath)`.

2. Delete `action.RemovePin{}` as the trailing hygiene that step 1
   made mechanical. The action type, its `Describe` case, the
   executor case, and the exhaustiveness-table entry all go.
   `manager/operation/operation_test.go`'s test stand-in switches
   from `action.RemovePin{Path: label}` to
   `action.RemoveProgPin{Path: label}`, which has the same shape
   and is a real production action; the operation tests do not
   assert on its semantics. A purely local test-only action was
   considered but rejected because the `action.Action` marker
   method is package-private by design — the sealed set is what
   makes the exhaustive `Describe` coverage meaningful.

What this still does not address:

- `bpffs.RemoveProgPin` / `bpffs.RemoveDispatcherProgPin` /
  `bpffs.RemoveLinkDir` etc. all still take `string`. They are
  domain-named so misuse is unlikely (the method name is the
  contract), but the type-shape is loose. Closing those is step 3
  territory: typed dispatcher teardown resources, where the bpffs
  layout helpers return distinct types and the bpffs methods only
  accept the corresponding type.

- `kernel.RemovePin` is semantically a filesystem operation
  (`os.Remove` with ENOENT tolerance) living on a kernel
  interface. The layering oddness — kernel-side method doing
  filesystem work — is unchanged here. Either move it to bpffs
  alongside step 3, or accept it as a thin syscall-shape
  convenience.

### Step 3 — Typed dispatcher teardown resources (implemented here)

The remaining string-shaped removal surfaces are typed.

`fs/bpffs_ops.go`:

```go
RemoveProgPin(p bpfman.ProgPinPath) error
RemoveDispatcherProgPin(p bpfman.ProgPinPath) error
RemoveDispatcherLinkPin(p bpfman.LinkPath) error
```

`manager/action/action.go`:

```go
RemoveProgPin{Path bpfman.ProgPinPath}
RemoveDispatcherProgPin{Path bpfman.ProgPinPath}
RemoveDispatcherLinkPin{Path bpfman.LinkPath}
```

The other four `Remove*` methods (`RemoveLinkDir`, `RemoveMapDir`,
`RemoveDispatcherRevDir`, `RemoveSharedMapPin`) and four matching
action types were already typed. After this commit the surface is
uniform: every removal accepts a typed value, and the compiler
rejects category mistakes (feeding a `LinkPath` to a `ProgPin`
removal) at every layer that participates.

What was actually involved:

- 3 method signatures in `fs/bpffs_ops.go`.
- 3 struct field types in `manager/action/action.go`.
- 4 coherency call sites: 2 `.String()` calls dropped, 2 string
  values wrapped in newtypes.
- 0 changes in `manager/executor.go` — the executor cases pass
  `a.Path` straight through and the field type now matches the
  bpffs method signature.
- 6 test sites updated to wrap raw strings; untyped string
  literals pass through automatically.

Total: 5 files, ~50 lines, no behavioural change.

What this audit changed about the original framing:

The earlier versions of this note kept describing step 3 as ``the
cross-cutting change'' that ``forces the design question about
coherency'' and costs ``order of magnitude more than step 2.5''.
None of that held up. Most of the typed-pin work the codebase
needed had already been done incrementally; the bpffs layout
helpers already returned typed values; most of the bpffs removal
surface and most of the action types already accepted them.
Step 3 was closing three specific holes, not introducing a type
system.

The cost estimate was a guess against a model of the codebase
rather than against the codebase. Worth recording as a meta-
lesson: when a deferred step keeps growing in the design notes
without anyone verifying the model, it is probably overestimated
and worth a quick audit before deferring it again.

Coherency is also unchanged in shape. It continues to emit
lower-level `Remove*` actions for observed orphans rather than
going through `action.RemoveDispatcher`. That is the right
shape: coherency observes paths in bpffs and emits per-path
removals; the manager-driven empty-dispatcher teardown has a
snapshot and uses the higher-level intent. The two paths are
different by design.

### No step 4 — keep teardown lifecycle in the executor

A tempting next step is to fold empty-dispatcher teardown behind
`platform.RemoveXDPDispatcher` / `platform.RemoveTCDispatcher`.
Do not do that as a hardening step.

It looks like a deeper interface because the executor would call
one platform method instead of sequencing several lifecycle
methods. But the coherent unit of complexity is not just "kernel
+ bpffs teardown". Empty-dispatcher teardown also includes the
store cleanup and the failure contract:

1. kernel detach is the point of no return;
2. after detach, bpffs cleanup is best-effort;
3. after detach, store cleanup is best-effort;
4. joined cleanup errors describe residue;
5. coherency, doctor, and GC are the repair path.

The platform layer cannot own all of that without becoming
store-aware and policy-aware. The store dependency is one-way by
design: `platform/` does not depend on `platform/store/`. Moving
only the kernel/bpffs half into the platform layer would split
the lifecycle contract across two modules: platform would own
half the teardown, while the executor would own the store and
caller semantics. That is not a deeper module; it is two
shallower modules.

The executor's `removeEmptyDispatcher` is the deep module here.
It owns the coherent lifecycle operation and calls lower-level
kernel, bpffs, and store primitives as implementation details.
The named lifecycle methods (`detachXDPOuterLink`,
`detachTCDispatcherFilter`, `removeDispatcherProgPin`,
`removeDispatcherRevisionDir`, `deleteDispatcherSnapshot`) are
private to the executor and exist exactly so the contract has
one home.

Do not move this boundary unless a future design can move the
whole coherent lifecycle without making `platform` store-aware or
splitting the failure contract. That is a high bar: it implies
either inverting the `platform/` → `platform/store/` dependency
direction, or introducing a larger lifecycle service that owns
both. Neither follows from the current code.

The narrower variant — exposing platform helpers like
`detachXDPAttachment` / `detachTCAttachment` — also fails this
test: those wrappers would carry lifecycle decisions (which path
to compute, how to handle a missing TC handle) that belong above
the kernel boundary, not below it. The platform layer already
exposes the right primitives (`DetachLink`, `DetachTCFilter`,
`FindTCFilterHandle`); the executor's wrappers are correctly
positioned above them.

### Independent cleanup — move filesystem-only pin removal out of kernel

`kernel.RemovePin` is poorly named and poorly placed. It performs
filesystem removal of a bpffs pin with `ENOENT` tolerance; it is
not a kernel operation in the same sense as `DetachLink` or
`DetachTCFilter`. After step 2.5b it is typed
(`bpfman.ProgPinPath`), but the layering oddness is unchanged.

Callers should use typed `bpffs` removal helpers
(`RemoveProgPin`, `RemoveDispatcherProgPin`, `RemoveSharedMapPin`,
etc.) instead of going through the `kernel.RemovePin` syscall
shim. This is layering housekeeping, not dispatcher lifecycle
hardening, and is independent of the step 1–3 work above.

A related contract question is worth surfacing while the layering
is reconsidered: `ENOENT` tolerance has at least three overlapping
motivations in this codebase — concurrent-detach race tolerance
(commit `30a96aa`, January 2026), idempotent GC (commit `eaa4a91`,
February 2026, deliberate), and incidental coverage of e2e
flakiness. The race surfaces have narrowed substantially since
2026 with the global writer lock and the dispatcher snapshot
model. It may be that nominal empty-dispatcher teardown should
fail-fast on unexpected `ENOENT` (because the writer lock and
snapshot model say it cannot legitimately happen), while
coherency-driven removal continues to swallow it (because GC by
nature observes orphans that another path may have already
cleaned up). Same syscall, two callers, different lifecycle
expectations. Worth a follow-up commit once the e2e baseline at
`STRESS_COUNT=1000` proves stable across architectures.

## Closing position — what we did and did not close

**The original bug, in its exact syntactic form, is uncompilable.**
Multiple types and surfaces would have to be revived to write it
again: `action.RemovePin{}` does not exist, the manager-level
recipe builder does not exist, and `kernel.RemovePin(ctx, x)` is
a compile error for any `x` that is not a `bpfman.ProgPinPath`.
Three layers each independently reject the original diff.

**The underlying bug class is still expressible at one narrow
surface.** Specifically: an editor of `removeEmptyDispatcher` (or
of one of its named lifecycle methods) could call
`bpffs.RemoveDispatcherLinkPin` where `kernel.DetachLink` is
required. Both accept `bpfman.LinkPath`. Both compile. Only the
second performs the synchronous kernel detach.

**This is not a typing problem.** It is a context-recognition
problem. There are two legitimate operations on dispatcher link
pins:

- **Live-dispatcher teardown** has a known kernel link backing
  the pin and needs the synchronous `BPF_LINK_DETACH` to stop
  packets reaching the program before any cleanup. That is the
  manager's path.
- **Orphan-pin reclamation** has no live kernel link — the
  object is already gone, only the pin file remains, and
  `os.Remove` is the correct operation. That is coherency's
  path.

The path type cannot encode whether the kernel object is alive,
so the type system cannot enforce the choice between these
operations. Forcing coherency through `kernel.DetachLink` would
push a broken abstraction onto the repair path:
`LoadPinnedLink` fails when there is no kernel object backing
the pin, so `DetachLink` would error out on true orphans.
Deleting `bpffs.RemoveDispatcherLinkPin` is therefore the wrong
move — it exists for a real reason that has nothing to do with
the original bug.

**The architecture, not the compiler, distinguishes the
contexts.** The manager carries a `DispatcherSnapshot` with a
known live kernel link; coherency carries observed `FsOrphan`
records with no backing kernel state. These are categorically
different inputs and have always been different inputs; this
work pushed the distinction down through the layers (typed
paths, named lifecycle methods, explicit failure contract)
without collapsing it. The compiler cannot tell which situation
you are in. The architecture does.

**What is keeping the residual surface safe.** Three things,
none of them compiler-enforced:

1. The named lifecycle methods (`detachXDPOuterLink`,
   `detachTCDispatcherFilter`, `removeDispatcherProgPin`,
   `removeDispatcherRevisionDir`, `deleteDispatcherSnapshot`)
   make the right operation per step legible at the call site.
2. The `removeEmptyDispatcher` docstring states the
   point-of-no-return contract and the best-effort cleanup
   contract explicitly.
3. The fact that the manager's path now goes through the
   high-level `action.RemoveDispatcher` intent and the
   executor's `removeDispatcherIfEmpty` helper, rather than
   composing primitives at the manager level, means a
   contributor would have to deliberately edit
   `removeEmptyDispatcher` itself to reintroduce the bug class.

**This is the strongest position the work could reach without
restructuring the operations themselves.** The original bug is
gone; the bug class is reduced to one narrow surface; the
remaining safety relies on naming, contracts, and architectural
discipline rather than on the type system. That is honest, and
it matches Ousterhout's own framing — deep modules hide
complexity behind a coherent abstraction; the compiler is one
tool for enforcing the abstraction, but it is not the only one
and not always the right one.
