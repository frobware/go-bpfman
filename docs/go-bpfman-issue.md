# TCX attach fails with ENOENT after a ClusterBpfApplication is deleted and recreated

## Summary

When a `ClusterBpfApplication` is deleted and a new one is created for the
same workload (for example deleting and recreating a NetObserv
`FlowCollector`), TCX attaches on a node can fail indefinitely with:

```
attach TCX: attach TCX to ifindex <N> egress: attach tcx link: no such file or directory
```

The node's `ClusterBpfApplicationState` stays `Error` and never recovers on
its own. The only workaround found is to wipe the daemon's persistent store
(`/run/bpfman/db/store.db*`) on the affected node and restart the daemon, or
reboot the node (which clears the tmpfs `/run`).

## Environment

- go-bpfman daemon, commit `f0fe7b74` (branch `fix-attach-netns-resolution`),
  deployed via bpfman-operator on OCP 4.21.
- NetObserv driving the `netobserv` `ClusterBpfApplication` with interface
  auto-discovery (TCX ingress + egress).
- Daemon store at `/run/bpfman/db/store.db`, mounted from the node hostPath
  `/run/bpfman` (so it survives pod restarts; only a node reboot clears it).

## Confirmed by inspecting the on-node store

The daemon's sqlite store was copied off the wedged node (master-2) and
inspected. It contained two generations of programs at once:

```
managed_programs:
  224  tcx_ingress_flow_parse  16:28:32   <- old generation
  240  tcx_egress_flow_parse   16:28:33   <- old generation
  271  tcx_ingress_flow_parse  16:33:49   <- new generation (after daemon restart)
  290  tcx_egress_flow_parse   16:33:50   <- new generation

links (156 total): all reference the OLD programs
  224 -> 78 ingress links
  240 -> 78 egress links
  271, 290 (new) -> 0 links

link_tcx_details for ifindex 2, egress: 37 link records, every one -> program 240 (old)
```

The new programs own no links; the old generation still owns all of them,
with heavy duplication (37 records on a single interface/direction). When the
new daemon attaches program 290 to ifindex 2 egress, the order computation
reads those existing links, sees only old-program-240 entries, and anchors
the attach against program 240 -- whose kernel link died when the previous
daemon was killed. `link.AttachTCX` then returns ENOENT. This matches the
observed failure exactly.

## Root cause

Background: TCX lets several eBPF programs attach to the same interface and
direction, running in an ordered chain. When attaching a new program you must
say where in that chain it goes, expressed *relative to an existing program*:
`Head` (first), `Tail` (last), `BeforeProgramByID(X)`, or `AfterProgramByID(X)`.
That reference program X is the **anchor** -- the fixed point the newcomer is
positioned against. If X is no longer loaded in the kernel, the kernel cannot
resolve the reference and `BPF_LINK_CREATE` fails with `ENOENT` ("no such
program X"). This issue calls that case a *dead anchor*: an anchor naming a
program ID that has since been unloaded.

`platform/ebpf/attach_tc.go:AttachTCX` attaches the link with an ordering
anchor derived from the existing links recorded in the store:

```go
case order.AfterProgID != 0:
    anchor = link.AfterProgramByID(ebpf.ProgramID(order.AfterProgID))
case order.BeforeProgID != 0:
    anchor = link.BeforeProgramByID(ebpf.ProgramID(order.BeforeProgID))
```

`computeTCXAttachOrder` builds that anchor from the link records the manager
read out of the store for the same (nsid, ifindex, direction). After a
`ClusterBpfApplication` is deleted and recreated, bpfman loads *new* programs
with *new* IDs, but the store still holds link rows from the previous
generation. The new attach computes an anchor that references a program ID
that no longer exists in the kernel, and `link.AttachTCX` returns `ENOENT`
("no such file or directory"). Every subsequent reconcile recomputes the same
dead anchor, so the node never recovers.

Evidence consistent with this:

- A node that had its store cleared (via reboot, tmpfs `/run` wiped) attaches
  cleanly: 100+ `attached TCX program` log lines, zero ENOENT, and the
  `ClusterBpfApplicationState` reaches `Success`.
- A node whose store was NOT cleared (hostPath survived the pod restart)
  fails every egress attach with the ENOENT above and stays `Error`.
- Deleting the `ClusterBpfApplicationState` object forces a fresh
  computation, but it recomputes `Error` immediately -- so it is the stored
  link records, not a frozen status, that drive the failure.

## Code locations

Proximate cause -- `manager/attach_tc.go:228`, `computeTCXAttachOrder`:

```go
return bpfman.TCXAttachBefore(link.KernelProgramID)    // anchor against a store link
...
return bpfman.TCXAttachAfter(lastLink.KernelProgramID) // ...same
```

`existingLinks` is supplied verbatim by the store
(`platform/store/sqlite/links.go:ListTCXLinksByInterface`). The function
anchors the new attach against an existing link's `KernelProgramID` with no
check that the program is still live in the kernel and no fallback to
`Head`. After a reload the store still returns the previous generation's
links, so it emits `AttachAfter(<dead id>)` and `link.AttachTCX`
(`platform/ebpf/attach_tc.go`) returns ENOENT.

Root cause -- nothing reconciles the store against the kernel:

- `manager/list.go:60` and `server/list.go:94` only *detect* the divergence
  and return it as an error: `program N exists in store but not in kernel
  (requires reconciliation)`. Nothing acts on "requires reconciliation".
- The coherency machinery (`Manager.Snapshot`, the `bpfman audit` command,
  `bpfman-e2e-cleanup`) is read-only or manual -- `audit` is labelled
  "(read-only)". No startup or periodic reconcile/GC is wired into
  `server.New`, `manager.New`, or the serve path, so dead-generation
  program and link records persist across daemon restarts and program
  death.

## Impact

- Deleting and recreating a `FlowCollector` (a routine operation) leaves
  affected nodes wedged with no flows until their store is manually cleared.
- It is plausibly part of the original NetObserv-on-go-bpfman failure report:
  anyone who recreated the collector during testing would hit this on top of
  the netns-resolution bug fixed in PR #108.

## Reproduction

1. Deploy NetObserv with bpfman integration; confirm flows.
2. Delete the `FlowCollector` (or the `netobserv` `ClusterBpfApplication`),
   wait for teardown, then recreate it.
3. Observe one or more `ClusterBpfApplicationState` objects stuck `Error`
   with the ENOENT above in the daemon log, and no recovery across reconciles
   or daemon-pod restarts.

## Proposed fix (either or both)

1. Clean up link/program records when their kernel state is gone, so the
   store does not carry a dead generation into the next attach. Either prune
   on `ClusterBpfApplication`/program deletion, or -- more robustly -- wire a
   store-vs-kernel reconcile into daemon startup so "requires reconciliation"
   (`manager/list.go:60`) stops being a dead-end error and actually removes
   the orphaned records. The detection (`Manager.Snapshot`) already exists;
   it just needs a write path on the startup edge.
2. Make `computeTCXAttachOrder` (`manager/attach_tc.go:228`) tolerant of a
   dead anchor: filter `existingLinks` down to those whose `KernelProgramID`
   is live in the kernel before choosing the anchor, and fall back to
   `TCXAttachFirst()` (`Head`) if none remain, rather than emitting
   `AttachBefore/After(<dead id>)` and failing the whole attach with ENOENT.

(2) is the more robust option because it also covers crash/restart cases
where the kernel state and the store legitimately diverge; (1) addresses the
underlying record leak (the 37-links-per-interface duplication is the same
wound). Doing both is ideal.

## Notes

- Separate from PR #108 (netns-aware interface resolution + removal of the
  obsolete TCX nsid panic). This is a store-lifecycle issue, not a resolution
  issue.
- The `attach tcx link: no such file or directory` wording is the wrapped
  `link.AttachTCX` error from `platform/ebpf/attach_tc.go`; the inner ENOENT
  is the kernel rejecting `BPF_LINK_CREATE` against a non-existent anchor
  program.

---

# Separate concern: the gRPC server is not a thin shim

The `server` package is meant to be a thin veneer over the gRPC service:
unmarshal the request into a domain spec, call the `Manager`, marshal the
response, map errors to gRPC codes. It is slated for removal over time, so
any domain logic living in it is both an inversion of ownership and a thing
that vanishes (or must be re-found in the CLI) when `server` goes. The
interface-resolution case was the first instance -- resolution was fixed by
moving it into the manager (`platform.InterfaceResolver` on the kernel
adapter), leaving `server`/CLI to pass interface names through untouched. An
audit of `server` found more of the same shape.

Good news first: `server` has no direct store/kernel/fs access -- it reaches
only `s.mgr` and `s.layout`, so nothing bypasses the manager. The remaining
items are domain *logic* that should move down, ranked.

1. `PullBytecode` orchestrates the pull itself (`server/image.go`). It calls
   `s.mgr.ImagePuller()` to fetch the puller and drives `puller.Pull(ctx,
   ref)` directly. `ImagePuller()` is an accessor that leaks a manager
   dependency to the edge, and there is no `Manager.PullBytecode`, so the
   pre-pull operation lives only in the server (and would have to be
   duplicated in the CLI). Fix: add `Manager.PullBytecode(ctx, ref)`; the
   server converts the proto image ref and calls it; drop `ImagePuller()`
   from the manager's public surface. This is the closest analogue to the
   resolution bug and the one to treat as a real defect.

2. `Get` interprets domain state (`server/list.go`, the `prog.Status.Kernel
   == nil` branch). Deciding that "in store, absent from kernel" is an error
   -- "requires reconciliation" -- is a domain verdict, and it is duplicated:
   `manager/list.go:60` already returns the same error on the enriching path.
   The verdict should live solely in the manager (a typed error/status); the
   server should only map it to a gRPC code.

3. Tracepoint `group/name` parsing (`server/attach.go`, attachTracepoint).
   The server splits and validates the `"group/name"` format before calling
   `NewTracepointAttachSpec(group, name)`. That format knowledge is domain
   logic and `cmd/bpfman` parses it too. Fix (mirrors the resolution fix):
   `NewTracepointAttachSpec(rawTracepoint string)` parses internally; the
   server and CLI pass the raw field.

4. TC/TCX direction parsing (`server/attach.go`, attachTC/attachTCX):
   `ParseTCDirection(strings.ToLower(info.Direction))` at the boundary,
   duplicated in the CLI and the bpfman-shell builtin. The spec constructor
   could take the raw direction string and parse it, so every front-end
   passes `info.Direction` untouched.

Not violations -- legitimate gRPC boundary work, left as is: proto<->domain
conversion (`server/convert.go` and the `append`/`range` loops in
`list.go`/`load.go`), error -> `codes.*` mapping, and thin nil/empty input
guards.

The through-line: every item above is also implemented in `cmd/bpfman` and
the bpfman-shell builtin. It is duplicated front-end logic, and `server` is
not special. The fix is the resolution pattern -- push the
parsing/decision/operation into the spec constructors or `Manager` methods so
each front-end only marshals and maps errors. Item 1 is a real bug; 2--4 are
ownership cleanups that pay off precisely when the CLI and server stop
duplicating each other (and when `server` is finally deleted).
