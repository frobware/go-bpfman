# Cleanup tool: what's good, what to revisit

Snapshot taken at the end of the `hack-cleanup-fix-xdp-link-detach`
branch. `bpfman-e2e-cleanup` builds, runs, and removes the residue
classes it sees. This doc is the punch list for follow-up work, not
a redesign.

## What's load-bearing and right

- `inspect` is the correlation layer. One value (`Observation`) joins
  store, kernel, and bpf fs by ID and decorates each row with
  `Presence` flags. Every consumer that wants to ask "where does this
  object exist?" routes through here; nothing re-implements the join.
- `bpfresidue.Plan` is a slice of `Action`. `Describe` writes the
  shell-shaped audit line; `Apply` performs the kernel-side mutation.
  The two interpreters share one data shape, so dry-run output is
  exactly what `--apply` will do. Same Plan-shaped split as
  OpContext; SANS-IO at the package boundary.
- Two scanners cover disjoint universes:
  `PlanFromObservation` (BPF objects, gated by the store) and
  `ScanE2EResidue` (network interfaces and netns, gated by the
  `B<hex>N[ab]?` regex). They compose by concatenation; pin-path
  dedup folds the overlap.
- `Manager` is still a facade. `Snapshot` exposes the one composite
  operation external callers need; the underlying `store` and `kernel`
  remain unexported. Same pattern as the rest of the manager.
- The orphan predicate qualifies kernel-only links by "wraps a
  program bpfman has a record of". Other kernel links -- systemd,
  Cilium, ad-hoc bpftool sessions -- are not bpfman residue just
  because they're absent from bpfman's store.

## Mildly suboptimal, not worth chasing yet

- `Manager.ListPrograms` and `Manager.FindLoadedProgramByMetadata`
  call `inspect.Snapshot` when point-shaped queries would do less
  work. The snapshot is a few ms per call; profile-driven decision,
  not now.
- `inspect.LinkRow.FSPinPath` is now populated for kernel-only links
  via a recursive walk of the bpf fs root. Cheap on bpfman-sized
  trees; if it ever becomes hot, the walk can move behind a lazy /
  memoised wrapper. Today it runs on every snapshot.
- `cmd/bpfman-e2e-cleanup` is one command with conditional scans
  rather than subcommands. The conditional manager construction
  (best-effort, skipped if `--runtime-dir` is absent) is correct but
  obscures the failure mode when the manager is half-built. A clearer
  error path for "manager constructed but Snapshot failed" would help
  when the DB is locked or corrupt.

## Real follow-ups, in priority order

1. **Dispatcher publish atomicity.** The user-observed bpfman crash
   left a half-written revision-4 directory that bpfman's own
   `program delete --all` couldn't reconcile (file-exists collisions
   on retry). The fix is in bpfman's dispatcher rebuild path, not
   the cleanup tool: write the next revision to a staging name, swap
   atomically, and have startup sweep half-written stages. Until
   then, `--wipe` is the only path out.
2. **Inspect dispatcher row pin paths.** `DispatcherRow` carries
   nsid, ifindex, revision, and link count but not the dispatcher dir
   path or its extension link pin paths. `PlanFromObservation`
   therefore can't emit `RemovePin` actions for orphan extension
   slots directly -- it relies on the bpf fs link-pin walk built in
   this branch to find them by side effect. Adding `Path` to
   `DispatcherRow` (and `LinkPins []string` for the per-slot files)
   would let the orphan plan name dispatcher orphans precisely
   instead of inferring them from the link table.
3. **Stale DB record garbage collection.** Today the cleanup tool
   honours the store: anything `InStore=true` stays. With no daemon
   reconciling, store rows pointing at kernel objects that have
   vanished accumulate indefinitely. A `--gc-store` mode that
   removes (DB row + pin file + bytecode cache) for entries where
   `Presence.InKernel == false` would close the gap without
   resorting to `--wipe`. Requires the writer lock on the store and
   a careful order (kernel detach -> pin remove -> DB delete).
4. **e2e leak detector classification.** Now that `LinkRow.FSPinPath`
   is populated for kernel-only links, the suite leak detector can
   distinguish "pinned orphan that survived a crash" from "unpinned
   orphan held by a dying FD". Worth feeding through to the leak
   report so the failure message names the right remedy.

## Out of scope for this work

- Replacing `hack/cleanup-*.sh`. The scripts still work and still
  build without a Go toolchain. Kept.
- TC dispatcher attachment moved to the bpf_link API. Today
  `ScanTCDispatcherResidue` is a netlink scan because classic TC
  attachments aren't in the store; if bpfman migrates to TCX
  exclusively, that scanner can be deleted.
- A bpfman-side `serve` daemon. Out of scope here; if it comes back,
  the cleanup tool's orphan predicate may need to interact with a
  live writer lock rather than treating the runtime dir as
  daemon-less.
