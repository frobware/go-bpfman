# Plan: shell-driven e2e via bpfman-shell test scaffolding and `bpfman map`

## Context

This document is the follow-up to `docs/BPFMAN-SHELL-SPLIT.md`. The
split landed the binary boundary: `bpfman` for the production
manager, `bpfman-shell` for the REPL, the DSL runner, and the
forthcoming dev/test/ops verbs. What it deliberately did not land
was the test scaffolding that makes the DSL lane usable as a
replacement for the Go embedding suite under `e2e/`.

The Go suite drives the manager directly. Tests reach for
`mgr.LoadProgramFromFile(...)`, set up veth pairs and namespaces
via `e2e/helpers.go`, generate deterministic traffic, read BPF
maps with cilium/ebpf typed APIs, and assert exact counter values.
The DSL scripts under `e2e/scripts/*.bpfman` cover a subset of
the same lifecycle but cannot match the precision: there's no
veth/namespace/lease verb on bpfman-shell yet, and there's no map
read verb on bpfman, so DSL tests run with hardcoded interface
names and "counter > 0" style assertions that don't catch
regressions cleanly.

This plan describes the verbs needed to close that gap, the
package extraction that supports them, and the order in which
they should land. The end state is a DSL lane that exercises the
real CLI surface (the binary a user installs) end-to-end with
deterministic inputs and exact-equality assertions, and a Go
embedding lane that shrinks to the cases that genuinely cannot be
expressed at the CLI: init-time tests, race coordination,
recorder inspection.

## Goal

Three pieces of work that compose into a usable shell-driven
e2e lane:

1. **`internal/netlab/`**. Lift the veth pair creation, namespace
   setup, ARP warming, IP assignment, and connectivity
   verification from `e2e/helpers.go` into a non-test package that
   does not take a `*testing.T`. The existing
   `NewTestVethPair(t)` stays as a thin shim that registers
   `t.Cleanup` so the Go suite keeps working during the
   transition.

2. **bpfman-shell test scaffolding subcommands**. `veth
   create/destroy/ping`, `reap`, `lease list/show`. JSON output,
   lease-tracked cleanup under `<runtime-dir>/leases/<uuid>.json`,
   unique-name allocation. These let DSL scripts compose veth
   plumbing the same way they compose bpfman commands today.

3. **`bpfman map` diagnostics**. `map dump <id>` and `map lookup
   <id> --key K`, with JSON output and per-CPU handling. This is
   a dual-use diagnostic that belongs in `bpfman` (production):
   reading bpfman-managed maps does not expand the threat model
   and is independently useful for production operators
   debugging counters.

Once these land, the lifecycle tests in `e2e/` convert
mechanically into DSL scripts and the Go embedding lane shrinks
to the small remainder.

## Non-goals

- Defining our own JSON schema for `bpfman map dump` /
  `lookup`. Stage A passes whatever bpftool produces through;
  Stage B (cilium/ebpf reimplementation) is where we'd
  commit to a schema we own.
- Ringbuf and perf-event-array support. These are
  consume-once data structures with semantics that don't fit
  `dump`/`lookup`. Tests that use them stay Go.
- Parallel test execution at the DSL level. Scripts are
  sequential; CI already serialises script runs because of
  shared kernel state (bpffs mounts, dispatcher slots, the
  global program-id space).
- Replacement of `*testing.T`'s rich assertion vocabulary. DSL
  has `require ok`, `assert <expr>`, and `retry { } until { }`;
  that's enough for the lifecycle suite. Tests that need
  `assert.Eventually` with custom poll intervals or
  `assert.ErrorIs` chains over typed sentinel errors stay Go.
- Removing the Go embedding lane. The lane shrinks but does not
  disappear; phase 6 of the split doc described the residual
  whitebox surface.

## Threat model recap

The split argues that production `bpfman` should stay narrow.
This plan keeps that constraint:

- The new test scaffolding verbs (`veth`, `reap`, `lease`) are
  on `bpfman-shell` only. They create network resources and
  manipulate namespaces; that's exactly the surface the split
  pushed out of the production binary.
- `bpfman map dump`/`map lookup` is on `bpfman` because it reads
  bpfman-managed maps. bpfman already has the kernel access to
  read those maps (it owns them); exposing the read via a
  diagnostic verb is not a new privilege. Production operators
  benefit from `bpfman map dump <id>` when chasing counter
  regressions in the field; that's why it lives in the
  production binary, not behind dev-only gating.
- Map-write verbs (`map update`, `map delete-elem`, etc.) are
  out of scope for this plan. Reading a map is dual-use; writing
  one is privilege amplification (an attacker with code execution
  in bpfman could already do it, but the verb makes it
  ergonomic). If the e2e suite ever needs map writes, those
  go on `bpfman-shell`, not `bpfman`.

## Architecture

### internal/netlab/

`e2e/helpers.go` currently mixes test-only concerns
(`t.Cleanup`, `t.Logf`, `require.NoError(t, err)`) with the
underlying network plumbing. The plumbing is:

- `CreateVethPair(opts)` -- atomic veth pair creation with
  unique names, IP assignment to both ends, link-up.
- `MoveToNamespace(iface, netnsPath)` -- move one end into a
  network namespace (created on demand).
- `WarmARP(pair)` -- prime the neighbour cache so the first
  ping doesn't get lost in ARP resolution.
- `Ping(pair, count, exact)` -- send N pings, optionally
  require exactly N replies.
- `Cleanup(pair)` -- delete veth + namespace + leases.

Move these into `internal/netlab/` as functions that return a
`VethPair` value (interface names, IP addresses, namespace
inodes, lease ID) and an error. No `*T`. The existing
`NewTestVethPair(t *testing.T)` becomes a thin shim:

```go
func NewTestVethPair(t *testing.T) netlab.VethPair {
    t.Helper()
    pair, err := netlab.CreateVethPair(netlab.DefaultOpts())
    require.NoError(t, err)
    t.Cleanup(func() {
        if err := netlab.Destroy(pair); err != nil {
            t.Logf("netlab cleanup: %v", err)
        }
    })
    return pair
}
```

Both consumers -- the e2e test binary and `bpfman-shell veth
create` -- share `internal/netlab/` for the underlying logic.
The package belongs in `internal/` because it's only used by
`bpfman-shell` and `e2e/`; nothing else in the tree should
reach for veth manipulation primitives.

The unique-name allocation should pick a short prefix per
process (e.g. `nl-<pid-suffix>-`) so two concurrent script
runs do not collide. Lease IDs are UUIDs; lease files live at
`<runtime-dir>/leases/<uuid>.json` carrying:

```json
{
  "id": "...",
  "pid": 12345,
  "created_at": "2026-...",
  "kind": "veth",
  "resources": {
    "interfaces": ["nl-12345-a", "nl-12345-b"],
    "namespaces": ["/var/run/netns/nl-12345"]
  }
}
```

### bpfman-shell test scaffolding subcommands

The verbs:

- `bpfman-shell veth create [--warm] [--cidr CIDR]` --
  allocate, return JSON `{lease_id, name_a, name_b, addr_a,
  addr_b, netns_a, netns_b}`. With `--warm`, send a single ARP
  probe so subsequent traffic is timing-stable.
- `bpfman-shell veth destroy <lease_id>` -- tear down the
  resources named in the lease, remove the lease file. Idempotent
  on missing-lease (just returns success).
- `bpfman-shell veth ping <lease_id> --count N [--exact]` --
  send N ICMP echoes from one end, return JSON `{sent, received,
  loss_pct}`. With `--exact`, exit non-zero if `received != sent`
  so DSL `require ok exec ...` catches loss.
- `bpfman-shell reap` -- walk `<runtime-dir>/leases/`, check
  PID liveness via `/proc/<pid>`, destroy resources for dead PIDs.
  Same pattern CRI runtimes use for orphan container cleanup.
  Replaces the per-script `exec status ip link del ...` hygiene
  lines and gives correctness on cleanup-after-failure rather
  than convention.
- `bpfman-shell lease list` -- enumerate leases with PID + age
  + resource summary.
- `bpfman-shell lease show <lease_id>` -- single lease detail.

JSON output shape mirrors what `bpfman` does for its own verbs:
`-o json` produces structured output, `-o jsonpath=EXPR`
extracts a field, default is a human table. The DSL composition
pattern is the same as for bpfman commands:

```
let v = [bpfman-shell veth create --warm]
let prog = [bpfman program load file --path testdata/bpf/xdp_counter_nopin.bpf.o
                                    --programs xdp:xdp_stats]
let link = [bpfman link attach xdp --iface $v.name_a $prog]
require ok exec bpfman-shell veth ping $v.lease_id --count 7 --exact
```

### bpfman map diagnostics

The verbs on the production binary:

- `bpfman map dump <id>` -- iterate the entire map, return JSON.
- `bpfman map lookup <id> --key K` -- single-key lookup.
  ENOENT exits non-zero with no JSON output.

The first-cut implementation shells out to bpftool with `-j`
JSON output. Rationale:

- bpftool is already present in the dev shell (`bpftools` in
  `flake.nix`) and in the CI image -- zero new dependency for
  the test lane. The only operational change is for production
  deployments wanting `bpfman map dump`: `Dockerfile.bpfman`
  needs bpftool added (`dnf install bpftool` plus a small
  image-size bump). For test-lane use that's a no-op.
- The CLI surface stays the same regardless of implementation,
  so replacing the shell-out later with a native cilium/ebpf
  implementation is purely an internal change. The two-stage
  path: Stage A wraps bpftool now; Stage B implements
  `bpfman map` natively against cilium/ebpf if production
  prefers no bpftool dependency or we want a JSON schema we
  control.

The CLI takes bpfman's program-scoped map ID -- the same
`status.maps[].id` value `bpfman program get <id> -o json`
exposes. Internally the verb looks up the kernel map ID from
the bpfman database, refuses if the map is not bpfman-owned (so
the verb cannot be turned into a generic "read any kernel map"
primitive), and execs bpftool with the kernel ID. Whatever JSON
bpftool emits is passed through and consumed via jq from DSL
scripts; the exact shape gets pinned when tests read against
real maps.

Stage B replaces the shell-out with a native implementation in
the `bpfman` package using cilium/ebpf, exposing the same CLI
surface. The DSL scripts don't change; only the internals do.
We commit to that path if production pushes back on the
bpftool dependency, or if we want a JSON schema we control.

Out of scope for the first cut:

- Ringbuf and perf-event-array. The consume-once semantics
  don't fit `dump`. A future `bpfman map drain --timeout`
  could land if a test pushes for it.
- Map writes (`map update`, `map delete-elem`). Out of scope
  per the threat-model recap above.

## Phased plan

Each phase is independently shippable. The order is chosen so
each PR demonstrates value on its own and the next builds on
verified ground.

### Phase 1: Extract `internal/netlab/`

1. Create `internal/netlab/` with `CreateVethPair`, `Destroy`,
   `MoveToNamespace`, `WarmARP`, `Ping`. No `*T`.
2. Move the implementation bodies from `e2e/helpers.go`. Keep
   `NewTestVethPair(t)` in `e2e/helpers.go` as a `t.Cleanup`-
   registering shim around the netlab function.
3. Verify `make test-e2e` passes unchanged.

   Verify: pure refactor; the Go embedding lane is the canary.
   Reviewable in isolation; no behaviour change.

### Phase 2: bpfman-shell veth/reap/lease verbs

4. Add `cmd/bpfman-shell/veth.go`, `reap.go`, `lease.go`. JSON
   output via the existing `cliformat` package -- the verbs
   define their own output structs and call `cliformat.Format*`
   for table/json/jsonpath rendering.
5. Add lease tracking under `<runtime-dir>/leases/`. The shell's
   `--runtime-dir` flag is already inherited from `bpfmancli.CLI`.
6. Add unit tests for the formatters (golden files over fixture
   structs). Reap-on-dead-PID test that forks a child, kills it,
   and asserts cleanup.

   Verify: `bpfman-shell veth create --warm` returns JSON with a
   live veth pair; `bpfman-shell veth ping <id> --count 7
   --exact` exits zero on a clean pair; `bpfman-shell reap`
   after killing the parent removes the lease and the
   resources.

### Phase 3: bpfman map dump/lookup (bpftool wrapper)

7. Add `cmd/bpfman/map.go` with `MapDumpCmd` and `MapLookupCmd`.
   The verbs take bpfman's program-scoped map ID, look up the
   kernel ID via the database, and exec bpftool with `-j` to
   get JSON output.
8. Pass bpftool's JSON through unmodified for `-o json`. A
   human table renderer can come later if anyone needs it; for
   now `-o json` is the only consumer that matters.
9. Refuse to read maps not in the bpfman database -- look up
   the kernel ID via the database, error if not present. The
   verb cannot be turned into a generic "read any kernel map"
   primitive.
10. Translate bpftool's exit codes / stderr into bpfman-shaped
    errors (no leak of "bpftool not found" to users; map-gone
    becomes a clean "map id N not found").
11. Add unit tests for the ID translation and error mapping
    with bpftool stubbed out, plus an integration test that
    loads a known program, increments its counter, and asserts
    the dumped value via the real bpftool path.
12. Document bpftool as a runtime requirement for `bpfman map
    *`. Add `bpftool` to `Dockerfile.bpfman`'s install step (or
    accept "map dump unsupported on this image" if bpftool is
    deliberately omitted).

    Verify: `bpfman map dump $id` prints the table form;
    `-o json` is consumable from jq; bpfman-database absence
    is rejected cleanly; bpftool absence is reported with a
    helpful "install bpftool" message.

### Phase 4: Convert one lifecycle test as a proof

12. Rewrite `TestXDP_LoadAttachDetachUnload` (the simplest
    representative) as `e2e/scripts/TestXDP_Lifecycle.bpfman`
    using the new veth + map verbs. Use `_nopin.bpf.o` map
    variant for exact counter assertions (per the existing
    project memory).
13. Run side-by-side with the Go version. Compare wall-clock
    and diagnostics on induced failures (kill the script
    mid-run, verify reap cleans up).
14. If the DSL version is strictly better, mark the Go test for
    removal in a follow-up batch.

    Verify: the converted script passes locally and in CI;
    induced mid-script failure leaves no leaked resources after
    the next reap pass.

### Phase 5: Convert the rest in batches

15. Convert `TestKprobe_*`, `TestUprobe_*`, `TestTracepoint_*`,
    `TestFentry/Fexit_*` (all simple lifecycle tests). Most
    will be straight transliterations.
16. Convert `TestTC_*` and `TestTCX_*` (slightly more involved
    because of dispatcher chains).
17. Convert any tests that use map-sharing via `--map-owner-id`.

    Verify: `make test-e2e-scripts` covers the lifecycle
    surface that `make test-e2e` did, with deterministic
    counters and lease-reaped cleanup.

### Phase 6: Whitebox tests, dispatcher inspection

18. Expose dispatcher state via `bpfman dispatcher get -o json`:
    slot membership, current revision, the recipe shape. This
    is a useful CLI improvement independent of test conversion;
    operators want it for debugging too.
19. Convert `TestDispatcher_*` tests that currently use
    `env.Manager.GetDispatcherSnapshot()` to consume the JSON.
20. Audit what's left in the Go embedding lane. The expected
    residue:
    - Init-time tests (helper-init absent-`/proc` reproducer).
    - Race tests with `sync.WaitGroup` coordination.
    - Recorder tape inspection.
    - Tests that need ringbuf or perf-event-array semantics.

    Verify: the embedding lane shrinks to the genuinely
    Go-only residue; the DSL lane covers everything
    user-observable.

## What stays Go

After phases 1-6, the Go embedding lane retains:

- **Init-time tests**. The `e2e/helper-init` reproducer
  (commit `20db3d91`) for absent-`/proc` mount namespaces
  needs to control the process startup environment before
  Go's `init()` runs. There's no DSL primitive for that and
  there shouldn't be -- it's a property of the bpfman binary's
  launch path.
- **True whitebox**. Tests that assert against types only
  expressible in Go: `errors.Is` chains on typed sentinel
  errors, recorder-tape inspection, anything that goes
  deeper than `-o json` can flatten.
- **Race tests**. `sync.WaitGroup`-coordinated concurrent
  operations. The DSL is sequential; concurrency happens
  across multiple bpfman-shell processes which conflict on
  shared kernel state (bpffs mounts, dispatcher slots), so the
  race surface stays in Go.
- **Ringbuf and perf-event-array**. Consume-once data
  structures with semantics `dump`/`lookup` doesn't fit. A
  future `bpfman map drain --timeout` could land if a
  test needs it; until then these tests stay Go.

This is a small slice. The big chunk -- lifecycle, multi-program
priority chains, counter assertions, dispatcher inspection --
moves to DSL.

## Open decisions

1. **Lease ID format**. UUIDs are obvious but verbose; a
   short pid-prefixed counter (`nl-12345-001`) is more
   readable. Pick before phase 2.

2. **Map ID space across binaries**. `bpfman map dump <id>`
   takes a bpfman-scoped ID. The DSL composes this via
   `$prog.status.maps[0].id`. Confirm that the JSON shape of
   `bpfman program get <id>` exposes map IDs in a way that
   survives the CLI -> CLI handoff cleanly. (It already
   should; verify before phase 3.)

3. **JSON shape and key/value encoding** in Stage A are
   whatever bpftool emits and accepts. DSL scripts compose
   with jq against the actual output once we run it against
   our maps. If the shape proves awkward to consume, a
   `bpfman-shell sum-counter <map-id> --key K` helper that
   wraps the lookup plus jq reduction in one verb is a
   reasonable escape hatch. Stage B is where we'd commit to
   our own schema.

4. **bpftool dependency in production**. `Dockerfile.bpfman`
   based on `ubi9-minimal` doesn't ship bpftool by default.
   Either add it via `dnf install` (small image-size bump,
   simple dep), or document `bpfman map *` as "available
   where bpftool is installed" and let distributors decide.
   The dev/CI lane is unaffected either way.

6. **Where does `bpfman-shell veth ping` live in the
   namespace structure?**. The veth pair has two ends that
   may be in different network namespaces. `ping` runs from
   one end's namespace. The verb needs to spawn the ping in
   the right netns; reuse the bpfman-ns helper pattern or
   `setns(2)` directly. Decide based on what's cleanest --
   the bpfman-ns helper is heavy machinery for what could
   be a 10-line `nsenter` invocation here.

7. **Production CI assertion that bpfman-shell is absent**.
   Carried forward from BPFMAN-SHELL-SPLIT.md as item 2 in
   "what done looks like". `Dockerfile.bpfman` structurally
   only `COPY`s `/bpfman` so the absence is guaranteed at
   the current shape, but a defensive runtime/layer
   assertion catches future drift. Probably a step in
   `image.yaml` that runs `docker run --rm <image> sh -c '!
   [ -e /bpfman-shell ]'`. Land alongside or before phase 1.

## Implications for existing work

- **`docs/E2E-CLI-PLAN.md`** is partially superseded again.
  The Go-driven CLI lane sketched there remains useful for
  the smoke test (`TestCLI_ProgramListEmpty`) and for any
  Go-only CLI scenarios, but the multi-program e2e work
  moves into the DSL once the verbs above land. Keep the
  document; this one supersedes the architecture decisions
  for the test lane.
- **`e2e/helpers.go`** keeps its public API
  (`NewTestVethPair(t)`) until the Go embedding lane is
  fully converted. After phase 6, either delete the helper
  outright (no callers left) or leave it as a thin
  netlab-package wrapper if any whitebox test still wants
  veth+`*T`.
- **`testdata/bpf/*.bpf.o`** continues to be the canonical
  source of test BPF objects. The `_nopin` variants (per
  the project memory note on `_nopin.bpf.o`) become
  load-bearing because exact-equality counter assertions
  require maps that aren't shared across loaded copies.
  Make sure the build rules cover both pinned and `_nopin`
  variants for every test object that participates in
  counter assertions.
- **`make test-e2e`** shrinks but doesn't disappear; the
  whitebox tests that genuinely need typed Go APIs stay
  there. `make test-e2e-scripts` becomes the main lane and
  grows to cover what `test-e2e` used to.

## What "done" looks like

1. `internal/netlab/` exists and is the single source of
   truth for veth/namespace/ARP/connectivity primitives.
   `e2e/helpers.go` is a `t.Cleanup`-registering shim.
2. `bpfman-shell veth create/destroy/ping`, `reap`, `lease
   list/show` exist with JSON output, and `<runtime-dir>/
   leases/` is the lease store. `bpfman-shell reap` reaps
   orphans from dead PIDs.
3. `bpfman map dump <id>` and `bpfman map lookup <id> --key
   K` exist with JSON output, backed by bpftool in Stage A
   and replaceable with a native cilium/ebpf implementation
   in Stage B.
4. `e2e/scripts/*.bpfman` covers the lifecycle, multi-program
   priority chains, and dispatcher inspection that the Go
   embedding suite covered, with exact-equality counter
   assertions and lease-reaped cleanup that survives
   mid-script failure.
5. `make test-e2e` shrinks to a small whitebox-only residue
   (init-time, race, recorder, ringbuf). `make
   test-e2e-scripts` is the main e2e lane.
6. CI runs both lanes; failures are diagnosable from the
   script source line or the Go test name as appropriate.

The threat-model story carries over from the split: production
`bpfman` gains `map dump`/`lookup` (read-only, dual-use,
no expansion), and bpfman-shell gains the test scaffolding
verbs that stay outside production images.
