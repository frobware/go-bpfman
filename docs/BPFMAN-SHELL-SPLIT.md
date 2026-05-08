# Plan: split `bpfman` and `bpfman-shell` as two binaries

## Context

This document captures the plan for separating the bpfman binary
into two artefacts: a narrow production `bpfman` (the BPF manager
proper) and a development / test / ops tool `bpfman-shell` that
contains the REPL, the DSL runner, and a set of e2e test
scaffolding subcommands.

The motivation arrived through two converging lines of work:

1. The CLI-driven e2e test lane (see `docs/E2E-CLI-PLAN.md`) needs
   network-plumbing helpers (veth pair creation, namespace setup,
   ARP warm-up, traffic generation, deterministic counter
   readback, lease-tracked cleanup) so that DSL scripts under
   `e2e/scripts/` can match the precision of the Go embedding
   lane in `e2e/`. Today the existing scripts shell out to `ip(8)`
   directly with hardcoded names and best-effort cleanup; this
   limits them to serial execution and to "counter > 0" style
   assertions. A structured helper that emits JSON like bpfman
   itself, exposes unique-name leases, and survives mid-script
   failure cleanly would lift those limits.

2. Building those helpers into the production `bpfman` binary
   (even gated behind a build tag) is a threat-model expansion.
   bpfman runs with significant capabilities (CAP_BPF,
   CAP_NET_ADMIN, root-equivalent for bpffs mounting); a
   compromised bpfman process today can manipulate the BPF
   programs and links bpfman manages. Adding "create arbitrary
   veth pairs", "move interfaces between namespaces", "exec ping
   in arbitrary netns" verbs to the on-disk binary -- regardless
   of how they got there -- gives an attacker who lands code
   execution a much bigger primitive than the manager's stated
   job. Build tags are a build-time discipline, not a security
   boundary; one misconfigured CI job, one copy-pasted
   Containerfile recipe, one inherited tag in a release pipeline
   and the production artefact ships with verbs we never intended
   to ship.

Once that argument is admitted for veth-creation, it extends to
the REPL itself. The REPL exposes `exec` (arbitrary command
execution), `source` (arbitrary script loading), `let` and jq
pipelines (data manipulation), and full bpfman API access from a
single entry point. A production `bpfman` that can be invoked as
`bpfman repl` -- or whose code path includes the REPL even if no
verb mounts it -- is a privilege-amplification surface for the
same reason. The REPL is enormously useful for development, ops,
and DSL-based testing; it is not what production deployments
should be running.

The conclusion: production `bpfman` should be narrow and
auditable. The REPL, the DSL runner, and the test scaffolding
share an audience (developers, operators, CI) and a threat
profile (run on trusted hosts, never inside production
containers). They belong in a separate binary, named distinctly,
shipped distinctly, never copied into production container
stages.

## Goal

Land two binaries built from this tree:

- `bpfman`: the production manager. Narrow CLI surface --
  `program`, `link`, `dispatcher`, `get`, `list`, `load`,
  `unload`, plus dual-use diagnostics (`map dump`, `gc`,
  `dispatcher get -o json`) that are useful regardless of
  audience and do not expand the threat model. No REPL, no
  `exec` builtin, no test scaffolding, no veth verbs.

- `bpfman-shell`: the development / test / ops tool. Contains
  the REPL, the DSL script runner, and the e2e test extras
  (`veth create/destroy/ping`, `reap`, lease management). Built
  from the same module, distributed only to dev and CI
  environments, not into production container images.

The line between the two is drawn on threat-model expansion:
verbs that operate on bpfman's own state stay in `bpfman`; verbs
that create or manipulate resources outside that scope move to
`bpfman-shell`.

## Non-goals

- A third binary for "test only" extras separate from the shell.
  The shell and the test extras have the same audience and the
  same security profile; one binary is enough.
- Removing the REPL. The REPL stays a first-class citizen, just
  in a different binary.
- Reworking the bpfman core architecture. SANS-IO, manager,
  interpreter, store -- unchanged. This is a packaging and
  surface-area split, not a redesign.
- Making `bpfman-shell` available through bpfman's RPC server,
  or vice versa. They are independent CLIs against the same
  store; integration is via the on-disk runtime directory and
  the writer lock that bpfman already uses.

## Threat model (the load-bearing argument)

bpfman's current threat surface, in rough terms: anyone who
lands code execution as the bpfman process can issue any
program/link operation that bpfman supports against the runtime
directory and the kernel BPF subsystem. That is the cost of
running a manager at all and is bounded by what the manager's
verbs do.

The proposed addition of test scaffolding ("create veth pair",
"move interface to netns", "ping target", "execute arbitrary
command via REPL `exec`") expands that surface in three
directions: arbitrary network resource creation, arbitrary
namespace manipulation, and arbitrary command execution. Each
is a useful primitive for an attacker performing lateral
movement or persistence even if the underlying capabilities
were already granted to the process; the verbs make those
capabilities ergonomic to invoke.

Build tags do not address this for three reasons:

1. They are build-time discipline. A misconfigured Makefile
   target, an inherited `EXTRA_TAGS` value in a release CI job,
   a wrong base image in a Dockerfile -- any of these and the
   production artefact ships with the verbs.
2. Verifying tag absence requires inspecting the binary. Symbol
   grep, disassembly, or invoking suspect verbs and checking for
   "unknown command". Nobody does this per release.
3. Defence in depth dies at the boundary. "We made sure the
   production CI did not set the tag" is a single procedural
   check.

A separate binary with a distinct name is structurally
auditable: `bpfman-shell` either exists in the production image
or it does not. CI can assert its absence with `find /usr/bin
-name 'bpfman-shell'` and fail the image build if it appears.

The same argument applies to the REPL. The REPL's `exec`
builtin is functionally equivalent to "we shipped a shell as
part of the manager". If we accept the argument for veth
helpers, we accept it for the REPL.

## Architecture

```
cmd/bpfman/                 production binary entry point
  cli.go                    Kong tree: program, link, dispatcher,
                            get, list, load, unload, ... (no repl,
                            no test verbs)
  format.go                 (existing) SANS-IO formatters; shared
  ...

cmd/bpfman-shell/           dev/test/ops binary entry point
  main.go                   Kong tree mounts the REPL plus test
                            scaffolding subcommands
  repl/                     REPL package, moved from cmd/bpfman/
                            (currently cmd/bpfman/repl*.go)
  testlab/                  veth/ping/reap/lease subcommands
  ...

internal/cliformat/         (or kept in cmd/bpfman and imported
                            by cmd/bpfman-shell) -- the format
                            functions become a shared dependency
                            of both binaries.
internal/netlab/            (new) the veth/ARP/connectivity
                            machinery currently in
                            e2e/helpers.go, lifted out of the
                            test-only package so cmd/bpfman-shell
                            can reuse it without taking a *T.
                            NewTestVethPair becomes a thin wrapper.
```

`bpfman-shell`'s test scaffolding subcommands emit JSON / accept
`-o jsonpath=...` like bpfman does, so DSL scripts compose them
the same way:

```
require ok exec bpfman-shell reap
let v = [bpfman-shell veth create --warm]
let prog = [bpfman program load file --path testdata/bpf/xdp_counter.bpf.o
                                    --programs xdp:xdp_stats]
let link = [bpfman link attach xdp --iface $v.name_a $prog]
require ok exec bpfman-shell veth ping $v.lease_id --count 7 --exact
let stats = [bpfman-shell map dump $prog.status.maps[0].id --key 2 --sum]
assert $stats.sum == 7
bpfman link detach $link
bpfman program unload $prog
exec bpfman-shell veth destroy $v.lease_id
```

`reap` walks lease files (`<runtime-dir>/leases/<id>.json`)
written at resource creation, removes any whose owning PID is
dead. Same pattern CRI runtimes use for orphan container
cleanup. Replaces the per-script `exec status ip link del ...`
hygiene lines with one centralised reaper, and gives correctness
on cleanup-after-failure rather than convention.

## What goes where

This list is illustrative, not exhaustive. Expect refinements as
the work proceeds.

In `bpfman` (production), unconditional:

- `program load`, `program unload`, `program list`, `program get`,
  `program delete`
- `link attach`, `link detach`, `link list`, `link get`,
  `link delete`
- `dispatcher list`, `dispatcher get`
- `gc`, `doctor`
- `map dump <id>` (new -- diagnostic, useful in production for
  debugging counter maps; reads bpfman-managed maps only,
  doesn't expand the threat model)
- `version`
- All output formats: `-o table/wide/json/tree/jsonpath`

In `bpfman-shell` (dev/test/ops only):

- `repl` (with `exec`, `source`, `let`, jq pipelines)
- `script <file>` (DSL one-shot runner; today this is
  `bpfman repl -f <file>`)
- `veth create/destroy/ping` (test scaffolding)
- `reap` (lease-based orphan cleanup)
- `lease list/show` (introspection on test resource leases)

Borderline cases worth deciding explicitly:

- `dispatcher get -o json` exposing slot membership: probably
  in `bpfman` -- it is a diagnostic over bpfman's own state.
  Whitebox tests that today reach for `env.Manager.GetDispatcherSnapshot()`
  could then move to DSL.
- `gc reap-orphans` (a counterpart to the test-resource reap):
  in `bpfman` if it is a real production utility; otherwise in
  `bpfman-shell`.
- `bpfman test --help` invocation in production must not exist.
  CI assertion: `bin/bpfman test 2>&1 | grep -q 'unknown command'`.

## Phased plan

Each phase is independently shippable. Bigger phases than the
e2e CLI lane plan because there is genuine refactor work.

### Phase 1: Skeleton split, REPL stays where it is

1. Create `cmd/bpfman-shell/main.go` with a Kong skeleton that
   currently contains only a `version` subcommand. Build it from
   the Makefile alongside `bin/bpfman`.
2. Production `bpfman` continues to contain the REPL for now;
   the goal of this phase is to have both binaries shipping.
3. CI assertion: production image build never includes
   `bpfman-shell`.

   Verify: `make` builds both binaries; `bin/bpfman-shell version`
   prints the version banner; production container image build
   fails if `bpfman-shell` is COPY'd in.

### Phase 2: Move the REPL

4. Move `cmd/bpfman/repl*.go` into `cmd/bpfman-shell/repl/` (or
   equivalent layout). Adjust imports.
5. Production `bpfman repl` either disappears entirely (preferred
   for cleanest threat-model story) or becomes a stub that prints
   "REPL is in `bpfman-shell`" and exits non-zero.
6. Update everything that invokes `bpfman repl ...`: CI jobs,
   `e2e/scripts/*.bpfman` test runner targets in the Makefile,
   docs, Containerfile examples.
7. Audit the production binary surface: `bin/bpfman --help` lists
   no REPL verb, no `exec` builtin, no `source`. Spot-check by
   grep over compiled symbols.

   Verify: `make test-e2e-scripts` still passes by invoking
   `bpfman-shell` instead of `bpfman repl`. Production image
   builds and `bpfman repl` is absent.

### Phase 3: Test scaffolding subcommands

8. Extract `e2e/helpers.go` veth/ARP/connectivity machinery into
   `internal/netlab/`. The current `NewTestVethPair(t *testing.T)`
   becomes a thin wrapper around a `netlab.CreateVethPair(opts)`
   that does not take a `*T`. The test helper retains its
   `t.Cleanup` registration; the new `bpfman-shell` subcommand
   uses the lower-level API directly and writes a lease file.
9. Add `bpfman-shell veth create/destroy/ping` and
   `bpfman-shell reap` (with lease tracking under
   `<runtime-dir>/leases/`). JSON output by default, `-o jsonpath`
   supported via the shared `executeJSONPath` from
   `cmd/bpfman/format.go` (or its extracted internal package).
10. Unit tests for the formatters (golden files over fixture
    structs), mirroring `cmd/bpfman/format_*_test.go`.

    Verify: `bpfman-shell veth create --warm` prints the expected
    JSON; the resulting lease file exists; `bpfman-shell reap`
    after killing the parent removes it.

### Phase 4: Convert DSL scripts to the new shape

11. Rewrite `e2e/scripts/TestXDP_LoadAttachDetachUnload.bpfman`
    (and the other lifecycle scripts) to use `bpfman-shell veth
    ...` and `bpfman-shell reap` instead of `exec ip ...` lines.
    Drop hardcoded interface names; the helper assigns them.
12. Convert one Go e2e test that has a clean DSL fit (e.g. one
    of the multi-program TC priority tests) to a DSL script.
13. Decide whether the Go `TestCLI_XDP_Lifecycle` we just wrote
    stays. By this point the DSL version is strictly better;
    keeping the Go version is duplicate coverage.

    Verify: converted scripts pass under `make test-e2e-scripts`
    and clean up correctly on induced mid-script failure.

### Phase 5: Migrate whitebox tests where possible

14. Identify which Go embedding tests genuinely need typed
    manager APIs (`env.Manager.GetDispatcherSnapshot()`, recorder
    inspection, etc.) versus which only use them out of
    convenience. Migrate the latter to DSL.
15. For dispatcher whitebox tests: decide whether to expose
    dispatcher state via `bpfman dispatcher get -o json` (a
    production-shaped diagnostic) so those tests can move to
    DSL too. This is a useful CLI improvement independent of
    the test rewrite.
16. The remaining Go embedding lane tests are then
    legitimately whitebox (init() in absent-/proc namespaces,
    typed-error assertions, race tests). Keep them; they are a
    small slice.

    Verify: the embedding lane shrinks to whitebox tests only;
    the DSL lane covers everything user-observable.

## Open decisions for the next session

1. **Binary name.** `bpfman-shell` is descriptive but verbose;
   `bpfctl` is short but conflates "control" with "shell";
   `bpfsh` is terse but obscure. Pick before phase 1.

2. **Subcommand layout in `bpfman-shell`.** Flat
   (`bpfman-shell veth create`, `bpfman-shell repl`,
   `bpfman-shell reap`) versus grouped (`bpfman-shell test
   veth create`, `bpfman-shell repl`). Flat reads better at
   the call site; grouped scales if the test surface grows.

3. **`bpfman repl` behaviour during the transition.** Hard
   removal in phase 2 versus stub-with-error-message. Hard
   removal is cleaner; stub avoids breaking existing scripts
   in flight. Probably hard removal with a one-release stub if
   we cared about that, but this is an internal tree -- hard
   removal is fine.

4. **Where the formatters live.** Stay in `cmd/bpfman/` and get
   imported by `cmd/bpfman-shell/`, or extract to
   `internal/cliformat/`. Either works; extraction is cleaner
   if `bpfman-shell` ends up with its own non-bpfman-shaped
   commands (veth, reap) that still want consistent output.

5. **`internal/netlab/` package name.** Could also be
   `internal/testlab/`, `internal/labnet/`, or stay in
   `e2e/internal/...` if its only consumer is the test binary
   plus `bpfman-shell`. The package is the home of veth
   plumbing, ARP warm-up, connectivity verification, and
   IP-address allocation; "netlab" feels right because the
   word "test" overstates the scope.

6. **Lease file format and location.** JSON under
   `<runtime-dir>/leases/<uuid>.json` containing PID, creation
   time, resource list (interfaces, namespaces). `reap` walks
   the directory, checks PID liveness via `/proc/<pid>`,
   removes resources for dead PIDs and unlinks the lease. Need
   to settle: lease ID format, conflict handling if two
   processes race on the same name (probably should not happen
   given unique-name generation but worth defining).

7. **Container image hygiene assertion.** Where in the
   Containerfile or CI does the "production image must not
   contain bpfman-shell" check live? Probably a stage that
   runs `find` over the layer and asserts negative.

## Implications for existing work

- `docs/E2E-CLI-PLAN.md` is partially superseded. The Go-driven
  CLI lane sketched there remains useful for the smoke test
  (`TestCLI_ProgramListEmpty`) and for any genuinely Go-only
  scenarios, but the multi-program phase 3 and beyond move into
  the DSL once `bpfman-shell veth ...` exists. Keep the existing
  document; this one supersedes the architecture decisions.
- The `feedback_repl_decomposition.md` memory note about
  `cmd/bpfman/repl.go` being too large is partially addressed
  by the package-level extraction in phase 2. File-level
  decomposition can still happen inside `cmd/bpfman-shell/repl/`,
  but the load-bearing improvement is the package boundary.
- `cmd/bpfman/format_*_test.go` continues to be the canonical
  place to assert JSON output correctness; the SANS-IO format
  layer is the real coverage. The CLI lane does not duplicate
  this responsibility, only smoke-tests that the binary plumbs
  through to it.
- Future test work writes to `e2e/scripts/` first; only falls
  back to Go for whitebox cases. The Go embedding lane shrinks
  over time but does not disappear.

## What "done" looks like

1. Two binaries shipping from this repo: `bpfman` (narrow,
   production) and `bpfman-shell` (REPL plus test extras).
2. Production container images contain only `bpfman`. CI
   actively asserts the absence of `bpfman-shell`.
3. The production `bpfman` binary surface is auditable:
   `--help` lists only manager verbs and dual-use diagnostics;
   no `repl`, no `exec`, no `source`, no veth verbs.
4. `e2e/scripts/*.bpfman` runs against `bpfman-shell`,
   leverages structured veth/ping/reap helpers, and survives
   mid-script failure with deterministic cleanup via lease
   reaping.
5. Whitebox Go tests remain only for cases that genuinely need
   typed Go APIs; user-observable behaviour is covered by the
   DSL lane.

The threat-model story is the durable bit. The packaging is the
mechanism. Once the split lands, expanding the test or ops
surface is a `cmd/bpfman-shell/` change with no production
impact, and "is this verb safe to ship to users" becomes a
question about which binary it goes in -- structurally
auditable rather than procedurally trusted.
