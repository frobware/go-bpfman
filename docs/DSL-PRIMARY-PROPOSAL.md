# Proposal: make the DSL the primary e2e corpus

## Goal

Move the centre of gravity of bpfman's e2e testing from `e2e/*_test.go`
to `e2e/new/*.bpfman` over a small number of phases. The DSL becomes
the authoritative reference for operational behaviour, CLI surface,
structural shape of records, dispatcher semantics, and multi-program
composition. The Go suite shrinks to the minimum surface only Go can
pin: the library API contract and the few behavioural-precision cases
that need exact-count workload coordination.

The motivation is documentation power. `TestKprobe_LoadAndGet.bpfman`
already does more for a newcomer per line than any Go test in the
suite. The DSL's `matches exhaustive` is a stronger schema lock than
scattered `require.Equal`. The CLI is the test, so the test doubles
as user documentation. The Go suite carries weight it does not need
to carry.

## What is already in place

The capabilities the DSL needs to take primary status mostly already
exist:

- `bpfman-shell --runtime-dir <path>` (via embedded `bpfmancli.CLI`)
  gives per-script runtime root; bpffs, SQLite, pin tree, and
  dispatcher state all anchor there.
- `tempdir` builtin gives per-script scratch space with auto-cleanup
  via `defer rm -rf`.
- `eventually` with the now-typed-error contract supports robust
  polling.
- `matches exhaustive` for whole-record schema assertion.
- `import` for shared helper libraries (`lib.bpfman` model).
- `def` + `guard` + envelope-shaped failures, all parity-tested
  against the AST walker via the recent matrices.
- `make test-e2e-scripts` + `hack/test-e2e-scripts.sh` already iterates
  every `.bpfman` under `e2e/scripts/` and `e2e/new/`.
- The dispatcher scripts (`TestDispatcher_*`,
  `TestTC_DispatcherFillDrainRefill`) are arguably already clearer
  than their Go counterparts.

The gaps are not primitives but discipline: scripts don't currently
pass `--runtime-dir`, the harness runs scripts serially, and a few
patterns (post-detach quiescence, behavioural-precision workloads,
organised error matrices) are not consistently applied across the
corpus.

## Phase 1: parity with NewTestEnv isolation

Plumb per-script isolation through the harness and the scripts.

1. Extend `hack/test-e2e-scripts.sh` to mint a unique runtime dir per
   script (`mktemp -d -t bpfman-script-XXXXXX`), pass it as
   `--runtime-dir <path>` to the bpfman-shell invocation, materialise
   the embedded BPF objects under that root (mirroring
   `materialiseBPFFS(baseDir)` in `e2e/helpers_test.go`), and
   unmount/clean up on exit (`umount $path/fs && rm -rf $path`).
2. Run scripts concurrently with a worker pool keyed off `nproc / 2`
   or an explicit `PARALLEL=N` knob, matching the `make test` style.
   This is the actual scaling unlock; the Go suite's `t.Parallel()`
   win was always isolation, never the test code.
3. Add a `--scope-assert clean` flag (or similar) on `bpfman-shell`
   that asserts zero programs and zero links at script exit,
   mirroring `env.AssertCleanState()`. Wire it into the harness so a
   script that leaks bpfman state fails even without explicit
   assertions.
4. Keep network-test interface allocation per-script: scripts that
   need interfaces should call a `tempnetif` builtin (new, modelled
   on `tempdir`) that yields a fresh dummy interface and registers
   cleanup.

Exit criterion: every script under `e2e/new/` runs concurrently with
peers without contention. CI wall time for the DSL suite matches or
beats `make test-e2e`.

## Phase 2: robust quiescence and exact-count workloads

Replace the brittle patterns the kprobe script openly admits to.

1. Add a `wait_counter_stable` builtin (or formalise the pattern as a
   library `def` in `e2e/lib.bpfman`):

   ```
   def wait_counter_stable(map_id timeout interval) {
     # eventually loop, snapshot, compare; succeeds when delta == 0
     # across N consecutive samples
   }
   ```

   Apply across every script that currently uses `sleep 0.1` for
   detach quiescence.
2. Generalise the workload driver. Today the kprobe script uses
   `BPFMAN_SHELL_MODE=unlinkat-fire-worker`. The Go suite has one
   `startWorkload` / NDJSON protocol that drives exact-count syscall
   firings across every program type. The DSL needs one bpfman-shell
   worker mode parameterised by
   `(syscall, count, pid_sentinel, ack_sentinel)`, replacing the
   per-syscall fire-worker files. Targets:
   - `unlinkat-fire-worker` (already exists)
   - `kill-fire-worker` (for tracepoint sched_kill tests)
   - `mmap-fire-worker`, `read-fire-worker`, etc. as needed
   Or, better, one `syscall-fire-worker` mode with a `--syscall` flag.
3. Establish the post-detach pattern as a library
   `def detach_and_assert_quiescent($link $map_id)` in
   `e2e/lib.bpfman` and use it everywhere. The current
   ad-hoc-per-script approach is exactly what made the Go suite
   drift, and the DSL is at the right moment to centralise.

Exit criterion: no `sleep` in any script except as a deliberate "let
event propagate to a separate process" pause with a comment explaining
why polling won't work.

## Phase 3: error-path matrices

The DSL is already excellent at typed failure assertion
(`assert fail ...`, `guard <- ` with envelope inspection, `match` on
error code/stderr). Apply this surface to negative paths
systematically.

1. Per primitive, add a `Test<Type>_NegativePaths.bpfman` that covers:
   - **Load:** missing file, malformed ELF, type mismatch (the
     existing `TestLoad_FentryFexit_TypeMismatchFailsLoudly` Go test
     moves over verbatim), missing program in object, missing global
     data variable.
   - **Attach:** nonexistent hook (tracepoint, kprobe, uprobe), wrong
     interface, missing program ID.
   - **Detach:** stale link ID, link of wrong kind, double-detach.
   - **Unload:** unknown ID, double-unload, unload-with-active-link
     (should refuse or cascade per documented contract).
2. Each case uses `assert fail bpfman ...` with an `--error` matcher
   on stderr to pin the exact diagnostic text. The diagnostic text
   becomes part of the test contract.

Exit criterion: the negative-path matrix is at least as wide as the
positive-path one across all six primitives (load, attach, detach,
unload, get, list).

## Phase 4: Go suite retreat

With Phases 1-3 done, the Go suite can shrink to its essential role.

Keep in Go:

- `manager.LoadOpts` / `bpfman.AttachSpec` / `bpfman.LinkRecord` and
  similar Go API contract tests, one per public type, validating that
  round-trip serialisation, JSON shape, and required fields are
  stable. These break at compile time when the API changes, which the
  DSL can never do.
- Race-detector and `-count=N` stress runs against the manager and
  dispatcher: the structures and concurrency invariants the Go race
  detector knows how to find.
- One `TestE2E_LibraryConsumer` smoke test per major primitive that
  calls the bpfman Go client directly, proving the embedded-library
  contract.

Delete or move to `e2e/new/`:

- Every `Test*_LoadAttachDetachUnload` lifecycle test, superseded by
  the DSL equivalents.
- Every `TestMultiProg*` and `TestMultiProgChain*`: DSL versions are
  clearer.
- All `TestDispatcher_*`: DSL versions are already preferable.

Target: `e2e/e2e_test.go` shrinks from 3,644 lines to under 500 (Go
API contract + library smoke + a few stress runs).

## Phase 5: signposting

Update `e2e/doc.go` (or replace it with `e2e/README.md`) to put the
DSL first. "If you are learning bpfman, read
`e2e/new/TestKprobe_LoadAndGet.bpfman` first. If you are writing a
Go consumer, read `e2e/api_contract_test.go`. The two suites have
non-overlapping purposes." Make the Go suite findable but not the
front door.

## Risks

- *DSL coverage gaps materialising late.* Mitigation: keep the Go
  suite running until Phase 4 is complete and DSL coverage has been
  verified equivalent (test-name-by-test-name audit; the matrices
  already establish parity at the engine level, so this is mostly a
  "did we port the assertion" exercise).
- *CI tooling drift.* `gotestsum`, IDE integration, coverage tooling
  expect `go test` output. Phase 1 should produce DSL test output in a
  format `gotestsum --raw-command` accepts (TAP, JSON-lines, or a
  small adapter shim). Don't ship Phase 4 until this is in place;
  losing test-runner integration would be a real regression.
- *Behavioural-precision cases that the DSL can't reach.* Phase 2
  needs to actually deliver a generalised workload driver. If the
  `syscall-fire-worker` design hits limitations (kernel function
  variants, BPF tail calls, etc.), some Go behavioural tests stay in
  `e2e/`. That is a fine outcome; small focused Go corpus is the
  explicit goal.
- *Migration churn vs. ongoing development.* The phases are
  independent; Phase 1 alone is a strict win (parallel scripted CI).
  Do not gate Phase 1 on later phases.

## Success criteria

The migration succeeds when:

1. A new contributor learning bpfman reads `.bpfman` files, not
   `_test.go` files.
2. CI wall time for the DSL suite is at or below the Go suite's,
   including isolation cost.
3. The negative-path coverage is at least as wide in the DSL as in
   the Go suite was.
4. Go suite has shrunk to a small, sharp set of API-contract tests
   and stress runs; nobody disputes any of them belong there.
5. A behavioural regression (counter math wrong, dispatcher chain
   wrong, detach not quiescing) is caught by a DSL test, not only by
   a Go test.

Phase 1 is the gating phase: without per-script isolation, "DSL
primary" is a non-starter. The rest is incremental and can land over
weeks.
