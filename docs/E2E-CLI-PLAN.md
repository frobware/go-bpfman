# Plan: CLI-shaped e2e test lane

## Context

This document captures the plan for adding a new e2e test lane that
drives the bpfman CLI exactly as a user does, in addition to the
existing library-level e2e suite that embeds the manager.

The motivation is concrete: today's only deployment-shaped coverage
of the bpfman CLI surface comes from the bpfman-operator integration
suite (most visibly `TestApplicationGoCounter`), which lives in a
different repository, requires Kubernetes, and tests at coarse grain.
If that suite goes away, bitrots, or moves, we have no replacement
for the user-facing-tool coverage. A Fedora-only future where the
operator is not part of the picture is the cleanest expression of
that risk: the user-facing tool is bpfman, and our tests would not
exercise the user-facing tool.

The current e2e suite (`e2e/`, build tag `e2e`) embeds the manager
into the test binary and asserts on typed return values. That
covers manager state machine, dispatcher logic, sqlite store, BPF
loading, link lifecycle, and kernel-side correctness. It does not
cover: Kong argument parsing, lock acquisition across processes,
config-file loading, version-banner suppression, error-to-exit-code
mapping, output formatting, sqlite contention across separate bpfman
invocations, or anything else specific to the CLI plumbing. Each of
those has been a regression source historically; today the operator
suite is the only thing that catches them.

Investment in CLI-driven e2e tests is investment in the only durable
surface. The daemon is going away (per project direction); the
operator's exact shape may change; the CLI is what every consumer --
end users, scripts, and the operator itself indirectly -- ultimately
exercises.

## Goal

Build out an e2e test lane that runs `bpfman` as a user does:
spawn the binary per command, feed it CLI arguments, capture
stdout/stderr/exit code, observe real kernel state, assert on
observable outcomes. The first scenario should mirror the spirit of
the operator's `TestApplicationGoCounter` -- multi-program types
loaded, real triggers fired, counters verified -- but realised
locally without Kubernetes.

## Non-goals

- Replacing the existing library-level e2e suite. Both lanes have
  legitimate value; the embedding lane stays.
- Replacing the bpfman-operator integration suite. The operator
  suite still adds value at the k8s-shape grain.
- Reaching feature parity with the embedding lane in the first
  pass. The CLI lane should accrete tests over time.
- Exercising gRPC. The daemon is sunsetting; gRPC-specific
  testing is not worth the investment.

## Success criteria (for "phase 3 done", see below)

A single test exists that, when run via `make test-e2e-cli`:

1. Loads six programs (kprobe, tc, tcx, tracepoint, uprobe, xdp) via
   separate `bpfman load file` invocations.
2. Attaches each to a real target (veth pair for tc/tcx/xdp, kernel
   function for kprobe, tracepoint for tracepoint, the e2e binary
   itself for uprobe).
3. Generates real triggers (ping through the veth, `kill -USR1` to
   a target process, exec'ing a uprobe-firing helper).
4. Verifies via direct BPF map reads (using cilium/ebpf, not via
   bpfman) that each counter incremented.
5. Detaches and unloads via separate CLI invocations.
6. Asserts via `bpfman list -o json` that the manager state is
   empty at the end.
7. Asserts via kernel observation that no programs or links remain.

Test passes deterministically. Suite-end leak detection (mirroring
the existing pattern) confirms no residual state.

## Reference: how the operator test does it

`/home/aim/src/github.com/bpfman/bpfman-operator/worktrees/go-bpfman/test/integration/app_test.go`
deploys a `ClusterBpfApplication` CR via kustomize, picks a
userspace pod, scrapes its logs, and asserts on the strings each
program prints. The CR references bytecode OCI images that the
upstream `bpfman/bpfman` repo's `examples/config/default/go-app-counter/`
directory packages.

We will not use the operator path or the OCI bytecode images. We
already have:

- `e2e/testdata/bpf/*.bpf.o` -- BPF objects for every program type
  the operator test exercises (kprobe, tc, tcx, tracepoint,
  uprobe, xdp). The CLI lane loads these directly via
  `bpfman load file --path testdata/bpf/<name>.bpf.o`.
- `e2e/helpers.go` -- veth pair setup, ping helpers, target
  binary infrastructure. The CLI lane reuses these.
- `e2e_uprobe_call_malloc` mode in `e2e/main_test.go` -- the
  e2e binary self-execs to fire a uprobe target. The CLI lane
  reuses this dispatch.

## Phased plan

Each phase is independently shippable. PR-sized.

### Phase 1: Scaffolding

1. Create `e2e/cli/` directory and `package cli`. Build tag
   `e2e_cli` (separate from `e2e` so the lanes can run independently
   and so the embedding lane's TestMain does not interfere).
2. Add a minimal `TestMain` that mirrors the existing one's helper-
   mode dispatch (acquire suite lock, set up rootNetnsName mount,
   resolve selfExe, etc.) but without the embedding-specific
   shared-runtime initialisation.
3. Add `BpfmanCLI` helper type that wraps `exec.Command(bpfmanPath, args...)`,
   captures stdout/stderr, parses exit codes, decodes JSON output
   for commands that support `-o json`. Locate bpfman by absolute
   path (built by the Makefile prerequisite); verify it exists at
   suite startup.
4. Add Makefile target `test-e2e-cli` that depends on `bin/bpfman`
   and `$(DISPATCHER_BPF_EMBEDS)`, builds the test binary with
   `-tags=e2e_cli,osusergo,netgo`, and runs as root with the same
   shape as `test-e2e` (`-test.v -test.failfast` etc.).

   Verify: `make test-e2e-cli TEST=^TestNothing$` builds and runs
   to "no tests to run" without errors. The bpfman binary path is
   resolvable from the test process.

### Phase 2: First scenario (single program)

5. Pick the simplest program type as the entry test: XDP counter
   on a veth pair. Single attach, ping, verify counter increments,
   detach, unload, verify clean.
6. Implementation:
   - Set up `TestVethPair` (reuse existing helper).
   - `bpfman load file --path e2e/testdata/bpf/xdp_counter.bpf.o
     --programs xdp:xdp_stats` -- parse JSON to extract program ID
     and pinned-map paths.
   - `bpfman link attach xdp <progID> --interface <iface>` -- parse
     JSON to extract link ID.
   - Generate traffic via the existing ping helper.
   - Open the pinned `xdp_stats_map` directly with cilium/ebpf,
     read the per-CPU counter, sum, assert > 0.
   - `bpfman link detach <linkID>`.
   - `bpfman program unload <progID>`.
   - `bpfman list` -- assert no programs remain owned by this test
     (filter by metadata).

   Verify: test passes against a freshly built `bin/bpfman`. Run
   five times in sequence; no flakiness, no leaks.

### Phase 3: Multi-program scenario (operator-test parity)

7. Add `TestCLI_MultiProgramAppCounter` (the name mirrors
   `TestApplicationGoCounter`'s spirit). One test, six program
   types, all loaded and attached via CLI.
8. Specifics for each program type:
   - **kprobe**: hook `try_to_wake_up` via
     `bpfman link attach kprobe <progID> --fn-name try_to_wake_up`.
     Trigger fires from kernel scheduling activity; we generate
     wake-ups by exec'ing a small process and waiting on it.
   - **tc**: attach to veth A ingress; ping through.
   - **tcx**: attach to veth A ingress; ping through.
   - **tracepoint**: hook `sched/sched_switch` (ubiquitous); just
     ensure scheduler activity (any sleep + wake will fire it).
     Or hook `syscalls/sys_enter_kill` and `kill -USR1 <pid>` like
     the operator test does.
   - **uprobe**: target the e2e binary's
     `e2e_uprobe_call_malloc` symbol. Re-exec self in helper mode
     to fire it.
   - **xdp**: attach to veth A; ping through.
9. Each program reads its own pinned counter map and is asserted
   directly via cilium/ebpf.
10. Cleanup: detach and unload all in reverse order. Final
    `bpfman list` is empty.

    Verify: test passes deterministically. The same six programs
    that the operator test verifies are exercised here, with the
    same kernel-level outcomes, but driven entirely through the
    CLI.

### Phase 4: Cleanup invariants and leak detection

11. Suite-end teardown: enumerate via `bpfman list -o json` and
    flag any leftover programs or links. Mirror the pattern in
    `e2e/shared_runtime_test.go::assertSuiteCleanState` so the
    failure messages match the existing convention.
12. Per-test cleanup: `t.Cleanup` chains call CLI invocations to
    unwind state. Lazy-cleanup helper that takes a list of program
    and link IDs and calls the right CLI verbs in reverse order,
    tolerating already-deleted resources.

    Verify: deliberately leak a program in a test (skip the
    cleanup); suite-end teardown reports the leak with the
    program's ID and metadata.

### Phase 5: CI integration

13. Add `test-e2e-cli` job to `.github/workflows/test.yaml`
    matrix (amd64 + arm64, RACE=1 + RACE=0, ISOLATED_RUNTIME=0).
    Reuse the existing buildx-cache scope.
14. Validate: PR run shows the new lane green.

## Design decisions to make in the next session

1. **JSON output format**: does `bpfman list -o json` already
   exist for every relevant verb? Audit `cmd/bpfman/list.go` and
   friends. If a verb lacks JSON output, either add it (small) or
   parse the human-readable form (brittle). Strong preference for
   JSON.

2. **Metadata for ownership**: tag every test-loaded program with
   `bpfman.io/e2e-test=<t.Name()>` via `--metadata` flag (if
   supported) so cleanup and leak detection can attribute orphans
   to the test that created them. Confirm the CLI supports
   metadata on `load`.

3. **Concurrency model**: do CLI tests run in parallel? Each
   `bpfman` invocation acquires the global writer lock via flock;
   contention is the kernel's problem, but contention in the
   *test side* (multiple t.Parallel tests issuing CLI commands)
   could produce spurious failures from lock-acquisition timeouts.
   Default to serial within the CLI lane until contention is
   measured. Explicit `LockTimeout` set on each invocation.

4. **bpfman binary discovery**: hardcode `bin/bpfman` relative to
   module root, or honour `BPFMAN_PATH` env var? Latter is more
   flexible but adds plumbing. Probably hardcode for now; switch
   if a real need surfaces.

5. **Build dependency**: `make test-e2e-cli` depends on
   `bin/bpfman` and the BPF objects. The dispatch in test code
   does not rebuild bpfman. The Makefile's existing dependency
   chain should make this straightforward.

6. **Failure ergonomics**: when a CLI invocation fails, capture
   stdout, stderr, exit code, and the full argv into the test
   failure message. The current embedding lane uses typed return
   values; the CLI lane needs richer string-based diagnostics.

## Relevant code references (state at time of writing)

- `e2e/helpers.go:1056` -- `TestVethPair` and friends.
- `e2e/main_test.go` -- existing TestMain dispatch and helper-
  mode pattern.
- `e2e/testdata/bpf/` -- BPF objects ready for CLI loading.
- `e2e/shared_runtime_test.go::assertSuiteCleanState` -- leak
  detection pattern to mirror.
- `cmd/bpfman/cli.go` -- CLI entry point and Kong setup.
- `cmd/bpfman/list.go`, `cmd/bpfman/load_file.go`,
  `cmd/bpfman/link.go` -- the CLI verbs the lane will exercise.
- `Makefile` -- build conventions, test-e2e recipe to mirror.
- bpfman-operator's `app_test.go` -- the integration test we are
  mirroring in spirit.

## What "done" looks like at the end of this work

Phase 5 complete: a green CI run on a PR that introduces a
`make test-e2e-cli` lane, exercising at least one multi-program
end-to-end scenario through the bpfman CLI, with real kernel-
side observation, deterministic per-test cleanup, and suite-end
leak detection. Future tests written against the CLI surface
accumulate into this lane naturally; the lane's value
compounds independently of the embedding lane and independently
of the bpfman-operator integration suite.
