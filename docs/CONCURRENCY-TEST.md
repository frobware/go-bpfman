# Concurrency test design

## Context

bpfman is a CLI-only tool — there is no long-lived daemon.
Every `bpfman` invocation is a fresh process that:

1. Opens the SQLite store at `/run/bpfman/bpfman.db`.
2. Acquires the cross-process writer lock (`lock/` package) for
   mutations.
3. Performs its operation (load, attach, detach, unload, get,
   list).
4. Releases the lock and exits.

Multiple `bpfman` invocations running concurrently therefore
contend on a shared on-disk store and a shared on-disk lock.
This is a different concurrency model from a daemon where all
mutations go through one process with in-process synchronisation,
and it requires its own dedicated test.

A goroutine-based test inside a single Go process cannot exercise
the model it needs to prove. In-process mutex primitives do not
catch bugs in SQLite's multi-process locking, `flock`/`fcntl`
contention, stranded lock files from killed processes, or WAL
mode corner cases.

## What the test must exercise

1. **Parallel writers.** N bpfman subprocesses each doing
   `load` + `attach` + `detach` + `unload`, all against the
   same store. Every operation must complete successfully; no
   subprocess should see `SQLITE_BUSY`, `database is locked`,
   or deadlock.

2. **Readers concurrent with writers.** `bpfman program list` /
   `bpfman program get` running while other subprocesses
   mutate the store. Readers must not block indefinitely and
   must see consistent snapshots (either pre-commit or
   post-commit state, never partial rows).

3. **Kill-mid-operation.** One or more subprocesses receive
   `SIGKILL` during the write critical section. On its next
   invocation, bpfman must be able to:
   - Acquire the writer lock (the killed process's lock entry
     must be reclaimable).
   - Observe the store as self-consistent — no half-written
     records, no orphan links referencing a half-loaded
     program.
   - Reconcile kernel state if the killed process had already
     loaded into the kernel before being killed. (Either the
     next GC cycle or doctor pass cleans up; the test should
     specify which.)

4. **Post-storm consistency.** After all parallel work
   finishes, the store + kernel + filesystem must be mutually
   consistent. Every managed program has its pin directory.
   Every managed link has either a kernel link or a synthetic
   id with its pin. No orphan FS entries referencing
   nonexistent programs. `bpfman doctor checkup` should return
   clean.

## Test shape

A top-level Go test in a new package (for example
`e2e/concurrency/` or `platform/store/sqlite/concurrency_test.go`,
depending on how much it relies on a bpf-build). The Go test
drives bpfman subprocesses via `os/exec`:

```go
func TestConcurrent_LoadUnloadStorm(t *testing.T) {
    RequireRoot(t)
    env := NewTestEnv(t)  // reuse the isolated-world helper from e2e

    const workers = 32
    var wg sync.WaitGroup
    errs := make(chan error, workers)
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            pid, err := loadProgramViaCLI(env, i)
            if err != nil {
                errs <- err; return
            }
            if err := unloadProgramViaCLI(env, pid); err != nil {
                errs <- err; return
            }
        }(i)
    }
    wg.Wait()
    close(errs)

    for err := range errs {
        t.Errorf("subprocess: %v", err)
    }
    env.AssertCleanState()
}
```

The Go harness is responsible for:

- Spawning bpfman subprocesses with the correct `--runtime-dir`,
  `--config`, and env pointing at the TestEnv's isolated world.
- Collecting exit codes and stderr from each subprocess.
- Asserting no subprocess exited with a lock-contention error
  (stderr must not contain `database is locked` or
  `SQLITE_BUSY`).
- Asserting final state via `bpfman program list` + kernel +
  filesystem checks.

The existing `TestEnv` helper from the Go e2e suite already
provides per-test isolation (fresh tmp dir, fresh DB, fresh
bpffs mount) — reuse it so each concurrency test starts from a
known-clean state and cannot interfere with parallel tests of
its own.

## Concrete scenarios

1. **LoadUnload storm.** N workers, each doing one full
   load/unload cycle against a small BPF object (e.g.
   `tracepoint_counter.bpf.o`). Verifies the writer lock
   works under contention and the store stays consistent. Start
   with N=8 and scale up as the test stabilises.

2. **Attach/detach storm.** Pre-load M programs in serial, then
   launch N workers that attach and detach links in parallel.
   Verifies the link-mutation path specifically.

3. **Reader/writer race.** One goroutine runs
   `bpfman program list -o json` in a tight loop; another
   runs load/unload cycles. Assert readers never see
   half-loaded records (e.g. a program with empty pin_path),
   and that their list counts are monotonically sensible
   (count moves up by 1 at a time, not by 3 from seeing a
   transient interleaving).

4. **Kill-mid-op recovery.** Start a bpfman load, wait for it
   to acquire the writer lock (observable via lock file mtime
   or an injected sleep in debug builds), SIGKILL it, then
   launch another bpfman load. The second must succeed; a
   third `doctor checkup` must return clean.

5. **Write amplification under concurrency.** N workers each
   do load + 3 attaches + 3 detaches + unload. Verifies
   multi-step operations hold their locks correctly and don't
   release early under contention.

## Success criteria

- All subprocesses exit with status 0 (or with the specific
  test-expected non-zero status for kill scenarios).
- No subprocess's stderr contains `database is locked`,
  `SQLITE_BUSY`, `timeout waiting for lock`, or similar.
- Post-test, `bpfman doctor checkup` returns no findings.
- `bpfman program list` length matches the expected count.
- No orphan FS entries under `/run/bpfman/programs/` or
  `/run/bpfman/fs/`.
- Run the test under `-race` for the harness Go code, even
  though the real concurrency is in subprocesses.

## Scope and sequencing

This test is its own artefact, not an extension of the REPL e2e
scripts:

- The REPL e2e scripts exercise functional equivalence with the
  Go e2e tests. Each runs sequentially against a shared bpfman
  state. They prove the CLI does what it says for each verb in
  isolation.
- The concurrency test exercises the store and lock model under
  process-level contention. It cares about liveness and
  consistency under load, not about any individual verb's
  behaviour.

Both belong in CI but run as separate jobs with separate
reporting. The concurrency test will likely be slower and more
flake-prone than the scripts; it needs its own retry policy and
its own tolerance for environmental noise (system load, kernel
scheduling).

## Implementation notes

- The `lock/` package is the design surface to scrutinise
  first: confirm it uses `flock` (or `fcntl`, or a lock file
  with ownership recorded) in a way that survives process
  death. An advisory lock held by a killed process is
  automatically released by the kernel on exit, which is the
  property the kill-mid-op scenario relies on.
- SQLite should run in WAL mode for best concurrent-reader
  behaviour. Confirm the store opens with
  `_journal_mode=WAL` (check `platform/store/sqlite`).
- `busy_timeout` should be set high enough that transient
  contention resolves without surfacing `SQLITE_BUSY` to the
  user. The existing store code likely already does this;
  the concurrency test is how we prove it.
- When the test fails, collect and attach the stderr from every
  subprocess plus the final `bpfman doctor checkup` output.
  Debugging concurrency bugs without that evidence is
  impossible.
