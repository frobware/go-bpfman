# Global Writer Lock for bpfman State

## Background

`bpfman` manages host-local state rooted at:

```
/run/bpfman/...
```

This includes:

* bpffs pins (programs, links, dispatchers)
* SQLite database records
* staging / scratch directories
* long-lived kernel objects whose lifetime is coordinated via filesystem
  pins and database entries

Historically, this state was mutated by a single long-running daemon.
That assumption is no longer valid.

---

## Current and Near-Term Execution Model

There are **multiple concurrent entrypoints** capable of mutating the
same state:

1. **CLI invocations**
   `bpfman load`, `bpfman attach`, `bpfman gc`, etc.

2. **The gRPC server (`bpfman serve`)**
   Still required for compatibility (CSI, operator integration),
   but **temporary**.

3. **Helper subprocesses (`bpfman-ns`)**
   Spawned by both CLI and server to perform namespace-sensitive kernel
   operations (uprobes today, potentially more in future). These are
   **child processes** (fork+exec), not process replacements. The parent
   waits for the helper to complete and receives results via IPC.

These processes may run **concurrently on the same node**.

---

## The Core Problem

Without coordination, concurrent writers can interleave operations such
as:

* pinning/unpinning links in bpffs
* attaching kernel programs while DB writes race
* GC removing filesystem entries while another process is mid-attach
* helper processes mutating state while a parent exits

SQLite’s internal locking **is insufficient**, because:

* it only serialises DB access
* it does not cover kernel operations
* it does not cover bpffs or filesystem layout

We need **cross-process, cross-resource serialisation**.

---

## Design Goals

The locking design must be:

* **Correct** across multiple processes
* **Safe across exec/re-exec**
* **Obvious and hard to misuse**
* **Enforced structurally**, not by convention
* Compatible with the **temporary server**, without baking in server-only
  assumptions

---

## Chosen Design: Global Writer Lock with FD Inheritance (Option D)

We adopt a **single global advisory writer lock** protecting all
mutations of `/run/bpfman/...`.

Abbreviation: **BGL** = bpfman global writer lock.

### Key properties

* Implemented using `flock(2)` on a lock file:

  ```
  /run/bpfman/.lock
  ```
* The lock is **held for the entire duration of a mutating operation**:
  kernel I/O + filesystem changes + database writes.
* The lock is **passed across exec boundaries** by passing the locked
  file descriptor to helper processes.
* Helpers **do not attempt to acquire the lock themselves**. They must
  inherit and verify it.

This is a well-established Unix pattern and avoids deadlock hazards while
making misuse difficult.

---

## Why FD Passing Is Required

A naïve design where helpers "just reacquire the lock" fails:

* If the parent already holds the lock, the helper deadlocks.
* If the parent releases first, there is a race window.
* If helpers sometimes lock and sometimes don't, correctness depends on
  undocumented conventions.

Passing the **already-held lock fd** into the helper:

* Preserves atomicity across exec
* Avoids deadlock
* Makes future helper filesystem writes safe by construction

### Why inheritance matters even though the parent waits

In normal operation, the parent holds the lock and waits for the helper
to complete. So why bother passing the lock fd?

**Failure window protection.** If the parent is killed (SIGKILL, OOM,
panic) after spawning the helper but before the helper completes:

* Without inheritance: parent dies → lock fd closes → lock releases →
  another writer acquires → helper is still running → two writers
  interleave → state corruption.

* With inheritance: parent dies → helper still holds lock via duped fd →
  other writers blocked → helper finishes or fails → lock releases →
  state remains consistent.

**Future footgun prevention.** If someone adds filesystem or pin
operations to `bpfman-ns` and forgets "this must run under the lock",
the code will fail immediately because the helper refuses to run without
an inherited lock. The invariant is enforced structurally, not by
developer memory.

---

## Lock Semantics

### Writer Lock

* Exactly one writer at a time per host.
* Advisory (cooperative), process-local to the host.
* Lifetime is the lifetime of the **open file description**.
* Closing the last fd releases the lock.

### Failure semantics

* If the parent process dies, the helper still holds the lock.
* Other processes remain blocked until the helper exits.
* When the helper exits, the lock is released.

This behaviour is **intentional and correct**.

---

## Context Cancellation and UX

Lock acquisition is **context-aware**:

* Uses `LOCK_EX | LOCK_NB` with retry loop
* Aborts on `ctx.Done()`
* CLI can add `--lock-timeout` by setting a context deadline
* Ctrl-C is a valid escape hatch

No unkillable hangs.

---

## Lock Ordering Rule

> **The global writer lock is always outermost.**

Ordering is:

1. Global writer lock (`flock`)
2. In-process mutexes (`sync.Mutex`, `sync.RWMutex`)
3. SQLite transactions, kernel ops, filesystem changes

Each mutex must document its place in the hierarchy.

---

## Structural Enforcement (“Illegal States Unrepresentable”)

### Rule 1: All mutators require a `*lock.Writer`

Any function that may mutate `/run/bpfman/...` **must accept a writer
lock parameter**.

This includes:

* Manager attach/load/unload/GC methods
* Kernel adapter attach/detach methods
* Any future helper-invoked filesystem operations

If you don’t have a `*lock.Writer`, you **cannot call** these methods.

---

### Rule 2: Helpers inherit and verify, never acquire

Three distinct operations:

* **Acquire**: take the lock (blocking/retry until held). Only the
  parent does this.
* **Inherit**: receive an already-held lock fd via `ExtraFiles`. The
  helper does this.
* **Verify**: confirm the inherited fd actually holds the lock. The
  helper does this immediately on startup.

Helpers refuse to operate unless:

* a writer lock fd is provided via environment (`BPFMAN_WRITER_LOCK_FD`)
* that fd actually holds the exclusive lock (verified via non-blocking
  `flock(LOCK_EX|LOCK_NB)`)

**There is no fallback.** If the lock fd is missing or invalid, the
helper exits immediately with an error. There is no "proceed without
lock" path. This makes accidental unlocked execution unrepresentable.

---

## Code Sketches

### Lock acquisition (context-aware)

```go
type Writer struct {
	f *os.File
}

// AcquireWriter opens (or creates) the lock file and acquires an
// exclusive advisory lock. The lock is held until Close() is called.
//
// Acquisition respects context cancellation, allowing CLI commands to
// be interrupted with Ctrl-C rather than hanging indefinitely.
func AcquireWriter(ctx context.Context, path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	backoff := 25 * time.Millisecond
	const maxBackoff = 500 * time.Millisecond

	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &Writer{f: f}, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, fmt.Errorf("flock: %w", err)
		}

		// Another process holds the lock. Wait and retry.
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

func (w *Writer) FD() uintptr { return w.f.Fd() }

func (w *Writer) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	return w.f.Close()
}
```

---

### Passing the lock to a helper

```go
// Define fd layout explicitly to avoid off-by-one errors.
const (
	ChildFDBase       = 3 // ExtraFiles[0] becomes fd 3 in child
	ChildFDProg       = ChildFDBase + iota
	ChildFDSocket
	ChildFDWriterLock
)

// Duplicate the lock fd for the child.
//
// flock locks are associated with the open file description. Dup()
// creates a new fd referring to the same open file description, so
// both parent and child can close independently while the lock
// remains held until the last fd is closed.
dup, err := syscall.Dup(int(w.FD()))
if err != nil {
	return fmt.Errorf("dup writer lock fd: %w", err)
}
lockFile := os.NewFile(uintptr(dup), "bpfman-writer-lock")
defer lockFile.Close() // Close parent's dup after child starts

cmd.ExtraFiles = []*os.File{
	progFile,   // ChildFDProg (fd 3)
	socketFile, // ChildFDSocket (fd 4)
	lockFile,   // ChildFDWriterLock (fd 5)
}
cmd.Env = append(cmd.Env,
	fmt.Sprintf("BPFMAN_WRITER_LOCK_FD=%d", ChildFDWriterLock))
```

---

### Helper verification

```go
const envVar = "BPFMAN_WRITER_LOCK_FD"

s := os.Getenv(envVar)
if s == "" {
	return fmt.Errorf("%s not set: helper must be spawned with lock fd", envVar)
}

fd, err := strconv.Atoi(s)
if err != nil || fd < 0 {
	return fmt.Errorf("invalid %s=%q", envVar, s)
}

f := os.NewFile(uintptr(fd), "bpfman-writer-lock")
if f == nil {
	return fmt.Errorf("failed to create file from fd %d", fd)
}

// Verify we actually hold the lock.
//
// A non-blocking exclusive flock on an fd that already holds the lock
// succeeds immediately. If this fails, the parent passed the wrong fd
// or did not acquire the lock.
//
// NOTE: flock cannot distinguish "already held via inherited fd" from
// "just acquired because uncontended". This is acceptable:
// - parents MUST acquire before spawning (enforced by type system)
// - helpers must hold the lock regardless of how they got it
if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
	f.Close()
	return fmt.Errorf("fd %d does not hold writer lock: %w", fd, err)
}

// Keep f open for the lifetime of the helper to maintain the lock.
defer f.Close()
```

---

## Concrete Example: Uprobe Attachment Flow

This illustrates the complete locking flow for a container uprobe, which
requires a helper subprocess.

1. **CLI acquires lock.** `bpfman attach uprobe ...` calls
   `lock.AcquireWriter()` before any mutation.

2. **CLI invokes manager.** Passes `*lock.Writer` to
   `manager.AttachUprobe()`.

3. **Manager invokes kernel adapter.** Passes lock to
   `kernel.AttachUprobe()`.

4. **Kernel adapter spawns helper.** For container uprobes:
   * Creates socketpair for fd passing (link fd will come back this way)
   * Dups the lock fd for the child
   * Sets up `ExtraFiles`: program fd (3), socket fd (4), lock fd (5)
   * Sets `BPFMAN_WRITER_LOCK_FD=5`
   * Execs `bpfman-ns uprobe ...`

5. **Helper starts.** CGO constructor calls `setns()` into target mount
   namespace before Go runtime starts.

6. **Helper verifies lock.** Reads `BPFMAN_WRITER_LOCK_FD`, calls
   `flock(LOCK_EX|LOCK_NB)` to confirm lock is held. If not, exits with
   error.

7. **Helper attaches uprobe.** Uses inherited program fd to attach in
   the container's namespace context.

8. **Helper sends link fd back.** Sends the resulting perf_event/link fd
   to parent via `SCM_RIGHTS` over the socket, prints "ok", exits.

9. **Parent receives fd.** Stores it in `k.linkFds` to keep the
   attachment alive (perf_event uprobes often cannot be pinned to bpffs).

10. **Parent commits to database.** Writes metadata to SQLite.

11. **Parent releases lock.** `w.Close()` releases the global lock.

Throughout this flow:

* The parent holds the lock from step 1 to step 11.
* The helper holds a duped copy from step 5 to step 8.
* If the parent dies at any point after step 4, the helper's copy keeps
  the lock held until step 8.
* No other writer can interleave.

---

## The gRPC Server (Short-Term but Must Obey the Rules)

Although `bpfman serve` is temporary, **it must obey the same locking
rules**, because:

* it mutates the same state
* it can run concurrently with the CLI
* it spawns `bpfman-ns`, which may mutate state in future

### Server strategy

* Acquire writer lock **per mutating request** via a gRPC interceptor
* Store the lock in request context
* Extract and pass it explicitly to manager/kernel code
* Helpers inherit the lock via fd passing, exactly as in CLI flows

The interceptor acquires and releases the writer lock **around the
entire handler**, not just the manager call. This ensures helpers
spawned during request handling inherit the lock.

### Why per-request?

* Avoids blocking the CLI for the lifetime of the server
* Matches the future “CLI-only” world
* Makes server removal trivial: delete the interceptor

---

## Interaction with SQLite

SQLite locking remains in place and unchanged.

The global writer lock sits **above** SQLite and provides:

* atomicity across DB + kernel + filesystem
* a single serialisation point for all writers

SQLite alone cannot provide this.

---

## Read-Only Operations

Read-only commands (`bpfman list`, `bpfman get`, etc.) **do not acquire
the writer lock**. They observe eventually-consistent state.

If a read spans multiple resources (e.g., database query then pin check)
and a write interleaves, the read may see partial state. This is
acceptable for CLI tooling; users can re-run the command.

If stronger consistency is required in future, a reader lock
(`LOCK_SH`) can be added without changing the writer design.

---

## Lock File Notes

**Stale lock files are harmless.** If a process crashes while holding
the lock, the kernel closes its file descriptors, releasing the lock.
The lock file itself remains on disk. The next process opens it and
acquires a fresh lock. No cleanup is needed.

**Local filesystem required.** `flock` semantics are not reliable on
network filesystems (NFS, etc.). The lock file must reside on a local
filesystem. `/run` is typically `tmpfs`, which is correct.

---

## Audit Notes

* `sync.Map` usages (e.g. `k.linkFds`) must only be accessed while holding
  the global writer lock.
* No code may attempt to acquire the global lock while holding a local
  mutex.
* New helper subcommands **must** inherit the lock fd, even if they do
  not currently touch the filesystem.

---

## Summary

* Concurrent mutation of `/run/bpfman/...` is real and unavoidable today.
* The server, though temporary, must participate fully in locking.
* A single global writer lock with fd inheritance:

  * solves cross-process coordination
  * is re-exec safe
  * avoids deadlocks
  * is enforceable in code
* The design scales cleanly into a future where the server disappears and
  only the CLI remains.

**This is the locking model going forward.**
