# bpfman-ns: Namespace Helper Subprocess

`bpfman-ns` is a helper mode used for namespace-sensitive operations
(uprobes in containers today, potentially more in future). It is
invoked as a child subprocess, not a process replacement.

See [LOCKING.md](LOCKING.md) for the full global writer lock design.

---

## What happens on `bpfman attach ... (uprobe)`

1. **CLI process starts** (this is the "parent").
2. It acquires the **global writer lock** (`/run/bpfman/.lock`).
3. It loads the pinned BPF program (or otherwise arranges a program fd).
4. It creates a **socketpair** for fd passing.
5. It **spawns a child subprocess** by execing the same binary with args
   like `bpfman-ns uprobe ...`, plus:

   * `ExtraFiles[0]` → program fd (child sees it as fd 3)
   * `ExtraFiles[1]` → socket fd (child sees it as fd 4)
   * `ExtraFiles[2]` → writer-lock fd (proof of active WriterScope)
   * `BPFMAN_MODE=bpfman-ns` (tells child it is in helper mode)
   * `BPFMAN_WRITER_LOCK_FD=5` (tells child which fd holds the lock)

6. **Child starts**. Before Go runtime, the CGO constructor does
   `setns()` into the target mount namespace.
7. **Child verifies lock**. Reads `BPFMAN_WRITER_LOCK_FD`, constructs an
   `InheritedLock`, and confirms the fd holds the exclusive lock via
   `flock(LOCK_EX|LOCK_NB)`. If verification fails, exits immediately
   with error. (Note: this verifies that the helper *holds* the lock,
   not that the parent acquired it earlier; parent-side locking is
   enforced by the type system. If the parent passed an unlocked fd and
   the lock is uncontended, the helper will acquire it - still correct.)
8. Child uses the inherited **program fd** to attach the uprobe in that
   namespace (so the target binary path resolves correctly).
9. Child sends the resulting **link/perf_event fd back** to the parent
   over the socket (`SCM_RIGHTS`), prints "ok", and exits.
10. Parent receives the fd and **stores it in `k.linkFds`** to keep the
    attachment alive (since perf_event uprobes often can't be pinned).
11. Parent persists metadata to SQLite.
12. Parent releases the global writer lock.

Key points:

* The **child** does the namespace-sensitive part.
* The **parent** owns the lifetime of the attachment, because it holds
  the returned fd open.
* The parent *cannot* die early, or you lose the attachment immediately
  (the perf_event fd closes with the process, detaching the uprobe).
* The **lock is held by both** parent and child (via duped fd) for the
  duration of the operation.

---

## Fork+exec, Not Process Replacement

In Unix terms, "re-exec" can mean either:

* `execve()` in-place (process image replaced, original process ends), or
* `fork+exec` (spawn a subprocess, parent continues)

bpfman-ns uses the second form. The parent waits for the child to
complete and receives results via IPC (the socketpair).

If we used in-place exec, we'd lose the ability to return cleanly to
the CLI caller and would need the new process to handle database writes.

---

## Locking Requirements for bpfman-ns

The helper **inherits and verifies** the global writer lock. It never
acquires the lock itself. The helper never receives a pointer or handle
to the lock; it receives only a duplicated file descriptor that proves
the lock is already held. It verifies this fd before performing any
operation.

**Mandatory**: If `BPFMAN_WRITER_LOCK_FD` is missing or the fd does not
hold the lock, the helper must exit immediately with an error. There is
no "proceed without lock" fallback.

**Why?** Even though the parent waits, lock inheritance protects against:

1. **Failure window**: If the parent is killed after spawning but before
   the child completes, the child's copy of the lock fd keeps other
   writers blocked until it exits.

2. **Future safety**: If someone adds filesystem or database operations
   to bpfman-ns later, they're automatically protected because the lock
   is already required.

See [LOCKING.md](LOCKING.md) for the full design and rationale.
