# BIG-OOPS

The bpfman daemon does not survive a restart cleanly. Two pieces of pure-process-memory state held by `platform/ebpf.kernelAdapter` -- forced by kernel ABI -- have no durable backing.

- `linkFds`: file descriptors for `perf_event_open`-based attachments (container uprobes). The attachment is alive only while *some* userspace process holds the FD. The kernel offers no way to pin perf_event-based handles in bpffs.
- `liveLinks`: `*link.Link` handles for tracepoint, k(ret)probe, u(ret)probe, fentry, fexit. These are bpffs-pinnable, but kernel cleanup does not run `perf_event_free_bpf_prog` until the userspace `link.Link` is closed. See `docs/DETACH-DOES-NOT-STOP-PROGRAM.md`.

## Why we can't just persist this in SQLite

Both are file descriptors. A file descriptor is a per-process integer index into the kernel's FD table; the integer means nothing in another process, and the kernel object the FD references is released when the original process exits. Writing FD=42 to SQLite and reading it back after a restart gives you the integer 42, which is meaningless.

For probe-style pinned links the DB already stores the pin path; what is missing on restart is the userspace `link.Link` object. We could reconstruct it at startup via `link.LoadPinnedLink(path)` from cilium/ebpf -- the kernel object survives in bpffs, only the Go-side handle is gone.

For container uprobes there is no path at all -- perf_event-based attachments cannot be pinned in bpffs, so there is nothing to load from. The only way to keep these alive across a daemon restart is to hand the FDs to a supervisor process via `SCM_RIGHTS`, or to lobby upstream to expose pinning for perf_event-based BPF links.

## What breaks on `systemctl restart bpfman` (or pod restart, or crash)

- **Container uprobes** silently tear down. No log, no signal, no reattachment unless an external reconciler (operator/agent) does it.
- **Probe-style pinned links** (tracepoint, k(ret)probe, u(ret)probe, fentry, fexit) become orphaned in the kernel. The bpffs pin still exists; a subsequent detach removes the pin; but the kernel-side program is not released because nothing closes the `link.Link` the dead daemon held. The leak persists until reboot.
- **XDP / TC / TCX** -- unaffected. The bpffs pin alone is sufficient teardown.

## What might fix it (roughly easiest first)

1. At startup, scan bpffs for probe-type pins and re-acquire `link.Link` handles via `link.LoadPinnedLink`. Populates `liveLinks` so post-restart detach correctly releases kernel objects. Container uprobes still die on restart, but the orphan-leak class of bugs goes away.
2. Supervisor process pattern for container uprobes: a small, never-restarted process holds the perf_event FDs and hands them back to the daemon via `SCM_RIGHTS` on each daemon start.
3. Upstream kernel work to expose pinning for perf_event-based BPF attachments.
