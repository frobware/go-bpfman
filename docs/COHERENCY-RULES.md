# Coherency Rules

All coherency rules are comparisons between sources; no rule
inspects a single source in isolation. This document enumerates
every coherency rule enforced by `bpfman doctor` and `bpfman gc`.
Each rule cross-references two of the three state sources (database,
kernel, filesystem) and specifies what constitutes a violation.

Rule names match the `Name` field in the `Rule` struct in
`manager/coherency.go`. Rules are grouped by source comparison, not
by subsystem. Rule names are stable identifiers that may be consumed
programmatically by tooling.

## Notation

- **DB**: the SQLite database (programs, links, dispatchers)
- **Kernel**: BPF subsystem state (program IDs, link IDs, TC filters)
- **FS**: the bpffs filesystem under `/run/bpfman/fs/`

Severity levels:

- **ERROR**: the system is in an inconsistent state that affects
  correctness. A DB record references a kernel object that does not
  exist.
- **WARNING**: the system has stale artefacts that do not affect
  running programs but indicate incomplete cleanup. Orphan
  filesystem entries or missing pins.

## Dispatcher Invariants

A dispatcher is considered live if and only if:

- its kernel program exists, and
- it has at least one active attachment mechanism:
  - **XDP**: a kernel BPF link
  - **TC**: a netlink filter at the expected (ifindex, parent, priority)

A dispatcher with zero extension links and no active attachment
mechanism is functionally dead and eligible for GC, even if its
kernel program is still loaded.

## Doctor Rules (read-only checks)

### DB vs Kernel

| Rule | Scope | Predicate | Severity | Exceptions |
|------|-------|-----------|----------|------------|
| program-in-kernel | Each DB program | Kernel program with matching ID exists | ERROR | None |
| link-in-kernel | Each DB link | Kernel link with matching ID exists | ERROR | Synthetic link IDs (>= 0x80000000) are skipped |
| dispatcher-prog-in-kernel | Each DB dispatcher | Kernel program with matching KernelID exists | ERROR | None |
| xdp-link-in-kernel | Each XDP dispatcher with LinkID != 0 | Kernel link with matching LinkID exists | ERROR | None |
| tc-filter-exists | Each TC dispatcher with Priority > 0 | TC filter exists at (ifindex, parent, priority) | ERROR if extensions > 0, WARNING if 0 | None |

### DB vs Filesystem

| Rule | Scope | Predicate | Severity | Exceptions |
|------|-------|-----------|----------|------------|
| program-pin-exists | Each DB program with PinPath | `os.Stat(PinPath)` succeeds | WARNING | None |
| link-pin-exists | Each DB link with PinPath | `os.Stat(PinPath)` succeeds | WARNING | Synthetic link IDs skipped |
| dispatcher-prog-pin-exists | Each DB dispatcher | Prog pin exists at `{type}/dispatcher_{nsid}_{ifindex}_{revision}/dispatcher` | WARNING | None |
| xdp-link-pin-exists | Each XDP dispatcher | Link pin exists at `{type}/dispatcher_{nsid}_{ifindex}_link` | WARNING | None |

### Filesystem vs DB (orphan detection)

| Rule | Scope | Predicate | Severity | Exceptions |
|------|-------|-----------|----------|------------|
| orphan-fs-entries | Each `prog_*` entry in bpffs root | Matching DB program exists (by pin path) | WARNING | None |
| orphan-fs-entries | Each program ID directory in `fs/links/` | Matching DB program exists (by kernel ID) | WARNING | None |
| orphan-fs-entries | Each numeric directory in `fs/maps/` | Matching DB program exists (by kernel ID) | WARNING | None |
| orphan-fs-entries | Each `dispatcher_{nsid}_{ifindex}_{rev}` directory | Matching DB dispatcher exists (by type, nsid, ifindex) | WARNING | None |

### Derived State Consistency

| Rule | Scope | Predicate | Severity | Exceptions |
|------|-------|-----------|----------|------------|
| dispatcher-link-count | Each DB dispatcher | `CountDispatcherLinks(KernelID)` equals count of `link_*` files in revision directory | WARNING | None |

## GC Rules (store layer)

These rules are enforced by `store.GC()` which receives the set of
kernel program IDs and kernel link IDs gathered by the manager.
They are not part of the rule engine; they run as imperative code
in the store layer because they require transactional ordering
constraints (delete dependents before owners).

| Rule | Scope | Condition | Action |
|------|-------|-----------|--------|
| (store) | Each DB program | Kernel program ID not in kernel set | Delete program from DB (dependents first, then owners) |
| (store) | Each DB dispatcher | KernelID not in kernel program set | Delete dispatcher from DB |
| (store) | Each DB link | Kernel link ID not in kernel set | Delete link from DB |
| (store) | Each DB link | Link ID is synthetic (>= 0x80000000) | Skip — synthetic links are not enumerable via kernel iterator |
| (store) | Each surviving dispatcher (after link removal) | `CountDispatcherLinks` returns 0 | Delete dispatcher from DB |

## GC Rules (manager layer, post-store)

These rules run after the store GC via the coherency rule engine.
They handle dispatchers that the store GC cannot catch because the
kernel program still exists, and orphan filesystem artefacts.

| Rule | Scope | Condition | Action |
|------|-------|-----------|--------|
| stale-dispatcher | Each surviving dispatcher with 0 extension links | Prog pin missing or TC filter missing | Delete dispatcher from DB; remove filesystem artefacts (prog pin, revision dir, XDP link pin) |
| orphan-program-artefacts | Each orphan `prog_*` pin, `links/{id}` dir, `maps/{id}` dir | No matching DB record AND kernel program ID not alive | Remove pin or directory |
| orphan-dispatcher-artefacts | Each orphan `dispatcher_*` directory or link pin | No matching DB dispatcher (by type, nsid, ifindex) | Remove directory or file |

## Known Gaps

### Not yet checked by doctor

- **Kernel to DB**: kernel programs or links that exist but are not
  tracked in the DB. This would detect programs loaded by bpfman
  that lost their DB record (e.g., DB corruption or manual DB
  editing). Distinguishing bpfman-managed programs from unrelated
  kernel programs is the challenge — we would need to filter by pin
  path prefix or program name convention. Kernel objects not tracked
  in the DB are considered leaked or unmanaged, but not correctness
  failures (WARNING severity, not ERROR).

## Design Notes

All doctor rules are read-only. They gather facts from the three
sources and evaluate predicates, but never mutate state. GC rules
are the action counterpart: they apply the same predicates but
delete the violating records.

Synthetic link IDs (rule `link-in-kernel`) exist because
perf_event-based attachments (container uprobes) do not create
kernel BPF links. They use a generated ID in the range
0x80000000-0xFFFFFFFF to avoid collision with real kernel link IDs.
These must be excluded from any check that enumerates kernel links.

The TC filter check (rule `tc-filter-exists`) is specific to legacy
TC dispatchers that use netlink rather than BPF links. The TC filter
is the mechanism that routes packets to the dispatcher program.
Without it, the program is loaded but inert. XDP dispatchers use
BPF links instead, so their liveness is covered by the kernel link
check (rule `xdp-link-in-kernel`).
