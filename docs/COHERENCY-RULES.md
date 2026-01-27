# Coherency Rules

This document enumerates every coherency rule enforced by `bpfman
doctor` and `bpfman gc`. Each rule cross-references two of the three
state sources (database, kernel, filesystem) and specifies what
constitutes a violation.

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

## Doctor Rules (read-only checks)

### DB vs Kernel

| # | Scope | Predicate | Severity | Exceptions |
|---|-------|-----------|----------|------------|
| D1 | Each DB program | Kernel program with matching ID exists | ERROR | None |
| D2 | Each DB link | Kernel link with matching ID exists | ERROR | Synthetic link IDs (>= 0x80000000) are skipped |
| D3 | Each DB dispatcher | Kernel program with matching KernelID exists | ERROR | None |
| D4 | Each XDP dispatcher with LinkID != 0 | Kernel link with matching LinkID exists | ERROR | None |
| D5 | Each TC dispatcher with Priority > 0 | TC filter exists at (ifindex, parent, priority) | ERROR | None |

### DB vs Filesystem

| # | Scope | Predicate | Severity | Exceptions |
|---|-------|-----------|----------|------------|
| D6 | Each DB program with PinPath | `os.Stat(PinPath)` succeeds | WARNING | None |
| D7 | Each DB link with PinPath | `os.Stat(PinPath)` succeeds | WARNING | Synthetic link IDs skipped |
| D8 | Each DB dispatcher | Prog pin exists at `{type}/dispatcher_{nsid}_{ifindex}_{revision}/dispatcher` | WARNING | None |
| D9 | Each XDP dispatcher | Link pin exists at `{type}/dispatcher_{nsid}_{ifindex}_link` | WARNING | None |

### Filesystem vs DB (orphan detection)

| # | Scope | Predicate | Severity | Exceptions |
|---|-------|-----------|----------|------------|
| D10 | Each `prog_*` entry in bpffs root | Matching DB program exists (by pin path) | WARNING | None |
| D11 | Each numeric directory in `fs/links/` | Matching DB program exists (by kernel ID) | WARNING | None |
| D12 | Each numeric directory in `fs/maps/` | Matching DB program exists (by kernel ID) | WARNING | None |
| D13 | Each `dispatcher_{nsid}_{ifindex}_{rev}` directory | Matching DB dispatcher exists (by type, nsid, ifindex) | WARNING | None |

### Derived State Consistency

| # | Scope | Predicate | Severity | Exceptions |
|---|-------|-----------|----------|------------|
| D14 | Each DB dispatcher | `CountDispatcherLinks(KernelID)` equals count of `link_*` files in revision directory | WARNING | None |

## GC Rules (store layer)

These rules are enforced by `store.GC()` which receives the set of
kernel program IDs and kernel link IDs gathered by the manager.

| # | Scope | Condition | Action |
|---|-------|-----------|--------|
| G1 | Each DB program | Kernel program ID not in kernel set | Delete program from DB (dependents first, then owners) |
| G2 | Each DB dispatcher | KernelID not in kernel program set | Delete dispatcher from DB |
| G3 | Each DB link | Kernel link ID not in kernel set | Delete link from DB |
| G3a | Each DB link | Link ID is synthetic (>= 0x80000000) | Skip — synthetic links are not enumerable via kernel iterator |
| G4 | Each surviving dispatcher (after G3) | `CountDispatcherLinks` returns 0 | Delete dispatcher from DB |
| G4a | G4 guard | Only runs when G3 removed at least one link | — |

## GC Rules (manager layer, post-store)

These rules run after the store GC and have access to the
filesystem. They handle dispatchers that the store GC cannot catch
because the kernel program still exists.

| # | Scope | Condition | Action |
|---|-------|-----------|--------|
| G5 | Each surviving dispatcher with 0 extension links | Prog pin does not exist on filesystem | Delete dispatcher from DB; remove filesystem artefacts |
| G6 | Each surviving TC dispatcher with 0 extension links and prog pin present | TC filter does not exist at (ifindex, parent, priority) | Delete dispatcher from DB; remove filesystem artefacts (prog pin, revision dir) |
| G7 | Each surviving XDP dispatcher deleted by G5/G6 | — | Also remove link pin at `{type}/dispatcher_{nsid}_{ifindex}_link` |

## GC Rules (orphan filesystem cleanup)

These rules run after the store and dispatcher GC phases. They
remove filesystem artefacts that have no corresponding DB record
and no live kernel object. An orphan is only removed when both
conditions hold: not in the DB AND not in the kernel.

| # | Scope | Condition | Action |
|---|-------|-----------|--------|
| G8 | Each `prog_*` entry in bpffs root | No matching DB program (by pin path) AND kernel program ID not alive | Remove pin |
| G9 | Each numeric directory in `fs/links/` | No matching DB program (by kernel ID) AND kernel program ID not alive | Remove directory and contents |
| G10 | Each numeric directory in `fs/maps/` | No matching DB program (by kernel ID) AND kernel program ID not alive | Remove directory and contents |
| G11 | Each `dispatcher_{nsid}_{ifindex}_{rev}` directory | No matching DB dispatcher (by type, nsid, ifindex) | Remove directory and contents |
| G12 | Each `dispatcher_{nsid}_{ifindex}_link` file | No matching DB dispatcher (by type, nsid, ifindex) | Remove file |

## Known Gaps

### Not yet checked by doctor

- **Kernel to DB**: kernel programs or links that exist but are not
  tracked in the DB. This would detect programs loaded by bpfman
  that lost their DB record (e.g., DB corruption or manual DB
  editing). Distinguishing bpfman-managed programs from unrelated
  kernel programs is the challenge — we would need to filter by pin
  path prefix or program name convention.

## Design Notes

All doctor rules are read-only. They gather facts from the three
sources and evaluate predicates, but never mutate state. GC rules
are the action counterpart: they apply the same predicates but
delete the violating records.

Synthetic link IDs (rules D2, G3a) exist because perf_event-based
attachments (container uprobes) do not create kernel BPF links.
They use a generated ID in the range 0x80000000-0xFFFFFFFF to
avoid collision with real kernel link IDs. These must be excluded
from any check that enumerates kernel links.

The TC filter check (rules D5, G6) is specific to legacy TC
dispatchers that use netlink rather than BPF links. The TC filter
is the mechanism that routes packets to the dispatcher program.
Without it, the program is loaded but inert. XDP dispatchers use
BPF links instead, so their liveness is covered by the kernel link
check (rule D4).
