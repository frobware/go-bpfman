# CLI Ergonomics: Tracepoint Attach

This document records the first round of CLI ergonomics work on the
tracepoint attach path. It captures what was changed, why those
choices were made, and what related work remains.

## What Triggered the Change

Two recurring sources of friction for users attaching to tracepoints:

1. The CLI required them to restate the subcommand name:

        sudo bpfman link attach tracepoint --tracepoint sched/sched_switch 2907

    The `--tracepoint` flag adds no information beyond the `tracepoint`
    subcommand itself.

2. The value they pass is often not the same as the `SEC(...)` string
    in their BPF object file. A common example is an object with
    `SEC("tracepoint/syscalls/sched_switch")` where the real kernel
    tracepoint path is `sched/sched_switch` --- the ELF section name
    is an auto-attach hint that libbpf treats as best effort, and when
    the hint lies the kernel rejects the attach with an opaque `no
    such file or directory` error with no easy way to tell why.

Both problems sit at the CLI boundary. The first is pure noise in the
command shape. The second is a missing validation that the domain
layer is perfectly placed to provide. Fixing them together made for a
coherent slice of work.

## What Shipped (Tier 1)

Five commits on the `cli-tracepoint-positional` branch:

1. **`cli: take tracepoint group/name as a positional argument`**
   Dropped the redundant `--tracepoint` flag. Introduced a
   `TracepointName` type in `cmd/bpfman/types.go` with a
   `ParseTracepointName` parser that validates shape only (non-empty
   group and name, exactly one slash, no whitespace) and wired it
   through a Kong mapper so the CLI accepts the path as a positional
   argument after the program ID. The REPL parser in
   `cmd/bpfman/command.go` and all tracked `.bpfman` scripts were
   updated to the positional form.

2. **`go.mod: drop the patch component from the go directive`**
   Unrelated normalisation surfaced by the nix toolchain; kept as a
   separate commit so the CLI change is reviewable on its own.

3. **`platform: expose tracepoints via a TracepointLister interface`**
   Added a `TracepointLister` interface in `platform/interfaces.go`
   with a single `ListTracepoints(ctx) ([]string, error)` method, and
   added it to the `KernelOperations` aggregate so it rides the same
   adapter as the existing kernel operations. The real implementation
   in `platform/ebpf/tracepoint.go` globs the `id` files under
   `/sys/kernel/tracing/events/` and returns sorted `group/name`
   strings. The fake kernel used by manager tests returns an empty
   slice by default (the "cannot validate" branch of the contract),
   and the stub used by executor tests panics in line with its
   siblings.

4. **`manager: validate tracepoints before hitting the kernel`**
   Added a pre-flight check in `manager.attachTracepoint` that calls
   the new interface and rejects absent tracepoints with
   `bpfman.ErrTracepointNotFound` before any kernel work begins. An
   empty list from the kernel side is treated as "cannot validate"
   and the attach is allowed to proceed, preserving the behaviour of
   existing manager tests that do not stage a list. Retired the
   previous post-hoc rewrite logic (`validateTracepoint`,
   `tracepointExists`, `isTracepointNotFoundError`, and the
   package-local `ErrTracepointNotFound`) from `platform/ebpf`.

5. **`manager: suggest nearest tracepoints in ErrTracepointNotFound`**
   Added a `Suggestions []string` field to the error, populated with
   up to three nearest matches by a hand-rolled Levenshtein distance.
   The helpers live in `manager/suggest.go` and have standalone unit
   tests covering empty-string boundaries, single-edit primitives,
   pure insertions and deletions, case sensitivity, transpositions,
   multi-byte runes, disjoint strings, large shared prefixes and
   suffixes, the lexicographic tie-break, and the distance cap; a
   triangle-inequality property check exercises the metric over a
   handful of realistic inputs. No external library was pulled in.

End-to-end, a mistyped path such as

    sudo bpfman link attach tracepoint 2907 syscalls/sched_switch

now fails pre-flight with

    tracepoint "syscalls/sched_switch" not found; did you mean: sched/sched_switch?

## Design Choices and Why

A handful of decisions are worth recording because they are easy to
second-guess without the context.

**Positional argument, not a flag.** The subcommand already names the
kind of attach. Repeating it in a required flag adds nothing; dropping
it makes the command read like ordinary English.

**Shape validation at the CLI, existence validation in the manager.**
The CLI knows the argument is a string of the form `group/name` and
can reject anything that is not, using the same Kong mapper pattern as
`ProgramID`, `LinkID`, and `ProgramSpec`. Existence, on the other
hand, depends on the kernel running the daemon. In the eventual
RPC-split deployment, the daemon is the authority and a client-side
tracefs read would be actively wrong. Pre-flight therefore lives in
`manager.attachTracepoint`, where the same kernel abstraction that
will do the attach is also available for the existence check.

**A typed error with structured suggestions.** `bpfman.ErrTracepointNotFound`
carries `Group`, `Name`, and `Suggestions []string`. The default
`Error()` renders suggestions inline so any consumer sees the "did you
mean" hint without special handling. The typed fields are there so a
caller that wants to format suggestions differently (a TUI, a
machine-readable API response) can reach for them without parsing the
message.

**No inference from the BPF object's `SEC(...)` hint.** The original
confusion that prompted this work came from exactly that hint being
wrong. Tracepoint is the one case where the hint lies most often,
because every BPF tutorial seems to copy the wrong category string
from another. We deliberately rely on the user supplying the real
tracepoint path and let pre-flight catch mistakes. If we ever want to help the user more
here, the natural place would be to surface the ELF hint in the load
output, not to silently use it as an attach default.

**Interface over free function for `ListTracepoints`.** Early drafts
had a bare helper in `kernel/`. The repository's convention is that
kernel-facing I/O sits behind interfaces in `platform/`, with real,
fake, and panic-stub implementations. Introducing
`TracepointLister` lets manager-level tests stage a canned list via
the fakeKernel, and makes future additions (Damerau-Levenshtein,
caching, remote lookup) a single-file change.

**Hand-rolled Levenshtein.** About thirty lines of plain dynamic
programming, no allocation in the hot path beyond two scratch slices.
The only reason to reach for a library here is if we grow much
richer string-similarity needs; at that point the library choice
becomes a proper trade-off. For three-word "did you mean" hints over
a list of a few thousand tracepoints, the trade-off favours owning
the code.

## What Was Explicitly Out of Scope

**A `bpfman map` subtree.** A related question that surfaced
alongside the tracepoint ergonomics work was how to see the state of
a map. The answer today is `bpftool map show`; bpfman does not expose
map inspection and adding it is a real feature, not an ergonomics
tweak. It should land on a separate branch when we decide it is worth
doing.

**Changes to fentry/fexit attach.** These already take no target
argument at all because the attach function is baked into the BPF
object at load time. That asymmetry (tracepoint requires a target,
fentry/fexit do not) is worth revisiting, but only in the context of
the wider attach-family reshape below.

**`.bpfman` scripts outside the repo.** Only tracked scripts were
updated. The author's untracked scratch files were edited on disk to
keep them working but not staged.

## Remaining Tiers

The tier labels come from the original scoping conversation that
preceded this work.

### Tier 2: Consistent Positionals Across the Attach Family

The same redundancy the tracepoint command suffered from exists
across the rest of the attach subcommands. Every entry in
`cmd/bpfman/attach.go:AttachCmd` except `fentry` and `fexit` has at
least one required flag that is really the defining identifier for
the attach:

| Subcommand  | Current required flag(s)              | Positional candidate             |
|-------------|----------------------------------------|----------------------------------|
| `xdp`       | `--iface`                              | `<iface>`                        |
| `tc`        | `--iface`, `--direction`               | `<iface> <direction>`            |
| `tcx`       | `--iface`, `--direction`               | `<iface> <direction>`            |
| `kprobe`    | `--fn-name`                            | `<fn-name>`                      |
| `uprobe`    | `--target` (+ optional `--fn-name`)    | `<target>` (flag stays optional) |
| `fentry`    | (none; attach function baked into ELF) | no change                        |
| `fexit`     | (none; attach function baked into ELF) | no change                        |

Each move repeats the tracepoint recipe: a typed wrapper in
`types.go`, a Kong mapper, and a positional argument on the
subcommand struct. The REPL parser needs the corresponding update.
Where a subcommand has multiple required identifiers (`tc`, `tcx`),
positional order should read naturally; `<iface> <direction>` is
fine, beyond two positionals flags regain the upper hand.

Out of this work a small opportunity opens up: each of these
identifiers has a natural existence check too (network interface for
xdp/tc/tcx, kernel symbol for kprobe, file path for uprobe). Those
can follow the tracepoint pre-flight pattern, with a new
`KernelSymbolLister` or similar interface. Whether to do them in one
branch or split per kind depends on review appetite.

### Tier 3: Reshape to `bpfman <kind> attach <id>`

Today the command tree is resource-first: `bpfman program
load|unload|list|get|delete`, `bpfman link attach <kind>|detach|list|
get|delete`, `bpfman dispatcher list|get`. The `link` node holds
eight attach subcommands (one per hook kind) plus the generic
detach/list/get. A kind-first reshape would push the hook kind up
one level:

    bpfman tracepoint attach 2907 sched/sched_switch
    bpfman xdp attach 2907 eth0 --priority 50
    bpfman kprobe attach 2907 do_sys_open

and make discovery via `--help` sharper: `bpfman tracepoint --help`
would show everything you can do with tracepoints, instead of the
user having to know the verb lives under `link`. It also lets the
kind-specific flags move to where the kind is named, which is
hard to argue with.

There are real trade-offs though. `link list` and `link detach` are
naturally generic today (they operate across all hook kinds); a
kind-first tree either duplicates them under every kind or keeps a
separate `bpfman link list` alongside the kind-first attach
commands, which is the worst of both. The blast radius is larger
than Tier 2: every doc, every `.bpfman` script, `examples.go`, and
quite possibly the gRPC surface in `bpfman/internal/server/`. No
user has asked for it. It wants its own branch and a deliberate
decision about when to take the churn.

### Explicitly Not Planned

**A `bpfman map` subtree.** Kept as a separate future feature, as
noted above.

**Replacing the CLI framework.** Kong is working well enough; there
is no itch to move to cobra, urfave/cli, or anything else.

## Running the New Behaviour

Quick sanity check (needs root and a kernel with tracefs mounted):

    sudo bpfman program load file --path e2e/testdata/bpf/tracepoint_counter_pinned.bpf.o \
        --programs tracepoint:tracepoint_kill_recorder

    # Happy path:
    sudo bpfman link attach tracepoint <prog-id> syscalls/sys_enter_kill

    # Original confusion --- the ELF section name is not the real
    # tracepoint path. Now rejected at the CLI parser before the
    # daemon is even invoked:
    sudo bpfman link attach tracepoint <prog-id> tracepoint/syscalls/sys_enter_kill
    # => invalid tracepoint "tracepoint/syscalls/sys_enter_kill": expected group/name (only one '/' allowed)

    sudo bpfman link attach tracepoint <prog-id> syscalls/sched_switch
    # => tracepoint "syscalls/sched_switch" not found; did you mean: sched/sched_switch?

`tracepoint-cli.bpfman` at the repo root exercises the shape-level
validation end to end under the REPL and can be extended to cover the
kernel-side path once someone runs it with root.
