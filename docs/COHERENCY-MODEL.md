# Coherency Model: Intent vs Reality

## At a Glance

- **Sources**: DB (intent), FS (pins), Kernel (reality)
- **Doctor**: detects violations (read-only)
- **GC**: deletes DB rows and filesystem artefacts
- **Manager GC**: handles cases store GC cannot see
- **Invariant**: DB intent must be satisfiable by kernel + filesystem

All coherency rules are comparisons between sources; no rule
inspects a single source in isolation.

## The Three Sources of State

bpfman maintains state in three places:

1. **Database** — records of intent. What was requested and why.
   User metadata, image source URLs, tags, global data overrides,
   attach specifications. None of this can be derived from the
   kernel or filesystem alone.

2. **Filesystem (bpffs)** — records of pinned existence. Program
   pins, link pins, dispatcher directories, extension link files.
   Convention-based paths encode identity (kernel ID, namespace,
   interface, revision).

3. **Kernel** — records of reality. Which programs are loaded, which
   links are active, which TC filters are installed. The kernel is
   the ultimate authority on what is actually running.

Every coherency problem in bpfman arises from these three sources
disagreeing.

## Current Architecture

The current doctor and GC implementations are hand-written
imperative phases that cross-reference pairs of sources:

- DB vs kernel: does every DB record have a corresponding kernel
  object?
- DB vs filesystem: does every DB record have its expected pins?
- Filesystem vs DB: are there orphan pins with no DB record?
- Kernel vs DB: are there kernel objects we don't track?
- Internal consistency: do derived counts (e.g., dispatcher link
  count) match filesystem state?

Each check is a bespoke loop with ad-hoc conditions. Adding a new
check means writing another nested if block. The checks for doctor
(read-only reporting), GC (deletion), and reconciliation (repair)
share the same predicates but differ only in their response.

## Observation: This Is a Constraint System

The checks are not really procedural logic. They are declarative
constraints over gathered facts:

```
for each db.program:
  require kernel.program(id) exists        -> ERROR if absent
  require fs.pin(pin_path) exists          -> WARNING if absent

for each fs.prog_pin:
  require db.program(id) exists            -> WARNING if orphan

for each db.dispatcher where link_count == 0:
  require fs.prog_pin exists               -> stale if absent
```

Each constraint has:
- A **scope**: which facts it iterates over
- A **predicate**: a condition that must hold
- A **severity**: what it means when the predicate fails
- A **category**: for grouping in output

Doctor, GC, and reconciliation are the same engine with different
action sets. Doctor emits findings. GC emits deletions.
Reconciliation emits repairs. The rules are identical; only the
response differs.

## The Database as Intent Store

An early question was whether the database could be eliminated
entirely, using the filesystem as the sole source of truth. The
answer is no, because bpfman manages programs on behalf of users,
and the management metadata — image references, user tags, global
data overrides, attach specifications — cannot be derived from the
kernel or filesystem.

The kernel knows "program 123 is loaded". The filesystem knows
"it is pinned at this path". Neither knows "the user asked for
this image at this tag with these overrides and this metadata".

So the model is:
- **DB**: records of intent — what was requested and why
- **Filesystem + kernel**: records of reality — what exists
- **Coherency engine**: compares intent against reality

The database also defines ownership boundaries: only kernel objects
traceable to a DB record are considered bpfman-managed.

The database is not a cache of kernel state. It is the only record
of user intent. This is why it cannot be eliminated, but it is also
why disagreements between the DB and reality are the most
consequential class of bug.

## Towards a Rule Engine

The current five-phase doctor implementation works, but it does not
scale well as the number of checks grows. Each new check requires
understanding the existing phase structure and finding the right
place to insert another conditional block.

A declarative approach would separate fact gathering from rule
evaluation:

### Phase 1: Gather Facts

Scan all three sources and build a fact set:

- `db_program(id, pin_path, metadata...)`
- `db_link(link_id, program_id, pin_path)`
- `db_dispatcher(type, nsid, ifindex, revision, kernel_id, link_id)`
- `kernel_program(id)`
- `kernel_link(id)`
- `fs_pin(path)`
- `fs_directory(path)`

### Phase 2: Evaluate Rules

Each rule is a predicate over the fact set:

```
rule(error, "db-vs-kernel", "Program {id} in DB not found in kernel") :-
    db_program(id, _),
    not kernel_program(id).

rule(warning, "fs-vs-db", "Orphan program pin: {path}") :-
    fs_prog_pin(path, id),
    not db_program(id, _).

rule(warning, "consistency", "Stale dispatcher") :-
    db_dispatcher(type, nsid, ifindex, _, kernel_id, _),
    db_dispatcher_link_count(kernel_id, 0),
    not fs_dispatcher_prog_pin(type, nsid, ifindex).
```

### Phase 3: Act

The rule evaluator produces findings. The caller decides what to
do with them:

- **Doctor**: print them
- **GC**: execute deletions for error/warning findings
- **Reconcile**: execute repairs

This is the Prolog model. The facts are the database. The rules
are the program. The query determines the action.

## Practical Considerations

Embedding a Prolog engine (e.g., ichiban/prolog) in a Go binary is
possible but adds a dependency and a paradigm shift for
contributors. A middle ground is a Go DSL that captures the same
structure: facts as typed maps, rules as predicate functions,
organised declaratively rather than as hand-written loops.

The key insight is that the current doctor, GC, and reconciliation
code is hand-unrolled Prolog. Recognising this makes it possible
to refactor towards a unified coherency engine without necessarily
adopting a logic programming runtime.

The question of whether to build this depends on trajectory. Five
phases with a dozen checks is manageable as imperative code. If
the system grows to twenty or thirty checks — especially as new
attach types, dispatcher variants, or filesystem conventions are
added — the declarative model pays for itself in maintainability
and correctness.

This refactor is not required today. It becomes justified once the
coherency surface grows beyond a small, reviewable set of rules.
