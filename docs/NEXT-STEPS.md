# Next Steps

Ranked by impact-to-effort ratio. Derived from an architectural review
through the lenses of *Functional Programming in Scala* (Red Book, 2nd
edition) and Ousterhout's *A Philosophy of Software Design*, building
on the analysis in `DESIGN-WARTS.md`.

## 1. Extract `buildProgramRecord` from the two scan functions

**File:** `platform/store/sqlite/programs.go`

`scanProgram` (lines 38-167, single `*sql.Row`) and
`scanProgramFromRows` (lines 335-469, `*sql.Rows`) contain identical
parsing logic: nullable scalar fields, JSON unmarshalling, timestamp
parsing, `ProgramRecord` construction. The only difference is the Scan
call and zero-value return shape.

Extract a `buildProgramRecord` helper that takes the already-scanned
local variables and returns `(bpfman.ProgramRecord, error)`. Both scan
functions call it after their respective `Scan` calls. This is
mechanical extraction -- no design trade-off, just removing ~90 lines
of exact duplication. A schema change today requires updating both
functions with identical edits; that is a maintenance hazard.

**Effort:** small.

## 2. Extract scaffolding helpers for link detail batch/get/save

**File:** `platform/store/sqlite/links.go`

24 functions share identical scaffolding:

- 8 `batchPopulate*Details` (lines 188-396): `rows.Next()` / `Scan()`
  / index-lookup / assign
- 8 `get*Details` (lines 695-890): `QueryRow` / `Scan` /
  three-branch error handling
- 8 `save*Details` (lines 441-555): `ExecContext` / timing / logging

The inner logic varies (different Scan columns, JSON unmarshalling for
XDP/TC, bool-to-int conversion for kprobe/uprobe), but the
scaffolding is the same. Each new link type requires cloning three
functions.

Go's `database/sql` package does not support generics on Scan, but the
scaffolding can be extracted without generics. For the batch populate
case:

```go
func (s *sqliteStore) batchPopulate(
    ctx context.Context,
    stmt *sql.Stmt,
    label string,
    links []bpfman.LinkRecord,
    linkIndex map[kernel.LinkID]int,
    scanRow func(*sql.Rows) (kernel.LinkID, bpfman.LinkDetails, error),
) error
```

Each link type supplies a `scanRow` closure. The 8 functions become 8
two-line closures. The same pattern applies to the get and save
families. This would eliminate roughly 350 lines of repetitive code
and make adding a new link type a two-line closure instead of a
three-function clone.

**Ousterhout lens.** These are shallow modules -- each does little
internal work, mostly boilerplate. Pushing the scaffolding into a
shared helper deepens them.

**Effort:** moderate.

## 3. Factor the shared "save link record" node

**Files:** `manager/attach_simple.go:121-145`,
`manager/attach_dispatcher.go:141-164`, `manager/attach_tc.go:198-228`

All three attach plan builders produce `linkKey` with the same
skeleton: call `NewPinnedLinkRecord`, build `bpfman.Link` with status
fields, call `exec.Execute(ctx, action.SaveLink{Record: record})`,
return link. The variation is only in how `LinkID`, `LinkDetails`, and
`pinPath` are sourced.

A helper like:

```go
func saveLinkNode(
    target string,
    programID kernel.ProgramID,
    getLinkID func(*operation.Bindings) kernel.LinkID,
    getDetails func(*operation.Bindings) bpfman.LinkDetails,
    getPinPath func(*operation.Bindings) string,
    getKernelLink func(*operation.Bindings) (*kernel.Link, bool),
) operation.Node
```

would reduce three 20-line closures to three 5-line call sites.

**Red Book lens.** Three plan builders producing structurally identical
nodes with slightly different projections from bindings is a failure
to identify a reusable combinator.

**Ousterhout lens.** This is the pass-through pattern (chapter 7)
applied to plan construction.

**Effort:** small to moderate.

## 4. Implement `Compensatable`

As described in `DESIGN-WARTS.md` (lines 434-570). Produced values
that implement `Compensatable` have their compensation actions
automatically registered on the undo stack by the interpreter, removing
explicit `UndoFrom` wiring from plan sites.

The interpreter change is one type assertion and one helper function.
Migration is incremental -- each `UndoFrom` can be removed independently
as its produced type gains a `Compensation()` method. The five existing
`UndoFrom` sites are correct but fragile; each relies on the plan author
placing the closure correctly and extracting the right values from
bindings. `Compensatable` makes the right thing automatic and scales
to new attach/load types without plan-site wiring.

**Ordering note.** The design proposes that `Compensatable` actions are
registered before explicit `UndoFrom`/`WithUndo` on the same node, so
they execute later during reverse traversal. Ensure this is the
intended semantics and document the ordering invariant.

**Effort:** moderate (interpreter change is surgical; migration is
incremental).

## 5. Log Try node failures at debug level

**File:** `manager/operation/run.go`

`interpret()` handles Try nodes by discarding the error entirely
(line 75: `_ = n.execFn(...)`). The error is not logged. A Try node
that fails produces no observable signal unless the caller
independently checks the outcome. The interpreter already receives a
logger; log Try failures at debug level.

**Effort:** trivial.

## 6. Unify CLI batch-mutation boilerplate

**Files:** `cmd/bpfman/unload.go`, `cmd/bpfman/detach.go`

Both implement the same batch-mutation skeleton: define a local result
struct with ID + error, create a results slice, lock, iterate, collect
results, count failures, print errors, return aggregated error. The
only variation is `ProgramID` vs `LinkID` and the manager method
called. A generic helper or closure pattern would collapse both.

**Effort:** small.

## 7. Remove or document `WithUndo`

**File:** `manager/operation/node.go`

`WithUndo` (static undo) has no production call sites; all undo uses
`UndoFrom`. If it exists to support a future use case (e.g., the
`Compensatable` proposal), document that intent. If not, remove it.
Unused API surface is conceptual weight for anyone reading the
operation package.

**Effort:** trivial.
