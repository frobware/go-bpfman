# Shape contract -- remainder

Follow-ups left on the table after the shape-tests asymmetry round.

## 1. v10 -> v11 schema migration for nullable `updated_at`

The change to `managed_programs.updated_at` (dropped `NOT NULL`,
added the `*time.Time` semantics on the in-memory record) landed
without a migration. A fresh database created from `schema.sql`
works. A v10 database does not: the column keeps its `NOT NULL`
constraint, and the next Save where the in-memory `UpdatedAt` is
nil binds `sql.NullString{Valid: false}` and the insert fails.

SQLite has no direct `ALTER COLUMN ... DROP NOT NULL`, so the
migration is the standard create-new/copy/drop/rename dance.
`managed_programs` has a self-referential `map_owner_id` FK that
needs to survive the recreation; foreign keys are off by default
inside `PRAGMA foreign_keys` blocks, so the safe ordering is:

1. Disable FK enforcement for the migration scope.
2. Create `managed_programs_v11` with the new column shape.
3. `INSERT INTO managed_programs_v11 SELECT ... FROM managed_programs`.
4. Drop `managed_programs`.
5. Rename `managed_programs_v11` to `managed_programs`.
6. Re-enable FK enforcement.

Bump `SCHEMA_VERSION` to 11. The migration test should round-trip
a v10 fixture through the migrator and assert column nullability
plus row equivalence.

Effort: medium. One migration file, one test, careful with the
FK toggle. Independent of every other item in this list.

## 2. Close the Load `Status` filesystem-path asymmetry

`status.prog_pin`, `status.map_dir`, `status.link_dir`,
`status.bytecode`, `status.provenance` are zero `PathPresence`
on Load and populated `PathPresence` on Get. The design split is
"Load is action result, Get is observation"; the asymmetry is
real and the XDP shape script papers over it with five
`path: "" / present: false` claims.

Every one of those paths is derivable at Load time without a
stat call -- the plan just produced the files. The values are
already in scope at `manager/load.go:loadBody`:

- `ProgPin.Path` = `lo.PinPath`
- `MapDir.Path` = `bpffs.MapPinDir(mapOwner)`
- `LinkDir.Path` = `bpffs.LinkPinDir(programID)`
- `Bytecode.Path` = `rt.Bytecode().ProgramBytecodePath(programID)`
- `Provenance.Path` = `rt.Bytecode().ProgramProvenancePath(programID)`

`Present` follows from load-time invariants: prog_pin, map_dir,
bytecode, provenance are `true` (the plan just produced them);
link_dir is `false` (no attach has happened, the directory is
not created until first link).

Populate the five fields from the plan's post-conditions in
`loadBody`. No filesystem scan. Update the script's Load block
to claim the same paths the Get block already claims (the
existing `$expect_prog_pin`, `$expect_map_dir`,
`$expect_link_dir`, `$expect_bytecode`, `$expect_provenance`
let-bindings cover all five).

Effort: small. The construction is mechanical and the test
update is trivial because the script already has the expected
values bound.

## 3. `ProgramMeta` strings (`owner`, `description`) to nullable

`meta.name` is always present and required; leave it alone.
`meta.owner` and `meta.description` are optional user-supplied
free-form strings still using the empty-string-as-absent
encoding -- the same shape `attach_func` had before slice 5
(b3528b6f) promoted it to nullable. Finishing this aligns the
last empty-string holdouts in the response and matches the
convention `image_source`, `map_owner_id`, `updated_at`, and
`attach_func` now share.

Apply the same MarshalJSON / UnmarshalJSON pattern used for
`attach_func`: promote the JSON-shape field to `*string`, nil
when the internal field is empty, dereference on the way in.
Internal callers keep their string-typed accessors.

Counter-argument worth recording: empty string is plausibly a
legitimate user value for these fields ("clear my description"),
which pointer-with-null distinguishes from "not provided." If
that distinction is one we want, nullable is strictly more
expressive than the empty-string encoding. If it is one we do
not care about, nullable is harmless and consistent.

Script update: two claims per response (owner and description)
on Load and Get, total four edits.

Effort: small. Same diff shape as the attach_func slice.

## 4. Document `record.load.object_path` rewriting

`record.load.object_path` is rewritten by `buildProgramRecord`
in `manager/load.go` to `<runtime>/programs/<pid>/bytecode.o` --
bpfman's stored copy, not the user's original `--path`
argument. This is intentional (after load, the canonical
location of the bytecode is bpfman's copy, not whatever path
the user happened to invoke load from -- the user's path may
no longer exist) but surprising in a round-trip when the
caller compares `record.load.object_path` against what they
supplied.

Add a docstring to `LoadSpec.ObjectPath()` and a matching
clarification on the `loadSpecJSON.ObjectPath` field comment
spelling out the post-load semantic. No code change.

Effort: trivial. One-liner doc.

## Ordering

1. Migration (independent, biggest correctness win).
2. Load filesystem fields (touches Load response shape,
   e2e-verifiable).
3. ProgramMeta strings (continues the encoding cleanup).
4. object_path doc (smallest tail).
