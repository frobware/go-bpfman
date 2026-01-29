# Implementation Plan: SQL-Based Coherency Engine

## Status

**Proposed** — This document describes the implementation plan for
replacing Go-based coherency rule evaluation with SQL queries over a
fact snapshot.

---

## Document Roles

| Document | Purpose |
|----------|---------|
| `COHERENCY-RULES.md` | Normative semantics and stable rule names |
| `SQL-Driven-Coherency-Implementation.md` (this doc) | How we build it: phases, API, schema, tests |
| `COHERENCY-MODEL.md` | Conceptual model (intent vs reality) |
| `DATA-COHERENCY.md` | Divergence scenarios and consequences |

This document is the canonical implementation plan. Rule semantics live
in `COHERENCY-RULES.md`; this document specifies how to realise them.

---

## Goals

1. **Mechanical separation of gather/reason/act**
   - Gather: all I/O (store, kernel, filesystem)
   - Reason: SQL queries over gathered facts (no I/O)
   - Act: execute planned operations

2. **Coherency sits above store implementation**
   - Fact schema populated only via public interfaces
   - No dependency on store's internal SQL schema

3. **Stable rule identifiers**
   - `rule_name` is a first-class output field
   - Rules map 1:1 to COHERENCY-RULES.md

4. **Testability**
   - Unit tests: `INSERT facts -> run SQL -> assert findings`
   - No mocks of kernel, filesystem, or store for rule tests

5. **Deterministic output**
   - Findings and planned ops have stable ordering
   - Same facts produce identical output across runs

---

## Determinism

All outputs must be deterministic for testing and user experience.

SQL rules may INSERT rows in any order; determinism is enforced only at
SELECT time via explicit ORDER BY clauses.

### Findings

Order by: `(severity (ERROR first), category, rule_name, description)`

```sql
SELECT rule_name, severity, category, description
FROM finding
ORDER BY
  CASE severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,
  category,
  rule_name,
  description;
```

### Planned Operations

Order by: `(kind priority, sort key)`

1. `delete-dispatcher` first (may remove dirs that orphan rules target)
2. `remove-path` second
3. `remove-all` third

Within each kind, sort lexicographically by `(disp_type, nsid, ifindex)`
or `path`.

```sql
SELECT *
FROM planned_op
ORDER BY
  CASE kind
    WHEN 'delete-dispatcher' THEN 0
    WHEN 'remove-path' THEN 1
    WHEN 'remove-all' THEN 2
  END,
  COALESCE(disp_type, ''),
  COALESCE(nsid, 0),
  COALESCE(ifindex, 0),
  COALESCE(path, '');
```

---

## Executor Semantics

The executor applies planned operations. Planning is pure SQL; execution
is imperative Go with strict error handling.

### Accounting

- `applied++` when the op's intended side-effect happened (or was already
  true, e.g. ENOENT means "already removed")
- `failed++` when a non-ENOENT error occurs in any step of an op
- The `err` return value is reserved for executor-level failures (context
  cancelled, executor is broken); individual op failures increment `failed`
  but do not stop execution

This makes `ExecuteGCOps` usable in CI and scripts: it runs all ops and
reports counts rather than failing fast.

### remove-path

- Call `os.Remove(path)`
- `ENOENT` is success (already gone): `applied++`
- Any other error: log warning, `failed++`

### remove-all

- Call `os.RemoveAll(path)`
- `ENOENT` is success: `applied++`
- Any other error: log warning, `failed++`

### delete-dispatcher

The executor re-reads dispatcher state from the store to obtain current
`revision`, `link_id`, and `priority` before computing paths. The
`PlannedOp` carries only the dispatcher key `(disp_type, nsid, ifindex)`.

1. Fetch dispatcher state from store (if not found: already deleted, `applied++`)

2. Compute paths using dispatcher helpers:
   - `revDir := DispatcherRevisionDir(dirs.FS, dispType, nsid, ifindex, revision)`
   - `progPin := DispatcherProgPath(revDir)`
   - `linkPin := DispatcherLinkPath(dirs.FS, dispType, nsid, ifindex)` (XDP only)

3. Remove filesystem artefacts **first**:
   - Remove prog pin (ignore ENOENT)
   - Remove revision dir recursively (ignore ENOENT)
   - Remove link pin for XDP (ignore ENOENT)
   - If any removal fails with non-ENOENT: abort this op, `failed++`, do not delete from store

4. Delete from store:
   - `store.DeleteDispatcher(ctx, dispType, nsid, ifindex)`
   - If store delete fails: log warning, `failed++`
   - If store delete succeeds: `applied++`

This ordering prevents the documented divergence where the DB record is
deleted but filesystem artefacts remain.

---

## Snapshot Semantics

Gather produces a best-effort snapshot. The contract is:

- **Gather is not transactional across sources.** The kernel, filesystem,
  and store are read sequentially; state may change between reads.

- **Enumeration failures are recorded, not fatal.** If `kernel.Programs()`
  or `kernel.Links()` yields errors, gather continues and inserts a
  `kernel-enumeration-incomplete` finding. Doctor results are best-effort
  but the user is informed the snapshot may be partial.

- **Transient inconsistencies are acceptable.** Running doctor during
  active attach/detach may show findings that resolve immediately. GC
  must still be safe: it only deletes artefacts when both DB record is
  missing AND kernel object is not alive.

- **No writer lock required for doctor.** Doctor is read-only and
  tolerates stale reads. GC should ideally run when no mutations are
  in flight, but the safety invariants hold regardless.

- **Context is honoured throughout gather.** All gather operations
  (kernel iterators, TC filter lookups, filesystem scans) respect `ctx`
  deadline and cancellation. Cancellation is fatal to gather and returns
  an error, but if `--dump-facts` is used the partially-populated facts
  DB may still be written for debugging.

---

## Package Layout

```
coherency/
|-- facts/
|   |-- schema.sql      # DDL for fact tables
|   |-- gather.go       # GatherFacts implementation
|   +-- gather_test.go  # Integration tests for gather
|-- rules/
|   |-- doctor.go       # Doctor rule SQL statements
|   |-- planner.go      # GC planner SQL statements
|   +-- rules_test.go   # Pure SQL unit tests
|-- engine.go           # DoctorSQL, PlanGCSQL orchestration
|-- exec.go             # ExecuteGCOps (imperative step)
+-- types.go            # Finding, PlannedOp, Severity
```

---

## Public API

### Types

```go
type Severity string

const (
    SeverityOK      Severity = "OK"
    SeverityWarning Severity = "WARNING"
    SeverityError   Severity = "ERROR"
)

type Finding struct {
    RuleName    string
    Severity    Severity
    Category    string
    Description string
}

type PlannedOpKind string

const (
    OpRemovePath       PlannedOpKind = "remove-path"
    OpRemoveAll        PlannedOpKind = "remove-all"
    OpDeleteDispatcher PlannedOpKind = "delete-dispatcher"
)

type PlannedOp struct {
    Kind        PlannedOpKind
    Path        string
    DispType    string
    Nsid        uint64
    Ifindex     uint32
    ReasonRule  string
    Description string
}
```

### Entry Points

```go
// DoctorSQL gathers facts, runs doctor rules, returns findings.
func DoctorSQL(
    ctx context.Context,
    store interpreter.Store,
    kernel interpreter.KernelOperations,
    dirs config.RuntimeDirs,
    opts ...Option,
) ([]Finding, error)

// PlanGCSQL gathers facts, runs planner rules, returns planned ops.
func PlanGCSQL(
    ctx context.Context,
    store interpreter.Store,
    kernel interpreter.KernelOperations,
    dirs config.RuntimeDirs,
    opts ...Option,
) ([]PlannedOp, []Finding, error)

// ExecuteGCOps executes planned ops (the only mutating step).
func ExecuteGCOps(
    ctx context.Context,
    store interpreter.Store,
    kernel interpreter.KernelOperations,
    dirs config.RuntimeDirs,
    ops []PlannedOp,
) (applied int, failed int, err error)
```

### Options

```go
type Option func(*engineOpts)

type engineOpts struct {
    factsPath string // "" means in-memory
    keepFacts bool   // keep facts DB after completion
}

func WithFactsFile(path string) Option
func WithKeepFacts() Option
```

---

## Facts Database

### Lifecycle

```go
type FactsDB struct {
    DB    *sql.DB
    Path  string // empty if in-memory
    Close func() error
}

func GatherFacts(
    ctx context.Context,
    store interpreter.Store,
    kernel interpreter.KernelOperations,
    dirs config.RuntimeDirs,
    opts ...Option,
) (*FactsDB, error)
```

### SQLite Configuration

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = MEMORY;
PRAGMA synchronous = OFF;
PRAGMA temp_store = MEMORY;
PRAGMA locking_mode = EXCLUSIVE;
PRAGMA cache_size = -2000;  -- 2MB (negative = KiB)
```

Facts are ephemeral; these pragmas optimise for speed over durability.
`locking_mode = EXCLUSIVE` avoids surprises if the DB is file-backed
during debugging.

---

## Gather Phase

Populate facts from public interfaces only.

### Store Facts

| Interface Call | Target Table |
|----------------|--------------|
| `store.List(ctx)` | `db_program` |
| `store.ListLinks(ctx)` | `db_link` |
| `store.ListDispatchers(ctx)` | `db_dispatcher` |
| `store.CountDispatcherLinks(ctx, kernelID)` | `db_dispatcher_link_count` |

### Kernel Facts

| Interface Call | Target Table |
|----------------|--------------|
| `kernel.Programs(ctx)` | `k_program` |
| `kernel.Links(ctx)` | `k_link` |
| `kernel.FindTCFilterHandle(...)` | `k_tc_filter` |

Enumeration errors are recorded in `gather_status`. Both program and
link enumeration failures should be tracked.

### Filesystem Facts

| Scan | Target Table |
|------|--------------|
| `{dirs.FS}/prog_*` | `fs_prog_pin` |
| `{dirs.FS}/links/{id}` | `fs_link_dir` |
| `{dirs.FS}/maps/{id}` | `fs_map_dir` |
| `{dirs.FS}/{type}/dispatcher_{nsid}_{ifindex}_{rev}` | `fs_dispatcher_dir` |
| `{dirs.FS}/{type}/dispatcher_{nsid}_{ifindex}_link` | `fs_dispatcher_link_pin` |
| Count `link_*` in revision dir | `fs_dispatcher_link_count` |
| `os.Stat` on every `db_program.pin_path` | `fs_pin` |
| `os.Stat` on every `db_link.pin_path` | `fs_pin` |
| `os.Stat` on every dispatcher link pin path | `fs_pin` |

The `fs_pin` table is a generic existence check: if `os.Stat` succeeds,
insert the path. This keeps pin-existence rules simple (`LEFT JOIN fs_pin`).

---

## Implementation Phases

### Phase 1: Prove the Architecture

Minimal slice that validates gather/reason/act separation.

#### Scope

**Fact tables:**
- `gather_status`
- `k_program`
- `db_program`
- `fs_pin`
- `fs_prog_pin`
- `fs_link_dir`
- `fs_map_dir`

**Doctor rules:**

| Rule | Category | Severity |
|------|----------|----------|
| `kernel-enumeration-incomplete` | gather | WARNING |
| `program-in-kernel` | db-vs-kernel | ERROR |
| `program-pin-exists` | db-vs-fs | WARNING |
| `orphan-fs-entries` | fs-vs-db | WARNING |
| `kernel-program-pinned-but-not-in-db` | kernel-vs-db | WARNING |

**Planner rules:**

| Rule | Action |
|------|--------|
| `orphan-program-artefacts` | remove-path (prog pin), remove-all (link/map dirs) |

#### SQL Statements

**kernel-enumeration-incomplete**
```sql
INSERT INTO finding(rule_name, severity, category, description)
SELECT
    'kernel-enumeration-incomplete',
    'WARNING',
    'gather',
    'Kernel enumeration incomplete (' || source || '): ' || COALESCE(error, '(unknown)')
FROM gather_status
WHERE source IN ('kernel_programs', 'kernel_links') AND ok = 0;
```

**program-in-kernel**
```sql
INSERT INTO finding(rule_name, severity, category, description)
SELECT
    'program-in-kernel',
    'ERROR',
    'db-vs-kernel',
    'Program ' || p.kernel_id || ' in DB not found in kernel (pin: ' || p.pin_path || ')'
FROM db_program p
LEFT JOIN k_program k ON k.kernel_id = p.kernel_id
WHERE k.kernel_id IS NULL;
```

**program-pin-exists**
```sql
INSERT INTO finding(rule_name, severity, category, description)
SELECT
    'program-pin-exists',
    'WARNING',
    'db-vs-fs',
    'Program ' || p.kernel_id || ': pin path missing: ' || p.pin_path
FROM db_program p
LEFT JOIN fs_pin f ON f.path = p.pin_path
WHERE p.has_pin_path = 1
  AND f.path IS NULL;
```

**orphan-fs-entries**
```sql
INSERT INTO finding(rule_name, severity, category, description)
SELECT 'orphan-fs-entries', 'WARNING', 'fs-vs-db',
       'Orphan prog pin: ' || f.path
FROM fs_prog_pin f
LEFT JOIN db_program p ON p.kernel_id = f.kernel_id
WHERE p.kernel_id IS NULL

UNION ALL

SELECT 'orphan-fs-entries', 'WARNING', 'fs-vs-db',
       'Orphan link dir: ' || l.path
FROM fs_link_dir l
LEFT JOIN db_program p ON p.kernel_id = l.program_id
WHERE p.kernel_id IS NULL

UNION ALL

SELECT 'orphan-fs-entries', 'WARNING', 'fs-vs-db',
       'Orphan map dir: ' || m.path
FROM fs_map_dir m
LEFT JOIN db_program p ON p.kernel_id = m.program_id
WHERE p.kernel_id IS NULL;
```

**kernel-program-pinned-but-not-in-db**
```sql
INSERT INTO finding(rule_name, severity, category, description)
SELECT
    'kernel-program-pinned-but-not-in-db',
    'WARNING',
    'kernel-vs-db',
    'Live orphan: prog pin ' || f.path ||
    ' (kernel_id ' || f.kernel_id || ') has no DB record'
FROM fs_prog_pin f
LEFT JOIN db_program p ON p.kernel_id = f.kernel_id
JOIN k_program k ON k.kernel_id = f.kernel_id
WHERE p.kernel_id IS NULL;
```

**orphan-program-artefacts (planner)**
```sql
INSERT INTO planned_op(kind, path, reason_rule, description)
SELECT
    'remove-path',
    f.path,
    'orphan-program-artefacts',
    'Remove orphan prog pin (kernel dead): ' || f.path
FROM fs_prog_pin f
LEFT JOIN db_program p ON p.kernel_id = f.kernel_id
LEFT JOIN k_program k ON k.kernel_id = f.kernel_id
WHERE p.kernel_id IS NULL
  AND k.kernel_id IS NULL;

INSERT INTO planned_op(kind, path, reason_rule, description)
SELECT
    'remove-all',
    l.path,
    'orphan-program-artefacts',
    'Remove orphan link dir: ' || l.path
FROM fs_link_dir l
LEFT JOIN db_program p ON p.kernel_id = l.program_id
LEFT JOIN k_program k ON k.kernel_id = l.program_id
WHERE p.kernel_id IS NULL
  AND k.kernel_id IS NULL;

INSERT INTO planned_op(kind, path, reason_rule, description)
SELECT
    'remove-all',
    m.path,
    'orphan-program-artefacts',
    'Remove orphan map dir: ' || m.path
FROM fs_map_dir m
LEFT JOIN db_program p ON p.kernel_id = m.program_id
LEFT JOIN k_program k ON k.kernel_id = m.program_id
WHERE p.kernel_id IS NULL
  AND k.kernel_id IS NULL;
```

#### Deliverables

1. `coherency/facts/schema.sql` - DDL for phase 1 tables
2. `coherency/facts/gather.go` - GatherFacts implementation
3. `coherency/rules/doctor.go` - Phase 1 doctor rules
4. `coherency/rules/planner.go` - Phase 1 planner rules
5. `coherency/rules/rules_test.go` - Pure SQL unit tests
6. `coherency/engine.go` - DoctorSQL orchestration
7. Integration: run Go doctor and SQL doctor side-by-side, diff results

#### Testing Strategy

**Pure SQL tests (no I/O):**
```go
func TestProgramInKernel(t *testing.T) {
    db := createTestDB(t)
    applyDDL(t, db)

    // Program in DB but not in kernel
    exec(t, db, `INSERT INTO db_program VALUES(123, '/run/bpfman/fs/prog_123', 1, 'test', 'xdp')`)
    // No row in k_program

    runRule(t, db, rules.ProgramInKernel)

    findings := queryFindings(t, db)
    require.Len(t, findings, 1)
    assert.Equal(t, "program-in-kernel", findings[0].RuleName)
    assert.Equal(t, "ERROR", findings[0].Severity)
}

func TestProgramInKernel_NoFinding(t *testing.T) {
    db := createTestDB(t)
    applyDDL(t, db)

    // Program in both DB and kernel
    exec(t, db, `INSERT INTO db_program VALUES(123, '/run/bpfman/fs/prog_123', 1, 'test', 'xdp')`)
    exec(t, db, `INSERT INTO k_program VALUES(123)`)

    runRule(t, db, rules.ProgramInKernel)

    findings := queryFindings(t, db)
    require.Len(t, findings, 0)
}
```

**Gather tests (I/O boundary):**
- Create temp directories with fake bpffs layout
- Provide stub Store/KernelOperations
- Call GatherFacts, assert fact table contents

---

### Phase 2: Links and Dispatchers

**Fact tables:**
- `k_link`
- `db_link`
- `db_dispatcher`
- `db_dispatcher_link_count`
- `fs_dispatcher_dir`
- `fs_dispatcher_link_pin`
- `fs_dispatcher_link_count`

**Doctor rules:**
- `link-in-kernel`
- `dispatcher-prog-in-kernel`
- `xdp-link-in-kernel`
- `dispatcher-prog-pin-exists`
- `xdp-link-pin-exists`
- `dispatcher-link-count`
- `orphan-fs-entries` (dispatcher dirs)

**Planner rules:**
- `orphan-dispatcher-artefacts`

---

### Phase 3: TC Filters and Stale Dispatchers

**Fact tables:**
- `k_tc_filter`

**Doctor rules:**
- `tc-filter-exists`

**Planner rules:**
- `stale-dispatcher`

---

### Phase 4: Migration Complete

1. Run Go coherency and SQL coherency side-by-side
2. Compare outputs, fail tests on divergence
3. Add `--dump-facts` flag for debugging
4. Add `--explain` flag for query plans
5. Remove Go coherency implementation
6. Update CLI to use SQL engine

---

## Debugging Hooks

### --dump-facts

Write the facts DB to a file for inspection:

```
bpfman doctor --dump-facts /tmp/facts.db
```

Then:
```
sqlite3 /tmp/facts.db "SELECT * FROM db_program"
sqlite3 /tmp/facts.db "SELECT * FROM finding"
```

### --explain

Show query plans for each rule:

```
bpfman doctor --explain
```

Runs `EXPLAIN QUERY PLAN` for each rule SQL statement.

---

## Store GC Integration

Store GC remains imperative (transactional ordering constraints).

To maintain a unified interface:

1. Store GC emits `(rule_name, severity, category, description)` tuples
2. Manager combines store GC findings with SQL findings
3. Single findings stream for CLI output

Contract:
- **Store GC guarantees:** DB has no rows referring to missing kernel IDs
- **SQL coherency guarantees:** DB intent is satisfiable by kernel+FS, no safe-to-delete orphans remain

---

## Parity Checklist

Before removing the Go coherency implementation, verify:

- [ ] Findings include: `rule_name`, `severity`, `category`, `description`
- [ ] Output ordering is deterministic and matches Go implementation
- [ ] Synthetic link IDs excluded from kernel-link rules
- [ ] Live orphan detection reports WARNING and does not plan deletion
- [ ] TC filter severity depends on dispatcher link count (ERROR if >0, WARNING if 0)
- [ ] GC does not delete anything "alive in kernel" based on program ID
- [ ] `kernel-enumeration-incomplete` covers both programs and links

---

## Appendix A: Complete Fact Schema (DDL)

Full schema for all phases.

```sql
-- SQLite configuration
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = MEMORY;
PRAGMA synchronous = OFF;
PRAGMA temp_store = MEMORY;
PRAGMA locking_mode = EXCLUSIVE;
PRAGMA cache_size = -2000;  -- 2MB (negative = KiB)

-- Gather status (enumeration quality)
CREATE TABLE IF NOT EXISTS gather_status (
    source TEXT PRIMARY KEY,  -- 'kernel_programs', 'kernel_links', 'store', 'fs'
    ok     INTEGER NOT NULL CHECK (ok IN (0, 1)),
    error  TEXT               -- NULL if ok
);

-- Kernel facts
CREATE TABLE IF NOT EXISTS k_program (
    kernel_id INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS k_link (
    kernel_id INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS k_tc_filter (
    disp_type TEXT NOT NULL,
    nsid      INTEGER NOT NULL,
    ifindex   INTEGER NOT NULL,
    ok        INTEGER NOT NULL,  -- 1/0
    handle    INTEGER,           -- optional diagnostic
    PRIMARY KEY (disp_type, nsid, ifindex)
);

-- Store facts (from public interfaces)
CREATE TABLE IF NOT EXISTS db_program (
    kernel_id    INTEGER PRIMARY KEY,
    pin_path     TEXT NOT NULL,
    has_pin_path INTEGER NOT NULL,  -- 1/0
    program_name TEXT NOT NULL,
    program_type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS db_link (
    kernel_link_id    INTEGER PRIMARY KEY,
    kernel_program_id INTEGER NOT NULL,
    link_type         TEXT NOT NULL,
    pin_path          TEXT,
    has_pin_path      INTEGER NOT NULL,  -- 1/0
    is_synthetic      INTEGER NOT NULL   -- 1/0
);

CREATE TABLE IF NOT EXISTS db_dispatcher (
    disp_type TEXT NOT NULL,
    nsid      INTEGER NOT NULL,
    ifindex   INTEGER NOT NULL,
    revision  INTEGER NOT NULL,
    kernel_id INTEGER NOT NULL,
    link_id   INTEGER NOT NULL,   -- 0 for TC
    priority  INTEGER NOT NULL,   -- 0 for XDP
    PRIMARY KEY (disp_type, nsid, ifindex)
);

CREATE TABLE IF NOT EXISTS db_dispatcher_link_count (
    dispatcher_kernel_id INTEGER PRIMARY KEY,
    link_count           INTEGER NOT NULL
);

-- Filesystem facts

-- Generic pin existence table: populated by os.Stat on every pin path
-- from db_program.pin_path, db_link.pin_path, and dispatcher link pins.
CREATE TABLE IF NOT EXISTS fs_pin (
    path TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS fs_prog_pin (
    path      TEXT PRIMARY KEY,
    kernel_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fs_link_dir (
    path       TEXT PRIMARY KEY,
    program_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fs_map_dir (
    path       TEXT PRIMARY KEY,
    program_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fs_dispatcher_dir (
    path      TEXT PRIMARY KEY,
    disp_type TEXT NOT NULL,
    nsid      INTEGER NOT NULL,
    ifindex   INTEGER NOT NULL,
    revision  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fs_dispatcher_link_pin (
    path      TEXT PRIMARY KEY,
    disp_type TEXT NOT NULL,
    nsid      INTEGER NOT NULL,
    ifindex   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fs_dispatcher_link_count (
    disp_type  TEXT NOT NULL,
    nsid       INTEGER NOT NULL,
    ifindex    INTEGER NOT NULL,
    revision   INTEGER NOT NULL,
    link_count INTEGER NOT NULL,
    PRIMARY KEY (disp_type, nsid, ifindex, revision)
);

-- Output tables
CREATE TABLE IF NOT EXISTS finding (
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('OK', 'WARNING', 'ERROR')),
    category    TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS planned_op (
    kind        TEXT NOT NULL,
    path        TEXT,
    disp_type   TEXT,
    nsid        INTEGER,
    ifindex     INTEGER,
    reason_rule TEXT NOT NULL,
    description TEXT NOT NULL,

    CHECK (
        (kind IN ('remove-path', 'remove-all')
         AND path IS NOT NULL
         AND disp_type IS NULL AND nsid IS NULL AND ifindex IS NULL)
        OR
        (kind = 'delete-dispatcher'
         AND path IS NULL
         AND disp_type IS NOT NULL AND nsid IS NOT NULL AND ifindex IS NOT NULL)
    )
);

-- Recommended indices (optional, add if profiling shows need)
CREATE INDEX IF NOT EXISTS idx_db_link_program
    ON db_link(kernel_program_id);

CREATE INDEX IF NOT EXISTS idx_db_dispatcher_kernel_id
    ON db_dispatcher(kernel_id);

CREATE INDEX IF NOT EXISTS idx_fs_prog_pin_kernel_id
    ON fs_prog_pin(kernel_id);

CREATE INDEX IF NOT EXISTS idx_fs_link_dir_program_id
    ON fs_link_dir(program_id);

CREATE INDEX IF NOT EXISTS idx_fs_map_dir_program_id
    ON fs_map_dir(program_id);
```

---

## Appendix B: Complete Rule Catalogue

| Rule | Fact Tables | Output | Notes |
|------|-------------|--------|-------|
| `kernel-enumeration-incomplete` | `gather_status` | finding | Covers both programs and links |
| `program-in-kernel` | `db_program`, `k_program` | finding | |
| `link-in-kernel` | `db_link`, `k_link` | finding | Skip synthetic (is_synthetic=1) and zero IDs |
| `dispatcher-prog-in-kernel` | `db_dispatcher`, `k_program` | finding | |
| `xdp-link-in-kernel` | `db_dispatcher`, `k_link` | finding | XDP only, link_id != 0 |
| `tc-filter-exists` | `db_dispatcher`, `db_dispatcher_link_count`, `k_tc_filter` | finding | Severity: ERROR if link_count>0, else WARNING |
| `program-pin-exists` | `db_program`, `fs_pin` | finding | |
| `link-pin-exists` | `db_link`, `fs_pin` | finding | Skip synthetic |
| `dispatcher-prog-pin-exists` | `db_dispatcher`, `fs_dispatcher_dir` | finding | |
| `xdp-link-pin-exists` | `db_dispatcher`, `fs_dispatcher_link_pin` | finding | XDP only |
| `orphan-fs-entries` | `fs_prog_pin`, `fs_link_dir`, `fs_map_dir`, `fs_dispatcher_dir` vs `db_*` | finding | Multiple scopes |
| `kernel-program-pinned-but-not-in-db` | `fs_prog_pin`, `db_program`, `k_program` | finding | Live orphan: warn but never delete |
| `dispatcher-link-count` | `db_dispatcher`, `db_dispatcher_link_count`, `fs_dispatcher_link_count` | finding | |
| `orphan-program-artefacts` | `fs_prog_pin`, `fs_link_dir`, `fs_map_dir`, `db_program`, `k_program` | planned_op | Only when kernel program not alive |
| `orphan-dispatcher-artefacts` | `fs_dispatcher_dir`, `db_dispatcher` | planned_op | |
| `stale-dispatcher` | `db_dispatcher`, `db_dispatcher_link_count`, `fs_dispatcher_dir`, `k_tc_filter` | planned_op | link_count=0 AND (missing dir OR missing TC filter) |

---

## References

- [COHERENCY-MODEL.md](COHERENCY-MODEL.md) - Conceptual model
- [COHERENCY-RULES.md](COHERENCY-RULES.md) - Rule reference (normative)
- [DATA-COHERENCY.md](DATA-COHERENCY.md) - Divergence scenarios
