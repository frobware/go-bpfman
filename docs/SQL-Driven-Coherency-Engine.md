Alright — let’s write this as a **proper design document**, not a think-piece. I’ll be concrete, opinionated, and scoped so it’s actionable rather than aspirational.

---

# Design: SQL-Driven Coherency Engine for bpfman

## Status

**Proposed**
This document describes a replacement for the current Go-based coherency
rule evaluation with a SQL-driven model using SQLite as a temporary fact
store.

---

## Goals

### Primary goals

1. **Make coherency checking declarative**

   * Express rules as relations and predicates, not imperative loops.
   * Treat coherency as a query problem, not a control-flow problem.

2. **Improve correctness and robustness**

   * Eliminate accidental I/O during rule evaluation.
   * Avoid partial snapshots and mixed concerns.
   * Make failure modes explicit and inspectable.

3. **Improve testability**

   * Allow rules to be tested using `INSERT` + `SELECT`.
   * No mocks of kernel, filesystem, or store interfaces for rule tests.

4. **Preserve current semantics**

   * Same rules, same severities, same GC behaviour.
   * No change in user-visible meaning unless explicitly documented.

### Non-goals

* No recursive reasoning or fixpoint computation.
* No long-lived database; the SQL database is ephemeral.
* No embedded Prolog/Datalog runtime.
* No attempt to “auto-repair” kernel-only state.

---

## Problem Statement

The current coherency implementation:

* Correctly models the problem conceptually (facts + rules)
* But implements it imperatively in Go, leading to:

  * I/O during rule evaluation
  * Hidden joins across loops
  * Difficult unit testing
  * Accidental coupling between snapshot and execution

This design replaces **rule evaluation** with SQL queries over a
temporary SQLite database populated with gathered facts.

---

## Core Idea

> Treat coherency as a **relational consistency problem**, not a Go
> control-flow problem.

### Architecture overview

```
┌─────────────┐
│ GatherState │  (Go, imperative, I/O)
└─────┬───────┘
      │ facts
      ▼
┌─────────────────┐
│ SQLite (temp DB)│  ← facts as tables
└─────┬───────────┘
      │ queries
      ▼
┌─────────────────┐
│ Rule Queries    │  ← SQL = declarative rules
└─────┬───────────┘
      │ rows
      ▼
┌─────────────────┐
│ Findings / Ops  │  (Go, no I/O)
└─────────────────┘
```

* **Go gathers facts**
* **SQL reasons about them**
* **Go executes side effects**

This enforces the gather / reason / act separation mechanically.

---

## Fact Model (Schema)

The schema mirrors *observed reality*, not intent.

### Kernel facts

```sql
CREATE TABLE kernel_program (
    kernel_id INTEGER PRIMARY KEY
);

CREATE TABLE kernel_link (
    kernel_id INTEGER PRIMARY KEY
);

CREATE TABLE kernel_tc_filter (
    ifindex   INTEGER,
    parent    INTEGER,
    priority  INTEGER,
    PRIMARY KEY (ifindex, parent, priority)
);
```

---

### Database facts

```sql
CREATE TABLE db_program (
    kernel_id INTEGER PRIMARY KEY,
    pin_path  TEXT
);

CREATE TABLE db_link (
    kernel_link_id    INTEGER PRIMARY KEY,
    kernel_program_id INTEGER,
    pin_path          TEXT,
    synthetic         BOOLEAN
);

CREATE TABLE db_dispatcher (
    type       TEXT,
    nsid       INTEGER,
    ifindex    INTEGER,
    revision   INTEGER,
    kernel_id  INTEGER,
    link_id    INTEGER,
    priority   INTEGER,
    PRIMARY KEY (type, nsid, ifindex)
);

CREATE TABLE db_dispatcher_link_count (
    dispatcher_kernel_id INTEGER PRIMARY KEY,
    link_count INTEGER
);
```

---

### Filesystem facts

```sql
CREATE TABLE fs_prog_pin (
    kernel_id INTEGER,
    path      TEXT PRIMARY KEY
);

CREATE TABLE fs_link_dir (
    kernel_program_id INTEGER PRIMARY KEY
);

CREATE TABLE fs_map_dir (
    kernel_program_id INTEGER PRIMARY KEY
);

CREATE TABLE fs_dispatcher_prog_pin (
    type     TEXT,
    nsid     INTEGER,
    ifindex  INTEGER,
    revision INTEGER,
    path     TEXT,
    PRIMARY KEY (type, nsid, ifindex, revision)
);

CREATE TABLE fs_dispatcher_link_pin (
    type     TEXT,
    nsid     INTEGER,
    ifindex  INTEGER,
    path     TEXT,
    PRIMARY KEY (type, nsid, ifindex)
);

CREATE TABLE fs_dispatcher_link_count (
    type     TEXT,
    nsid     INTEGER,
    ifindex  INTEGER,
    count    INTEGER,
    PRIMARY KEY (type, nsid, ifindex)
);
```

---

## Rule Representation

Each coherency rule is a **SQL query** that produces rows of:

```sql
(rule_name, severity, category, description, action_key)
```

### Example: DB program not in kernel

```sql
SELECT
  'program-in-kernel'      AS rule_name,
  'ERROR'                  AS severity,
  'db-vs-kernel'           AS category,
  'Program ' || p.kernel_id || ' in DB not found in kernel' AS description,
  NULL                     AS action_key
FROM db_program p
LEFT JOIN kernel_program k ON k.kernel_id = p.kernel_id
WHERE k.kernel_id IS NULL;
```

---

### Example: orphan program pin (FS vs DB)

```sql
SELECT
  'orphan-fs-prog-pin' AS rule_name,
  'WARNING'           AS severity,
  'fs-vs-db'           AS category,
  'Orphan program pin: ' || f.path AS description,
  f.path               AS action_key
FROM fs_prog_pin f
LEFT JOIN db_program p ON p.pin_path = f.path
WHERE p.kernel_id IS NULL;
```

---

### Example: TC filter missing (severity depends on extension count)

```sql
SELECT
  'tc-filter-exists' AS rule_name,
  CASE
    WHEN c.link_count > 0 THEN 'ERROR'
    ELSE 'WARNING'
  END AS severity,
  'db-vs-kernel' AS category,
  'Dispatcher ' || d.type || ' nsid=' || d.nsid || ' ifindex=' || d.ifindex ||
  ': TC filter missing' AS description,
  NULL AS action_key
FROM db_dispatcher d
LEFT JOIN kernel_tc_filter f
  ON f.ifindex = d.ifindex
 AND f.priority = d.priority
LEFT JOIN db_dispatcher_link_count c
  ON c.dispatcher_kernel_id = d.kernel_id
WHERE f.ifindex IS NULL
  AND d.priority > 0;
```

---

## Doctor Execution Model

1. Create in-memory SQLite DB
2. Populate all fact tables (single snapshot)
3. Execute all rule queries
4. Collect rows into `Finding` structs
5. Sort / group / print

**No mutation. No side effects.**

---

## GC Execution Model

1. Run store-level GC (unchanged)
2. Re-gather facts
3. Execute GC rule queries
4. Each row yields an **action key**
5. Go maps action keys → operations
6. Execute operations with error handling

Important:

* SQL **plans**, Go **executes**
* FS failures prevent DB deletion

---

## Testing Strategy

### Rule tests (pure SQL)

* Load schema
* Insert minimal rows
* Run rule query
* Assert result rows

Example:

```sql
INSERT INTO db_program VALUES (123, '/run/bpfman/fs/prog_123');

-- no kernel_program row

SELECT * FROM rule_program_in_kernel;
```

### Integration tests

* Reuse GatherState
* Verify parity with existing behaviour

---

## Why SQL (and not Datalog)

* This system is **non-recursive**
* SQLite already provides:

  * negation
  * joins
  * views
  * tooling
* No new language runtime
* Easier contributor onboarding

Conceptually, this *is* Datalog — implemented using relational algebra.

---

## Migration Plan

1. Introduce SQL fact schema + gatherer
2. Implement doctor rules in SQL
3. Run Go + SQL engines side-by-side
4. Compare outputs
5. Remove Go rule evaluation
6. Move GC planning to SQL incrementally

---

## Summary

This design:

* Aligns implementation with the documented model
* Makes coherency rules **explicit, inspectable, testable**
* Eliminates accidental complexity in Go
* Preserves current semantics
* Leaves room for future expansion (adopt, explain, visualise)

Most importantly:

> **It stops pretending this is a control-flow problem and admits that
> it’s a data-consistency problem.**

If you want, next step can be:

* a concrete SQL schema file,
* a single rule fully ported end-to-end,
* or a comparison table mapping current Go rules → SQL queries.
