# Schema Design

This document discusses the practical challenges of implementing the
storage model described in [MANAGED-PROGRAMS.md](MANAGED-PROGRAMS.md).

## The Core Tension

We have eight link types with different fields:

| Type | Specific Fields |
|------|-----------------|
| Tracepoint | group, name |
| Kprobe | fn_name, offset, retprobe |
| Uprobe | fn_name, offset, retprobe, target, pid |
| Fentry | fn_name |
| Fexit | fn_name |
| XDP | interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id |
| TC | interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id |
| TCX | interface, ifindex, direction, priority, netns, nsid |

But the CLI needs to treat links polymorphically:

```bash
bpfman list links              # All links, any type
bpfman get program 123         # Program details including all its links
bpfman detach <uuid>           # Delete by UUID, type unknown
```

## Option 1: Single Table with Discriminated Union

```sql
CREATE TABLE managed_links (
    uuid TEXT PRIMARY KEY,
    link_type TEXT NOT NULL,
    kernel_program_id INTEGER NOT NULL,
    kernel_link_id INTEGER,
    pin_path TEXT,

    -- All type-specific fields as nullable columns
    tracepoint_group TEXT,
    tracepoint_name TEXT,
    fn_name TEXT,
    offset INTEGER,
    retprobe INTEGER,
    target TEXT,
    pid INTEGER,
    interface TEXT,
    ifindex INTEGER,
    direction TEXT,
    priority INTEGER,
    position INTEGER,
    proceed_on TEXT,
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER,

    created_at TEXT NOT NULL
);
```

**Pros:**
- Simple polymorphic queries
- One table, one Go type, one set of CRUD operations

**Cons:**
- Illegal states are representable (tracepoint with interface set)
- Many NULL columns per row
- No type-specific constraints
- Schema doesn't document what each type needs

## Option 2: Separate Tables per Link Type

```sql
CREATE TABLE tracepoint_links (
    uuid TEXT PRIMARY KEY,
    kernel_program_id INTEGER NOT NULL,
    kernel_link_id INTEGER,
    pin_path TEXT,
    "group" TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE xdp_links (
    uuid TEXT PRIMARY KEY,
    kernel_program_id INTEGER NOT NULL,
    kernel_link_id INTEGER,
    pin_path TEXT,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    position INTEGER NOT NULL,
    proceed_on TEXT NOT NULL,
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

-- ... 6 more tables
```

**Pros:**
- Illegal states unrepresentable
- Type-specific NOT NULL constraints
- Schema self-documents requirements
- Queries scoped to type are clean

**Cons:**
- Polymorphic queries require UNION ALL across 8 tables
- 8x the Go types and store methods
- `detach <uuid>` doesn't know which table to query
- Adding new link type requires new table + new code
- **UUID uniqueness not enforced across tables**

## Option 3: Registry Table + Type-Specific Detail Tables (Recommended)

This option combines **normalised storage**, **hard invariants**, and
**polymorphic access** without relying on wide nullable tables or
`UNION ALL` views.

The core idea is to split link state into two layers:

1. **A single registry table** containing all polymorphic, common fields
2. **Type-specific detail tables** containing only the fields required for
   that link type

This mirrors the conceptual model:

* The registry represents *"a managed link exists"*
* The detail table represents *"this is what kind of link it is"*

### Schema Overview

#### Link Registry (Polymorphic Core)

```sql
CREATE TABLE link_registry (
    uuid TEXT PRIMARY KEY,
    link_type TEXT NOT NULL,              -- tracepoint, kprobe, xdp, tc, tcx, ...
    kernel_program_id INTEGER NOT NULL,
    kernel_link_id INTEGER,
    pin_path TEXT,
    created_at TEXT NOT NULL,

    FOREIGN KEY (kernel_program_id)
      REFERENCES managed_programs(kernel_id)
      ON DELETE CASCADE
) STRICT;

CREATE INDEX idx_link_registry_program
    ON link_registry(kernel_program_id);

CREATE INDEX idx_link_registry_type
    ON link_registry(link_type);
```

**Invariants:**

* UUIDs are globally unique across all link types
* Every managed link exists in exactly one place
* Polymorphic operations (`list`, `detach <uuid>`) operate only on this
  table

---

#### Type-Specific Detail Tables

Each link type gets its own table containing **only** the fields relevant
to that attachment model. Each table is in a 1:1 relationship with
`link_registry`.

##### Tracepoint Links

```sql
CREATE TABLE tracepoint_link_details (
    uuid TEXT PRIMARY KEY,
    tracepoint_group TEXT NOT NULL,
    tracepoint_name  TEXT NOT NULL,

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;
```

##### Kprobe / Kretprobe Links

```sql
CREATE TABLE kprobe_link_details (
    uuid TEXT PRIMARY KEY,
    fn_name TEXT NOT NULL,
    offset INTEGER NOT NULL DEFAULT 0,
    retprobe INTEGER NOT NULL DEFAULT 0 CHECK (retprobe IN (0,1)),

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;
```

##### Uprobe / Uretprobe Links

```sql
CREATE TABLE uprobe_link_details (
    uuid TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    fn_name TEXT,
    offset INTEGER NOT NULL DEFAULT 0,
    pid INTEGER,
    retprobe INTEGER NOT NULL DEFAULT 0 CHECK (retprobe IN (0,1)),

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;
```

##### Fentry Links

```sql
CREATE TABLE fentry_link_details (
    uuid TEXT PRIMARY KEY,
    fn_name TEXT NOT NULL,

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;
```

##### Fexit Links

```sql
CREATE TABLE fexit_link_details (
    uuid TEXT PRIMARY KEY,
    fn_name TEXT NOT NULL,

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;
```

##### XDP Links (Dispatcher-Based)

```sql
CREATE TABLE xdp_link_details (
    uuid TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    priority INTEGER NOT NULL CHECK (priority >= 0),
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    proceed_on TEXT NOT NULL CHECK (json_valid(proceed_on)),
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER NOT NULL,

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;

-- Enforce unique position per dispatcher
CREATE UNIQUE INDEX uq_xdp_dispatcher_position
    ON xdp_link_details(dispatcher_id, nsid, position);
```

##### TC Links (Dispatcher-Based)

```sql
CREATE TABLE tc_link_details (
    uuid TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('ingress','egress')),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    proceed_on TEXT NOT NULL CHECK (json_valid(proceed_on)),
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER NOT NULL,

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;

-- Enforce unique position per dispatcher + direction
CREATE UNIQUE INDEX uq_tc_dispatcher_position
    ON tc_link_details(dispatcher_id, direction, nsid, position);
```

##### TCX Links (Kernel Multi-Attach)

```sql
CREATE TABLE tcx_link_details (
    uuid TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('ingress','egress')),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    netns TEXT,
    nsid INTEGER,

    FOREIGN KEY (uuid)
      REFERENCES link_registry(uuid)
      ON DELETE CASCADE
) STRICT;
```

---

### Constraints and Invariants

The schema enforces these invariants at the database level:

| Invariant | Enforcement |
|-----------|-------------|
| UUID globally unique | `link_registry.uuid` is PRIMARY KEY |
| Link belongs to valid program | FK to `managed_programs` with CASCADE |
| Detail exists for every link | Application-level (insert both atomically) |
| Position in valid range | `CHECK (position BETWEEN 0 AND 9)` |
| Priority non-negative | `CHECK (priority >= 0)` |
| Direction valid | `CHECK (direction IN ('ingress','egress'))` |
| Proceed-on is valid JSON | `CHECK (json_valid(proceed_on))` |
| Unique position per dispatcher | UNIQUE INDEX on `(dispatcher_id, nsid, position)` |
| Retprobe is boolean | `CHECK (retprobe IN (0,1))` |

---

### Query Patterns

| Operation | Query |
|-----------|-------|
| List all links | `SELECT * FROM link_registry` |
| Links for program | `SELECT * FROM link_registry WHERE kernel_program_id = ?` |
| Find link type | `SELECT link_type FROM link_registry WHERE uuid = ?` |
| Get link details | Lookup type, then query corresponding detail table |
| Delete link | `DELETE FROM link_registry WHERE uuid = ?` (cascade cleans up) |

**No UNIONs, no views, no ambiguity.**

---

### Two-Phase Lookup (Type-Safe)

```go
// LinkSummary contains the common fields from link_registry.
type LinkSummary struct {
    UUID            string
    LinkType        LinkType
    KernelProgramID uint32
    KernelLinkID    uint32
    PinPath         string
    CreatedAt       time.Time
}

// LinkDetails is a marker interface for type-specific details.
type LinkDetails interface {
    linkDetails()
}

type TracepointDetails struct {
    Group string
    Name  string
}
func (TracepointDetails) linkDetails() {}

type XDPDetails struct {
    Interface    string
    Ifindex      uint32
    Priority     int32
    Position     int32
    ProceedOn    []int32
    Netns        string
    Nsid         uint32
    DispatcherID uint32
}
func (XDPDetails) linkDetails() {}

// ... other detail types

func (s *Store) GetLink(ctx context.Context, uuid string) (LinkSummary, LinkDetails, error) {
    var summary LinkSummary

    err := s.db.QueryRowContext(ctx,
        `SELECT uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at
         FROM link_registry WHERE uuid = ?`,
        uuid,
    ).Scan(
        &summary.UUID,
        &summary.LinkType,
        &summary.KernelProgramID,
        &summary.KernelLinkID,
        &summary.PinPath,
        &summary.CreatedAt,
    )
    if err != nil {
        return LinkSummary{}, nil, err
    }

    details, err := s.getLinkDetails(ctx, summary.LinkType, uuid)
    if err != nil {
        return LinkSummary{}, nil, err
    }

    return summary, details, nil
}

func (s *Store) getLinkDetails(ctx context.Context, linkType LinkType, uuid string) (LinkDetails, error) {
    switch linkType {
    case LinkTypeTracepoint:
        return s.getTracepointDetails(ctx, uuid)
    case LinkTypeXDP:
        return s.getXDPDetails(ctx, uuid)
    // ... other types
    default:
        return nil, fmt.Errorf("unknown link type: %s", linkType)
    }
}
```

---

### Why This Works Better Than a View

Compared to "8 tables + summary view", this approach:

1. **Enforces global UUID uniqueness** at the database level
2. **Simplifies detach/delete** to a single statement
3. **Avoids view maintenance** when adding new link types
4. **Keeps polymorphic queries cheap and obvious**
5. **Preserves strict type safety** in both SQL and Go

The registry table becomes the stable backbone; link-type detail tables
are free to evolve independently.

---

### Adding a New Link Type

With this pattern, adding a new link type requires:

1. Add new detail table (one `CREATE TABLE` statement)
2. Add new Go detail struct with `linkDetails()` marker
3. Add case to `getLinkDetails` switch
4. Update tests

**No view edits, no UNION changes, no touching existing tables.**

---

## Go Design Principles

### Keep `LinkSummary` as the Primary Polymorphic Type

In most codepaths you'll only need summary fields. Treat full detail as an
opt-in expansion:

* `ListLinks()` returns `[]LinkSummary`
* `GetLink(uuid)` returns `(LinkSummary, LinkDetails, error)`

This keeps the CLI fast and avoids pulling in per-type structs everywhere.

### Make Illegal States Unrepresentable at Construction Time

Force construction via functions rather than exporting struct fields:

```go
func NewXDPDetails(iface string, ifindex uint32, priority int32, ...) (XDPDetails, error) {
    if priority < 0 {
        return XDPDetails{}, fmt.Errorf("priority must be non-negative")
    }
    if position < 0 || position > 9 {
        return XDPDetails{}, fmt.Errorf("position must be 0-9")
    }
    // ...
    return XDPDetails{
        Interface: iface,
        Ifindex:   ifindex,
        Priority:  priority,
        // ...
    }, nil
}
```

Then your store can accept only validated types.

### Atomic Insert Pattern

When creating a link, insert into both tables in a transaction:

```go
func (s *Store) SaveTracepointLink(ctx context.Context, summary LinkSummary, details TracepointDetails) error {
    tx, err := s.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    _, err = tx.ExecContext(ctx,
        `INSERT INTO link_registry (uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        summary.UUID, summary.LinkType, summary.KernelProgramID,
        summary.KernelLinkID, summary.PinPath, summary.CreatedAt.Format(time.RFC3339))
    if err != nil {
        return err
    }

    _, err = tx.ExecContext(ctx,
        `INSERT INTO tracepoint_link_details (uuid, tracepoint_group, tracepoint_name)
         VALUES (?, ?, ?)`,
        summary.UUID, details.Group, details.Name)
    if err != nil {
        return err
    }

    return tx.Commit()
}
```

---

## Summary

**Use a registry table with per-type detail tables.**

This preserves all the benefits of normalised storage while eliminating the
weakest points of the pure multi-table approach (UUID collisions, view
churn, and deletion complexity). It aligns cleanly with bpfman's core rule:

> Persist intent and abstraction, not kernel facts — and make illegal
> states unrepresentable.

If you later add new attachment models (new dispatcher variants, kernel
extensions, or experimental link types), this structure absorbs them with
minimal disruption.
