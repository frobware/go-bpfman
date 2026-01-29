# SQL-Driven Coherency: Snapshot Layer

This document defines the snapshot/inspection layer used by the
SQL-driven coherency engine. A "snapshot" is best-effort observed state
from three sources (store, kernel, bpffs). The same inspection primitives
are reusable by the CLI and diagnostics; coherency consumes them by
persisting a snapshot into SQLite fact tables.

## Motivation

Multiple components need to query bpfman's state:

| Consumer | Purpose |
|----------|---------|
| Coherency engine | Gather facts into SQL for rule evaluation |
| CLI list commands | Display programs, links, dispatchers to users |
| Diagnostic tools | Inspect state for debugging and troubleshooting |

Rather than each consumer implementing its own inspection logic, we
define shared abstractions. The key insight: only the filesystem needs
a new public abstraction (to encapsulate path conventions). Kernel and
store already have interfaces (`interpreter.KernelOperations`,
`interpreter.Store`).

## Position in the Architecture

The snapshot abstractions defined here sit *above* the coherency engine.

They are reusable inspection primitives that expose the observable state
of bpfman from three sources:

- the kernel
- the bpfman-managed filesystem (bpffs)
- the persistent store (via public interfaces)

Consumers include:

- the SQL coherency engine (doctor / GC)
- CLI commands (`list`, `inspect`, future `adopt`)
- debugging and test tooling

Coherency does not own these abstractions; it consumes them.

**Terminology:** "Snapshot" in this document means observed state exposed
via iterators; it is not transactional across sources. Each source is
enumerated independently, reflecting a best-effort view at enumeration
time.

## Design Principles

1. **Streaming by default** — Iterators yield items one at a time.
   Consumers decide whether to collect into a slice, insert into SQL,
   or format for display. Bulk snapshots are a convenience for
   tests/debugging, not the primary API.

2. **Scanner returns parsed structures** — Path convention parsing
   happens once, in the scanner. Output types expose the semantic
   content (program ID, kernel ID, dispatcher coordinates) not raw
   paths.

3. **Scanner is read-only** — No mounting, no directory creation. Just
   inspection of an existing layout.

4. **Errors mean "cannot continue"** — Iterators yield errors only for
   failures that prevent further enumeration (e.g. directory unreadable).
   Malformed entries (unparseable filenames) are skipped silently or
   surfaced via an optional callback, not as iterator errors.

5. **Layered above coherency** — These abstractions are general-purpose.
   Coherency is one consumer that persists facts to SQL. CLI is another
   that formats for display. The abstractions don't know about SQL.

---

## Package Structure

```
bpffs/
├── scanner.go       # Public: Scanner, streaming iterators, Scan()
└── scanner_test.go

# Consumers:

coherency/
├── facts/
│   ├── schema.sql
│   ├── gather.go    # Uses Scanner + store + kernel, writes to SQL
│   └── gather_test.go
└── ...

cmd/bpfman/
└── ...              # CLI commands use Scanner + store + kernel
```

The `bpffs` package is a leaf dependency with no knowledge of its
consumers. Coherency and CLI both import it.

---

## Composing a Unified View

Consumers that need a combined kernel+store+bpffs view compose the three
sources in their own layer. The `bpffs` package intentionally does not
define a "global state" struct.

For CLI and diagnostics, a small composition helper can provide
display-friendly streams without SQL:

```go
// Package inspect composes kernel/store/bpffs to produce display-friendly
// streams. It performs no mutation and has no SQL dependency.
package inspect

type Sources struct {
    Store  interpreter.Store
    Kernel interpreter.KernelOperations
    FS     *bpffs.Scanner
}

// Programs returns a unified view: store data enriched with kernel/FS status.
func (s Sources) Programs(ctx context.Context) iter.Seq2[ProgramRow, error]

// Links returns link info from store, annotated with kernel liveness.
func (s Sources) Links(ctx context.Context) iter.Seq2[LinkRow, error]

// Dispatchers returns dispatcher info with kernel/FS cross-references.
func (s Sources) Dispatchers(ctx context.Context) iter.Seq2[DispatcherRow, error]
```

Where `ProgramRow` might include:

- store fields (name, type, pin path)
- `AliveInKernel bool` (via `kernel.Programs()`)
- `PinnedInFS bool` (via `scanner.ProgPins()` or `PathExists()`)

This keeps responsibilities clear:

| Layer | Responsibility |
|-------|----------------|
| `bpffs.Scanner` | Parse FS layout, yield typed facts |
| `interpreter.*` | Kernel and store access |
| `inspect.Sources` | Compose and correlate for display |
| `coherency/facts` | Compose and persist to SQL for rules |

Coherency uses SQL; CLI uses `inspect`. Both consume the same primitives.

---

## bpffs.Scanner (public)

The scanner encapsulates path conventions and provides streaming access
to bpfman's managed filesystem state.

```go
package bpffs

import (
    "context"
    "iter"

    "github.com/frobware/go-bpfman/config"
)

// Scanner provides read-only access to bpfman's filesystem layout.
type Scanner struct {
    dirs        config.RuntimeDirs
    OnMalformed func(path string, err error) // optional: called for unparseable entries
}

func NewScanner(dirs config.RuntimeDirs) *Scanner {
    return &Scanner{dirs: dirs}
}

// WithOnMalformed returns a Scanner that calls f for unparseable entries.
func (s *Scanner) WithOnMalformed(f func(path string, err error)) *Scanner {
    s.OnMalformed = f
    return s
}

// Streaming iterators (primary API)
// These yield parsed structures ready for consumption by any consumer.

func (s *Scanner) ProgPins(ctx context.Context) iter.Seq2[ProgPin, error]
func (s *Scanner) LinkDirs(ctx context.Context) iter.Seq2[LinkDir, error]
func (s *Scanner) MapDirs(ctx context.Context) iter.Seq2[MapDir, error]
func (s *Scanner) DispatcherDirs(ctx context.Context) iter.Seq2[DispatcherDir, error]
func (s *Scanner) DispatcherLinkPins(ctx context.Context) iter.Seq2[DispatcherLinkPin, error]

// PathExists checks if an arbitrary path exists on the filesystem.
// Unlike the layout iterators above, this is a general stat() probe
// used to verify store-recorded pin paths actually exist.
func (s *Scanner) PathExists(path string) bool

// Scan materialises everything into an FSState (for tests/debugging).
func (s *Scanner) Scan(ctx context.Context) (*FSState, error)
```

### Parsed types

These types expose the semantic content extracted from filesystem paths.
Path convention parsing happens once, in the scanner. Consumers use
these fields directly (coherency inserts into SQL, CLI formats for
display).

```go
// ProgPin represents a program pin: {dirs.FS}/prog_{kernel_id}
type ProgPin struct {
    Path     string
    KernelID uint32
}

// LinkDir represents a link directory: {dirs.FS}/links/{program_id}
type LinkDir struct {
    Path      string
    ProgramID uint32
}

// MapDir represents a map directory: {dirs.FS}/maps/{program_id}
type MapDir struct {
    Path      string
    ProgramID uint32
}

// DispatcherDir represents a dispatcher revision directory.
// Path: {dirs.FS}/{type}/dispatcher_{nsid}_{ifindex}_{revision}
// LinkCount is derived by counting link_* files in the directory.
type DispatcherDir struct {
    Path      string
    DispType  string // "xdp", "tc-ingress", "tc-egress"
    Nsid      uint64
    Ifindex   uint32
    Revision  uint32
    LinkCount int
}

// DispatcherLinkPin represents a dispatcher link pin (XDP only).
// Path: {dirs.FS}/{type}/dispatcher_{nsid}_{ifindex}_link
type DispatcherLinkPin struct {
    Path     string
    DispType string
    Nsid     uint64
    Ifindex  uint32
}
```

### FSState (convenience for tests/debugging)

```go
// FSState is a materialised snapshot of the filesystem.
// Use Scanner.Scan() to create, or construct directly in tests.
type FSState struct {
    ProgPins           []ProgPin
    LinkDirs           []LinkDir
    MapDirs            []MapDir
    DispatcherDirs     []DispatcherDir
    DispatcherLinkPins []DispatcherLinkPin
}
```

---

## Example Consumer: Coherency Gather

This section shows how the coherency engine uses these abstractions.
Gather iterates all three sources and writes facts to SQLite. Other
consumers (CLI, diagnostics) would iterate similarly but format output
differently.

```go
package facts

func GatherFacts(
    ctx context.Context,
    store interpreter.Store,
    kernel interpreter.KernelOperations,
    dirs config.RuntimeDirs,
    opts ...Option,
) (*FactsDB, error) {
    db, err := openFactsDB(opts)
    if err != nil {
        return nil, err
    }

    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        db.Close()
        return nil, err
    }
    defer tx.Rollback()

    if err := applyDDL(ctx, tx); err != nil {
        db.Close()
        return nil, err
    }

    // 1. Gather store facts (needed for TC probes and pin existence checks)
    storeCtx := &storeGatherContext{tx: tx}
    if err := gatherStoreFacts(ctx, tx, store, storeCtx); err != nil {
        db.Close()
        return nil, err
    }

    // 2. Gather kernel facts (uses dispatcher info for TC probes)
    if err := gatherKernelFacts(ctx, tx, kernel, storeCtx.tcDispatchers); err != nil {
        db.Close()
        return nil, err
    }

    // 3. Gather FS facts (uses pin paths for existence checks)
    scanner := bpffs.NewScanner(dirs)
    if err := gatherFSFacts(ctx, tx, scanner, storeCtx.pinPaths); err != nil {
        db.Close()
        return nil, err
    }

    if err := tx.Commit(); err != nil {
        db.Close()
        return nil, err
    }

    return &FactsDB{DB: db}, nil
}
```

### Store facts (inline)

```go
type storeGatherContext struct {
    tx            *sql.Tx
    pinPaths      []string          // for FS pin existence checks
    tcDispatchers []tcDispatcherKey // for kernel TC filter probes
}

type tcDispatcherKey struct {
    dispType string
    nsid     uint64
    ifindex  uint32
    priority uint32
}

func gatherStoreFacts(
    ctx context.Context,
    tx *sql.Tx,
    store interpreter.Store,
    out *storeGatherContext,
) error {
    // Programs
    programs, err := store.List(ctx)
    if err != nil {
        return recordGatherStatus(ctx, tx, "store", false, err.Error())
    }

    stmt, _ := tx.PrepareContext(ctx, `
        INSERT INTO db_program(kernel_id, pin_path, has_pin_path, program_name, program_type)
        VALUES (?, ?, ?, ?, ?)
    `)
    defer stmt.Close()

    for id, p := range programs {
        hasPin := 0
        if p.PinPath != "" {
            hasPin = 1
            out.pinPaths = append(out.pinPaths, p.PinPath)
        }
        if _, err := stmt.ExecContext(ctx, id, p.PinPath, hasPin, p.ProgramName, p.ProgramType.String()); err != nil {
            return err
        }
    }

    // Links
    links, err := store.ListLinks(ctx)
    if err != nil {
        return recordGatherStatus(ctx, tx, "store_links", false, err.Error())
    }

    // ... insert into db_link, collect pin paths ...

    // Dispatchers
    dispatchers, err := store.ListDispatchers(ctx)
    if err != nil {
        return recordGatherStatus(ctx, tx, "store_dispatchers", false, err.Error())
    }

    // ... insert into db_dispatcher, collect TC dispatchers for probing ...

    // Dispatcher link counts
    for _, d := range dispatchers {
        count, _ := store.CountDispatcherLinks(ctx, d.KernelID)
        // insert into db_dispatcher_link_count
    }

    return recordGatherStatus(ctx, tx, "store", true, "")
}
```

### Kernel facts (inline)

```go
func gatherKernelFacts(
    ctx context.Context,
    tx *sql.Tx,
    kernel interpreter.KernelOperations,
    tcDispatchers []tcDispatcherKey,
) error {
    // Programs
    var progErr error
    stmt, _ := tx.PrepareContext(ctx, `INSERT INTO k_program(kernel_id) VALUES (?)`)
    for kp, err := range kernel.Programs(ctx) {
        if err != nil {
            progErr = err
            break
        }
        stmt.ExecContext(ctx, kp.ID)
    }
    stmt.Close()
    recordGatherStatus(ctx, tx, "kernel_programs", progErr == nil, errorString(progErr))

    // Links
    var linkErr error
    stmt, _ = tx.PrepareContext(ctx, `INSERT INTO k_link(kernel_id) VALUES (?)`)
    for kl, err := range kernel.Links(ctx) {
        if err != nil {
            linkErr = err
            break
        }
        stmt.ExecContext(ctx, kl.ID)
    }
    stmt.Close()
    recordGatherStatus(ctx, tx, "kernel_links", linkErr == nil, errorString(linkErr))

    // TC filter probes
    stmt, _ = tx.PrepareContext(ctx, `
        INSERT INTO k_tc_filter(disp_type, nsid, ifindex, ok, handle)
        VALUES (?, ?, ?, ?, ?)
    `)
    for _, d := range tcDispatchers {
        handle, err := kernel.FindTCFilterHandle(ctx, d.ifindex, parentFromType(d.dispType), d.priority)
        ok := 0
        if err == nil {
            ok = 1
        }
        stmt.ExecContext(ctx, d.dispType, d.nsid, d.ifindex, ok, handle)
    }
    stmt.Close()

    return nil
}
```

### FS facts (using scanner)

```go
func gatherFSFacts(
    ctx context.Context,
    tx *sql.Tx,
    scanner *bpffs.Scanner,
    pinPaths []string,
) error {
    var fsErr error

    // ProgPins (streaming)
    stmt, _ := tx.PrepareContext(ctx, `
        INSERT INTO fs_prog_pin(path, kernel_id) VALUES (?, ?)
    `)
    for pin, err := range scanner.ProgPins(ctx) {
        if err != nil {
            fsErr = err
            break
        }
        stmt.ExecContext(ctx, pin.Path, pin.KernelID)
    }
    stmt.Close()

    // LinkDirs (streaming)
    stmt, _ = tx.PrepareContext(ctx, `
        INSERT INTO fs_link_dir(path, program_id) VALUES (?, ?)
    `)
    for dir, err := range scanner.LinkDirs(ctx) {
        if err != nil {
            fsErr = err
            break
        }
        stmt.ExecContext(ctx, dir.Path, dir.ProgramID)
    }
    stmt.Close()

    // MapDirs (streaming)
    // ... same pattern ...

    // DispatcherDirs (streaming, includes LinkCount)
    stmt, _ = tx.PrepareContext(ctx, `
        INSERT INTO fs_dispatcher_dir(path, disp_type, nsid, ifindex, revision)
        VALUES (?, ?, ?, ?, ?)
    `)
    stmtCount, _ := tx.PrepareContext(ctx, `
        INSERT INTO fs_dispatcher_link_count(disp_type, nsid, ifindex, revision, link_count)
        VALUES (?, ?, ?, ?, ?)
    `)
    for dir, err := range scanner.DispatcherDirs(ctx) {
        if err != nil {
            fsErr = err
            break
        }
        stmt.ExecContext(ctx, dir.Path, dir.DispType, dir.Nsid, dir.Ifindex, dir.Revision)
        stmtCount.ExecContext(ctx, dir.DispType, dir.Nsid, dir.Ifindex, dir.Revision, dir.LinkCount)
    }
    stmt.Close()
    stmtCount.Close()

    // DispatcherLinkPins
    // ... same pattern ...

    // Pin existence checks (for DB paths)
    stmt, _ = tx.PrepareContext(ctx, `INSERT INTO fs_pin(path) VALUES (?)`)
    for _, path := range pinPaths {
        if scanner.PathExists(path) {
            stmt.ExecContext(ctx, path)
        }
    }
    stmt.Close()

    recordGatherStatus(ctx, tx, "fs", fsErr == nil, errorString(fsErr))
    return nil
}
```

---

## FS Scan Quality

Like kernel enumeration, FS scanning can fail partially:

| Failure | Handling |
|---------|----------|
| Directory scan fails (permission, etc.) | Record `gather_status(source='fs', ok=0, error='...')`, stop that scan |
| Single entry malformed (unparseable name) | Skip entry, optionally record finding `fs-entry-unparseable` |
| Path doesn't exist for pin check | Normal — just don't insert into `fs_pin` |

The "best effort snapshot" story applies consistently across sources.

---

## Testing

### Rule tests (pure SQL)

Unchanged. `INSERT` facts directly, run rule SQL, assert findings.
No scanner involved.

### Scanner tests

```go
func TestScanner_ProgPins(t *testing.T) {
    // Create temp dir with prog_123, prog_456
    dir := t.TempDir()
    os.WriteFile(filepath.Join(dir, "prog_123"), nil, 0644)
    os.WriteFile(filepath.Join(dir, "prog_456"), nil, 0644)

    scanner := bpffs.NewScanner(config.RuntimeDirs{FS: dir})

    var pins []bpffs.ProgPin
    for pin, err := range scanner.ProgPins(context.Background()) {
        require.NoError(t, err)
        pins = append(pins, pin)
    }

    assert.Len(t, pins, 2)
    assert.Contains(t, pins, bpffs.ProgPin{Path: filepath.Join(dir, "prog_123"), KernelID: 123})
    assert.Contains(t, pins, bpffs.ProgPin{Path: filepath.Join(dir, "prog_456"), KernelID: 456})
}
```

### Gather tests

Option A: Use real temp dirs + stub store/kernel.
Option B: Add `FSSource` interface for fake scanner (optional).

```go
// Optional interface for gather tests
type FSSource interface {
    ProgPins(ctx context.Context) iter.Seq2[ProgPin, error]
    LinkDirs(ctx context.Context) iter.Seq2[LinkDir, error]
    // ...
    PathExists(path string) bool
}
```

Given rule tests are pure SQL, this is optional — but it does make
gather tests cleaner if you want to avoid temp dirs entirely.

---

## Summary

### Abstractions

| Component | Public? | Notes |
|-----------|---------|-------|
| `bpffs.Scanner` | Yes | Encapsulates path conventions, streaming iterators |
| `bpffs.FSState` | Yes | Materialised snapshot for tests/debugging |
| `bpffs.ProgPin`, etc. | Yes | Parsed types with semantic fields |
| `interpreter.KernelOperations` | Yes | Existing interface for kernel state |
| `interpreter.Store` | Yes | Existing interface for persistent store |

### Consumers

| Consumer | What it does with the abstractions |
|----------|-----------------------------------|
| Coherency gather | Iterates all three sources, inserts into SQL fact tables |
| CLI list commands | Iterates relevant sources, formats for terminal display |
| Diagnostic tools | Queries specific state for troubleshooting |

The scanner is the one *new* public abstraction because it encapsulates
path conventions that don't exist elsewhere. Kernel and store already
have public interfaces. All three sources are available to any consumer
that needs a snapshot of bpfman's state.
