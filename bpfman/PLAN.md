# Minimal bpfman experiment

## Goal

Prove out the architecture: Go orchestration + tiny C/libbpf shim + SQLite
persistence. Get `load` working end-to-end.

## Scope

- **In scope:** `load` a BPF program, persist the result, `list` managed
  programs
- **Out of scope:** attach, detach, unload, GC, reconciliation, Kubernetes
  integration, container builds (for now)

## Development approach

Host-first: build and run everything locally against the host's BPF filesystem.
Container/pod deployment comes later once the core works.

## Architecture

```
┌─────────────────┐      JSON/stdin/stdout      ┌──────────────────┐
│  bpfman (Go)    │ ◄──────────────────────────► │ bpfman-kernel (C)│
│                 │                              │                  │
│  - CLI          │                              │  - libbpf        │
│  - SQLite       │                              │  - stateless     │
│  - Policy       │                              │  - no DB         │
└─────────────────┘                              └──────────────────┘
```

## Components

### bpfman-kernel (C)

- Single op: `load`
- Input: object file path, program name, pin path
- Output: program_id, map_ids[], pinned paths
- Uses libbpf

### bpfman (Go)

- CLI: `bpfman load <object.o> --program <name> --pin-path <path>`
- CLI: `bpfman list`
- SQLite: programs table, maps table
- Calls shim, persists result

### SQLite schema (minimal)

- `programs`: id, kernel_id, name, type, pinned_path, created_at
- `maps`: id, kernel_id, name, pinned_path
- `program_maps`: program_id, map_id

## Milestones

1. **C shim loads a program**
   - Hardcoded test: load an XDP program, pin it, print JSON to stdout
   - No Go yet

2. **Go calls shim**
   - Go spawns shim, passes JSON on stdin, reads JSON from stdout
   - No DB yet, just prints result

3. **Go persists to SQLite**
   - Schema created
   - `load` stores result
   - `list` queries and prints

4. **End-to-end test**
   - `bpfman load foo.o --program xdp_pass --pin-path /sys/fs/bpf/test/prog`
   - `bpfman list` shows it

## Directory structure

```
bpfman/
  cmd/
    bpfman/
      main.go        # CLI entry point
  internal/
    db/              # SQLite schema + queries
    shim/            # Go code to invoke C shim
  bpfman-kernel/
    main.c           # C shim
    Makefile
```

## Open questions (defer for now)

- Exact JSON schema (nail down during implementation)
- Error handling conventions
- Where to put the SQLite DB file
- Which program types to support first (XDP is simplest)
