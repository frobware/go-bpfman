# SQL-Driven Coherency: Snapshots

**This document has been superseded.**

The snapshot/inspection layer is now documented in [INSPECT.md](INSPECT.md).

Key points:

- The `inspect` package provides the "state of the bpfman world" correlation
  layer, used by CLI and diagnostics.

- The `bpffs.Scanner` is a leaf primitive for filesystem enumeration.

- Coherency (`manager/coherency.go`) maintains its own `GatherState` for
  rule evaluation, sharing `bpffs.Scanner` as the FS primitive.

See [INSPECT.md](INSPECT.md) for the current design.
