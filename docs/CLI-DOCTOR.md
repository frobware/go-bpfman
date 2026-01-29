# Running bpfman doctor

`bpfman doctor` performs read-only coherency checks across the three
state sources: database, kernel, and filesystem. It reports
discrepancies that may indicate stale state, resource leaks, or
conditions that could cause operations to fail (e.g., EBUSY).

## Basic usage

```
bpfman doctor
```

If all checks pass:
```
All checks passed. Database, kernel, and filesystem are coherent.
```

If issues are found, they are grouped by category and rule:
```
Checking kernel vs database...
  [kernel-program-pinned-but-not-in-db] (3)
    WARNING  Kernel program 12345 is pinned under /run/bpfman/fs/prog_12345 but not tracked in DB; may cause EBUSY

Summary: 0 error(s), 3 warning(s)
```

## Explaining rules

List all coherency rules:
```
bpfman doctor explain
```

Get details about a specific rule:
```
bpfman doctor explain kernel-program-pinned-but-not-in-db
```

## Running in Kubernetes / OpenShift

In containerised deployments, the bpfman daemon container typically
has `BPFMAN_MODE=bpfman-rpc` set, which restricts the CLI to
serve-only mode. To run doctor, unset this variable:

```
oc exec $(oc get pod -n bpfman -l name=bpfman-daemon -o name) -n bpfman -c bpfman -- env -u BPFMAN_MODE /bpfman doctor
```

Breaking this down:
- `oc get pod -n bpfman -l name=bpfman-daemon -o name` finds the
  daemon pod by label and returns `pod/<name>`
- `-n bpfman` specifies the namespace
- `-c bpfman` targets the bpfman container
- `env -u BPFMAN_MODE` unsets the environment variable
- `/bpfman doctor` runs the doctor command

For kubectl, replace `oc` with `kubectl`.

### Targeting a specific node

If running a daemonset across multiple nodes and you want to check a
specific node (replace $NODE with the node name):

```
oc exec $(oc get pod -n bpfman -l name=bpfman-daemon --field-selector spec.nodeName=$NODE -o name) -n bpfman -c bpfman -- env -u BPFMAN_MODE /bpfman doctor
```

## Understanding the output

### Severity levels

- **ERROR**: State that will cause operations to fail. A database
  record references a kernel object that no longer exists.
- **WARNING**: Stale artefacts that do not block operations but
  indicate incomplete cleanup or potential issues.

### Categories

- **db-vs-kernel**: Database records that have no corresponding
  kernel object.
- **db-vs-fs**: Database records whose expected filesystem pins are
  missing.
- **fs-vs-db**: Filesystem entries with no corresponding database
  record (orphans).
- **kernel-vs-db**: Kernel programs pinned under bpfman's root but
  not tracked in the database (EBUSY risk).
- **consistency**: Derived state mismatches (e.g., link counts).
- **enumeration**: Warnings about incomplete kernel enumeration.

### Common findings

**kernel-program-pinned-but-not-in-db**: A program is pinned under
bpfman's bpffs root and still alive in the kernel, but has no
database record. This typically happens after database deletion or
corruption. These "live orphans" may occupy hook points (XDP, TC),
causing EBUSY when attaching new programs to the same interface.

**orphan-fs-entries**: Filesystem entries (pins, directories) with no
database record. These waste space but don't affect running programs.

## Related commands

- `bpfman gc` — Remove stale state (respects live orphans)
- `bpfman gc <rule>...` — Run specific GC rules
- `bpfman list` — List managed programs
