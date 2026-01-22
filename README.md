# bpfman

A minimal BPF program manager for Kubernetes with an integrated CSI driver. Loads BPF programs, pins them to bpffs, and exposes maps to containers via CSI volumes.

## Overview

bpfman runs as a DaemonSet on each node, providing:

- **gRPC API** for loading/unloading BPF programs
- **CSI driver** for exposing BPF maps to pods
- **SQLite store** for tracking managed programs
- **Garbage collection** for cleaning up stale resources

### How it works

```
1. Load BPF program via CLI
   bpfman load file -m bpfman.io/application=stats stats.o count_sched_switch
        |
        v
2. Program pinned to bpffs
   /run/bpfman/fs/<id>/count_sched_switch
   /run/bpfman/fs/<id>/stats_map
        |
        v
3. Pod requests CSI volume with metadata selector
   volumes:
     - name: bpf-maps
       csi:
         driver: csi.go-bpfman.io
         volumeAttributes:
           bpfman.io/application: stats
        |
        v
4. CSI driver re-pins matching maps to pod's volume
   Container sees: /bpf/stats_map
```

## Project structure

```
bpfman/
├── cmd/bpfman/           CLI and daemon entry point
├── pkg/
│   ├── bpfman/
│   │   ├── domain/       Pure data types
│   │   ├── action/       Reified effects
│   │   ├── compute/      Pure business logic
│   │   ├── interpreter/  I/O implementations
│   │   │   ├── store/    SQLite, in-memory stores
│   │   │   └── kernel/   cilium/ebpf adapter
│   │   ├── manager/      Orchestration layer
│   │   └── server/       gRPC server
│   └── csi/driver/       CSI implementation
├── manifests/            Kubernetes manifests
├── examples/             Example applications
└── proto/                gRPC service definitions
```

## Building and deploying

Create a kind cluster with bpffs mounted:

```bash
make kind-create
```

Build and deploy:

```bash
make bpfman-deploy    # Build image, load to kind, deploy
make bpfman-logs      # Follow logs
make bpfman-delete    # Remove from cluster
```

Run `make` to see all available targets.

## Usage

### Loading a BPF program

```bash
# Exec into bpfman pod
kubectl exec -it -n bpfman daemonset/bpfman-daemon-go -c bpfman -- sh

# Load program with metadata for CSI matching
bpfman load file -m bpfman.io/application=stats /opt/bpf/stats.o count_sched_switch
```

### Consuming BPF maps in a pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: stats-reader
spec:
  containers:
    - name: reader
      image: stats-reader:dev
      volumeMounts:
        - name: bpf-maps
          mountPath: /bpf
  volumes:
    - name: bpf-maps
      csi:
        driver: csi.go-bpfman.io
        volumeAttributes:
          bpfman.io/application: stats
```

### Listing programs

```bash
bpfman list           # List managed programs
bpfman list --all     # Include kernel programs
```

### Garbage collection

```bash
bpfman gc             # Show what would be cleaned (dry-run)
bpfman gc --prune     # Actually clean up
```

## gRPC API

bpfman exposes a gRPC API on `/run/bpfman-sock/bpfman.sock`:

| Method | Description |
|--------|-------------|
| `Load` | Load and pin a BPF program |
| `Unload` | Unpin and remove a program |
| `List` | List managed programs |
| `Get` | Get program details |

## Key paths

| Path | Description |
|------|-------------|
| `/run/bpfman-sock/bpfman.sock` | gRPC socket |
| `/run/bpfman/db/store.db` | SQLite state |
| `/run/bpfman/fs/` | BPF pins |
| `/var/lib/kubelet/plugins/csi.go-bpfman.io/csi.sock` | CSI socket |

## Design

bpfman follows functional programming principles:

- **SANS-IO**: Core logic performs no I/O; effects are reified as data
- **Fetch/Compute/Execute**: Clear separation of phases
- **Interface segregation**: Small, focused interfaces

See [CLAUDE.md](CLAUDE.md) for detailed design documentation.
