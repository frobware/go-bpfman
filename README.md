# bpffs-csi-driver

A minimal CSI (Container Storage Interface) driver for learning and experimentation. Currently creates empty volumes; designed to evolve toward mounting bpffs and exposing pinned BPF maps to containers.

## What is CSI?

CSI is a standardised gRPC API that lets Kubernetes delegate storage operations to external drivers. Instead of Kubernetes knowing how to talk to every storage system, it speaks one protocol and the driver translates.

### The players

- **Kubelet** - the node agent that runs pods
- **Our driver** - listens on a Unix socket, answers gRPC calls
- **Node-driver-registrar** - sidecar that introduces our driver to kubelet

### What happens at startup

1. Our DaemonSet starts on each node
2. The registrar sidecar tells kubelet: "There's a driver called `bpffs.csi.frobware.io` at this socket"
3. Kubelet notes this down in its plugin registry

### What happens when a pod wants a volume

```
Pod spec says:
  "I want a volume from bpffs.csi.frobware.io"
       │
       ▼
Kubelet sees this, calls our driver:
  "NodePublishVolume please, put it at /var/lib/kubelet/pods/<pod-id>/volumes/..."
       │
       ▼
Our driver does something at that path
  (currently: creates empty dir + marker file)
  (future: mount bpffs, expose BPF maps)
       │
       ▼
Kubelet bind-mounts that path into the container
       │
       ▼
Container sees files at the mount point
```

### When the pod dies

```
Kubelet calls: "NodeUnpublishVolume please"
       │
       ▼
Our driver cleans up the directory
```

## Project structure

```
bpffs-csi-driver/
  main.go                 # Entry point, flag parsing, signal handling
  pkg/driver/
    driver.go             # gRPC server setup
    identity.go           # Identity service (GetPluginInfo, Probe)
    node.go               # Node service (NodePublishVolume, etc.)
  deploy/
    csidriver.yaml        # CSIDriver API object
    daemonset.yaml        # DaemonSet with registrar sidecar
    test-pod.yaml         # Example pod using the driver
  Dockerfile
  Makefile
```

## Building and deploying

Requires a Kubernetes cluster. For local development, use kind:

```bash
# Build image and load into kind
make kind-load

# Deploy to cluster
make deploy

# Check status
make status

# View driver logs
make logs

# Rebuild and redeploy
make redeploy
```

## Testing

Deploy the test pod:

```bash
kubectl apply -f deploy/test-pod.yaml
kubectl exec bpffs-test-pod -- ls -la /bpf
kubectl exec bpffs-test-pod -- cat /bpf/csi-volume-info.txt
```

## CSI services implemented

### Identity service

| Method | Purpose |
|--------|---------|
| `GetPluginInfo` | Returns driver name and version |
| `GetPluginCapabilities` | Advertises what the driver supports |
| `Probe` | Health check |

### Node service

| Method | Purpose |
|--------|---------|
| `NodeGetInfo` | Returns the node ID |
| `NodeGetCapabilities` | Advertises node-level capabilities |
| `NodePublishVolume` | "Mount" the volume at target path |
| `NodeUnpublishVolume` | Clean up when pod is removed |

## Configuration

The driver accepts these flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--driver-name` | `bpffs.csi.frobware.io` | CSI driver name |
| `--endpoint` | `unix:///csi/csi.sock` | gRPC endpoint |
| `--node-id` | hostname | Node identifier |
| `--log-format` | `text` | Log format: text or json |

## Future work

- Mount actual bpffs instead of empty directories
- Expose specific pinned BPF maps based on volumeAttributes
- Implement staging (STAGE_UNSTAGE_VOLUME capability) for shared BPF resources
- Report volume health via VOLUME_CONDITION capability
