# Testing the Stats Example

This document describes how to test the complete workflow: loading a BPF
program, pinning its map, attaching to a tracepoint, and reading statistics
from a container via the CSI driver.

## Prerequisites

- A running kind cluster named `bpfman-deployment`
- Docker for building images

Create the cluster if it doesn't exist:

```bash
kind create cluster --name bpfman-deployment
kubectl create namespace bpfman
```

## Step 1: Build and Deploy bpfman

Build the bpfman image and deploy it to the cluster:

```bash
make bpfman-deploy
```

This will:
- Build the bpfman-builder image (if needed)
- Build the bpfman image with embedded stats.o BPF program
- Load the image into the kind cluster
- Deploy the CSI driver and bpfman DaemonSet

Verify bpfman is running:

```bash
kubectl -n bpfman get pods -l app=bpfman-daemon-go
```

Expected output:
```
NAME                     READY   STATUS    RESTARTS   AGE
bpfman-daemon-go-xxxxx   2/2     Running   0          30s
```

## Step 2: Load the BPF Program

Load the stats BPF program with metadata that the CSI driver will use to
locate it:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  bpfman load -m bpfman.io/ProgramName=my-stats \
  /opt/bpf/stats.o count_context_switches /sys/fs/bpf/go-bpfman/my-stats
```

The `-m bpfman.io/ProgramName=my-stats` flag attaches metadata that the CSI
driver uses to find the program when a pod requests it.

## Step 3: Attach to Tracepoint

Attach the loaded program to the `sched_switch` tracepoint:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  bpfman attach tracepoint /sys/fs/bpf/go-bpfman/my-stats/count_context_switches \
  sched sched_switch --link-pin-path /sys/fs/bpf/go-bpfman/my-stats/link
```

Verify the program is loaded and attached:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  ls -la /sys/fs/bpf/go-bpfman/my-stats/
```

Expected output:
```
total 0
drwxr-xr-x 2 root root 0 Jan 20 13:26 .
drwxr-xr-x 3 root root 0 Jan 20 13:26 ..
-rw------- 1 root root 0 Jan 20 13:26 count_context_switches
-rw------- 1 root root 0 Jan 20 13:26 link
-rw------- 1 root root 0 Jan 20 13:26 stats_map
```

## Step 4: Deploy the Stats Reader

Build and deploy the stats-reader application:

```bash
make stats-reader-deploy
```

The stats-reader pod requests a CSI volume with these attributes:

```yaml
volumes:
  - name: bpf-maps
    csi:
      driver: csi.go-bpfman.io
      volumeAttributes:
        csi.bpfman.io/program: "my-stats"
        csi.bpfman.io/maps: "stats_map"
```

The CSI driver:
1. Looks up the program by the `bpfman.io/ProgramName=my-stats` metadata
2. Finds the `stats_map` in the program's pin directory
3. Bind-mounts it into the container at `/bpf/stats_map`

## Step 5: View Statistics

Watch the stats-reader output:

```bash
kubectl logs -f stats-reader
```

Expected output:
```
2026/01/20 15:56:37 Opening map at /bpf/stats_map
2026/01/20 15:56:37 Map opened successfully (type=Hash, keySize=4, valueSize=24)
2026/01/20 15:56:37 Polling every 5s, showing top 10 processes by context switches

--- Top 10 processes by context switches (last 5s) ---
PID               Total CS        Delta CS
------------------------------------------
0                 73907346           53816
43159              9818966            6018
43220              6058384            3856
...

Total processes tracked: 1024
```

The output shows:
- **PID**: Process ID
- **Total CS**: Total context switches since the BPF program was loaded
- **Delta CS**: Context switches in the last polling interval

## Cleanup

Remove the stats-reader pod:

```bash
make stats-reader-delete
```

Unload the BPF program:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  bpfman unload /sys/fs/bpf/go-bpfman/my-stats
```

Remove bpfman:

```bash
make bpfman-delete
```

## Troubleshooting

### Stats-reader fails to start

Check if the BPF program is loaded with the correct metadata:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  bpfman list --maps /sys/fs/bpf/go-bpfman
```

### CSI volume mount fails

Check bpfman logs for CSI-related errors:

```bash
kubectl -n bpfman logs daemonset/bpfman-daemon-go -c bpfman | grep -i csi
```

### Map is empty

Ensure the tracepoint is attached. The `link` file should exist in the
program's pin directory. If missing, run the attach command again.
