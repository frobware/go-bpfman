# Testing the Stats Example

This document describes how to test the complete workflow: loading a BPF
program, pinning its map, attaching to a tracepoint, and reading statistics
from a container via the CSI driver.

## Prerequisites

- Docker for building images
- kind installed

Create the cluster if it doesn't exist:

```bash
make kind-create
```

This creates a kind cluster named `bpfman-go` with bpffs mounted on nodes.

## Step 1: Build and Deploy bpfman

Build the bpfman image and deploy it to the cluster:

```bash
make bpfman-deploy
```

This will:
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
  bpfman load file --path=/opt/bpf/stats.o \
  --programs=tracepoint:count_context_switches \
  -m bpfman.io/ProgramName=my-stats
```

This returns a table showing the program details including the kernel ID.
Note the kernel ID (e.g., 6786) for the next step.

The `-m bpfman.io/ProgramName=my-stats` flag attaches metadata that the CSI
driver uses to find the program when a pod requests it.

## Step 3: Attach to Tracepoint

Attach the loaded program to the `sched_switch` tracepoint, using the program
ID from step 2:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  bpfman attach tracepoint --program-id=6786 sched sched_switch
```

Replace `6786` with your actual program ID from the load output.

Verify the program is loaded:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- bpfman list
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
make stats-reader-logs
```

Or directly:

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

Unload the BPF program (using the program ID from step 2):

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- \
  bpfman unload 1234
```

Remove bpfman:

```bash
make bpfman-delete
```

## Troubleshooting

### Stats-reader fails to start

Check if the BPF program is loaded with the correct metadata:

```bash
kubectl -n bpfman exec daemonset/bpfman-daemon-go -c bpfman -- bpfman list
```

### CSI volume mount fails

Check bpfman logs for CSI-related errors:

```bash
make bpfman-logs
```

Or:

```bash
kubectl -n bpfman logs daemonset/bpfman-daemon-go -c bpfman | grep -i csi
```

### Map is empty

Ensure the tracepoint is attached. Use `bpfman list` to verify the program
shows an attached link.
