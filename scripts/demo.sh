#!/bin/bash
# Demo script: deploy bpfman, load a BPF program, attach to tracepoint, run stats-reader
set -euo pipefail

NAMESPACE="${NAMESPACE:-bpfman}"
PROGRAM_NAME="${PROGRAM_NAME:-my-stats}"

log() {
    echo "==> $*"
}

exec_bpfman() {
    kubectl -n "$NAMESPACE" exec daemonset/bpfman-daemon-go -c bpfman -- bpfman "$@"
}

# Step 1: Deploy bpfman
log "Deploying bpfman..."
make bpfman-deploy

# Step 2: Load program
log "Loading BPF program..."
LOAD_OUTPUT=$(exec_bpfman load file \
    --metadata "bpfman.io/ProgramName=$PROGRAM_NAME" \
    /opt/bpf/stats.o count_context_switches)
echo "$LOAD_OUTPUT"

# Extract program ID from load output using jq
PROG_ID=$(echo "$LOAD_OUTPUT" | jq -r '.id')
log "Program ID: $PROG_ID"

# Step 3: Get pin path using jsonpath
PIN_PATH=$(exec_bpfman get program "$PROG_ID" -o jsonpath='{.bpfman.program.load_spec.pin_path}')
log "Pin path: $PIN_PATH"

# Step 4: Attach to tracepoint
# Link pin path is auto-generated as <prog_pin_dir>/link
log "Attaching to sched/sched_switch tracepoint..."
exec_bpfman attach tracepoint \
    --program-id "$PROG_ID" \
    "${PIN_PATH}/count_context_switches" \
    sched sched_switch

# Step 5: Deploy stats-reader
log "Deploying stats-reader..."
make stats-reader-deploy

# Step 6: Show logs
log "Stats-reader is running. Showing logs..."
sleep 2
kubectl logs stats-reader --tail=20

log "Done. Follow logs with: kubectl logs stats-reader -f"
