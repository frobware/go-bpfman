#!/bin/bash
# bpfman CLI walkthrough -- runs real commands, captures real output.
# Requires: root, bpfman binary at ./bin/bpfman, config/test.toml
set -euo pipefail

BPFMAN="${BPFMAN:-./bin/bpfman}"
CONFIG="${CONFIG:-./config/test.toml}"
RUNTIME_DIR="/tmp/bpfman-demo-$$"
BYTECODE="${BYTECODE:-./integration-tests/bytecode/fentry.bpf.o}"

# Detect libc path portably
detect_libc() {
    for p in /lib64/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/libc.so.6; do
        if [ -f "$p" ]; then echo "$p"; return; fi
    done
    ldd /bin/sh 2>/dev/null | grep 'libc\.so' | awk '{print $3}' | head -1
}
LIBC=$(detect_libc)

bpfman() { "$BPFMAN" --config="$CONFIG" --runtime-dir="$RUNTIME_DIR" "$@"; }

# Print a command then run it, capturing output into $OUT.
run() {
    echo "  \$ bpfman $*"
    OUT=$(bpfman "$@" 2>&1) || true
    if [ -n "$OUT" ]; then
        echo "$OUT" | sed 's/^/  /'
    fi
    echo
}

cleanup_runtime() {
    local bpffs="$RUNTIME_DIR/fs"
    if mountpoint -q "$bpffs" 2>/dev/null; then
        umount "$bpffs" 2>/dev/null || true
    fi
    rm -rf "$RUNTIME_DIR" "${RUNTIME_DIR}-sock" 2>/dev/null || true
}

cleanup_iface() {
    if ip link show "$1" &>/dev/null; then
        ip link del "$1" 2>/dev/null || true
    fi
}

section() {
    echo "────────────────────────────────────────────────────────────"
    echo "$1"
    echo "────────────────────────────────────────────────────────────"
    echo
}

# Fresh state for each section
reset() {
    cleanup_iface "bpfman-demo" 2>/dev/null || true
    cleanup_runtime
}

trap 'cleanup_iface "bpfman-demo" 2>/dev/null; cleanup_runtime' EXIT

########################################################################
section "XDP: load, attach, list, detach, unload"
reset
ip link add bpfman-demo type dummy && ip link set bpfman-demo up

run program load image --programs xdp:pass --image-url quay.io/bpfman-bytecode/xdp_pass:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list
run link list

run link attach xdp --iface bpfman-demo -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "XDP: jsonpath variable capture (as shown in --example)"
reset
ip link add bpfman-demo type dummy && ip link set bpfman-demo up

echo '  $ BPFMAN_PROG_ID=$(bpfman program load image \'
echo '      --programs xdp:pass \'
echo '      --image-url quay.io/bpfman-bytecode/xdp_pass:latest \'
echo "      -o 'jsonpath={.programs[0].record.program_id}')"
BPFMAN_PROG_ID=$(bpfman program load image \
    --programs xdp:pass \
    --image-url quay.io/bpfman-bytecode/xdp_pass:latest \
    -o 'jsonpath={.programs[0].record.program_id}')
echo "  BPFMAN_PROG_ID=$BPFMAN_PROG_ID"
echo

run program list

echo '  $ BPFMAN_LINK_ID=$(bpfman link attach xdp --iface bpfman-demo \'
echo "      -o 'jsonpath={.record.id}' \"\$BPFMAN_PROG_ID\")"
BPFMAN_LINK_ID=$(bpfman link attach xdp --iface bpfman-demo \
    -o 'jsonpath={.record.id}' "$BPFMAN_PROG_ID")
echo "  BPFMAN_LINK_ID=$BPFMAN_LINK_ID"
echo

run program list
run link list

run link detach "$BPFMAN_LINK_ID"
run program unload "$BPFMAN_PROG_ID"

########################################################################
section "TC: load, attach ingress+egress, list, detach, unload"
reset
ip link add bpfman-demo type dummy && ip link set bpfman-demo up

run program load image --programs tc:stats --image-url quay.io/bpfman-bytecode/go-tc-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach tc --iface bpfman-demo --direction ingress --priority 50 -o json "$PROG_ID"
LINK_INGRESS=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_INGRESS=$LINK_INGRESS"
echo

run program list
run link list

run link attach tc --iface bpfman-demo --direction egress --priority 50 -o json "$PROG_ID"
LINK_EGRESS=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_EGRESS=$LINK_EGRESS"
echo

run program list
run link list

run link detach "$LINK_INGRESS"
run link detach "$LINK_EGRESS"
run program unload "$PROG_ID"

########################################################################
section "TCX: load, attach ingress, list, detach, unload"
reset
ip link add bpfman-demo type dummy && ip link set bpfman-demo up

run program load image --programs tcx:stats --image-url quay.io/bpfman-bytecode/go-tc-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach tcx --iface bpfman-demo --direction ingress --priority 50 -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Tracepoint: load, attach, list, detach, unload"
reset

run program load image --programs tracepoint:tracepoint_kill_recorder --image-url quay.io/bpfman-bytecode/go-tracepoint-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach tracepoint --tracepoint syscalls/sys_enter_kill -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Kprobe: load, attach, list, detach, unload"
reset

run program load image --programs kprobe:kprobe_counter --image-url quay.io/bpfman-bytecode/go-kprobe-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach kprobe --fn-name try_to_wake_up -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Kretprobe: load, attach, list, detach, unload"
reset

run program load image --programs kretprobe:kprobe_counter --image-url quay.io/bpfman-bytecode/go-kprobe-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach kprobe --fn-name try_to_wake_up -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Uprobe: load, attach to libc malloc, list, detach, unload"
reset

run program load image --programs uprobe:uprobe_counter --image-url quay.io/bpfman-bytecode/go-uprobe-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach uprobe --target "$LIBC" --fn-name malloc -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Uretprobe: load, attach to libc malloc, list, detach, unload"
reset

run program load image --programs uretprobe:uprobe_counter --image-url quay.io/bpfman-bytecode/go-uprobe-counter:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach uprobe --target "$LIBC" --fn-name malloc -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Fentry: load from file, attach, list, detach, unload"
reset

run program load file --path "$BYTECODE" --programs fentry:test_fentry:do_unlinkat -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach fentry -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Fexit: load from file, attach, list, detach, unload"
reset

run program load file --path "$BYTECODE" --programs fexit:test_fexit:do_unlinkat -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')
echo "  PROG_ID=$PROG_ID"
echo

run program list

run link attach fexit -o json "$PROG_ID"
LINK_ID=$(echo "$OUT" | jq -r '.record.id')
echo "  LINK_ID=$LINK_ID"
echo

run program list
run link list

run link detach "$LINK_ID"
run program unload "$PROG_ID"

########################################################################
section "Output formats: table, wide, json, tree, jsonpath, custom-columns"
reset
ip link add bpfman-demo type dummy && ip link set bpfman-demo up

run program load image --programs xdp:pass --image-url quay.io/bpfman-bytecode/xdp_pass:latest -o json
PROG_ID=$(echo "$OUT" | jq -r '.[0].record.program_id')

run link attach xdp --iface bpfman-demo "$PROG_ID"

echo "  # table (default)"
run program list
run link list

echo "  # wide"
run program list -o wide
run link list -o wide

echo "  # json"
run link list -o json

echo "  # tree"
run link list -o tree

echo "  # jsonpath"
run link list -o 'jsonpath={.links[0].id}'

echo "  # custom-columns"
run link list -o 'custom-columns=ID:.id,KIND:.kind,PROGRAM:.program_id'

LINK_ID=$(bpfman link list -o 'jsonpath={.links[0].id}')
run link detach "$LINK_ID"
run program unload "$PROG_ID"

echo
echo "Done."
