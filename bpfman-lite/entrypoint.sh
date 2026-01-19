#!/bin/bash
set -euo pipefail

BPF_PATH="${BPF_PATH:-/sys/fs/bpf}"
TEST_PATH="${BPF_PATH}/test"

echo "bpfman-lite starting"
echo "BPF_PATH: ${BPF_PATH}"

# Create test directory
mkdir -p "${TEST_PATH}"
echo "Created ${TEST_PATH}"

# Create a test hash map if it doesn't exist
if [[ ! -e "${TEST_PATH}/mymap" ]]; then
    bpftool map create "${TEST_PATH}/mymap" type hash key 4 value 4 entries 16 name testmap
    echo "Created ${TEST_PATH}/mymap"
else
    echo "${TEST_PATH}/mymap already exists"
fi

echo "bpfman-lite ready"

# Keep running
exec sleep infinity
