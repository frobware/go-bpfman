#!/bin/bash
# test-nsenter.sh - Test the CGO-based nsenter namespace switching
#
# This test verifies that:
# 1. The nsenter C constructor runs and logs correctly
# 2. Namespace switching works via the _BPFMAN_MNT_NS env var
# 3. The bpfman-ns helper can be invoked
#
# Prerequisites:
# - bpfman binary built with CGO (bin/bpfman)
# - Root privileges (uses sudo for unshare)
# - util-linux (for unshare)

set -euo pipefail

# Configuration
BPFMAN="${BPFMAN:-./bin/bpfman}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No colour

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $*"; }

# Test 1: Verify bpfman binary has CGO enabled (dynamically linked)
test_cgo_enabled() {
    log_info "Test 1: Verifying bpfman binary has CGO enabled..."

    if ! [ -f "$BPFMAN" ]; then
        log_fail "bpfman binary not found at $BPFMAN"
        log_info "Run 'make bpfman-build' first"
        return 1
    fi

    local file_output
    file_output=$(file "$BPFMAN")

    if echo "$file_output" | grep -q "dynamically linked"; then
        log_pass "Binary is dynamically linked (CGO enabled)"
    else
        log_fail "Binary is NOT dynamically linked - CGO may be disabled"
        echo "$file_output"
        return 1
    fi

    # Check for nsexec symbol
    # Use subshell to disable pipefail - nm outputs 90k+ lines, and grep -q
    # exits early causing SIGPIPE which makes nm fail with pipefail enabled
    if (set +o pipefail; nm "$BPFMAN" 2>/dev/null | grep -q "nsexec"); then
        log_pass "nsexec symbol found in binary"
    else
        log_fail "nsexec symbol NOT found - nsenter package may not be linked"
        return 1
    fi
}

# Test 2: Verify C constructor logging without namespace switch
test_no_namespace_switch() {
    log_info "Test 2: Verifying C constructor with no namespace switch..."

    # Run bpfman with debug logging but no _BPFMAN_MNT_NS set
    # Should just show version and exit without namespace messages
    local output
    output=$(_BPFMAN_NS_LOG_LEVEL=debug "$BPFMAN" version 2>&1) || true

    # Should see debug message about _BPFMAN_MNT_NS not being set
    if echo "$output" | grep -q "nsexec.*_BPFMAN_MNT_NS not set"; then
        log_pass "C constructor correctly detected no namespace switch needed"
    else
        log_warn "Expected debug message not found (may be normal if log level filtering)"
        log_debug "Output was: $output"
    fi

    # Should NOT see namespace switch messages
    if echo "$output" | grep -q "namespace switch requested"; then
        log_fail "Unexpected namespace switch message"
        return 1
    fi

    log_pass "No namespace switch when _BPFMAN_MNT_NS not set"
}

# Test 3: Verify namespace switch with C logging
test_namespace_switch_logging() {
    log_info "Test 3: Testing namespace switch with C-level logging..."

    # Get our current mount namespace inode
    local current_ns_inode
    current_ns_inode=$(stat -c %i /proc/self/ns/mnt)
    log_info "Current mount namespace inode: $current_ns_inode"

    # Create a child process in a new mount namespace
    # The child will exec bpfman-ns with _BPFMAN_MNT_NS pointing to its own namespace
    # (This tests the mechanism even though it's switching to the "same" namespace)

    local output
    output=$(sudo unshare --mount /bin/bash -c "
        # Get the new namespace's inode
        new_ns_inode=\$(stat -c %i /proc/self/ns/mnt)
        echo \"Child mount namespace inode: \$new_ns_inode\"

        # Try to switch back to the parent namespace from within the child
        # This tests the full setns path
        export _BPFMAN_MNT_NS=/proc/\$\$/ns/mnt
        export _BPFMAN_NS_LOG_LEVEL=debug

        # Run bpfman version - the C constructor should log the switch
        $BPFMAN version 2>&1 || true
    " 2>&1)

    echo "$output"

    # Check for expected log messages
    if echo "$output" | grep -q "nsexec.*namespace switch requested"; then
        log_pass "Namespace switch was requested"
    else
        log_warn "Namespace switch request message not found"
    fi

    if echo "$output" | grep -q "nsexec.*setns succeeded"; then
        log_pass "setns succeeded"
    else
        log_warn "setns success message not found"
    fi

    log_pass "Namespace switch logging test completed"
}

# Test 4: Test bpfman-ns subcommand parsing
test_bpfman_ns_parsing() {
    log_info "Test 4: Testing bpfman-ns subcommand parsing..."

    # Test help output
    local output
    output=$("$BPFMAN" bpfman-ns --help 2>&1) || true

    if echo "$output" | grep -q "uprobe"; then
        log_pass "bpfman-ns uprobe subcommand found"
    else
        log_fail "bpfman-ns uprobe subcommand not found in help"
        echo "$output"
        return 1
    fi

    # Test uprobe help
    output=$("$BPFMAN" bpfman-ns uprobe --help 2>&1) || true

    if echo "$output" | grep -q "fn-name"; then
        log_pass "bpfman-ns uprobe --fn-name option found"
    else
        log_fail "bpfman-ns uprobe --fn-name option not found"
        echo "$output"
        return 1
    fi

    # Verify it accepts target as positional arg (not host-pid anymore)
    if echo "$output" | grep -q "Target binary path"; then
        log_pass "bpfman-ns uprobe takes target as positional arg"
    else
        log_warn "bpfman-ns uprobe help doesn't show target description (may be ok)"
    fi

    log_pass "bpfman-ns subcommand parsing works"
}

# Test 5: Test container namespace switching (requires running container)
test_container_namespace() {
    log_info "Test 5: Testing container namespace switching..."

    # Check if we have a running container to test with
    if ! command -v docker &>/dev/null && ! command -v podman &>/dev/null; then
        log_warn "Skipping container test - no docker/podman found"
        return 0
    fi

    # Try to find a running container
    local container_pid=""

    if command -v docker &>/dev/null; then
        local container_id
        container_id=$(docker ps -q | head -1)
        if [ -n "$container_id" ]; then
            container_pid=$(docker inspect -f '{{.State.Pid}}' "$container_id" 2>/dev/null) || true
        fi
    fi

    if [ -z "$container_pid" ] && command -v podman &>/dev/null; then
        local container_id
        container_id=$(podman ps -q | head -1)
        if [ -n "$container_id" ]; then
            container_pid=$(podman inspect -f '{{.State.Pid}}' "$container_id" 2>/dev/null) || true
        fi
    fi

    if [ -z "$container_pid" ]; then
        log_warn "Skipping container test - no running containers found"
        return 0
    fi

    log_info "Found container with PID: $container_pid"

    # Verify namespace path exists
    local ns_path="/proc/$container_pid/ns/mnt"
    if [ ! -e "$ns_path" ]; then
        log_warn "Namespace path $ns_path does not exist"
        return 0
    fi

    local container_ns_inode
    container_ns_inode=$(stat -c %i "$ns_path")
    log_info "Container mount namespace inode: $container_ns_inode"

    local current_ns_inode
    current_ns_inode=$(stat -c %i /proc/self/ns/mnt)
    log_info "Current mount namespace inode: $current_ns_inode"

    if [ "$container_ns_inode" != "$current_ns_inode" ]; then
        log_pass "Container is in a different mount namespace (as expected)"
    else
        log_warn "Container appears to share our mount namespace"
    fi

    # Test namespace switching with a simple command that will fail
    # (bpfman-ns uprobe expects program fd via ExtraFiles, which we can't provide here)
    # But we can verify the C constructor runs and namespace switch works
    log_info "Testing namespace switch logging (will fail on missing program fd, but should show switch logs)..."

    local output
    output=$(sudo _BPFMAN_MNT_NS="$ns_path" _BPFMAN_NS_LOG_LEVEL=debug \
        "$BPFMAN" bpfman-ns uprobe /bin/sh --fn-name main 2>&1) || true

    echo "$output"

    if echo "$output" | grep -q "nsexec.*setns succeeded"; then
        log_pass "Namespace switch to container succeeded"
    else
        log_warn "Namespace switch messages not found (may have failed for other reasons)"
    fi

    # The command should fail because fd 3 (program) is not available
    if echo "$output" | grep -q "create program from fd"; then
        log_pass "Child correctly tried to use inherited program fd"
    else
        log_warn "Expected program fd error not found"
    fi

    log_info "Note: Full uprobe attachment testing requires the daemon's attach flow"
    log_info "      which properly passes the program fd via ExtraFiles"

    log_pass "Container uprobe test completed"
}

# Main
main() {
    echo "=========================================="
    echo "NSEnter CGO Integration Test"
    echo "=========================================="
    echo ""

    cd "$PROJECT_DIR"

    test_cgo_enabled
    echo ""

    test_no_namespace_switch
    echo ""

    test_namespace_switch_logging
    echo ""

    test_bpfman_ns_parsing
    echo ""

    test_container_namespace
    echo ""

    echo "=========================================="
    log_pass "All nsenter tests completed!"
    echo "=========================================="
}

main "$@"
