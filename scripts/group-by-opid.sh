#!/bin/bash
# Group bpfman daemon logs by op_id to show operation flow
# Usage: kubectl logs <pod> -c bpfman | ./group-by-opid.sh [op_id]
#
# Without op_id: shows summary of all operations
# With op_id: shows all log lines for that specific operation

set -euo pipefail

if [[ $# -eq 1 ]]; then
    # Show all logs for specific op_id
    op_id="$1"
    grep "op_id=$op_id\b" | while read -r line; do
        echo "$line"
    done
else
    # Group and summarise by op_id
    awk '
    /op_id=[0-9]+/ {
        # Extract op_id
        match($0, /op_id=([0-9]+)/, arr)
        if (arr[1] != "") {
            op_id = arr[1]

            # Extract timestamp
            match($0, /time=([^ ]+)/, ts)
            timestamp = ts[1]

            # Extract component
            match($0, /component=([^ ]+)/, comp)
            component = comp[1]

            # Extract msg
            match($0, /msg="?([^"]+)"?/, m)
            msg = m[1]
            # Clean up msg - remove trailing fields
            gsub(/ component=.*/, "", msg)
            gsub(/ kernel_id=.*/, "", msg)
            gsub(/ program_id=.*/, "", msg)

            # Track first/last timestamp per op_id
            if (!(op_id in first_ts)) {
                first_ts[op_id] = timestamp
                first_msg[op_id] = msg
                first_comp[op_id] = component
            }
            last_ts[op_id] = timestamp
            last_msg[op_id] = msg
            last_comp[op_id] = component
            count[op_id]++

            # Collect all messages
            if (op_id in messages) {
                messages[op_id] = messages[op_id] " -> " msg
            } else {
                messages[op_id] = msg
            }
        }
    }
    END {
        # Sort by op_id numerically
        n = asorti(first_ts, sorted, "@ind_num_asc")
        for (i = 1; i <= n; i++) {
            op_id = sorted[i]
            printf "op_id=%-4s [%d logs] %s\n", op_id, count[op_id], messages[op_id]
        }
    }
    '
fi
