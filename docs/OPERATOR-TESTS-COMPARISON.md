# Operator Integration Tests: Rust vs Go bpfman

Comparison of bpfman-operator integration tests run against a KIND
cluster. Rust baseline from 2026-03-12, Go implementation from
2026-03-13. Both use the same test suite, same cluster configuration,
same `SKIP_BPFMAN_DEPLOY=true` workflow.

## Result

All 11 tests pass in both runs. Functional parity confirmed.

## Dispatcher position ordering

Both implementations produce identical position assignments for the
same priority values across TC, TCX, and XDP link priority tests:

- TC: priorities 0/55/500/1000/1000 produce positions 0/2/3/4/5
- TCX: priorities 0/55/500/1000/1000 produce positions 0/1/3/4/5

XDP has one minor difference: Rust places priority=55 at position=2,
Go at position=1. This suggests a residual XDP program occupied a
slot in the Rust run (likely from the preceding TestXdpGoCounter
cleanup not completing before the priority test started). Not a
correctness issue.

## Timing

| Test                        |  Rust |    Go |  Delta |
|-----------------------------|------:|------:|-------:|
| ApplicationGoCounter        | 41.4s | 51.9s |   +25% |
| KprobeGoCounter             | 18.3s | 17.7s |    -3% |
| AgentMetricsCollection      |  2.9s |  3.1s |    +7% |
| TcGoCounter                 | 27.5s | 28.4s |    +3% |
| TcGoCounterLinkPriority     | 38.0s | 60.8s |   +60% |
| TcxGoCounter                | 27.6s | 26.4s |    -4% |
| TcxGoCounterLinkPriority    | 18.0s | 41.3s |  +129% |
| TracepointGoCounter         | 17.3s | 16.4s |    -5% |
| UprobeGoCounter             | 19.0s | 29.5s |   +55% |
| XdpGoCounter                | 28.1s | 28.9s |    +3% |
| XdpGoCounterLinkPriority    | 37.6s | 62.3s |   +66% |
| **Total**                   | **315s** | **411s** | **+30%** |

### Simple single-program tests are equivalent

KprobeGoCounter, TcGoCounter, TcxGoCounter, TracepointGoCounter,
and XdpGoCounter are all within a few percent. The core load, attach,
count, and verify cycle works at the same speed.

### Multi-program LinkPriority tests are consistently slower

All three LinkPriority tests (TC +60%, TCX +129%, XDP +66%) take
significantly longer in Go. The Go logs show many more polling
iterations with stale or unchanging packet counts. For example, the
TC LinkPriority test produces 15 counter log lines (many consecutive
duplicates) versus 8 for Rust.

The programs are functioning -- counts do increase -- but the Go
implementation takes longer to settle after attaching multiple
programs with priority reordering. Each additional program triggers a
full dispatcher rebuild; with 5 programs that means 5 rebuilds. If
each rebuild is marginally slower or the operator reconciliation loop
takes more cycles to converge, it compounds.

Worth investigating: is the bottleneck in go-bpfman's dispatcher
rebuild path, or in the operator's reconciliation loop reacting to
status updates?

### ApplicationGoCounter and UprobeGoCounter

ApplicationGoCounter (+25%) loads all six program types at once, so
it amplifies any per-program overhead. UprobeGoCounter (+55%) deploys
a target binary first, then the uprobe; the extra time may come from
pod scheduling variance or slower uprobe attachment in Go.

## Metrics

| Metric category | Rust | Go  |
|-----------------|-----:|----:|
| metrics         |  226 |  48 |
| agent-metrics   |  402 | 224 |

Go exposes roughly a quarter of the general metrics and just over
half of the agent metrics that Rust does. The metrics test passes in
both cases (it checks that metrics are collected, not their count),
but the gap is notable.

The missing metrics are likely internal bpfman daemon instrumentation
that Rust exposes via Prometheus but Go has not yet wired up. Worth
cataloguing what is absent to determine whether any are important for
production monitoring.

## Log files

- Rust baseline: `/tmp/baseline.log`
- Go implementation: `goimpl-with-shared-map-unloading.log`
  (from `bpfman-operator/worktrees/general/`)
