# Parameterised Dispatcher E2E Tests

## Problem

The TC dispatcher config tests thoroughly exercise the shared dispatcher
infrastructure: slot allocation, priority ordering, config recomputation,
double-buffer flip, slot reuse, lifecycle teardown. XDP uses the same
dispatcher infrastructure but different C code, different attach mechanisms
(BPF link vs netlink), and different fd handling. Bugs found in one (e.g.
fd leaks) will not necessarily surface in the other. We need equivalent XDP
coverage without duplicating hundreds of lines of test code.

TCX is a separate concern: it uses native kernel multi-program support, not
dispatchers. It needs its own test suite.

## Three attach mechanisms

| | XDP | TC (legacy) | TCX |
|---|---|---|---|
| Multi-prog | Dispatcher BPF program | Dispatcher BPF program | Native kernel BPF links |
| Kernel API | `link.AttachXDP` | netlink tc filter | `link.AttachTCX` |
| Kernel version | Any | Any | 6.6+ |
| Visible to CLI | No | `tc filter show` | No |
| Has WithPriority | No | Yes | Yes |
| Has WithProceedOn | No | Yes | No |
| Dispatcher types | `DispatcherTypeXDP` | `TCIngress`, `TCEgress` | None |
| Direction | N/A | ingress/egress | ingress/egress |

Only XDP and TC share the dispatcher code path. TCX is entirely different
and should not be conflated.

## Test taxonomy

### Pure dispatcher config tests (parameterisable: TC + XDP)

These test the shared dispatcher machinery. The only difference between TC
and XDP is the attach call and the dispatcher type constant.

1. **PriorityOrdering** -- scrambled priorities produce correct run_order
2. **AttachExceedsMaxPrograms** -- 11th attach fails with "no free slots"
3. **SlotReusedAfterDetach** -- vacated slot reclaimed, config updated
4. **LifecycleAfterLastDetach** -- dispatcher torn down, pins removed,
   fresh dispatcher on reattach
5. **DoubleBufferFlip** -- active index alternates on each mutation
6. **ConfigRecomputedOnDetach** -- detach lowest-priority, 9 remain
   correct (subsumes existing `TestXDP_DispatcherConfigAfterDetach`)
7. **MultipleInterfacesIndependent** -- detach from one interface leaves
   the other unchanged

### TC-only tests (traffic counting, proceed-on, direction)

These depend on `tc_stats_map`, TC proceed-on semantics, or the
ingress/egress direction distinction. They stay TC-specific.

8. **IngressEgressIndependence** -- exercises direction keying
9. **DispatcherChainExecution** -- reads `tc_stats_map`, verifies all
   programs in chain see packets
10. **DispatcherChainProceedOn** -- TC proceed-on bitmask halts chain
11. **EgressTrafficCounting** -- egress direction + traffic verification
12. **DispatcherSineWave** -- fill/drain/refill with traffic verification
13. **PriorityTieBreakByName** -- needs two distinctly-named programs
    with explicit priority; XDP has no priority control

### TCX tests (separate test suite, no dispatchers)

TCX uses native kernel multi-program support. Tests would cover:

14. **Priority ordering via kernel links** -- multiple TCX programs at
    different priorities, verify execution order
15. **Lifecycle** -- attach/detach/cleanup of BPF link pins
16. **Coexistence with TC dispatcher** -- TC dispatcher at priority 50,
    TCX program at priority 500, both active
17. **Kernel 6.6+ gating** -- `RequireKernelVersion(t, 6, 6)`

TCX tests are out of scope for the dispatcher parameterisation but the
design should not preclude adding them later.

## Proposed abstraction: `dispatcherTestHarness`

A struct in `dispatcher_config_test.go` that encapsulates TC-vs-XDP
differences behind a uniform interface:

```go
type dispatcherTestHarness struct {
    name     string                    // "tc-ingress" or "xdp"
    env      *TestEnv
    dispType dispatcher.DispatcherType
    ifname   string
    ifindex  int

    // loadProg loads the BPF object and returns a kernel program ID.
    loadProg func(t *testing.T) kernel.ProgramID

    // attach creates an attachment at the given priority.
    // For XDP, priority is ignored (always 0 in store).
    attach func(t *testing.T, progID kernel.ProgramID, priority int) bpfman.LinkRecord

    // verifyAttachPresent asserts the dispatcher's kernel-level
    // attachment exists (TC: tc filter present; XDP: link pin exists).
    verifyAttachPresent func(t *testing.T)

    // verifyAttachAbsent asserts the dispatcher's kernel-level
    // attachment has been cleaned up.
    verifyAttachAbsent func(t *testing.T)
}
```

### Constructors

```go
func newTCIngressHarness(t *testing.T) dispatcherTestHarness
func newXDPHarness(t *testing.T) dispatcherTestHarness
```

Each constructor:

- Creates its own `TestEnv` and `TestInterface` (isolation for parallel)
- Calls `RequireTC(t)` for TC, nothing extra for XDP
- Sets `loadProg` to call `env.LoadFile` with the appropriate testdata
  path (`testdata/tc_counter_pinned.bpf.o` or `testdata/xdp_pass_pinned.bpf.o`) and
  program spec
- Sets `attach` to build the appropriate attach spec and call
  `env.Attach`
- Sets `verifyAttachPresent`/`verifyAttachAbsent` to check TC filters
  or XDP link pins

### Convenience methods

```go
func (h *dispatcherTestHarness) configMapPin(t *testing.T) string
func (h *dispatcherTestHarness) activeMapPin(t *testing.T) string
func (h *dispatcherTestHarness) readConfig(t *testing.T) dispatcher.RuntimeConfig
func (h *dispatcherTestHarness) readActiveIndex(t *testing.T) uint32
```

These call `netns.GetCurrentNsid()` and `env.Layout.BPFFS()` internally.

### Iterator

```go
func eachDispatcherType(t *testing.T) []dispatcherTestHarness
```

Returns `[tcIngressHarness, xdpHarness]`. Each parameterised test
iterates:

```go
func TestDispatcher_PriorityOrdering(t *testing.T) {
    for _, h := range eachDispatcherType(t) {
        t.Run(h.name, func(t *testing.T) {
            t.Parallel()
            testPriorityOrdering(t, h)
        })
    }
}
```

## XDP priority behaviour

XDP has no `WithPriority`. All XDP attachments store priority 0. The
run_order sorts by `(priority ASC, program_name ASC)`. Since all slots
use the same program name ("pass") and the same priority (0), run_order
follows insertion order (stable sort preserves attachment order).

This means the PriorityOrdering test needs different expected values per
dispatcher type:

- TC: scrambled priorities produce a specific reordering
- XDP: all priority 0, run_order matches insertion order

The test body can branch on `h.dispType` for the expected assertion, or
the harness can carry a `supportsPriority bool` flag.

## New BPF source: `e2e/testdata/bpf/xdp_pass_pinned.bpf.c`

Minimal XDP program returning `XDP_PASS`. Section `xdp/pass`, function
name `pass`. No maps. The existing Makefile wildcard compiles it
automatically.

## Existing XDP test

`TestXDP_DispatcherConfigAfterDetach` stays unchanged. It still uses OCI
and exercises the XDP path independently. Once the parameterised tests
are proven, it can be removed in a follow-up.

## Files changed

| File | Change |
|---|---|
| `e2e/testdata/bpf/xdp_pass_pinned.bpf.c` | New: minimal XDP pass program |
| `e2e/dispatcher_config_test.go` | Refactor: harness + parameterised tests, delete standalone XDP test |

No Makefile changes needed (wildcard rule picks up `xdp_pass_pinned.bpf.c`
automatically, `test-e2e` already depends on `e2e-testdata-bpf`).
