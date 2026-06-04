# Next .bpfman Script Coverage

This is a focused follow-up list after comparing the operator
integration tests in:

`~/src/github.com/bpfman/bpfman-operator/worktrees/go-bpfman/test/integration`

against the local `.bpfman` corpus under `e2e/scripts`.

The operator tests prove Kubernetes reconciliation and userspace
daemon behaviour. `.bpfman` cannot replace CRD/status/DaemonSet
coverage, but it can cover the daemon-level load, attach, order,
traffic, detach, and cleanup contracts those tests depend on.

## Already Covered Locally

These operator-test behaviours already have direct daemon-level
coverage in `.bpfman` scripts:

- XDP attach, link get/list, traffic counter movement, detach cleanup:
  `TestXDP_LinkRoundTrip.bpfman`.
- TC ingress attach, link get/list, traffic counter movement, detach
  cleanup: `TestTC_LinkRoundTrip.bpfman`.
- TCX attach, link get/list, traffic counter movement, detach cleanup:
  `TestTCX_LinkRoundTrip.bpfman`.
- Kprobe attach and exact counter movement:
  `TestKprobe_LinkRoundTrip.bpfman`.
- Tracepoint attach and exact counter movement:
  `TestTracepoint_LinkRoundTrip.bpfman`.
- Uprobe attach to a live target and exact counter movement:
  `TestUprobe_LinkRoundTrip.bpfman`.
- XDP priority ordering:
  `TestDispatcher_PriorityOrderingXDP.bpfman`.
- TC priority ordering:
  `TestDispatcher_PriorityOrderingTC.bpfman`.
- TCX priority ordering:
  `TestTCX_PriorityOrdering.bpfman`.
- XDP/TC zero-priority semantics:
  `TestDispatcher_ZeroPriorityDefaultOrderingXDP.bpfman` and
  `TestDispatcher_ZeroPriorityDefaultOrderingTC.bpfman`.
- TC egress traffic and ingress/egress independence:
  `TestTC_EgressTrafficCounting.bpfman` and
  `TestTC_IngressEgressIndependence.bpfman`.
- Dispatcher lifecycle, refill, slot reuse, and multi-interface
  independence: the `TestDispatcher_*` scripts.
- Basic attach-time netns interface resolution for XDP, TC ingress,
  and TCX: `TestAttach_ResolvesIfaceInNetns.bpfman`.

## 1. TCX Operator Priority Parity

Suggested script:

`TestTCX_OperatorPriorityParity.bpfman`

The operator `TestTcxGoCounterLinkPriority` creates TCX applications
with priorities:

- omitted/default
- `0`
- `500`
- `1000`
- `55` from the original kustomize deployment

The local `TestTCX_PriorityOrdering.bpfman` covers TCX ordering, but
not this exact default/zero/operator-shaped set. Add a script that
loads one TCX program per priority, because TCX cannot attach the same
kernel program to the same `(interface, direction)` repeatedly.

Assertions:

- default priority records as the daemon default, matching current CLI
  semantics;
- explicit `0` records as `0`;
- final link positions are ordered by effective priority;
- `55` sorts between `0`/default as the current attach-ordering rules
  require;
- each link can be fetched after all attaches so positions reflect the
  final order, not the order at attach time.

## 2. Same Interface Name In Multiple Netns

Suggested script:

`TestAttach_SameIfaceNameAcrossNetns.bpfman`

The current netns script proves an interface that exists only in the
target namespace is resolved correctly. The second failure mode from
#108 was about same-name interfaces across different namespaces, such
as pod `eth0` on many pods.

Build two independent topologies whose peer-side interface names are
the same inside different netns. If `net veth-pair` cannot currently
force the peer-side name, add a narrow test builtin or flag that can
create:

- namespace A containing `eth0`;
- namespace B containing `eth0`;
- distinct host-side veth names so the host namespace remains valid.

Attach TCX to `eth0` through each namespace path.

Assertions:

- both attaches succeed;
- both links record interface `eth0`;
- both links record distinct netns paths/nsids;
- detach of one namespace's link does not remove or perturb the other;
- re-fetching both links never trips any per-`(iface,direction)` nsid
  assumption.

## 3. Namespaced Attach With Traffic Counters

Suggested script:

`TestAttach_NetnsTrafficCounting.bpfman`

`TestAttach_ResolvesIfaceInNetns.bpfman` intentionally stops at link
shape. Add a behavioural variant that proves packets traverse the
programs attached inside the peer namespace.

Possible shape:

- create `net veth-pair`;
- attach XDP, TC ingress, and TCX to `$pair.peer_link` with
  `--netns /var/run/netns/$pair.ns`;
- drive traffic from the host side to the peer side, or from inside
  the peer namespace, whichever hits the chosen hook deterministically;
- dump maps with `bpftool`.

Assertions:

- each map counter increases while attached;
- after detach, a second traffic burst leaves each detached counter
  unchanged;
- link records still show the peer interface and netns path.

## 4. Application-Style All-Kind Mixed Attach

Suggested script:

`TestMultiProgAllKinds_LoadAttachDetachUnload.bpfman`

The operator `TestApplicationGoCounter` validates one Application that
drives kprobe, TC, TCX, tracepoint, uprobe, and XDP together. The local
`TestMultiProgMixed_LoadAttachDetachUnload.bpfman` covers tracepoint,
kprobe, and kretprobe in one object, but not all operator Application
kinds in one run.

Add a script that loads and attaches:

- kprobe on a leased kfunc;
- tracepoint on `bpfman_e2e/bpfman_e2e_ping`;
- uprobe on the shell uprobe target;
- XDP on a veth;
- TC ingress on the same or another veth;
- TCX on a veth.

Assertions:

- all links are present at once;
- each stimulus moves only the intended counter;
- staged detaches freeze the detached counters while the remaining
  links keep working;
- all programs unload cleanly after final detach.

This does not replace the operator Application CR test, but it gives a
fast daemon-level failure when cross-kind attach state regresses.

## 5. Already-Gone TC Filter Cleanup

Suggested script:

`TestTC_DetachAlreadyGoneFilter.bpfman`

The current e2e output can hit the warning:

`failed to find TC filter handle; assuming already gone`

but no script deliberately owns that behaviour. Add one explicit test.

Script shape:

- attach a TC ingress program to `$pair.host_link`;
- verify `tc filter show dev $pair.host_link ingress` sees the filter;
- remove the filter externally with `tc filter del ...`, using the
  handle or priority shape that the daemon installs;
- run `bpfman link detach $link`.

Assertions:

- detach succeeds even though the kernel filter is already gone;
- `bpfman link get $linkID` fails after detach;
- `bpfman link list -o json` no longer includes the link;
- a second cleanup/detach path does not leave a dispatcher pin behind.

## 6. TCX Stale Anchor Recovery

Suggested script or builtin-backed test:

`TestTCX_StaleAnchorRecovery.bpfman`

The daemon has code to ignore stored TCX links whose anchor program is
no longer live in the kernel. This is hard to create through normal
public commands because normal detach/unload paths clean both kernel
and store state.

If there is a public sequence that leaves a stale TCX store row, use
it. Otherwise add a narrow test builtin that marks or injects a stale
TCX link row for the current test root.

Assertions:

- a new TCX attach does not anchor to a dead program ID;
- stale rows are ignored when computing attach order;
- live anchors are preserved;
- the recovered attach is visible through `bpfman link get` with the
  expected priority and position.
