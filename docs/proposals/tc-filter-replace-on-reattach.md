# Replace a pod's TC filter in place when it is already attached

Close the window in which a pod's traffic is unfiltered while the agent attaches the pod's program again after a restart (#790), by replacing the existing filter in one operation instead of deleting it and adding it again.

## Motivation

The agent enforces a pod's policy with two TC filters on the pod's host-side veth: the pod's ingress program at the veth's TC egress hook, and its egress program at the TC ingress hook. After every agent restart, the next PolicyEndpoint reconcile attaches both programs again for each pod a policy selects (`attachProbesForIdentifier` in `controllers/shared.go`), because the agent's record of attached pods (`ingressPodToProgMap`, `egressPodToProgMap`) is in memory and starts empty.

### Limitations of current behavior

The SDK attaches with `netlink.FilterAdd`, which fails with EEXIST when the filter is already there. The agent then deletes the filter and adds it again (`attachIngressBPFProbe` and `attachEgressBPFProbe` in `pkg/ebpf/bpf_client.go`):

```go
err = l.bpfTCClient.TCEgressAttach(hostVethName, progFD, utils.TC_INGRESS_PROG)
if err != nil && utils.IsFileExistsError(err) {
	// The hook has no filter from here until the attach below returns.
	if detachErr := l.bpfTCClient.TCEgressDetach(hostVethName); detachErr != nil { ... }
	err = l.bpfTCClient.TCEgressAttach(hostVethName, progFD, utils.TC_INGRESS_PROG)
}
```

This branch came in with the pod identifier change (#576, commit d145d20, first released in v1.4.0), which also renamed the agent's pins. Through v1.3.x the agent ignored EEXIST and kept the filter that was there (`bpf_client.go` at v1.3.7), which has no gap but can leave a pod on an old program (see Alternative 1).

Between the delete and the add, the hook has no filter, so every packet in that direction passes unchecked. The program the agent attaches is usually the one already attached: after a restart that recovers the pod's pinned programs, `ensureBPFProgram` returns the recovered program, so the delete and add only open the gap.

A connection opened in the gap stays allowed after it. The client's SYN reaches the pod unchecked; the pod's SYN-ACK passes its egress program, which records the flow in the agent's conntrack map; from then on the ingress program admits the client's packets as replies to that flow (the reverse-key lookup in `tc.v4ingress.bpf.c`). The entry lives as long as the kernel's flow, so the connection is allowed until one side closes it.

Measured on stock v1.4.3 with `kubectl rollout restart ds/aws-node`, a client the policy denies sending 200 requests/s on a new connection per request and on reused keep-alive connections, through an IP-mode NLB (#790):

| Node | Gap per pod | Denied requests that got through, reused connections | New connection per request |
|---|---|---|---|
| AL2023, kernel 6.1 | 0 to 2 ms | 4,001 of 137,842 (2.9%), on 3 of 8 restarts | 4 of 137,845 |
| AL2, kernel 5.10 | 30 to 50 ms | 31% to 41% of about 78,000 | about 60 of 78,000 |

With no restarts, no denied request got through in 30 minutes. Leaked keep-alive connections ended only when the server closed them.

### Use Cases

1. **Agent restarts.** Every restart, for any reason (an OOM kill, a node agent update that keeps the same TC binaries, a manual rollout), opens the gap on every policy-selected pod on the node.

### Non-Goals

- **Upgrades and downgrades that change the TC binaries.** On that path the agent detaches every pod's filters on purpose (`CleanupQdiscs` in `recoverBPFState`) before `ReAttachEbpfProbes` attaches the new programs, so the pod is unfiltered until the attach, and it also writes `DEFAULT_ALLOW` into a reloaded pod's state map until its policy is applied again (#791). Both need their own fix.
- **Pods no policy selects.** They aren't attached again after a restart, so they have no gap.
- **Connections that leaked before the upgrade** stay allowed until they close.

## Proposal

### Proposed Spec

No new flag. `aws-ebpf-sdk-go` gets a replace for each TC hook (aws/aws-ebpf-sdk-go#186), and the agent attaches every pod program with it (#821). The replace creates the filter when it isn't there and swaps the program in place when it is, so a new pod and a re-attach after a restart take the same path, one netlink call per hook.

### How It Works

**SDK (aws/aws-ebpf-sdk-go#186).** `TCIngressReplace` and `TCEgressReplace` share one implementation with the attach functions. They ensure the veth's clsact qdisc and build the same filter the attach does: the same hook, handle `DEFAULT_BPF_FILTER_HANDLE` (1), priority 1, protocol `ETH_P_ALL`, direct action, and the program's FD and name. Attach sends it with `netlink.FilterAdd`, as today. Replace sends it with `netlink.FilterReplace` (`tc filter replace`), the same `RTM_NEWTFILTER` without `NLM_F_EXCL`. If no filter has that handle, the kernel creates one. If one does, it calls `cls_bpf_change` with it, which swaps the program with `idr_replace` and `list_replace_rcu` and frees the old one after an RCU grace period (`net/sched/cls_api.c` and `net/sched/cls_bpf.c`, the same in 5.10 and 6.1). A packet runs either the old program or the new one; the hook is never empty.

The clsact step (`ensureClsact`) lists the veth's qdiscs and adds clsact only when no qdisc is in its place. clsact is shared with other TC users, so when the add returns EEXIST because another TC user added one after the list, a fresh list that shows a qdisc there counts as success. An `ingress` qdisc in clsact's place is accepted as before, now with a warning, since its two hooks share one filter block. `BpfTc` gains the two methods, and the mocks are regenerated.

**Agent (#821).** `attachIngressBPFProbe` and `attachEgressBPFProbe` call the replace for their hook instead of the attach, for a new pod and a re-attach alike. The EEXIST branch, its detach, and `utils.IsFileExistsError` go away. The agent picks up the replace with an SDK bump.

### Testing

This change adds two kernel tests, run with the other BPF kernel tests:
- `TestReattachAfterRestartKeepsPodFilteredKernel` (`pkg/ebpf/bpf_client_test.go`) is the regression test for #790. It attaches a pod's compiled programs to a veth in a test network namespace through `AttacheBPFProbes`, as on CNI ADD, then calls `AttacheBPFProbes` again from a client in the state a restarted agent is in (no record of attached pods, the programs recovered), as the reconcile does. After every TC call it checks both hooks, and asserts that each always holds one filter, that nothing is detached, and that the pod runs the same programs afterwards. Today both hooks are empty after their detach, so the test is checked in skipped. The skip comes off once the fix and this test are on the same branch; #821 doesn't carry this test yet.
- `TestReplyToEgressAllowedFlowPassesIngressDenyKernel` (`pkg/ebpf/tcp_reset_kernel_test.go`) runs the compiled v4 and v6 programs on packets: with the pod's ingress denied and its egress allowed, a reply to the pod's connection passes and a new connection from the same peer doesn't. This is intended behavior, and it is why a connection that gets in during the gap stays allowed.

The fix adds its own tests:
- **SDK (#186):** root tests in `pkg/tc` for the replace: it creates the filter, swaps an existing one, and fails cleanly without touching the existing filter. The clsact cases cover a clsact someone else added first or between the list and the add, an `ingress` qdisc in clsact's place, the CNI bandwidth plugin's qdisc, and a failing qdisc list. Next to other TC users' filters it ends in the same state as today's attach. Two tests look for a gap during 500 replaces, one in a filter dump and one in traffic through a veth, each with a detach-and-attach control that must show the gap.
- **Agent (#821):** unit tests with a fake TC client that has the kernel's replace semantics (swap or create) and fails the test on any attach or detach, and an integration spec that restarts the agent several times while a prober opens connections to a server a deny policy covers, and expects none to connect. It counts the SDK's replace log lines.

### Interaction with Existing Features

- **Strict and standard mode** are unaffected: the replace doesn't touch the pod's state maps.
- **Binary changes** keep their gap: `CleanupQdiscs` detaches the filters before `ReAttachEbpfProbes` attaches, so its replace usually creates the filter on an empty hook. That is the only path that still detaches.
- **Pod deletion** doesn't detach and is unchanged: `deleteBPFProgramAndMaps` unpins the pod's programs and maps, and the filters go away with the veth.
- **Another agent's clsact qdisc (#733).** Today the EEXIST branch misreads an EEXIST from the SDK's qdisc add, when another agent installs clsact on a new veth at the same time, as a stale filter, and the detach that follows fails the CNI ADD. With this change the SDK's clsact step accepts the clsact the other agent added and goes on to the filter, and the agent no longer has an EEXIST branch, so that failure goes away (inferred from the code in #186; not run against #733's setup). How the agent's filters coexist with another agent's filters is out of scope here.

### Observability

The agent adds no log line. The warning `Stale ingress TC filter on <veth>; detaching before re-attach` goes away with the EEXIST branch. The SDK logs `TC host egress filter replace done <veth>` (or `host ingress`) for every attach, which the integration spec in #821 counts, and a warning when an `ingress` qdisc sits in clsact's place.

## Alternatives Considered

### Alternative 1: keep the existing filter on EEXIST

This is what the agent did through v1.3.x, and it has no gap. But the filter already on the veth isn't always the program the agent means to attach: after an upgrade that changes the TC binaries, or one that renames the pins as #576 did, it runs the old program, and keeping it leaves the pod on that program. Checking the attached program's ID first and keeping only the agent's own avoids that, but a mismatch still has to swap programs, so it needs the replace anyway, plus a second path to keep correct.

### Alternative 2: rebuild the record of attached pods at startup

If `ingressPodToProgMap` and `egressPodToProgMap` were rebuilt from the kernel at startup, the reconcile wouldn't attach again. That is more state to recover and keep consistent across restarts, for the same result as the replace on same-binary restarts, and it doesn't help when the binaries change.

### Alternative 3: replace in the agent, behind an interface that embeds the SDK's TC client

The agent could send the replace itself, behind an interface that embeds `tc.BpfTc` and adds a replace per hook, and ship without an SDK release. But the agent would duplicate the SDK's filter attributes and qdisc handling, and the replace would have two implementations once the SDK has one. The SDK is the natural home and releases often (v1.0.18 to v1.0.20 in the two weeks to 2026-11-03), so the SDK bump costs little time.

### Alternative 4: tcx links

Since Linux 6.6, TC programs can be attached through `bpf_link`s and updated atomically. AL2 (5.10) and AL2023 (6.1) don't have them, and switching attach mechanisms is a larger change.

### Alternative 5: attach first, and replace on EEXIST

The agent could keep its attach and call the replace only when the attach returns EEXIST. A new pod's path would stay exactly as today. But every pod does a failed add per direction on each restart, two netlink calls instead of one, and EEXIST can come from the pod's filter or from the clsact add, so the agent would have to guess which. Always replacing has one path for both cases.

## Security Considerations

This closes a window in which traffic a policy denies reaches the pod, and in which such a connection can stay open afterwards. It adds no privileges or interfaces: the agent already manages these filters over netlink.

## Backward Compatibility

- **Filter attributes are unchanged.** Every SDK release since TC support (2362b58, July 2023) attaches with handle 1, priority 1 and `ETH_P_ALL`, so the replace finds the filter any released agent left and doesn't add a second one.
- **Affected releases:** v1.4.0 and later delete and add again. v1.3.x and earlier kept the existing filter, with no gap.
- **Upgrade from an older agent:** if the TC binaries are unchanged, the new agent replaces the old agent's filters with no gap. If they changed, the upgrade path's detach and the #791 window remain (see Non-Goals).
- **Rollback:** an older agent deletes and adds again, as today.
