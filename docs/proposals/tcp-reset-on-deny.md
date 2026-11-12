# TCP reset on deny

Answer a TCP connection attempt that a policy denies with a RST instead of dropping it silently, behind a flag that is off by default (`--enable-tcp-reset-on-deny`).

## Motivation

The agent drops a TCP SYN that a policy denies, silently. EC2 tracks the connection attempt anyway, and because the SYN is never answered, EC2 keeps its entry for about two minutes on both the client's and the server's instance. A flood of denied connections can use up the instance's connection tracking allowance, and then allowed connections on the instance fail too.

EC2 tracks connections in the instance's network card, below the operating system, and limits how many it tracks per instance. Per the [EC2 connection tracking documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html):
- Connections through a Network Load Balancer are always tracked, whatever the security group rules.
- Once the allowance is used up, "any packets that are sent or received are dropped because a new connection cannot be established". The `conntrack_allowance_exceeded` and `conntrack_allowance_available` ENA statistics show it.
- The idle timeouts that can be configured on an ENI are for established TCP connections (60 s minimum) and UDP flows. None of them applies to a connection that never completes.

A NetworkPolicy deny happens on the node, after EC2 has tracked the SYN. Neither side ever sees the connection complete or close, so EC2 holds the half-open entry until it times out: about 120 s on both instances, measured on our test cluster. A denied flood therefore costs EC2 about `rate × 120` entries. At 5,000 denied connections/s that is about 600,000, against an allowance of about 205,000 on an m5.xlarge (`conntrack_allowance_available` when idle). The allowance runs out in under a minute.

#704 doesn't help here: it shortens the node kernel's conntrack entry for a denied SYN, which is separate from EC2's tracking.

**Measured on our test cluster** (m5.large nodes, AL2023, kernel 6.1; 120 s of new connections, each from a new source port with a 2 s client timeout). An idle m5.large can track about 102,500 more connections; "entries used" below is how far the instance's `conntrack_allowance_available` fell from that during the run.

Hold time per denied connection, 300 new connections/s through an NLB (IP targets, client IP preservation on):

| | Entries used on the server | Entries used on the client | How long EC2 holds each one |
|---|---|---|---|
| Today (silent drop) | about 35,900 | about 35,900 | about 120 s |
| This change (RST) | 1 | 0 | freed at once |

5,000 denied connections/s through the NLB, with 75 allowed connections/s to the same pod alongside. Both columns are this change's build, with the flag off and on:

| | Flag off (today's behavior) | Flag on (RST) |
|---|---|---|
| Server's free entries (of about 102,500) | none left after 20 s | at most 8 used |
| Clients' free entries (of about 102,500 each) | none left after 42 s | at most 11 used |
| `conntrack_allowance_exceeded` on the clients | +395,000 each | 0 |
| Allowed traffic | 63% succeeded; p99 1.09 s | 100%; p99 15 ms |
| Denied attempts | 599,719 timed out | 599,765 refused |
| Agent container CPU | under 0.1% of one vCPU | under 0.1% of one vCPU |
| Kernel packet processing (softirq) on the server node | up to 0.9% of its CPU | up to 5% of its CPU |

With the flag on, the NLB counted 599,765 target resets and 0 of its own, so every RST went back through it. Node to node, with the flag on, the results were the same. The 300/s numbers are from a prototype that passed the RST through the egress program with an `skb->mark` bit instead of a map entry (see Alternative 7); the packets on the wire are the same.

### Use Cases

1. **A misbehaving internal client.** A service inside the VPC starts opening connections in a loop to a pod behind an internal NLB that its policy denies, for example after a bad deploy. The target's and the client's EC2 allowances fill, and every other client of that pod, and every other connection on both instances, starts to fail. There's no "bad source" to block ahead of time: the client is a legitimate service, so a security group deny isn't an option.
2. **Faster failure for denied clients.** A client whose access was removed by a policy change gets "connection refused" at once, instead of hanging on timeouts and retries.

### Non-Goals

- **Protocols other than TCP.** Denied UDP, SCTP and ICMP keep being dropped. This change covers TCP, where we measured the problem. Whether an ICMP "administratively prohibited" reply would free EC2's entry for a UDP flow is untested, and could be a follow-up.
- **TCP packets other than a bare SYN.** Other denied TCP packets (stray ACKs, data on a flow a policy no longer allows) keep being dropped. Only a SYN opens a connection, so only a SYN leaves a half-open entry. SYNs with IP options or IPv6 extension headers are also dropped as today, since the programs don't parse them.
- **Allowed traffic.** Allowed traffic alone can still fill an instance's allowance. This change doesn't affect that.
- **Rate limiting the RSTs sent.**

## Proposal

### Proposed Spec

A node agent flag, off by default:

```
--enable-tcp-reset-on-deny=true
```

With it off, the datapath behaves exactly as today. With it on, a bare TCP SYN that any policy tier denies (admin, network policy, baseline, or the pod's default deny) is answered with a RST|ACK from the pod; the client sees "connection refused". Every other denied packet is still dropped. IPv4 and IPv6, on AL2 (5.10) and later kernels, in both ingress program variants (with and without the #704 conntrack shortening). The flag is read at agent start; changing it doesn't need pods' programs reloaded.

### How It Works

**Ingress.** The ingress program runs at TC egress of the pod's host-side veth, just before a packet would reach the pod. When a policy denies a bare SYN and the flag is on, it:
1. Rewrites the packet in place into a RST|ACK from the pod to the client, as RFC 9293 3.10.7.1 prescribes for a SYN: sequence number 0, acknowledging the SYN's sequence number plus one, no options or payload, checksums recomputed.
2. Records the RST in a node-wide map, `aws_tcp_reset_pending`, keyed by its addresses, ports and the veth.
3. Redirects it to the ingress of the same veth (`bpf_redirect` with `BPF_F_INGRESS`).

The host then receives the RST as if the pod had sent it and routes it as a reply: netfilter sees it, so the kernel conntrack entry closes too, and SNAT, policy routing and the load balancer path all apply as for any other reply.

**Egress.** The redirected RST reaches the pod's egress program (TC ingress of the same veth). Evaluated as pod traffic, it would go wrong either way:
- If egress policy allowed it, the program would record pod to client in its flow cache, and the client's next SYN on the same ports would be accepted as a reply.
- If egress policy denied it (common with default-deny policies), the RST would be dropped, and the client would time out as today.

So the egress program passes a TCP RST that has an entry in `aws_tcp_reset_pending`, deletes the entry, and records nothing. Any other RST from the pod is evaluated as before. A pod can't use the map: it could only send a RST with the same addresses and ports in the microseconds before the egress program consumes the entry, and that RST would be the same packet.

**Flag and maps.** The flag's value and the pending map live in a new binary, `tc.shared.bpf.o`, which the agent loads once per node and pins:
- `aws_tc_config`: an array with one entry, holding the flag. The agent writes it at every start, so the value applies to programs pods already run.
- `aws_tcp_reset_pending`: an LRU hash of 8,192 entries. Entries normally live from the redirect to the egress program, microseconds later; the LRU evicts the rare ones the host dropped in between. Under the 5,000/s flood it held at most one entry at a time.

They are not in the events binary because a change to that binary makes the agent recreate its conntrack map, which drops the state of every allowed flow on the node. A runtime toggle in a map was chosen over more compiled variants: the ingress programs already come in two variants, and a compile-time flag would double that.

**Cost.** With the flag off, a denied bare SYN costs one array lookup more than today, other denied packets cost nothing more, and a RST from a pod costs one hash lookup. With it on, each denied SYN costs a map update, two checksum computations and a packet rewrite; at 5,000/s the server node's kernel spent up to 5% of its CPU (2 vCPUs) on packet processing, against 0.9% with the flag off, and the agent's own CPU didn't change.

### Interaction with Existing Features

- **Strict mode.** A pod under strict mode's default deny is denied by the pod's default tier, so with the flag on its denied SYNs are answered with RSTs too. That changes what a client sees while a new pod waits for its policies: today its SYN is dropped and the client's retransmit can succeed once the policies apply; with the flag on, the client gets "connection refused" at once and has to retry the connection itself.
- **Conntrack shortening on deny (#704).** Both ingress variants answer with a RST. In the #704 variant the kernel entry is shortened first, and the RST then closes it through netfilter.
- **Policy event logs.** With `--enable-policy-event-logs` on, each denied SYN is still logged as a deny, as today. Sending the RST doesn't add a log entry of its own.
- **Policy changes on existing flows.** A SYN on a flow that a policy change now denies (for example a retransmit) is answered with a RST like a new one. Established flows are unaffected.
- **Load balancers.** Through an IP-mode NLB with client IP preservation on, every RST reached the client (measured). With preservation off, in one test with pod-kernel RSTs, 3.6% didn't, and those clients timed out as today (measured; the cause is not known).

### Observability

- The agent logs `TCP reset on deny enabled: <true|false>` at start.
- On the client, a denied connection fails with "connection refused" instead of a timeout. On EC2, `conntrack_allowance_available` no longer falls under a denied flood.
- There is no counter of RSTs sent.

## Alternatives Considered

### Alternative 1: deny the sources at a security group

Traffic a security group denies doesn't reach the pod or use the instance's connection tracking, so this avoids the problem. But it needs a list of sources known ahead of time, kept outside the cluster's policy, and an NLB only supports security groups if it was created with one. It stays the right choice for known bad sources, and doesn't cover Use Case 1, where the source is a legitimate service.

### Alternative 2: lower the ENI's connection tracking timeouts

Only established TCP and UDP timeouts are configurable, so half-open entries are unaffected.

### Alternative 3: drop denied traffic earlier

For example with XDP on the node's interfaces. EC2 tracks the connection before the packet reaches the instance, so the entry is the same.

### Alternative 4: shorten the node's kernel conntrack entry (#704)

It keeps the node's own table from filling, but EC2's tracking is separate, so it doesn't help here. A RST was considered for #704 and set aside because it reveals the deny; that was weighed only against the node's kernel table, before EC2's tracking was found to be the limit.

### Alternative 5: scale out or up

More or larger instances raise the total allowance, at a cost, and a large enough flood still exhausts it.

### Alternative 6: answer with ICMP "administratively prohibited"

Untested: we don't know whether EC2 frees its entry when it sees this ICMP message. For TCP, a RST is the standard answer to a refused connection, and clients report it as "connection refused".

### Alternative 7: other signals for the egress bypass

- **A bit in `skb->mark`.** The prototype used one, and it worked on AL2023 (6.1) but not on AL2 (5.10). A BPF redirect to ingress goes `__bpf_rx_skb` → `dev_forward_skb` → `____dev_forward_skb` → `skb_scrub_packet(skb, xnet)`, which clears the mark only when `xnet` is true (`net/core/skbuff.c`: 5.10 lines 5228-5232, 6.1 lines 5518-5522). 5.10 always passes true (`include/linux/netdevice.h:3921`), so the mark is gone even within one network namespace; 6.1 passes `!net_eq(...)` (`netdevice.h:3960`) and keeps it. On 5.10 the egress program would then evaluate the RST: with egress allowed it would record pod to client, and the client's next SYN on the same ports would complete a handshake to the denied port. The mark is still unforgeable by pods on both kernels, since a packet from the pod crosses namespaces (`veth_xmit` → `__dev_forward_skb`, `xnet` true).
- **Never recording a flow for an outgoing RST.** That closes the bypass on every kernel, but a RST to a destination egress policy denies would still be dropped, so pods with default-deny egress would get nothing from the option. It would also change how the egress program treats every RST pods send.
- **Enabling the option only on kernels that keep the mark.** Simple, but it leaves AL2 out, and it ties correctness to a kernel detail that a load-time check can only infer from the version.

### Prior art

Other Kubernetes network policy implementations already offer rejecting denied traffic instead of dropping it, all opt-in:

| Implementation | Setting | Denied TCP connection gets | Default |
|---|---|---|---|
| Calico | FelixConfiguration `iptablesFilterDenyAction` / `nftablesFilterDenyAction` (`Drop` or `Reject`), node-wide | iptables `REJECT` | `Drop` |
| Antrea | `Reject` action on Antrea-native policy rules, per rule | "an explicit reject response for TCP" | set per rule |
| Cilium | `--policy-deny-response` (`none` or `icmp`, experimental), egress only | ICMP unreachable | `none` |

Sources: [Calico FelixConfiguration](https://docs.tigera.io/calico/latest/reference/resources/felixconfig), [Antrea network policy](https://antrea.io/docs/main/docs/antrea-network-policy/), [Cilium policy enforcement](https://docs.cilium.io/en/stable/security/policy/intro/). Calico's is the closest to this change: one node-wide switch from drop to reject, off by default.

## Security Considerations

Answering a denied connection tells the sender that the address exists and that policy blocks it, which a silent drop does not. Senders can also cause the node to send RSTs on their behalf. For these reasons the flag is off by default, and it is meant for clusters where denied traffic comes from inside the operator's own network. It does not weaken enforcement: denied connections are still refused, other denied packets are still dropped, and the only packet that skips egress evaluation is the RST the agent itself sent.

## Backward Compatibility

- **Default behavior is unchanged:** with the flag off, every denied packet is dropped as today.
- **Upgrade:** the new agent loads `tc.shared.bpf.o` if its maps aren't pinned, and the ingress and egress binaries change, so pods' programs are reloaded as for any binary change. The events binary and the conntrack map are untouched.
- **Shared binary changes:** the agent compares `tc.shared.bpf.o` with its copy on the host, as it does the events binary. If it changed, or either pin is missing, it creates the maps again and reloads every pod's programs against them, so no program is left on maps with an old layout.
- **Restart:** the pinned maps are reused, since running programs reference them, and the flag is rewritten. On the first start after an upgrade, before the maps are pinned, the agent loads them before choosing which ingress variant to use.
- **Downgrade:** an older agent ignores the two pinned maps, which stay on the node (well under 1 MiB, inferred from their sizes).
- **Enabling it** needs the flag passed to the node agent. Exposing it in the VPC CNI Helm chart and the EKS add-on configuration is a follow-up there.
