# Conntrack GC: look up the agent's own entries

Find the agent's stale conntrack map entries by looking each one up in the kernel conntrack table, instead of reading the whole kernel table every cleanup run, so the cleanup's memory and CPU follow the agent's own map rather than the node's table (#746).

## Motivation

Every half `--conntrack-cache-cleanup-period` (default 300 s), the agent's conntrack GC alternates between two runs, so each runs once per period. One copies the keys of its BPF conntrack map into a local cache. The next checks each cached key against the kernel conntrack table and deletes the ones no kernel flow keeps alive.

### Limitations of current behavior

The check reads the whole kernel table for the family with `netlink.ConntrackTableList`, which returns every flow parsed, all at once. The agent then builds a Go map with up to four keys per kernel flow, and only after that looks up its own entries in it. The cost of every check run therefore grows with the node's kernel table, not with the entries the agent tracks. The agent's map is bounded by `--conntrack-cache-table-size` and is often much smaller than the kernel table.

In our experiment, with about 400,000 entries in the kernel table and a few hundred in the agent's map, the agent's peak memory went from about 96 MiB to 466 MiB on every check run, and each run used about 3.4 s of CPU. The spike follows the cleanup timer, not the traffic, so it repeats every period for as long as the table stays large.

### Use Cases

1. **Nodes with a large kernel conntrack table.** A node that carries many connections, for example a node behind a load balancer or one running a busy proxy, has a kernel table far larger than what the agent tracks for its pods. Today the agent's memory limit has to cover the whole kernel table at its peak, and the headroom shrinks as the table grows.
2. **Predictable agent sizing.** An operator should be able to size the agent's memory from what it tracks, which `--conntrack-cache-table-size` bounds, without knowing how many connections the node's other workloads open.

### Non-Goals

- **Changing which entries count as live.** The rule that decides whether a kernel flow keeps an entry is unchanged.
- **The cleanup schedule, the BPF map, and the datapath.** The cleanup period, the hydrate run, the map layout and the BPF programs are unchanged.
- **Conntrack zones other than the default.** The lookups search the default zone only, which is the only zone the VPC CNI and kube-proxy use.
- **Making each lookup cheaper.** When the agent's map is about as large as the kernel table, this change uses more CPU than today (see Measurements). It doesn't try to recover that.

## Proposal

### Proposed Spec

No new flag. The check run looks up the agent's own entries instead of dumping the kernel table. Entries are kept and deleted as today, except for flows that a node's own rules place in a non-default conntrack zone (see the table below).

### How It Works

**TCP and UDP entries.** For each entry, the GC sends a ctnetlink `IPCTNL_MSG_CT_GET` for the entry's tuple. The kernel finds a flow by either of its tuples, so this finds any flow whose original or reply tuple is the entry's. If no flow is found, or the flow it returns doesn't produce the entry's key, the GC sends a second GET for the inverse tuple. That finds a DNAT'd flow by its reply tuple: for a connection from pod A to a Service VIP that kube-proxy DNATs to pod B, the agent's key from A to B is neither of the flow's tuples, but B to A is its reply tuple. The returned flow is checked with the same key rule as today: a flow `src:sport → dst:dport` with reply source `rsrc:rsport` produces `src:sport → dst:dport` owned by either end, and, if `dst` differs from `rsrc`, `src:sport → rsrc:rsport` owned by either end.

A live entry costs one GET and a stale one costs two. Each GET carries `NLM_F_ACK`, because the kernel sends the found flow with `NLM_F_MULTI` set and no `NLMSG_DONE`, so without an ACK the read would wait until the socket times out. When no flow matches, the kernel's only reply is `ENOENT`, which the GC reads as "no such flow". All of a run's GETs share one netlink socket, with the same send and receive timeouts the netlink library sets on its own sockets, so a reply that never arrives fails the lookup instead of blocking the GC.

**Entries without ports, such as ICMP.** The datapath stores ICMP entries with zero ports, and a GET needs the ICMP id, type and code, which the entry doesn't carry. So for each such protocol the agent tracks, the GC dumps the kernel's flows of that protocol once, and matches every port-less entry of the protocol against it. The dump asks the kernel to filter by protocol with `CTA_FILTER`, which ctnetlink supports since Linux 5.8. Older kernels ignore the attribute and send the whole family. That is still correct, only slower, because keys built from other protocols' flows carry their own protocol and match no entry. The dump is parsed one netlink message at a time into one reused flow, so it never holds more than one flow in memory. A run with no port-less entries does no dump.

**Its own parser.** The netlink library's flow parser is unexported, and the library only parses flows inside `ConntrackTableList`, which buffers the whole table. The GC therefore parses the messages itself, reading only the fields it uses: the family, and the addresses, ports and protocol of both tuples. It reads ports only for TCP and UDP, as the library does, so the keys it builds are the same.

**Errors.** As today, if the kernel table can't be read, the run deletes nothing and logs the error, rather than treating unread entries as stale. With lookups, that covers any GET error other than `ENOENT`, an ACK with no flow before it, a dump the kernel marks as interrupted, and a message that doesn't parse: a missing tuple, a tuple without both addresses, or an address that isn't 4 bytes for IPv4 or 16 bytes for IPv6. Each of these would otherwise make a live entry look stale.

### Measurements

In our experiment (m5.large, AL2023, kernel 6.1, IPv4), we measured today's build and this change, with the agent's peak memory taken from the process's peak resident memory. Appendix A has the test bed.

| Case | Today | This change |
|---|---|---|
| 400k kernel entries, a few hundred agent entries: peak memory | 466 MiB | 99 MiB |
| Same: CPU per check run | 3.4 to 3.5 s | 0.1 s |
| 100k agent entries, kernel table about the same size: peak memory | 166 MiB | 97 MiB |
| Same: CPU per check run | 0.65 to 0.86 s | 2.9 to 3.1 s |

The cost now follows the agent's entries, at about 25 to 30 µs of CPU per lookup. The second case is the worst for this change: at the default 300 s period, it is about 1% of one core, against 0.25% today. From these two cases we estimate that this change uses less CPU than today once the kernel table is more than about 4 times the agent's map.

### Interaction with Existing Features

**Which connections depend on the lookups.** The GC deletes an entry only if no kernel flow produces its key and the datapath has not touched the entry since the check run started; it re-reads the live map entry to see that. So a connection that sends a packet while the run is in progress keeps its entry whatever the lookups return. Only a connection that is quiet for the whole run depends on them. If its entry is wrongly deleted, its next packet is evaluated against policy again, and a reply that only its entry allowed is dropped.

| Case | Behavior with this change | Differs from today? |
|---|---|---|
| TCP or UDP flow without NAT, or with DNAT only | Found by the GET for its tuple or for the inverse tuple. Kept. | No |
| Port-less entry (ICMP) | Matched against a dump of its protocol, which covers all zones. Kept while its flow exists. | No |
| DNAT plus SNAT, for example a pod's connection to its own Service, which kube-proxy masquerades | The agent writes client to VIP, which the GET for the flow's original tuple finds, and node IP to backend, which is the "keys written after SNAT" row below. A client-to-backend key wouldn't be found, but the agent never writes one (see below). | No |
| Flow in a non-default conntrack zone | A GET searches the default zone only, so such an entry is deleted unless touched during the run. Neither the VPC CNI nor kube-proxy places flows in another zone (see below). | Only if a node's own rules set a zone |
| SCTP and other non-TCP, non-UDP entries with ports | Never match, because netlink reports their ports as zero. Kept only while active. | No |
| Keys written after SNAT, for example node IP to a local backend for a NodePort with `externalTrafficPolicy: Cluster` | No flow produces them. Kept only while active. Once deleted, the backend's replies to the node IP are allowed anyway, since the agent's NetworkPolicy maps always allow the node IP. | No |
| The kernel table can't be read, or a reply doesn't parse | Nothing is deleted this run, and the error is logged. | No |

Two of these rows need more explanation:

- **Why the agent never writes a client-to-backend key.** The pod-egress program is attached at tc ingress of the pod's host-side veth, and the pod-ingress program at its tc egress (`attachIngressBPFProbe` and `attachEgressBPFProbe` in `pkg/ebpf/bpf_client.go`). Both build keys from the packet's addresses at that point. tc ingress runs before netfilter's DNAT, and tc egress runs after its SNAT. So the client's egress program sees client to VIP, and the backend's ingress program sees node IP to backend. No program sees the packet as client to backend. On a cluster, a pod's idle connection to its own Service kept working through about 10 check runs, under a policy that allows no ingress and egress to the Service only.
- **Why only the default zone matters.** A flow leaves the default zone only if a netfilter rule assigns it one, for example `-j CT --zone`. Neither the VPC CNI (at a149c83) nor kube-proxy's iptables, IPVS and nftables modes (v1.32.0) sets a zone. A node whose operator adds such a rule for pod traffic would see quiet connections lose their entries. If that turns out to matter, the GC can fall back to a dump for the entries it doesn't find.

The cleanup period and table size flags, policy enforcement, and the conntrack shortening for denied connections (#704) are unaffected.

### Observability

- The existing `Done cleanup of conntrack map: deleted <D> stale entries out of <K> tracked` line, and the debug lines for each kept or deleted entry, are unchanged. IPv4 and IPv6 entries now print in the same format.
- A failed IPv6 read is logged as an error with its cause, as IPv4 already does, instead of at info level without it.

## Alternatives Considered

### Alternative 1: keep the dump, but stream and parse one message at a time

This fixes memory: in our experiment, such a build peaked at 102 MiB with 400k kernel entries. But its CPU per check run was still 1.4 to 2.8 s, because it still reads and parses every kernel flow. The cost stays tied to the kernel table, which is the problem in Use Case 1. This change keeps the streaming approach only for port-less entries, where a lookup isn't possible.

### Alternative 2: filter the dump with the netlink library

The library's `ConntrackTableList` takes no filter, and its `ConntrackFilter` is matched in the agent after the library has read and buffered the whole family (`dumpConntrackTable` returns every message). It doesn't use the kernel's `CTA_FILTER`. So memory would still grow with the kernel table.

### Alternative 3: follow conntrack destroy events

The agent could subscribe to the kernel's conntrack events and delete an entry when its flow is destroyed. We did not build this. We expect it to cost more than it saves: it needs a long-lived listener, handling for events the kernel drops when the listener falls behind, and a separate pass at startup for flows that ended before the listener started. That pass would be a lookup or a dump anyway.

### Alternative 4: one GET per entry, without the inverse lookup

This halves the GETs for stale entries, but misses a DNAT'd flow's backend keys, so a quiet connection through a Service loses its entry on the backend's side. The integration spec fails with a build that skips the inverse lookup.

## Security Considerations

No new privileges or interfaces: the agent already reads the kernel conntrack table over netlink. The change affects which BPF conntrack entries the GC deletes, and an entry deleted wrongly drops replies that only the entry allowed. It never keeps a stale entry that today's GC would delete: every flow a lookup finds is one the full dump would have listed, and the GC applies the same key rule to it. Any read or parse failure deletes nothing, as today.

## Backward Compatibility

- **No flags, no map or BPF program changes,** and no upgrade or rollback steps. An older or newer agent reads the same map.
- **One behavior change:** entries for flows in a non-default conntrack zone are deleted when their connection is quiet for a whole check run. Only a node's own netfilter rules put flows there; the VPC CNI and kube-proxy don't (see Interaction with Existing Features).
- **Logging:** a failed IPv6 read moves from info to error level, with its cause.
- **Kernels before 5.8** dump the whole family for port-less entries instead of one protocol; results are the same.

## Appendix A: Test bed

All runs used one m5.large node of an EKS 1.32 cluster in us-west-2, AL2023 x86_64, kernel 6.1, IPv4, with a 1 GiB memory limit on the agent container. Each run started a fresh agent. "Peak memory" is the process's peak resident memory (`VmHWM`). "CPU per check run" is the agent's user plus system CPU between samples taken just before and just after the run.

**Large kernel table.** 400,000 synthetic kernel conntrack entries plus the node's own (about 400.3k to 400.9k in total), `nf_conntrack_max` raised to 524,288, default cleanup period of 300 s, 3 check runs per build. The agent tracked 241 to 377 entries. Of 200 UDP flows from a pod, kernel entries were kept for 100 and not for the other 100. Both builds kept the first 100 and deleted the second 100. With this change, a pod pinging another pod for the whole run kept both of its ICMP entries, and each check run did one ICMP protocol dump. Today's build was main at c50d4bb; this change was revision 274ead4. The streaming build in Alternative 1 was 2736b31.

**Large agent map.** A pod sent 100,000 UDP datagrams, each on its own 5-tuple, to addresses its egress policy allows, so the agent wrote one entry each. The kernel table held them too, with the UDP timeout raised while sending. The cleanup period was 60 s. Over 3 check runs with the flows live, this change sent about one GET per entry (100,104 to 100,116 for about 100,075 entries). After the kernel flows were deleted, the next run sent two per entry (200,116) and deleted all of them, as did today's build. Today's build was main at 5cef5ef; this change was revision 08b5764. A run with 25,000 entries gave 0.17 to 0.31 s per check run today and 0.78 s with this change, with no change in peak memory.

**Correctness.** The GC's keep and delete tables run against a real kernel conntrack table in a test network namespace. Compared with today's full-dump GC on a real table of 292 flows, the only differences were a hairpin flow's client-to-backend key, which the agent never writes, and a flow in a non-default zone. An integration spec sets a 2 s cleanup period and checks that busy and idle connections, direct and through a Service, keep working through about 30 check runs while the server's egress is denied, that reset connections' entries leave the map, and that a pod's idle connection to its own Service keeps working. It passes on AL2023 (kernel 6.1) and AL2 (kernel 5.10) nodes.
