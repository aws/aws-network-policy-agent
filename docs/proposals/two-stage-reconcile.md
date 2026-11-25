# Two-stage reconcile for policy enforcement

Split each policy controller's reconcile in two:
- **Stage 1** records what each policy selects and queues the pod identifiers it affects.
- **Stage 2**, keyed by pod identifier, programs each identifier's eBPF maps from the newest state.

Repeated changes to one identifier coalesce into one write. Stage 2 runs one worker per controller, and `--max-concurrent-reconciles` stays unread. Its queue would keep more workers safe for any one identifier. One worker narrows a window during rollouts in which a new pod can be left at the baseline, but does not close it (see Risks).

## Motivation

The network policy controller (NPC) splits each NetworkPolicy and ClusterNetworkPolicy into slices, PolicyEndpoints and ClusterPolicyEndpoints, and each slice names its parent policy. Replicas of a workload share a **pod identifier**: the namespace plus the pod name minus its last segment. On a node, an identifier's pods share one set of eBPF rule maps.

Each controller runs one worker on `(slice, parent)` requests. Each reconcile recomputes the whole parent policy and rewrites the full rule set of every local identifier the parent selects. So a policy edit that changes 30 slices rewrites each identifier 30 times, and other changes wait behind those rewrites. Adding workers to this reconciler is unsafe: two reconciles that touch one identifier each compute its rules from their own snapshot, and the last write can come from the older one. That can leave a pod with rules but allow-all state, or the reverse.

**How the measurements are described.** Every scenario states:
- **its scale:** the pod identifiers on the agent's node, and in parentheses how many of them the scenario touches;
- **whether a policy spans the cluster:** its peers or subjects are every pod, so that any pod change anywhere turns into slice events for it;
- **whether it ran against real eBPF.**

The work this change removes grows with the identifiers on the node times the slice events that select them. It is large only when a cluster-wide policy makes every pod change an event for every identifier.

**On EKS, with real eBPF** (at `8fd1a15`, before the follow-up commits in #838). `awslbc-loadtest`: 29.5k pods in 100 namespaces with 12 NetworkPolicies each, none with peers outside its namespace; 3 real Bottlerocket nodes, kernel 6.12. Figures are the time from an agent restart until every identifier is programmed, where given, and agent CPU per node; 2 runs each:

| Identifiers per node (touched) | Scenario | Cluster-wide policy | Today | This change |
|---|---|---|---|---|
| 92–94 (all) | Agent restart, until every identifier is programmed | none | 50–52 s, 38 CPU-s | 44 s, 34 CPU-s |
| 92–94 (all) | Agent restart, until every identifier is programmed | one ClusterNetworkPolicy selecting all pods | 141–142 s, 152 CPU-s | 29–31 s, 42 CPU-s |
| 54–60 (25–30) | 90 pods replaced in 30 namespaces | none | 17–18 CPU-s | 17–18 CPU-s |
| 54–60 (25–30) | 90 pods replaced in 30 namespaces | one ClusterNetworkPolicy selecting all pods | 42–45 CPU-s | 18–20 CPU-s |
| 92–94 (63–68) | 196 pods replaced in 98 namespaces | one ClusterNetworkPolicy selecting all pods | 110–116 CPU-s | 42–43 CPU-s |

- **Latency.** With the cluster-wide policy, cluster-policy programming p50 drops from at most 1 s to at most 0.25 s.
- **Convergence.** A churn round takes 75–150 s to converge on both, set by the pod rollout.
- **Kernel work.** Kernel-visible map writes are about the same on both; the saving is recomputation.

**With a harness** (on the 2026-11-24 revision of #838, before the follow-up commits). It runs the agent's controllers and rule computation against a fake BPF client, so there are no kernel calls. It is modelled on `awslbc-loadtest`: 29.5k pods in 100 namespaces with 12 policies each. In 2 namespaces, one of those policies allows ingress from every pod. Figures are the median of 3 runs, wall time and agent CPU of one burst on the agent's node:

| Identifiers per node (touched) | Scenario | Cluster-wide policy | Today | This change (1 worker) |
|---|---|---|---|---|
| 360 (360) | Cold start: every policy created at once | all-pods peers | 128 s, 156 CPU-s | 6.8 s, 9.0 CPU-s |
| 360 (31) | 48 pods replaced in 8 namespaces | all-pods peers | 103 s, 124 CPU-s | 4.2 s, 4.6 CPU-s |
| 360 (10) | Port change on the all-pods-peer policy (30 slices) | all-pods peers | 101 s, 122 CPU-s | 3.6 s, 4.0 CPU-s |
| 360 (360) | A port added to allow-DNS in all 100 namespaces (1 slice each) | none | 6.8 s, 7.9 CPU-s | 6.5 s, 7.5 CPU-s |
| 360 (360, rules unchanged) | 48 pods replaced, under 3 cluster policies selecting all pods | cluster policies | 93 s, 123 CPU-s | 1.6 s, 3.9 CPU-s |
| 107 (107 / 6) | Cold start / 48 pods replaced; 110 pods per node | all-pods peers | 33 s / 28 s | 2.2 s / 1.4 s |
| 221 (221 / 19) | Cold start / 48 pods replaced; 250 pods per node | all-pods peers | 80 s / 68 s | 4.5 s / 2.8 s |
| 1,050 (1,050 / 94) | Cold start / 144 pods replaced; the cluster at 3× | all-pods peers | 1,510 s / 1,243 s | 26 s / 18 s |
| 3,678 (3,678 / 320) | Cold start / 480 pods replaced; the cluster at 10× | all-pods peers | not run | 85 s / 57 s |

- **Coalescing is the gain.** Rule-map writes per identifier fall from 6.7–77 to about 1.
- **Real nodes keep the seconds, not the ratio.** The fake client has no kernel cost. The agent writes only changed entries to the kernel, and coalescing cuts those by just 9–12%, so kernel time is nearly the same in both, and the speedup ratio will likely be smaller on real nodes; the time saved stays about the same.
- **Steady load.** An isolated change costs about 0.7 ms either way. Today's code falls behind at 10 events/s and saturates at 30/s; one stage-2 worker keeps up at 100/s with p99 under 3.5 s.
- **Failures.** With 10% of identifiers always failing, the healthy ones converge in 7.5 s (cold start) and 4.8 s (churn), against 126 s and 101 s today. With every write failing at random 30% of the time, today's code doesn't converge within 5 minutes of a cold start; this change converges in 146 s, and after churn in 8.6 s against 100 s.
- **Scaling.** Today's cost grows about as n^2.3 with the cluster, this change's about as n^1.1.

### Use Cases

1. **Pod churn on busy nodes.** A rollout or scale-up changes many slices of the policies that select a node's pods. Each identifier is written about once per burst instead of once per slice event.
2. **Large policy edits.** An edit that NPC spreads over many slices is applied once per identifier instead of once per slice.

### Non-Goals

- **Changing the rule computation.** The rule computation, the shared maps per identifier and target groups (#800) behave as today. An identifier's maps follow its live slices, which differs from today in the cases under Differences from Today.
- **Matching pods to each policy's `podSelector`.** Replicas that share an identifier also share rules, as today.
- **The upgrade window.** An upgrade that changes the BPF objects leaves policies unenforced for about 12 s on today's code too (`CleanupQdiscs`, then `DEFAULT_ALLOW` on the reloaded programs). That needs its own change.
- **The CNI ADD path.** It still attaches a new pod and writes its rules itself.

## Proposal

### Proposed Spec

There is no new flag, and no flag changes. `--max-concurrent-reconciles` is defined today but no code reads it, and that stays so: each controller runs one stage-2 worker (see Risks). Stage 1 keeps one worker.

### How It Works

**Stage 1** is the existing queue of `(slice, parent)` requests, with one worker. It never writes eBPF state. For each request it:
1. Lists the parent's live slices from the informer cache. It recomputes which pod identifiers they select on any node, and which of each identifier's pods are on this node.
2. Records the parent's live slices for each identifier it selects, replacing the previous set, and drops the parent from identifiers it no longer selects anywhere.
3. Queues the identifiers it selects pods of on this node, now or before, whether or not they have programs here yet: a pass that finds none writes nothing, and one whose first attach is creating them runs again after it. It also queues the identifiers it selects, or stopped selecting, only on other nodes, if they have programs here, since the policy's rules reach their replicas here through the shared maps.

**Stage 2** is a new priority queue keyed by pod identifier, with one worker, in each controller. Each writes its own controller's maps: the network-policy maps or the cluster-policy maps of the identifier's programs, which the two share. A pass for one identifier:
1. Attaches probes for its pods on this node that the recorded policies select. If an attach created the identifier's programs, the other controller's maps are new and empty too, and that controller may have nothing queued for the identifier, so the pass queues it on the other controller's stage 2 before writing. That attach finds the programs in place, so it queues nothing back.
2. Reads the identifier's recorded slices again after the attach, so a change recorded while it attached is written, and reads them from the informer cache. It writes the union of their rules, or the baseline if none: allow-all in standard mode, deny in strict mode. Attach and write happen in the same pass, as today.
3. Returns any attach or write failure, so the identifier is retried with backoff: 5 ms, doubling up to 30 s. A skipped attach (`ErrProbeAttachSkipped`, for a multi-NIC pod whose interface count is unknown) is not a failure and is not retried: the pod waits for a later policy event or CNI ADD.

The queue never hands an identifier to two workers at once. It processes an identifier again if it was queued during a pass, so the last pass always reads the newest state. That would keep more than one worker safe for any one identifier. It is also what coalesces: changes that arrive while an identifier waits are applied in one pass.

**Kept from today:**
- **Target groups (#800).** A grouped PolicyEndpoint applies only to the pods its group lists, within its own policy. The filter is in the slice lookup that stage 2 and the CNI ADD path share.
- **Namespaces and host network.** A PolicyEndpoint applies only to pods in its own namespace, and skips host-network pods.

**Differences from Today.** A replay of 6,000 random sequences of slice events, in random reconcile order, through today's code and this change (at `cff5316`), compared every identifier's maps with its live slices after the last reconcile. With replicas on other nodes, this change matched the live slices in all 18,000 final states and today's code differed in 2,242. With every pod on this node, both matched in all. The replay drives one controller at a time, so the difference for new programs comes from the code:
- **A live policy with no rules.** An identifier that a live PolicyEndpoint selects, but with no rules and no isolation, gets allow-all in both directions with policies applied, as today's programming path writes it. Today's cleanup path, run when a sibling slice changes, writes the baseline instead, which in strict mode is deny.
- **Slice deletion.** Deleting a slice rewrites the identifiers it affected from the live slices, as an update does: a policy whose other slices still select an identifier's pods, here or on another node, keeps its rules there. Today a deletion leaves the slice's whole policy out of an identifier whose pods here the policy no longer selects, until the next write of the identifier. That came from #159, which skipped every slice of the deleted slice's policy so that a policy deleted slice by slice released its pods, before one policy could span several slices (#185). Here a policy that stops selecting an identifier queues it, which releases it.
- **Identifiers selected only on other nodes.** When a policy starts selecting an identifier, changes its rules, or stops selecting it, only through replicas on other nodes, the identifier is rewritten here if it has programs here, since the policy's rules reach its replicas here through the shared maps. Today those changes reach the identifier only when something else rewrites it.
- **Order.** Stage 1 recomputes the whole policy from the informer cache on every reconcile, so an identifier can reach its new state a reconcile earlier or later than today.
- **New programs.** When one controller's pass creates an identifier's programs, the other controller writes its policies to them, including ones that select the identifier only on other nodes. Today the other controller's maps keep the state the creating reconcile seeded until its own reconcile reaches the identifier, and for good if its policies select the identifier only on other nodes.
- **Slices being deleted.** A slice whose deletion has started, which only a finalizer holds open, stops contributing rules at once, in stage 2 and in the CNI ADD's lookup. Today its rules stayed until the object was gone.
- **Retries.** A failing attach or map write is retried for its identifier alone, with backoff up to 30 s, so one that fails every time is retried every 30 s. Today the whole reconcile is retried, with controller-runtime's default backoff up to about 16 minutes. A skipped attach is not retried, now or today: the pod waits for a later policy event or CNI ADD.

### Interaction with Existing Features

- **CNI ADD.** For a pod whose attach creates the identifier's programs, it writes each policy type's rules if that type has recorded policies for the identifier, and otherwise only that type's pod state, as today. Its rule lookup is the one stage 2 uses, so it skips slices being deleted. It queues neither stage 2. Its write can race a stage-2 pass for the same identifier, as it raced a reconcile before.
- **Strict mode.** The baseline for an identifier with no policies is deny, as today.
- **Agent restart.** As today, programming starts while stage 1 is still reconciling the initial list. This change does not close the startup gaps that follow from that (see Open Items).

### Observability

**Latency metrics.** Names, types, labels and buckets are unchanged. What each sample stands for changes, so the values and counts are not comparable with today's:

| Metric | Today, one sample per | This change, one sample per | Value |
|---|---|---|---|
| `awsnodeagent_policy_setup_latency_ms`: summary, labels `name` and `namespace` of the PolicyEndpoint | Local identifier of a live PolicyEndpoint's reconcile, whether its write succeeded, failed, was skipped or had nothing to do. Identifiers whose rules could not be derived are left out. | Reconcile of a live PolicyEndpoint that queued at least one identifier, once each identifier it queued is programmed and some pass wrote maps. | Today: ms from the reconcile's start to that identifier's turn in the same pass. Now: ms from the start of the stage-1 reconcile to the last of its identifiers, including the stage-2 queue wait and retries. |
| `awsnodeagent_policy_teardown_latency_ms`: summary, same labels | Reconcile of a deleted, deleting or moved slice that had pods to rewrite and failed nowhere. | Reconcile of a deleted, deleting or moved slice that queued at least one identifier, once each is programmed and some pass wrote maps. | Today: ms of the attempt that succeeded, from that attempt's start. Now: as for setup. |
| `awsnodeagent_policy_programming_latency_seconds` and `awsnodeagent_cluster_policy_programming_latency_seconds`: histograms, no labels | New `last-change-trigger-time` value on a live slice, once a reconcile of it failed nowhere and wrote some identifier's maps. | New `last-change-trigger-time` value on a live slice, once each identifier its reconcile queued is programmed and some pass wrote maps. | Seconds from the trigger time, as today. It now includes the stage-2 queue wait. |

In this change, a change's sample is taken only when every identifier it queued has finished a pass and at least one of those passes wrote maps. An identifier finishes a pass when the pass succeeds, whether it wrote maps or found no programs to write to. A pass that writes nothing because every attach was skipped does not finish it.

How the cases differ, now and today:
- **Retries.** A failed pass keeps its identifier's samples pending, and the pass that succeeds takes them, so the value includes the retry delay and a retry adds no sample. Today the setup latency was also sampled on a failing pass, the teardown latency only on the attempt that succeeded, and the programming latency waited for the reconcile that succeeded, as now.
- **No local work.** A reconcile that queues nothing, or whose identifiers have no programs on this node, takes no sample. A trigger value is consumed either way, as today.
- **Skipped attaches.** A pass that writes nothing because every attach was skipped does not count as programming the identifier, so its samples wait for a later pass of it, and none is taken if no later pass comes. Today the programming latency was sampled once any identifier was written.
- **Coalescing.** Each reconcile is its own change. Changes programmed by the same pass take one sample each, from their own start or trigger time. A resync is sampled on the same terms as any other reconcile. Each trigger value is sampled at most once. Today a value replaced before its reconcile succeeded was never sampled; now a value is sampled once a stage-1 reconcile has seen it.
- **Bound.** An identifier holds at most 128 pending changes. Past that, the oldest is dropped without a sample.
- **Clock skew.** A negative programming latency is dropped, as today.
- **Cluster policies** have no setup or teardown metric, as today.

**Controller metrics.** `policyendpoint` and `clusterpolicyendpoint` now cover stage 1 only. `controller_runtime_reconcile_total` and `_reconcile_time_seconds` count and time recording and queueing, with no eBPF work, and `_reconcile_errors_total` counts only informer-cache read failures. The new `policyendpoint-programmer` and `clusterpolicyendpoint-programmer` controllers count and time stage-2 passes, count a failed pass in `_reconcile_errors_total`, and report the identifier queue in `workqueue_depth`, `workqueue_retries_total` and the other queue metrics. `controller_runtime_max_concurrent_reconciles` is 1 for all four.

**Logs.** A failed stage-2 pass logs one agent error line that names the identifier, and controller-runtime logs the returned error, as it does for a failed reconcile today.

### Risks

- **The rollout interval.** NPC can drop a workload's last old replica from a policy before it lists the new pod. A stage-2 pass that runs in between writes the identifier at the baseline (unenforced in standard mode, dropped in strict mode) until the next pass, with any number of workers. Today's reconcile does the same when it runs in between and the old replica was on this node. When the old replica was on another node, today's reconcile does not rewrite the identifier and this change does. Whether a pass lands there depends on timing, and with a backlog, more workers reach the identifier sooner. With two stage-2 workers and a backlog of 20 identifiers, on the 2026-11-24 revision, the new pod was left at the baseline in 9 of 9 harness replays with a 1 s gap, for a median of 308 ms. Today, and with one worker, it happened in 0 of 9. One worker narrows the window but does not close it.
- **Fresh programs.** Until the other controller's pass runs, its policy type on the new programs has the state the creating pass seeded: allow for cluster policies, the baseline for network policies. That lasts until the other controller's stage 2 reaches the identifier, behind whatever it has queued. Today it lasts until the other controller's reconcile reaches the identifier, and for good if its policies select the identifier only on other nodes.
- **More than one worker.** A second worker is 1.7× faster for network policies at 10–17% more CPU, but only 1.1× for cluster policies at 33% more, and widens the rollout interval above. Hence one worker, not configurable.

### Open Items

- **Startup reconstruction (follow-up, inherited from today).** While stage 1 reconciles the initial list after a restart, a pass writes the policies recorded so far, and so does a CNI ADD. Each later policy's reconcile queues the identifiers it selects that have programs here, so an identifier has its full set once every policy selecting it has been reconciled. Two gaps remain, and both leave stale rules only on identifiers that no current policy selects, on any node. The rules of policies deleted while the agent was down stay on such identifiers. And a deselection the agent has not written when it stops, whether a slice deletion or an update that stops selecting an identifier, is lost, since stopping drops both queues and the restarted agent does not know the earlier selection. Today such a change is lost if its reconcile has not started; here it can also be lost after stage 1 has recorded it, while it waits in stage 2. After a restart, each policy's first reconcile queues the identifiers it selects that have programs here, recovered from their pins, so an identifier that any current policy selects is rewritten from the current slices. Today it is rewritten only if a policy selects one of its pods on this node. The follow-up builds both controllers' state from the synced caches before either stage 2 starts, then queues every identifier with programs on the node, which needs a way to list them, and has a CNI ADD that creates an identifier's programs queue both stage 2s.
- **Attach rollback.** Detach filters on attach rollback.
- **Debounce.** A stage-2 debounce.
- **Unit tests.** Default-deny, cluster-policy stress and strict-mode unit tests.
- **Overlapping PRs.** #764 and #760 touch the same paths.

## Alternatives Considered

### Alternative 1: more workers on today's reconciler, with a lock per pod identifier

A lock around each identifier's derive-and-write would make concurrent reconciles safe, but every reconcile would still rewrite every identifier its policy selects. That removes none of the repeated writes, and it brings back a per-identifier lock map that has to be cleaned up as identifiers come and go.

### Alternative 2: shard locks

A fixed set of locks hashed by identifier avoids the cleanup, but has the same repeated writes, and adds contention between unrelated identifiers that share a shard.

### Alternative 3: a debounce in front of today's reconciler

Delaying each `(slice, parent)` request would merge some events of one slice. It wouldn't merge events of different slices that select the same identifier, which is how a 30-slice edit rewrites an identifier 30 times, and it adds latency to every change.

## Backward Compatibility

- **Flags.** None change. `--max-concurrent-reconciles` stays defined and unread, as today, so configurations that set it still start; its help text says it is ignored.
- **Datapath.** No BPF program, map or pin changes. Builds of this change and of `main` from the same toolchain produce byte-identical objects, so upgrading or downgrading between them reloads nothing. On EKS at `8fd1a15`, every identifier's maps stayed identical across restarts, and across upgrades and downgrades between v1.5.0, `main` and this change. The repo's integration suites and cyclonus pass on IPv6 (AL2023). They also pass on IPv4, apart from specs that run commands on Bottlerocket hosts. The code PR has the full results.
- **Metrics.** Names, types, labels and buckets are unchanged, but the setup and teardown latencies are sampled per reconcile rather than per identifier, and all four latencies include the stage-2 queue wait (see Observability). Programming failures are counted under the two new controllers, which add metric series.
- **Restart.** In-memory state is rebuilt from the informer cache, as today.
