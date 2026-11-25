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

**On EKS, with real eBPF.** `awslbc-loadtest`: 29.5k pods in 100 namespaces with 12 NetworkPolicies each, none with peers outside its namespace; 3 real Bottlerocket nodes, kernel 6.12. Figures are the time from an agent restart until every identifier is programmed, where given, and agent CPU per node; 2 runs each:

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

**With a harness.** It runs the agent's controllers and rule computation against a fake BPF client, so there are no kernel calls. It is modelled on `awslbc-loadtest`: 29.5k pods in 100 namespaces with 12 policies each. In 2 namespaces, one of those policies allows ingress from every pod. Figures are the median of 3 runs, wall time and agent CPU of one burst on the agent's node:

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

- **Changing what rules an identifier gets.** The rule computation, the shared maps per identifier, target groups (#800) and the slice-deletion cleanup behave as today, apart from the cases under Differences from Today.
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
3. Queues the identifiers it selects pods of on this node, now or before. An identifier whose pods here it stopped selecting is queued so it is rewritten, whether or not it has programs here yet: a pass that finds none writes nothing, and one whose first attach is creating them runs again after it. An identifier it selects only on other nodes is not queued, as today.

**Stage 2** is a new priority queue keyed by pod identifier, with one worker. A pass for one identifier:
1. Attaches probes for its pods on this node that the recorded policies select.
2. Reads the recorded slices from the informer cache. It writes the union of their rules, or the baseline if none: allow-all in standard mode, deny in strict mode. Attach and write happen in the same pass, as today.
3. Returns any attach or write failure, so the identifier is retried with backoff: 5 ms, doubling up to 30 s.

The queue never hands an identifier to two workers at once. It processes an identifier again if it was queued during a pass, so the last pass always reads the newest state. That would keep more than one worker safe for any one identifier. It is also what coalesces: changes that arrive while an identifier waits are applied in one pass.

**Kept from today:**
- **Target groups (#800).** A grouped PolicyEndpoint applies only to the pods its group lists, within its own policy. The filter is in the slice lookup that stage 2 and the CNI ADD path share.
- **Slice-deletion cleanup.** When a slice is deleted and its policy no longer selects any of an identifier's pods on this node, the identifier is written without that policy, even where the policy still selects its pods on other nodes, until a later reconcile or CNI ADD writes it. Stage 1 records the policy to leave out, and stage 2 leaves it out. As with today's per-slice selector entries, each stage-1 reconcile records under every live slice the identifiers the policy selects here, and reads the records of its slice and of the policy's live slices. So a slice's deletion finds what the policy selected when the slice was last seen, whichever slice is reconciled first, and also when the slice's own reconcile never ran, or when the slice was deleted and recreated under the same name in between. Cluster policies do the same.
- **Namespaces and host network.** A PolicyEndpoint applies only to pods in its own namespace, and skips host-network pods.

**Differences from Today.** Found by replaying 6,000 random sequences of slice events, in random reconcile order, through today's code and this change, and comparing every identifier's maps after each reconcile:
- **A live policy with no rules.** An identifier that a live PolicyEndpoint selects, but with no rules and no isolation, gets allow-all in both directions with policies applied, as today's programming path writes it. Today's cleanup path, run when a sibling slice changes, writes the baseline instead, which in strict mode is deny.
- **Identifiers selected only on other nodes.** An identifier a policy selects only on other nodes is not queued, as today, so it gets that policy's rule changes only when something else rewrites it. Today, an identifier a policy selects only on other nodes keeps the names of the policy's deleted slices until the policy stops selecting it, so a slice recreated under such a name can reach the identifier through another policy's write. Stage 1 lists only the slices the policy's last reconcile saw. In 6,000 replays, the maps after the last reconcile differed in 7, all of this kind.
- **Order.** Stage 1 recomputes the whole policy from the informer cache on every reconcile, so an identifier can reach its new state a reconcile earlier or later than today. With every pod on this node, the maps after the last reconcile matched in every replay.
- **Retries.** A failing identifier is retried on its own with backoff up to 30 s. Today the whole reconcile is retried, with controller-runtime's default backoff up to about 16 minutes. An identifier that can never attach is retried every 30 s.

### Interaction with Existing Features

- **CNI ADD.** Unchanged. It writes a new pod's rules from the recorded slices. Its write can race a stage-2 pass for the same identifier, as it raced a reconcile before.
- **Strict mode.** The baseline for an identifier with no policies is deny, as today.
- **Agent restart.** Stage 2 starts as soon as stage 1 queues identifiers (see Open Items).

### Observability

- **Latency metrics.** `awsnodeagent_policy_setup_latency_ms` and `_teardown_latency_ms` keep their meaning: time from a PolicyEndpoint's reconcile until stage 2 has programmed every identifier it queued, retries included. Each reconcile that queues work takes one sample, where today's setup latency took one per local identifier. The programming-latency histograms take one sample per change once all its identifiers are programmed.
- **New controllers.** `policyendpoint-programmer` and `clusterpolicyendpoint-programmer` add controller-runtime queue and reconcile metrics, including `workqueue_depth` and `workqueue_retries_total`. Programming failures are counted in `controller_runtime_reconcile_errors_total` under these controllers, not under `policyendpoint` and `clusterpolicyendpoint`.
- **Logs.** A failed stage-2 pass logs one agent error line that names the identifier, and controller-runtime logs the returned error, as it does for a failed reconcile today.

### Risks

- **The rollout interval.** NPC can drop a workload's last old replica from a policy before it lists the new pod. A stage-2 pass that runs in between writes the identifier at the baseline (unenforced in standard mode, dropped in strict mode) until the next pass, with any number of workers. Today's reconcile does the same when it runs in between. Whether a pass lands there depends on timing, and with a backlog, more workers reach the identifier sooner. With two stage-2 workers and a backlog of 20 identifiers, the new pod was left at the baseline in 9 of 9 harness replays with a 1 s gap, for a median of 308 ms. Today, and with one worker, it happened in 0 of 9. One worker narrows the window but does not close it.
- **More than one worker.** A second worker is 1.7× faster for network policies at 10–17% more CPU, but only 1.1× for cluster policies at 33% more, and widens the rollout interval above. Hence one worker, not configurable.

### Open Items

- **Startup.** Hold stage 2 until stage 1 has reconciled the initial list. Otherwise, after a restart, a pass writes only the policies seen so far, and the rules of policies deleted while the agent was down stay applied.
- **Fresh load.** A program loaded by one controller's pass should also queue the other controller, or a cluster-policy Deny can stay missing.
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
- **Datapath.** No BPF program, map or pin changes. Builds of this change and of `main` from the same toolchain produce byte-identical objects, so upgrading or downgrading between them reloads nothing. On EKS, every identifier's maps stayed identical across restarts, and across upgrades and downgrades between v1.5.0, `main` and this change. The repo's integration suites and cyclonus pass on IPv6 (AL2023). They also pass on IPv4, apart from specs that run commands on Bottlerocket hosts. The code PR has the full results.
- **Metrics.** Names are unchanged, and the setup and teardown latencies keep their meaning. The two new controllers add metric series.
- **Restart.** In-memory state is rebuilt from the informer cache, as today. The slice-deletion record is in memory, so after a restart identifiers are written with all their policies, as today's restart does.
