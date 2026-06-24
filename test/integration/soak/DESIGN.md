# NPA Soak Test — Design (working doc)

Tracking: ORR action item **X-2** (High, EC2 first). Closes the gap called out in
AAT-A-3 test-class 2 ("Soak — None"): the existing `test/integration/leak` suite
runs only 20 min and never reaches the conntrack-cleanup race on port reuse under
sustained churn.

Primary regression target: **GitHub
[#462](https://github.com/aws/aws-network-policy-agent/issues/462)** /
`V2221143078` (Kaltura) — "Race Condition in NPA Conntrack Cleanup Causing
Intermittent Traffic Denials". See §4a for the exact reproduction recipe; this is
the scenario the whole harness is built around.

This doc fixes **what we measure** and **what scenarios we run** before any Go is
written. Scope of v1 is **EC2 mode only** (sidecar `aws-eks-nodeagent` in the
`aws-node` DaemonSet). Auto-mode extensions (ANP/FQDN, DNS proxy load, watchdog
pressure) and AZ-impairment are deferred to a later section.

---

## 1. Goal

Run sustained mixed traffic + churn against NPA on a small node set (1–3 nodes)
for a configurable window (**default 4h**; `--soak-duration`) and prove the agent
does not:

- silently mis-enforce policy (false-allow / false-deny) at any point,
- drop return traffic due to the conntrack-cleanup race (#462),
- leak BPF programs or maps,
- grow memory unboundedly (>50 MiB growth over the run),
- regress policy-programming latency (>10s).

The soak is a **detector for slow/accumulating and timing-dependent failures**
that point-in-time integration tests miss. Correctness is judged on signals we
control directly (probes + BPF dumps + policy event logs); resource cost is judged
from CloudWatch Container Insights; agent-reported latency is advisory (see §6).

---

## 2. What we measure

Five signal classes. Each pass/fail criterion in §5 maps to one of these.

### 2a. Correctness — probe results (PRIMARY)

Ground truth for "is enforcement still correct". We send real packets and observe
the result, same pattern as `restart/conntrack_map_restart_test.go:execConnect`
and `policy/policy_test.go`. (Reference: k8s `test/e2e/network/netpol` builds an
N×N pod×pod reachability matrix and **retries a probe when observed != expected**
to tolerate programming lag — we adopt the same retry-to-expected idea so a
transient reconcile window isn't a false fail, while a *persistent* mismatch is.)

| Probe | How | Expected under policy |
|---|---|---|
| TCP allow | python socket connect / `agnhost connect` to an allowed peer:port | `CONNECTED` |
| TCP deny  | same to a denied peer:port  | `BLOCKED` |
| UDP allow/deny | `SOCK_DGRAM` + app-level ack | ack / no-ack |
| Cross-node allow/deny | client and server pinned to different nodes | per policy |
| **Port-reuse return-traffic** | short-lived outbound conns from a fixed source port (§4a) to a pod under ingress policy | must stay `CONNECTED` for the whole run |

A single persistent wrong result (false-allow on deny, false-deny on allow) is a
**hard fail**; the run records timestamp + probe identity.

**Long-lived-connection disruption detector** (from Cilium `upgrade.go` /
`no_interrupted_connections.go`): in addition to point probes, keep a set of
long-lived client→server connections open for the whole run, where the client
process **exits non-zero if its connection ever breaks** → kubelet bumps the pod's
`RestartCount`. Sampling restart-count == 0 across the run is a cheap, robust
"no disruption happened" signal that doesn't depend on log parsing. We sample the
counter after every disruptive event (churn, hot-update, agent kill).

### 2b. Conntrack-race detection — policy event logs (PRIMARY for #462)

The #462 race is invisible to a plain allow/deny probe unless you hit the exact
timing, so we detect it two ways:

1. **Behaviorally** via the port-reuse probe in §2a/§4a (a denied return packet
   shows up as a transient connection failure on a connection that should stay up).
2. **By signature** in NPA's policy event logs. Run the agent with
   `--enable-policy-event-logs=true` and scrape for the race signature from #462:
   a `Conntrack cleanup Delete` on a 5-tuple immediately (within ~50 ms to a few
   seconds) followed by a `Verdict DENY Direction ingress Tier NETWORK_POLICY` on
   that same 5-tuple's return path. Example from the issue:

   ```
   …Conntrack cleanup Delete - Conntrack Key:
        Source IP - 10.116.54.143 Source port - 42188
        Dest IP - 172.20.0.1 Dest port - 443
   …Flow Info: Src IP: 172.20.0.1 Src Port: 443
        Dest IP: 10.116.54.143 Dest Port: 42188 Proto TCP
        Verdict DENY Direction ingress Tier NETWORK_POLICY
   ```

   The harness correlates the two lines by reversed 5-tuple within a short time
   window. **Any matched Delete→DENY pair is a hard fail** (it is the bug). We also
   cross-check against `network_policy_drop_count_total{direction="ingress"}` —
   the counter should not tick for traffic that policy intends to allow.

### 2c. Resource cost — CloudWatch Container Insights (PRIMARY for mem/CPU)

Install the **Amazon CloudWatch Observability EKS add-on** on the soak cluster and
read the NPA container's CPU/memory from the cluster's **own AWS account**.

Critical nuance: the default `ContainerInsights` *metrics* only aggregate at
cluster/node/**pod** level — there is **no per-container metric**. The `aws-node`
pod bundles three containers (`aws-vpc-cni-init`, `aws-node`, `aws-eks-nodeagent`),
so pod-level memory would fold in the CNI and pollute the >50 MiB signal. To
isolate NPA we query the **performance log events**, which carry per-container
fields, via CloudWatch Logs Insights.

- Log group: `/aws/containerinsights/<cluster-name>/performance`
- Fields: `container_memory_working_set`, `container_cpu_usage_total`
- Filter dims: `ContainerName="aws-eks-nodeagent"`, `Namespace="kube-system"`,
  `ClusterName`, (optionally `FullPodName`/`NodeName` per node).

```
fields @timestamp, container_memory_working_set, FullPodName
| filter Type = "Container"
    and ContainerName = "aws-eks-nodeagent"
    and Namespace = "kube-system"
| stats max(container_memory_working_set) as peak_ws,
        min(container_memory_working_set) as start_ws by bin(5m), FullPodName
```

Why CloudWatch over the on-node Prometheus `:8162` surface for resource cost: the
Prometheus endpoint exposes NPA's *own* metrics but not its process RSS, and X-5
flags several NPA metrics as incorrect. Container Insights gets working-set from
cadvisor, independent of NPA's code.

**Memory-growth criterion** = `peak_ws (last bin)` − `working_set (first stable
bin, post-warmup)` per node. Discard the first ~10 min as warm-up.

(Alternative considered: the clusterloader2 / k8s `ContainerResourceGatherer` polls
kubelet stats per-container and `StopAndSummarize` checks p99 against a
`ResourceConstraint` — same per-container working-set source. We prefer CloudWatch
because it persists the trend off-cluster for post-run analysis and matches how
the fleet is actually observed. The gatherer is the in-cluster fallback if the
observability add-on isn't available.)

### 2d. BPF / leak — on-node `aws-eks-na-cli` dump (PRIMARY for leak)

Reuse `utils.BuildBPFCheckPod` + `aws-eks-na-cli ebpf loaded-ebpfdata` +
`utils.ParseLoadedEBPFData`. Sample at start, periodically, and end.

- **Prog/map count returns to baseline** after churned pods drain (no upward trend
  across samples). The leak detector the 20-min suite can't reach.
- Global `aws_conntrack_map` ID stable across the **repeated** agent kills (§4b,
  every `D/4`); the restart suite only asserts single-restart preservation.
- **Conntrack entry count bounded** under port-reuse churn — direct guard for the
  #462 accumulation noted in the issue comments (stale entries pile up between
  5-min reconciles under high churn). Read the host conntrack table the way k8s
  `test/e2e/network/kube_proxy.go` does: privileged `HostNetwork` pod running
  `conntrack -L` (and dump `aws_conntrack_map` via the CLI), parse + trend the
  counts.

### 2e. Programming latency — Prometheus `:8162` (ADVISORY)

Scrape `awsnodeagent_policy_programming_latency_seconds` / `..._cluster_...`
histograms and `network_policy_drop_count_total{direction}`. X-5 lists the latency
metrics as suspect, so we **chart** them but **hard-fail only on probe-observed
propagation delay** (apply→first-correct-probe). Promote to a gate after X-5 lands.

---

## 3. CloudWatch setup (per-run)

1. Cluster's node role / IRSA allows the CloudWatch agent to put metrics + logs
   (`CloudWatchAgentServerPolicy`).
2. Install: `aws eks create-addon --addon-name amazon-cloudwatch-observability`
   (or Helm). Enhanced observability is what emits the per-container performance
   log events §2c relies on.
3. **Fail fast**: verify `/aws/containerinsights/<cluster>/performance` is
   receiving `ContainerName=aws-eks-nodeagent` events before the soak starts —
   otherwise we'd run the whole window blind on memory.
4. Post-run, fold the Logs Insights results (§2c) into the verdict.

---

## 4. Scenarios (the soak loop)

One long-running `Ordered` Ginkgo spec. A setup phase establishes a stable
baseline (workloads + policies + first probe sweep + baseline BPF/mem samples).
Then the following run **concurrently** for the configured duration. Use Ginkgo
`Consistently` (not `Eventually`) for "this allow/deny must hold for the whole
window" assertions, mirroring Cilium `net_policies.go`.

**`--soak-duration` (default 4h) is the master knob.** Every periodic activity's
cadence is *derived* from it (see §4b) rather than hardcoded, so a 20-min smoke
still exercises a proportional slice of every activity — at least one agent kill,
several hot-updates, multiple churn and sampling cycles — instead of a smoke that
silently skips the rare events. Rates can still be overridden individually by flag.

| # | Driver | Default cadence (D = soak-duration) | Exercises |
|---|---|---|---|
| **1** | **Conntrack-race driver (#462)** — see §4a | continuous; short-lived outbound conns, fixed source port, ~10–50/s | the regression target |
| 2 | Sustained mixed traffic | continuous TCP+UDP allow/deny probes from long-lived clients | steady-state enforcement |
| 3 | Pod churn | continuous, 5–10 pods/min (rate, not count → scales with D) | attach/detach, BPF prog lifecycle |
| 4 | Policy hot-update | every `D/20`, min 1 min, max 5 min | reconcile path, no transient mis-enforce |
| 5 | Agent kill | every `D/4` (≈hourly at 4h; ≥1 kill even for a 20-min smoke), staggered across nodes | BPF recovery, conntrack-map preservation, re-attach |
| 6 | Namespace churn | every `D/8` | selector re-eval, cleanup |
| 7 | Cross-node traffic | continuous (subset of #2) | multi-node correctness |

Probe sweeps (§2a) run every `D/120` (≈2 min at 4h, floor 15 s) so every
transition is sampled. BPF/mem/conntrack trend samples (§2c/2d) every `D/48`
(≈5 min at 4h, floor 1 min). See §4b for the full derivation and the guarantees
that hold at any duration.

### 4a. Conntrack-cleanup-race scenario (#462 / V2221143078) — the core repro

From issue #462, the race needs **all** of these simultaneously, so the scenario
must construct exactly this:

1. **Target pod has an Ingress NetworkPolicy** that does *not* explicitly allow the
   return traffic, so the pod relies on NPA's conntrack map to permit responses.
   (A pod with no ingress policy defaults to allow and never hits the bug.)
2. **Frequent short-lived outbound connections with heavy source-port reuse**, so
   the same 5-tuple (src ip/port, dst ip/port, proto) recurs. Mechanism (k8s
   `test/e2e/network/conntrack.go` idiom): loop `nc`/`curl` pinned to a **fixed
   source port** at a **small interval** so the ephemeral port is reused every few
   hundred ms — e.g. `for i in $(seq 1 N); do nc -w1 -p $SRCPORT $DST $PORT; done`
   or `curl --local-port $SRCPORT`. Cycle across a small set of fixed ports
   (e.g. 60000/61000/62000, as Cilium `service_helpers.go` does) to raise the odds
   of landing in the delete window on several flows at once.
3. **Timing alignment with the reconcile cadence.** The bug surfaces when a kernel
   entry has aged out (`nf_conntrack_tcp_timeout_time_wait`, default 120 s) but the
   NPA local map (reconciled every ~5 min) still holds it, and a reused-port
   connection reinstalls the 5-tuple *during* the cleanup window. So the run must
   last well beyond several reconcile cycles, and the connection interval must be
   short relative to TIME_WAIT. To **shorten** repro time we can (a) lower
   `nf_conntrack_tcp_timeout_time_wait` on the test nodes, and/or (b) drive churn
   hard enough that many stale entries accumulate per reconcile (the issue comments
   note longer reconcile intervals + high churn make it more likely). Both are
   knobs the scenario exposes; defaults reproduce the customer's shape, "aggressive"
   mode compresses it.

**Detection** = §2b (Delete→DENY log signature, correlated by reversed 5-tuple) +
§2a (the long-lived return-traffic connection must never break). A confirmed
signature match or a return-traffic drop is a hard fail.

This scenario also serves as the **fix-validation harness**: when the long-term
fix lands (issue proposes a `last_used` timestamp on eBPF conntrack entries so
cleanup skips entries reused after deletion started), this run in "aggressive" mode
is what proves the fix holds.

### 4b. Duration-derived cadences

All periodic activity is scheduled as a fraction of `D = --soak-duration` (default
4h), clamped to a sane floor/ceiling, and individually overridable. The point: the
same spec is correct at 20 min and at 24 h, and a smoke run never silently skips
the rare-but-important events (agent kill, recovery, multi-cycle trends).

| Activity | Cadence | Floor | Ceiling | Override flag |
|---|---|---|---|---|
| Agent kill (per node, staggered) | `D/4` | — | — | `--kill-interval` |
| Policy hot-update | `D/20` | 1 min | 5 min | `--policy-update-interval` |
| Namespace churn | `D/8` | 2 min | — | `--ns-churn-interval` |
| Probe sweep | `D/120` | 15 s | 2 min | `--probe-interval` |
| BPF/mem/conntrack trend sample | `D/48` | 1 min | 5 min | `--sample-interval` |
| Pod churn | rate-based (5–10/min), continuous | — | — | `--churn-rate` |
| Conntrack-race conns (#462) | rate-based (10–50/s), continuous | — | — | `--reuse-conn-rate` |

Rate-based drivers (pod churn, #462 connections) are expressed as a **rate**, not a
count, so total work scales with `D` automatically and no derivation is needed.

**Guarantees that hold at any duration** (the spec asserts these at startup and
fails fast if the chosen `D` + overrides violate them):

- ≥ 1 agent kill **and** its full recovery validation occur, with enough time after
  the last kill (≥ 2 reconcile cycles, ~10 min, or `D/8`) to observe steady state.
- ≥ 3 policy hot-updates, each followed by a probe sweep before the next.
- ≥ 1 namespace-churn create+delete cycle completes (create, traffic, delete,
  cleanup-verify).
- ≥ 1 full leak cycle: churn → drain → BPF-count-returns-to-baseline check.
- The #462 driver runs across ≥ 2 NPA conntrack reconcile cycles (so the
  delete-window race is actually reachable); if `D` is too short for even one
  reconcile cycle at the configured reconcile interval, the suite **errors at
  startup** rather than reporting a misleading pass.
- Warm-up (first ~10 min or `D/24`) is excluded from the memory-growth baseline.

Setup and teardown time are **outside** `D`: `D` is the steady-state soak window,
measured after baseline is established and before final-state assertions begin.

---

## 5. Pass / fail criteria

| Criterion | Source | Threshold |
|---|---|---|
| No false-positive / false-negative enforcement | §2a probes | any persistent wrong result → **FAIL** |
| **No conntrack-cleanup-race denial (#462)** | §2b log signature + §2a return-traffic | any matched Delete→DENY pair, or any return-traffic drop → **FAIL** |
| No long-lived-connection disruption | §2a restart-counter | any client `RestartCount` increment → **FAIL** |
| No BPF prog/map leak | §2d dump | count returns to baseline after drain; no upward trend → else **FAIL** |
| Conntrack table bounded under churn | §2d | no unbounded growth, no freeze → else **FAIL** |
| Memory growth bounded | §2c CloudWatch | NPA container working-set growth **> 50 MiB** (post-warmup) → **FAIL** |
| Programming latency | §2a propagation (primary), §2e histogram (advisory) | observed apply→correct-probe **> 10 s** → **FAIL** |
| Agent recovers across kills | §2d + §2a | after each kill (§4b, every `D/4`): map preserved, progs re-attached, probes correct → else **FAIL** |

CPU is recorded/charted (context for X-3) but not a hard gate in v1.

---

## 6. Why probes/BPF/logs primary, metrics secondary

ORR item **X-5** documents that several NPA metrics are implemented incorrectly
(`BulkRefreshMapEntries` latency, `policy_teardown_latency_ms`,
`policy_programming_latency_seconds` + cluster variant, `updateEbpfMap-egress`
latency, uninstrumented `RecoverAllBpfProgramsAndMaps`). Gating a 4h soak on those
would produce false verdicts. So:

- **Correctness** → real packets (probes) + restart-counter liveness.
- **#462 race** → policy event log signature (the bug's own fingerprint).
- **Leak** → BPF dump + host conntrack count, independent of NPA's metric code.
- **Memory/CPU** → cadvisor via CloudWatch, independent of NPA.
- **Latency** → probe-observed propagation as the gate; NPA histogram advisory only.

---

## 7. Prior art — techniques adapted (Cilium, k8s, perf-tests)

| Technique | Source | What we take |
|---|---|---|
| Restart-counter disruption detector | Cilium `cilium-cli/connectivity/tests/upgrade.go`, `builder/no_interrupted_connections.go` | long-lived client exits non-zero on break → `RestartCount` is the no-disruption signal (§2a) |
| Fixed-source-port reuse loop | k8s `test/e2e/network/conntrack.go` (`nc -p <fixed>` ×3000), Cilium `test/k8s/service_helpers.go` (`curl --local-port`, multi-port + `ct flush`) | the §4a port-reuse driver |
| Host conntrack inspection | k8s `test/e2e/network/kube_proxy.go` (`conntrack -L` from privileged HostNetwork pod) | §2d conntrack-count trend |
| Retry-to-expected probe matrix | k8s `test/e2e/network/netpol/{probe,reachability}.go` | tolerate programming lag without flaking (§2a) |
| `Consistently` during policy swap + verdict cross-check | Cilium `test/k8s/net_policies.go` | §4 hot-update assertion style |
| Background long traffic + control-plane churn | Cilium `test/k8s/chaos.go` (`netperf` background, restart mid-stream) | §4 agent-kill-during-traffic |
| `TCP_CRR` connection-churn generator | Cilium `perf/benchmarks/netperf` | high-rate new-connection-per-txn load option |
| Per-container CPU/mem gatherer + `ResourceConstraint` gate | perf-tests `clusterloader2` `ContainerResourceGatherer` / `ResourceUsageSummary` | in-cluster fallback to CloudWatch (§2c) |
| Policy-churn at QPS via `rate.Limiter` | perf-tests `network-policy-enforcement-latency.go` | §4 hot-update rate control |
| Background tcpdump "0 packets" no-leak assert | Cilium `connectivity/sniff/sniffer.go` (Assert vs Sanity modes) | optional: assert no packet that policy should drop appears on the wire |

Note Cilium has **no** explicit conntrack-table-size assertion and **no** soak test
literally named "soak" — their endurance coverage is the restart-counter +
memory-threshold + periodic-pprof combination. NPA's #462 makes an explicit
conntrack assertion necessary, which is net-new here.

---

## 8. Open questions / decisions for review

1. **CloudWatch pull mechanism** — SDK inside the Ginkgo suite vs. post-run query
   step (leaning post-step, keeps the suite free of AWS-SDK/credential coupling).
2. **Node count** — cross-node (scenario 7) needs ≥2; default 2, allow 3 via flag.
3. **Run env** — no NPA pre-release pipeline yet (AI-7 / AI-A9). v1 targets manual
   on a long-lived cluster + a CI smoke; wire into the AI-7 Hydra pipeline once it
   exists.
4. **#462 repro tuning** — do we mutate node sysctls (`nf_conntrack_tcp_timeout_time_wait`)
   to compress repro time, or only drive churn rate? Affects whether the soak needs
   privileged node access beyond the BPF-check pod.
5. **Auto-mode** (deferred) — DNS proxy load, ANP/FQDN egress, systemd watchdog;
   needs systemd-unit probes + Bottlerocket/Tachyon env. Separate doc.
6. **AZ impairment** (deferred) — X-2 also asks for it; needs FIS fault injection.

---

## 9. Reuse map (what already exists in-repo)

| Need | Existing code |
|---|---|
| Privileged BPF-check pod | `test/framework/utils/bpf.go:BuildBPFCheckPod` |
| Parse `loaded-ebpfdata` | `test/framework/utils/bpf.go:ParseLoadedEBPFData` |
| TCP connect probe | `test/integration/restart/...:execConnect` |
| Agent kill + rollout wait | `test/integration/restart/...:waitForDaemonSetRollout` |
| Pod churn via CronJob | `test/integration/leak/leak_test.go:buildChurnCronJob` |
| Worker-node selection / labeling | `test/integration/leak/leak_test.go:getWorkerNodes` |
| NetworkPolicy build/apply | `test/framework/manifest/networkpolicy.go`, `.../networkpolicy/resource.go` |
| Namespace lifecycle | `test/framework/resources/k8s/namespace/resource.go` |

New code is mostly: the §4a port-reuse + ingress-policy repro driver, the §2b
policy-event-log signature scraper, the periodic sampling + trend math (§2c/§2d),
the restart-counter liveness clients, and the policy-hot-update + UDP helpers.
