# NPA Soak Test — Design (working doc)

Tracking: ORR action item **X-2** (High, EC2 first). Closes the gap called out in
AAT-A-3 test-class 2 ("Soak — None"): the existing `test/integration/leak` suite
runs only 20 min and never reaches the conntrack-cleanup race on port reuse under
sustained churn.

The soak's own lane is **accumulation and drift over time at fixed small scale**:
BPF and conntrack leaks, memory and CPU and goroutine growth, agent restarts, and
enforcement staying correct across the whole window and across repeated agent
kills. Scale ceilings and absolute perf baselines are not this suite's job; they
belong to X-1 (scale/breaking-point) and X-3 (perf baseline). See §5a for that
boundary.

GitHub [#462](https://github.com/aws/aws-network-policy-agent/issues/462) /
`V2221143078` (Kaltura), the conntrack-cleanup race that denies return traffic
under port reuse, is a **timing race, not an accumulation failure**. A single 4h
run samples the race once, which is a weak way to prove a fix holds. So it is split
in two: a **separate, fast, repeatable aggressive-timing test** owns the repro and
fix-validation (§4a), and the soak keeps only a **mild continuous regression
guard** so a reintroduced bug still trips a long run.

This doc fixes **what we measure** and **what scenarios we run** before any Go is
written. Scope of v1 is **EC2 mode only** (sidecar `aws-eks-nodeagent` in the
`aws-node` DaemonSet). Auto-mode (ANP/FQDN, DNS proxy load, watchdog pressure) is
deferred to §8, but note ORR X-2 names it in scope, so it is tracked for v2, not
dropped. AZ-impairment is also deferred.

---

## 1. Goals

Run sustained mixed traffic and churn against NPA on a small node set (1-3 nodes)
for a configurable window (**default 4h**; `--soak-duration`) and prove the agent
holds up over time. The goals are tiered by what v1 gates on. Tier ordering comes
from the goals/dimensions audit against the ORR and the Cilium/Calico prior art.

**Tier 1 (v1 gates on these):**

- **No BPF program or map leak.** Counts return to baseline after churn drains.
  This is the reason the suite exists; the 20-minute leak suite never reaches it.
- **No established-connection disruption.** Long-lived connections stay up across
  churn, hot-updates, and agent kills. This is the most robust correctness signal
  and needs no metrics endpoint.
- **No agent restart, OOM, or watchdog kill.** The `aws-eks-nodeagent` container's
  restart count does not move over the run. Maps to the top recurring failure class
  (ORR NDP-A-5 #1) and is always observable.
- **Enforcement stays correct over the window, ingress AND egress, false-allow AND
  false-deny.** Egress is a separate eBPF program, map, and conntrack direction, so
  it needs its own probes, not just ingress.
- **Recovery stays correct across repeated agent kills.** After each kill the
  conntrack map is preserved, programs re-attach, and enforcement still holds.
- **Memory, CPU, and goroutines do not grow unboundedly.** Judged as growth against
  the run's own post-warmup baseline, not a fixed absolute (see §2c and §3a for why
  the ORR's flat >50 MiB number is too loose at soak scale).

**Tier 2 (add to v1 as gates):**

- **Strict (DefaultDeny) mode holds over the window.** Strict mode is where
  programming drift becomes a customer-visible outage rather than a metrics blip,
  so it is the highest-risk dimension the plan was missing.
- **Policy hot-update does not transiently drop a newly allowed flow.** Distinct
  from established-connection survival; a new flow initiated mid-reconcile must not
  be dropped (see the coherence note in §2a about retry-to-expected).
- **#462 continuous regression guard.** A mild always-on port-reuse driver so a
  reintroduced conntrack-race bug trips a long run. The aggressive repro and
  fix-validation live in a separate targeted test (§4a).

**Advisory, not gated:** NPA's own Prometheus business-logic metrics (ORR X-6 flags
several as implemented incorrectly) and absolute programming latency (an X-3 perf
number, not a soak signal). Collected and charted; opt-in to gate (§2f).

The soak detects slow, accumulating, and timing-dependent failures that
point-in-time integration tests miss. It judges correctness from signals we control
directly (probes, BPF dumps, policy event logs) and resource cost from kubelet
per-container stats (§2c).

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

**Coherence note on retry-to-expected.** Retrying a probe until it matches the
expected verdict tolerates programming lag, but by construction it cannot see a
*transient* wrong result on a flow that was already correct. So the two tolerances
are stated explicitly: we tolerate first-probe lag right after a policy applies, and
we must catch a drop on an already-correct flow. The Tier-2 hot-update goal is
tested with a *newly initiated* allowed flow during the reconcile window (not a
retry-to-expected probe), so a transient drop there is caught rather than masked.

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

### 2c. Resource cost — kubelet per-container stats (PRIMARY for mem/CPU)

Read the NPA container's CPU and working-set memory from the kubelet
`/stats/summary` endpoint, reached through the API-server proxy with the kubeconfig
the suite already has. This is what the implemented harness uses.

Two reasons for kubelet stats over the alternatives. First, the signal must isolate
one container: the `aws-node` pod bundles `aws-vpc-cni-init`, `aws-node`, and
`aws-eks-nodeagent`, so a pod-level number folds in the CNI and pollutes the growth
signal. The kubelet summary reports per-container `workingSetBytes`, from the same
cadvisor source CloudWatch uses. Second, it needs no AWS credentials and no
observability add-on, so the soak runs anywhere the kubeconfig reaches, and it
sidesteps NPA's own metrics, which X-6 flags as incorrect.

- Endpoint: `/api/v1/nodes/<node>/proxy/stats/summary`
- Container: `aws-eks-nodeagent` in namespace `kube-system`
- Fields: `memory.workingSetBytes`, `cpu.usageNanoCores` / `usageCoreNanoSeconds`

**Growth model.** Per node, track a post-warmup baseline and the peak, and gate on
`peak - baseline` (see §3a for how the threshold is derived, and why the ORR's flat
>50 MiB is too loose). Discard the first ~10 min or `D/24` as warm-up, and baseline
on a short average of post-warmup samples rather than a single first reading.

CloudWatch Container Insights is a **future** off-cluster option, not v1. If the
`amazon-cloudwatch-observability` add-on is installed, the same per-container
working-set lives in the `/aws/containerinsights/<cluster>/performance` log group
(field `container_memory_working_set`, filter `ContainerName=aws-eks-nodeagent`),
which persists the trend off-cluster and matches how the fleet is observed. v1 does
not depend on it.

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
histograms and `network_policy_drop_count_total{direction}`. X-6 lists the latency
metrics as suspect, so we **chart** them but **hard-fail only on probe-observed
propagation delay** (apply→first-correct-probe). Promote to a gate after X-6 lands.

### 2f. NPA-emitted metrics and resource counters (opt-in assertions)

This is the goal added in §1: assert on NPA's own business-logic metrics and on
its restart, CPU, and memory counters. The assertions are opt-in. Two reasons.
Our test infra may not scrape the `:8162` Prometheus endpoint, and X-6 flags
several NPA metrics as implemented incorrectly. So the default is to collect and
chart every value without failing, and one env var promotes specific checks to
hard gates.

**Gating model.** `SOAK_ASSERT_METRICS` is a comma-separated env var, empty by
default. A metric not in the list is still scraped and logged for the trend, but
never fails the run. A metric in the list becomes a hard gate under the rule in
the table below. `all` enables every check; empty or `none` disables all of them.
It is an env var rather than a flag because the value describes the environment
(does this cluster expose metrics?), so it sits with the rest of the environment
config and CI can set it per-lane without touching the invocation.

**Three independent signal sources.** If the metrics endpoint is missing, the
run can still observe the other two:

1. **NPA Prometheus `:8162/metrics`** carries the business-logic metrics. We scrape
   it by running `curl -s localhost:8162/metrics` inside the nodeagent container,
   since the port is bound to localhost and a co-located exec reaches it without a
   Service or scrape config. Setup checks that the endpoint answers. If it does
   not, the metric assertions are skipped and the reason is logged, so a skip is
   never mistaken for a pass.
2. **Pod status** gives `containerStatuses[name=aws-eks-nodeagent].restartCount`
   from the k8s API. This is always available and needs no metrics endpoint.
3. **kubelet `/stats/summary`** gives per-container CPU and working-set memory. We
   already built this for §2c, and it works with the kubeconfig alone.

**Metrics inventory.** Read from the source, not the ORR appendix. NPA registers
exactly these on `:8162`:

| Metric | Type | Labels | Source file |
|---|---|---|---|
| `network_policy_drop_count_total` | Counter | `direction` | `pkg/ebpf/events/events.go` |
| `network_policy_drop_bytes_total` | Counter | `direction` | `pkg/ebpf/events/events.go` |
| `awsnodeagent_aws_ebpf_sdk_latency_ms` | Summary | `api`,`error` | `pkg/ebpf/bpf_client.go` |
| `awsnodeagent_aws_ebpfsdk_error_count` | Counter | `fn` | `pkg/ebpf/bpf_client.go` |
| `awsnodeagent_policy_setup_latency_ms` | Summary | `name`,`namespace` | `controllers/policyendpoints_controller.go` |
| `awsnodeagent_policy_teardown_latency_ms` | Summary | `name`,`namespace` | `controllers/policyendpoints_controller.go` |
| `awsnodeagent_policy_programming_latency_seconds` | Histogram | none | `controllers/policyendpoints_controller.go` |
| `awsnodeagent_cluster_policy_programming_latency_seconds` | Histogram | none | `controllers/clusterpolicyendpoints_controller.go` |

controller-runtime also exposes `process_resident_memory_bytes`,
`process_cpu_seconds_total`, and `go_goroutines` on the same endpoint. Confirm
these at runtime and use them to cross-check the kubelet stats, not as a primary
gate.

**What we assert, and when.** Each row is one `SOAK_ASSERT_METRICS` name:

| Assert name | Signal | Rule | Fires when | Default |
|---|---|---|---|---|
| `sdk-errors` | `awsnodeagent_aws_ebpfsdk_error_count` | delta over run == 0 | any eBPF SDK error during the soak | off |
| `programming-latency` | `awsnodeagent_policy_programming_latency_seconds` | p99 from histogram buckets ≤ `--soak-programming-latency-limit` (10s) | the latency histogram regressed | off (X-6 says suspect) |
| `drop-sanity` | `network_policy_drop_count_total{direction=ingress}` | must **rise** while a deny probe reads BLOCKED | drops stay flat while policy claims to block, so either the metric or enforcement is broken | off |
| `restarts` | pod `restartCount` (nodeagent) | delta over run == 0 | the agent was OOM-killed, crashed, or hit the watchdog | **on** (always available) |
| `cpu` | kubelet `container_cpu_usage_total` | mean-cores growth (post-warmup baseline vs peak) ≤ `--soak-cpu-growth-factor` × baseline (default 2) | CPU crept up on a steady workload | off (record-only) |
| `memory` | kubelet working-set (§2c) | growth ≤ 50 MiB | memory leaked | **on** (already a gate) |
| `goroutines` | `go_goroutines` | end ≤ baseline × `--soak-goroutine-growth-factor` (default 2) | goroutines leaked | off |

Notes:
- `restarts` and `memory` default **on** because their signals need no metrics
  endpoint. The rest default **off**, so a cluster that does not scrape `:8162`
  still runs green on the parts it can observe.
- CPU is a **growth** check, not an absolute-core threshold. NPA ships with no CPU
  limit, so its cadvisor core usage scales with whatever the node's shared pool
  offers. An absolute `≤ N cores` gate would pass or flake on hardware alone, not
  on NPA behavior. Growth (baseline vs peak on a steady workload) instead catches
  the real regression: NPA burning more CPU over time for the same work.
- The soak does not pin the node instance type. It records each node's
  instance-type and allocatable CPU in the trend log so a reader can tell whether
  two runs' CPU numbers are comparable. Cross-run CPU comparison is only valid when
  the recorded type matches; the growth check stays valid regardless, since it
  compares a run against its own baseline.
- If `SOAK_ASSERT_METRICS` names a metric whose source is unavailable, that is a
  setup error, not a silent skip. The operator asked to gate on it, so the run
  fails at setup rather than pretending the check passed.
- The histogram p99 comes from the bucket boundaries (the `_bucket`, `_count`, and
  `_sum` series), using the same math as `histogram_quantile`.
- All collected values (asserted or not) are logged on the trend cadence (§4b
  `TrendSample`) so a run always leaves a metrics progression for post-mortem,
  independent of whether anything gated on it.

Violation kinds this adds to §5: `MetricAssertion` (business-logic metric gate
failed) and `AgentRestart` (restart-count delta > 0). Memory already has
`MemoryGrowth`.

---

## 3. Thresholds and setup

### 3a. How the growth thresholds are derived (not the ORR's flat numbers)

The ORR X-2 text gives round numbers (>50 MiB growth, >10s latency) with no
derivation, and at the soak's actual scale (1-3 nodes, small policy count) they are
too loose to catch the failure they exist for. NPA's baseline working set is tens
of MiB, so a flat 50 MiB budget is a >100% allowance: a real slow leak of ~5 MiB/hr
(20 MiB over 4h) passes. That is the exact leak the soak is meant to catch.

So the memory, CPU, and goroutine gates are **relative to the run's own
post-warmup baseline**, not absolute:

- Baseline = mean of samples taken after the warm-up window (first ~10 min or
  `D/24`), not a single first reading.
- Gate on **slope** (per-hour growth above baseline) or **peak growth beyond
  N sigma** of the steady-state samples, whichever the implementation finds more
  stable. The flat 50 MiB stays only as a coarse absolute backstop, not the primary
  signal.
- Programming latency is gated on **drift within the run**, never an absolute. The
  >10s figure is an X-3 perf-baseline number and does not belong in a soak gate
  (§5a).

Node instance type is recorded, not pinned (§2f note), so absolute CPU is only
comparable across runs on the same type. The growth gates stay valid regardless,
since each compares a run against itself.

### 3b. Cluster setup (per-run)

1. Network policy enforcement is on (`--enable-network-policy=true`) and the NP
   controller is emitting PolicyEndpoints. **Fail fast at setup** if a freshly
   applied deny policy produces no PolicyEndpoint, otherwise the whole run
   default-allows and reports a meaningless green.
2. For #462 log-signature detection, the agent runs with
   `--enable-policy-event-logs=true`. Setup verifies Flow Info lines are actually
   being emitted before trusting a clean scan (§2b).
3. CloudWatch observability is **optional** (§2c). If the add-on is present the
   trend is also persisted off-cluster; v1 does not require it.

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

The **Status** column tracks plan vs. as-built, since the two have diverged during
implementation. "Built" means implemented and offline-verified; "broken" means
implemented but a review found it non-functional (see the implementation critique);
"planned" means designed, not yet coded.

| # | Driver | Default cadence (D = soak-duration) | Exercises | Status |
|---|---|---|---|---|
| 1 | Agent kill | every `D/4` (≈hourly at 4h; ≥1 kill even for a 20-min smoke), staggered across nodes | BPF recovery, conntrack-map preservation, re-attach | built |
| 2 | Pod / namespace churn | continuous, 5–10 pods/min (rate, not count, so it scales with D); namespace churn every `D/8` | attach/detach, BPF prog lifecycle, selector re-eval, cleanup | built |
| 3 | Policy hot-update | every `D/20`, min 1 min, max 5 min | reconcile path; must not drop an established or a newly initiated allowed flow | built (new-flow probe planned) |
| 4 | Ingress enforcement probes | probe sweep every `D/120` (floor 15s) | false-allow and false-deny on ingress | built (deny only; allow probe planned) |
| 5 | **Egress enforcement probes** | same sweep cadence | false-allow and false-deny on egress (separate eBPF prog/map/direction) | **planned (Tier 1 gap)** |
| 6 | **Strict-mode lane** | a parallel workload set under `strict` enforcing mode | strict-mode enforcement holds over the window | **planned (Tier 2 gap)** |
| 7 | Cross-node traffic | continuous (subset of the probes) | multi-node correctness | planned (pods currently pin to one node) |
| 8 | #462 continuous guard | mild port-reuse driver | reintroduced conntrack-race trips a long run | broken (see §4a; regex + timing + detector defects) |

Aggressive #462 repro and fix-validation is a **separate targeted timing test**,
not a soak driver (§4a).

Probe sweeps (§2a) run every `D/120` (≈2 min at 4h, floor 15 s) so every
transition is sampled. BPF/mem/conntrack trend samples (§2c/2d) every `D/48`
(≈5 min at 4h, floor 1 min). See §4b for the full derivation and the guarantees
that hold at any duration.

### 4a. Conntrack-cleanup-race repro (#462 / V2221143078) — a separate targeted test

This is **not a soak driver.** #462 is a timing race, and a 4h soak samples it once.
The repro and fix-validation live in a fast, repeatable test that reruns the window
many times; the soak carries only the mild continuous guard (driver #8 in §4).

**How the race actually works** (from `pkg/ebpf/conntrack/conntrack_client.go`).
NPA's cleanup snapshots the kernel conntrack table, then walks its own local eBPF
map and deletes any entry **absent from that kernel snapshot**. So a local entry is
a deletion candidate only once its 5-tuple has **aged out of the kernel table**
(past `nf_conntrack_tcp_timeout_time_wait`, default 120 s). The bug fires when a
reused-port connection reinstalls that exact 5-tuple *during* the delete pass: NPA
deletes an entry the kernel just recreated, and the return packet is denied.

**Why fast reuse is wrong** (this was a real defect in the first design). Reusing
the same 5-tuple every few hundred ms keeps the kernel entry perpetually alive, so
it is never a deletion candidate and the race can never occur. The repro needs the
opposite: reuse each tuple with a gap **larger** than the kernel timeout, so the
entry ages out of the kernel, becomes a delete candidate, and is then reused. For
TCP a fixed `--local-port` also cannot rebind while the prior 4-tuple sits in
TIME_WAIT, so the k8s idiom (`test/e2e/network/conntrack.go`) pins the source port
with **UDP** to avoid it.

**Recipe:**

1. The protected pod is the one making the **outbound** connection and carrying an
   ingress-deny policy, so its return traffic relies on NPA's conntrack map. (Getting
   this backwards, deny on the destination, blocks the forward SYN and the race
   never arms.)
2. Lower `nf_conntrack_tcp_timeout_time_wait` on the test nodes to a few seconds so
   entries age out of the kernel quickly.
3. Reuse each fixed source port with a gap **greater** than that lowered timeout
   (so the entry ages out between reuses), cycling a small port set to arm several
   flows at once. Prefer UDP fixed-source-port to sidestep TCP TIME_WAIT rebind.
4. Run long enough to cross several cleanup passes.

**Positive control (mandatory).** The test must reproduce #462 at least once in
aggressive mode before any green result is trusted. Without a proven repro, a clean
run is indistinguishable from a broken detector.

**Detection** = §2b (Delete→DENY log signature, correlated by reversed 5-tuple) +
§2a (the return-traffic connection must not break). Either a matched signature or a
return-traffic drop is a hard fail. Serves as the fix-validation harness for the
proposed `last_used`-timestamp fix.

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

Rows are grouped by tier, matching §1.

**Tier 1 gates:**

| Criterion | Source | Threshold |
|---|---|---|
| No BPF prog/map leak | §2d dump | count returns to baseline after drain, no upward trend, else **FAIL** |
| No long-lived-connection disruption | §2a restart-counter | any client connection break (RestartCount increment) → **FAIL** |
| No unexpected agent restart | pod `restartCount` (nodeagent) | restart-count delta over run **> 0** → **FAIL** |
| Enforcement correct, ingress + egress | §2a probes (both directions) | any persistent false-allow or false-deny → **FAIL** |
| Recovery correct across repeated kills | §2d + §2a | after each kill (§4b, every `D/4`): map preserved, progs re-attached, probes correct, else **FAIL** |
| Memory / CPU / goroutine growth bounded | §2c kubelet stats + §2f | growth over baseline exceeds the §3a-derived bound → **FAIL** |

**Tier 2 gates:**

| Criterion | Source | Threshold |
|---|---|---|
| Strict-mode enforcement holds | §2a probes on a strict-mode lane | any allowed flow dropped or denied flow allowed → **FAIL** |
| Hot-update: no transient new-flow drop | §2a new-flow probe mid-reconcile | a newly initiated allowed flow dropped during reconcile → **FAIL** |
| #462 continuous regression guard | §2b log signature + §2a return-traffic | any matched Delete→DENY pair, or any return-traffic drop → **FAIL** (aggressive repro is a separate test, §4a) |

**Advisory (recorded, charted, not gated unless opted in):**

| Signal | Source | Note |
|---|---|---|
| Conntrack table growth | §2d | trend for post-mortem; capacity/near-full is X-1, not this gate |
| Programming latency | §2a propagation (primary), §2e histogram (advisory) | drift within the run, not an absolute; the >10s absolute is an X-3 number |
| Business-logic metrics | §2f `:8162` scrape | opt-in per metric via `SOAK_ASSERT_METRICS`; X-6 flags several as unreliable |

### 5a. Scope boundary (what this soak does NOT own)

The soak's lane is accumulation and drift at fixed small scale. These belong to
other ORR items and must not creep into the soak's gates:

- **Absolute programming latency and CPU/memory at scale** (latency at 1K/5K
  PolicyEndpoints, CPU/mem at 500 pods + 50 policies) belong to **X-3** (perf
  baseline). The soak gates on drift within its own fixed-scale run, never on an
  absolute number. This is why the old ">10s latency" and flat ">50 MiB" gates are
  gone from Tier 1.
- **Scale ceilings** (policy count, conntrack cache near full, eBPF map size,
  DNS-proxy throughput) belong to **X-1**. The soak's conntrack-growth check is a
  leak/drift signal, not a capacity probe; it does not exercise the cache near full.
- **Metric-implementation correctness** belongs to **X-6**. The soak consumes
  metrics advisory-only and must not become a de-facto metric-correctness test.
- **#462 aggressive repro and fix-validation** is its own fast, repeatable timing
  test (§4a). The soak carries only the mild continuous guard.

---

## 6. Why probes/BPF/logs primary, metrics secondary

ORR item **X-6** documents that several NPA metrics are implemented incorrectly
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
| Per-container CPU/mem gatherer + `ResourceConstraint` gate | perf-tests `clusterloader2` `ContainerResourceGatherer` / `ResourceUsageSummary` | the per-container growth model behind §2c kubelet stats |
| Policy-churn at QPS via `rate.Limiter` | perf-tests `network-policy-enforcement-latency.go` | §4 hot-update rate control |
| Background tcpdump "0 packets" no-leak assert | Cilium `connectivity/sniff/sniffer.go` (Assert vs Sanity modes) | optional: assert no packet that policy should drop appears on the wire |

Note Cilium has **no** explicit conntrack-table-size assertion and **no** soak test
literally named "soak" — their endurance coverage is the restart-counter +
memory-threshold + periodic-pprof combination. NPA's #462 makes an explicit
conntrack assertion necessary, which is net-new here.

---

## 8. Backlog and open questions

Two reviews shaped this plan: an implementation critique (does the code do what the
plan says) and a goals/dimensions audit (are we testing the right things). The
backlog below folds in both, ordered by priority.

**Must-fix before the harness can gate anything** (from the implementation critique;
each verified against source):

1. **#462 log-signature detector matches the wrong format.** The parser matches the
   IPv6 Flow Info line (colon-delimited); the real IPv4 line is
   `Proto %s Verdict %s Direction %s, Tier %s` (no colons, trailing comma). On IPv4,
   the v1 scope, it matches nothing. Fix the regex, add a fixture from a real IPv4
   log, and add a setup check that Flow Info lines are actually emitted.
2. **#462 driver timing prevents the race** (§4a). Fast reuse keeps the kernel entry
   alive; the race needs reuse *slower* than the (lowered) kernel timeout. Rebuild
   the driver per §4a and add the mandatory positive control.
3. **Behavioral #462 detector can never fire.** The driver loop swallows every drop
   and never exits, and the pod is `RestartPolicyNever`, so RestartCount cannot move.
   Make it a liveness-bound client that exits on break, or gate on a real drop count.
4. **Nodeagent restart gate is not implemented.** §1/§5 make it Tier-1 and it needs
   no metrics endpoint, but only the driver pod's RestartCount is checked today.
5. **Log rotation loses evidence + agent-kill masks the leak.** The end-of-run
   single `cat` misses rotated segments (stream during the run instead), and the
   `D/4` kill caps the memory-leak horizon at one kill interval (measure per-process
   lifetime or exclude the last interval from the memory gate).

**Dimension gaps to add** (from the goals audit, by risk):

6. **Egress-policy probes** (Tier 1). Half the enforcement surface, currently unprobed.
7. **Strict-mode lane** (Tier 2). Highest-risk missing dimension.
8. **Hot-update new-flow correctness** (Tier 2). Close the retry-to-expected gap (§2a).
9. **IPv6 / dual-stack** and **multi-NIC secondary-ENI recovery** (v1.x, tracked).
10. **Auto-mode: ANP/FQDN + DNS-proxy endurance + watchdog pressure** (v2). ORR X-2
    names this in scope, so it is tracked, not dropped; needs systemd-unit probes and
    a Bottlerocket/Tachyon env.

**Open decisions:**

11. **Node count.** Cross-node probes need at least 2 nodes; default 2, allow 3 via flag.
12. **Run env.** No NPA pre-release pipeline yet (AI-7 / AI-A9). v1 targets manual on
    a long-lived cluster plus a CI smoke, then wires into the AI-7 Hydra gate once it exists.
13. **#462 node access.** Lowering `nf_conntrack_tcp_timeout_time_wait` needs
    privileged node access beyond the BPF-check pod. Confirm the test env allows it.
14. **AZ impairment** (deferred). X-2 also asks for it; needs FIS fault injection.
15. **ORR X-numbering.** The metric-correctness AI is X-6 in `npa-orr-quip.md` but
    X-5 in the live Quip. This doc uses X-6; confirm which is authoritative.

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
