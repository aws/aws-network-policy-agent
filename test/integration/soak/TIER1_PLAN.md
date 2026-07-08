# Tier 1 Implementation Plan — NPA Soak

Scope: implement the **Tier 1 gates** from DESIGN §1, plus the must-fix defects that
block them. Assumptions from the run environment:

- Runs on an **EC2** EKS cluster, **3 nodes**, but the code stays **environment
  agnostic** (no hardcoded cluster/account/region; everything from flags/env/kubeconfig).
- Default run is **4h** (`--soak-duration=4h`), also runnable as a short smoke.
- Metrics assertions (§2f) are **gated behind an env var** and off by default.
- CloudWatch metrics, when enabled, are assumed present in namespace **`DataplanePOC`**
  with dimensions **`ClusterName`, `Component`, `K8sVersion`, `Node`** (account
  975050023620, us-west-2 for the sample data). The exact metric names / what to
  assert will be supplied later; this plan builds the plumbing, not the thresholds.

Out of scope here: Tier 2 (strict mode, hot-update new-flow probe, #462 guard) and
the #462 driver defects (C1/C2/C3). #462 code stays as-is but is **quarantined** so a
Tier 1 run does not execute or gate on it.

---

## Tier 1 gates and their status today

| # | Gate (DESIGN §1) | Today | Work |
|---|---|---|---|
| 1 | No BPF prog/map leak | built (`checks_test.go:assertNoBPFLeak`) | keep; fix leak-masking (W5) |
| 2 | No established-connection disruption | **broken** (driver never exits, C3) | W2: liveness-bound client |
| 3 | No agent restart/OOM/watchdog | **missing** (H1) | W3: nodeagent restartCount gate |
| 4 | Enforcement correct, ingress+egress, both directions | partial (ingress-deny only; no allow, no egress; M1 probe ambiguity) | W1: probe rework + egress + allow |
| 5 | Recovery correct across repeated kills | shallow (M5: 10s wait, deny-only) | W4: real recovery assertions |
| 6 | Memory/CPU/goroutine growth bounded | memory built (kubestats); CPU/goroutine missing | W6: CPU + goroutine trackers |

Plus **W0** (env-agnostic + 3-node scaffolding) and **W7** (CW metrics plumbing
behind env var).

---

## Workstreams

### W0. Environment-agnostic 3-node scaffolding
- **Timeouts (C-1, blocks everything).** A 4h run aborts at Ginkgo's default 1h suite
  timeout (and `go test`'s 10-min binary timeout) before any end-state gate runs. The
  invocation MUST pass `-timeout=<D + slack>` and `--ginkgo.timeout=<D + slack>` (or set
  `NodeTimeout` on the `It`), and `schedule.Validate` MUST reject a `D` larger than the
  effective timeout so this can never silently truncate a run.
- **Distribute workload across all N nodes (C-3, makes multi-node non-vacuous).** Today
  server/prober/driver pin `node0` and churn pins `nodes[0]`, so on 3 nodes two agents
  enforce nothing and their per-node leak/memory/CPU/restart signals are meaningless.
  Place enforced workload (a policy-selected server + the churn set + a prober) on
  **every** node under test, and assert at setup that each node-under-test actually has
  an enforced pod before its signals are trusted.
- No hardcoded cluster name, account, or region anywhere. Cluster name comes from the
  existing `--cluster-name` flag; region from `--aws-region`; everything else from the
  kubeconfig. Grep-gate: no literal `975050023620`, `nft-soak`, or `us-west-2` in code.
- Setup precondition (fail fast): NP enforcement is on and a freshly applied deny
  policy produces a PolicyEndpoint within a timeout. Without it the run default-allows
  and every probe is vacuous (this is the exact trap the last real run hit).

### W1. Enforcement probing rework (gate 4) — the biggest correctness gap
- **Distinguish blocked from broken (M1).** The probe wrapper makes the exec always
  succeed and puts the result in stdout: `curl -sS -o /dev/null -w '%{http_code}' ...;
  echo "rc=$?"`. A connection-refused/timeout (rc=7/28, correct deny) is distinct from
  an exec/transport error (probe infra broke), which is not a verdict and is not
  recorded. `ExecInPod` collapses any non-zero exit into an opaque error today, which
  is why current `serverReachable` mis-scores every infra error as "correctly blocked."
- **Add allow probes (H4).** An `allow-server` reachable via an explicit allow policy;
  the prober asserts it stays CONNECTED. False-deny (over-blocking, the #462 class) is
  now observable, not just false-allow.
- **Separate prober identities for ingress vs egress (H-1, critical).** Do NOT put an
  egress-deny policy on the shared prober: its own egress program would drop the SYN of
  the *ingress* probe first, so an ingress false-allow becomes undetectable. Use one
  prober for ingress cases and a distinct prober for egress cases.
- **Egress addressed by IP, and DNS explicitly allowed (H-1 DNS trap).** A deny-all
  egress breaks DNS resolution, so a name-addressed curl fails with rc=6 (resolve) and
  is mis-scored as a correct deny. All probes address peers by pod IP (the current code
  already does, `loops_test.go:250`); any egress policy under test also allows egress to
  kube-dns:53 so the policy peer is the only variable.
- **Egress-allow must be paired with ingress-deny to exercise conntrack (L-2).** A
  default-allow-ingress prober's return SYN-ACK succeeds trivially, so an egress-allow
  probe alone does not test egress conntrack return handling. Pair egress-allow with
  ingress-deny on that prober so the return path depends on the egress-created conntrack
  entry.
- **Retry-to-expected** for lag tolerance (k8s netpol pattern), but only for
  first-probe-after-apply; a persistent mismatch and a drop on an already-correct flow
  still fail (DESIGN §2a coherence note).
- **Prober liveness is an infra gate (M-1).** A `sleep infinity` + `RestartPolicyNever`
  prober that gets evicted makes every later sweep an exec error, which post-M1 is
  correctly "not a verdict" — so the enforcement gate would silently no-op for the rest
  of the run. Detect prober-not-Running as an infra failure and fail the run.

### W2. Established-connection disruption (gate 2) — fix C3
- **Decision (H-4): `RestartPolicyOnFailure` + gate on `RestartCount == 0`.** Not
  `RestartPolicyNever` + phase: phase-sampling goes blind after the first exit, races
  the sampler, and cannot distinguish a policy break from an eviction. The monotonic
  restart count is sample-race-proof and catches any single drop over 4h (Cilium
  `no_interrupted_connections.go` prior art).
- **Model: one persistent connection with an in-band heartbeat, fail-closed.** Hold a
  single long-lived TCP connection to an allow-server and heartbeat on it (keep-alive
  request loop on the *same* connection); exit non-zero on any connect/request error.
  Do NOT open a new connection per iteration — that tests new-flow enforcement, not
  established-connection survival, which is a different gate.
- The allow-server's policy must also permit the **return path**, so the connection's
  survival depends on NPA's conntrack, which is what an agent kill stresses.
- Sample `RestartCount` after every disruptive event (kill, hot-update, churn) and at
  end. This replaces `checkPortReuseClientHealth` for Tier 1.
- **Sequencing (H-3):** land this in the *same* step that quarantines #462 (W8), since
  today Gate 2's only signal is the #462 driver pod. Removing that before W2 exists
  would leave no connection-disruption signal at all.

### W3. Agent restart gate (gate 3) — implement H1
- Add violation kind `AgentRestart`. At setup, record `restartCount` for the
  `aws-eks-nodeagent` container on every node (sum across the DaemonSet pods under
  test). At end, re-read; any positive delta → violation with which node and the new
  count. Uses the k8s API only (no metrics endpoint), so it is always on.
- Also capture `lastState.terminated.reason` (OOMKilled etc.) when the delta is >0, so
  the report says *why*.

### W4. Recovery correctness across repeated kills (gate 5) — deepen M5
- After each kill, instead of only "deny still blocks":
  - wait for the DaemonSet rollout to complete (reconcile-aware, not a flat 10s),
  - assert the `aws_conntrack_map` ID is preserved across the restart. **Read
    `GlobalMaps["aws_conntrack_map"]` (M-4), not `ProgIDs`/`MapIDs`** —
    `ParseLoadedEBPFData` routes global maps to a separate `GlobalMaps` field, and the
    check must hold across **every** kill, not once.
  - assert an **allowed** long-lived connection survived the kill (ties to W2),
  - assert a fresh probe in both directions is correct.
- Record `RecoveryFailure` with the specific sub-check that failed.
- **Settle window (M-2).** DESIGN §4b requires ≥2 reconcile cycles after the last kill,
  but `schedule.Validate` doesn't enforce it: at `D/4` the 4th kill lands at ~`t=D`,
  so the end-of-run leak/recovery checks fire while the agent is restarting → false
  `BPFLeak`/`RecoveryFailure`. Enforce "no kill inside the final settle window" in both
  `schedule.Validate` and the kill loop.

### W5. Make the leak/memory gates real (C-2, H-2, L-1)
- **Add a real, policy-selected pod-churn driver (C-2, critical).** Today there is NO
  continuous pod-churn driver in `start()`, and the one ns-churn pod carries no policy,
  so NPA never programs per-pod BPF for it and the leak gate compares a count nothing
  moves. Add a continuous churn driver (reuse `leak_test.go:buildChurnCronJob`) whose
  pods are **selected by a NetworkPolicy**, so per-pod progs/maps are actually created
  and then must drain to baseline. Distribute the churn across all N nodes (ties to C-3).
- **Judge leak in a quiet window (L-1).** The drain + baseline-return check runs when
  churn is paused, and retries to baseline rather than a single strict `>` read, so a
  pod mid-teardown at the sample instant is not a transient false positive.
- **Memory + CPU gate on slope, not absolute (H-2).** Convert the memory gate off the
  flat >50 MiB (DESIGN §3a) to slope/N-sigma over the post-warmup baseline. The `D/4`
  kill resets the process, so both memory working-set and CPU `usageCoreNanoSeconds`
  are per-lifetime: detect the restart and reset the per-lifetime baseline, gating on
  the worst per-lifetime slope. Keep one node in a **no-kill** set so a full-run trend
  exists; that node must still carry representative churn + probes so its leak signal
  is real (document it as the full-run leak-gate carrier).

### W6. CPU + goroutine growth (gate 6)
- Extend the kubestats growth model (already used for memory) to **CPU** (cores from
  `usageCoreNanoSeconds` delta / walltime) and **goroutines** (only if the metrics
  endpoint/CW is available; otherwise skip with a logged reason).
- All three gate on **growth vs post-warmup baseline** (slope or N-sigma), never an
  absolute (DESIGN §3a). CPU node type is recorded, not pinned.

### W7. CloudWatch metrics plumbing (behind env var, off by default)
- New `SOAK_ASSERT_METRICS` env var (DESIGN §2f) plus a `metrics` package that:
  - when disabled (default): no-op, no AWS calls, run is fully env-agnostic;
  - when enabled: queries CloudWatch `GetMetricData` in namespace **`DataplanePOC`**,
    filtering dims `ClusterName` (from `--cluster-name`), `Component` (const, e.g.
    `aws-eks-nodeagent`), `K8sVersion` (discovered from the cluster), `Node`.
  - Region/account come from the ambient AWS config / `--aws-region`; nothing hardcoded.
- The actual metric names and thresholds are **stubbed with a clear TODO** until you
  provide them; the plumbing, dimension wiring, and env-var gate ship now. A metric
  named for assertion whose source is unavailable is a **setup error**, but this must
  only fire when the env var actually names it — the default empty/none run makes zero
  AWS calls (L-3).
- Keep the pure parser/threshold logic unit-testable (like ctrace/kubestats); the AWS
  SDK call is the only untestable seam and stays thin.
- **Do not route the always-on gates through CloudWatch (M-3).** Restarts stay on the
  k8s API (W3) and memory/CPU stay on kubelet `/stats/summary` (W6), unconditionally,
  so the default run has no AWS dependency. CloudWatch is opt-in for business metrics
  only. Also verify the `:8162` in-container scrape is even possible before building on
  it: the nodeagent sidecar may be distroless with no shell/curl, so a
  `curl localhost:8162` exec could be impossible. Confirm the scrape mechanism first;
  if the sidecar can't be exec-scraped, the business-metric path needs a different
  reach (a sidecar-less HTTP GET via the API proxy, or skip with a logged reason).

### W8. Quarantine #462 for Tier 1 (H-3)
- A flag default is not enough: `scanForConntrackRace` and `checkPortReuseClientHealth`
  run **unconditionally** in the `It` today, and the ctrace IPv4 parser is broken
  (matches nothing on IPv4), so a clean scan is a *false green*, not a pass. W8 must
  **skip the scan and not deploy the reuse driver at all** when the guard is off
  (default off for Tier 1), behind `--soak-enable-462-guard=false`.
- Land W8 together with W2 (see H-3 sequencing) so Gate 2 keeps a live signal.

---

## Build order (each step compiles + unit-tests green before the next)

1. **W0 foundations (C-1, C-3):** timeout wiring + `schedule.Validate` rejecting
   `D > timeout`; workload distribution across all N nodes; fail-fast NP precondition.
   Nothing downstream is trustworthy until a 4h run can actually reach its end.
2. **W8 + W2 together (H-3):** quarantine the #462 scan + driver *and* land the
   liveness client, so Gate 2 never loses its signal.
3. **W3 restart gate** (small, always-on, k8s API only).
4. **W5 churn driver + leak-gate fix (C-2):** the policy-selected continuous churn that
   makes the leak gate non-vacuous, plus the quiet-window judging.
5. **W1 probe rework** (M1 exit-code fix, allow + egress with separate probers, DNS-safe).
6. **W4 recovery deepening** (GlobalMaps map-ID, settle window).
7. **W6 CPU/goroutine trackers** (slope, per-lifetime reset).
8. **W7 CW metrics plumbing** behind env var (opt-in only; always-on gates stay off it).

Each pure package (`kubestats` extensions, `metrics` parser) gets table-driven tests.
The suite compiles against the real framework and the full binary builds with the
go1.26.4 toolchain (verified working). After all steps, one **fresh 4h run on the
3-node EC2 cluster** with metrics gate off, expected green.

---

## Verification per step
- Offline: `go test ./test/integration/soak/...` (unit) + `go vet` + `gofmt` + `go test -c` (compile the suite).
- On-cluster smoke: a short `--soak-duration` run (>= the schedule minimum) proving each
  new gate fires correctly (deliberately trip it once, e.g. delete a policy to force a
  false-allow, confirm the violation is recorded) before trusting a clean 4h run.
