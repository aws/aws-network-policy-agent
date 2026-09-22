## Integration Test scripts

This package contains shell scripts and libraries used for running e2e integration tests.

### Shell scripts

`run-test.sh` - Can run various integration test suites against the current revision in the invoking directory. This script is primarily used for running tests github actions

`run-cyclonus-tests.sh` - Runs cyclonus tests against an existing cluster and validates the output

`run-npa-scale-tests.sh` - Runs the locked NPA scale workload through a caller-supplied ClusterLoader2 profile and monitor set.

`run-npa-scale-workload.sh` - Churns distinct pod and policy identities in bounded batches while continuously checking allowed and denied traffic.

`run-npa-bpf-snapshot.sh` - Captures baseline, full-load, and recovery bpffs pin identities on every Linux node and fails on missing activity or retained identities.

`run-npa-soak-tests.sh` - Repeats the same bounded churn and traffic checks for a configurable duration.

`update-node-agent-image.sh` - Update the node agent image in the cluster to the image specified in `AWS_EKS_NODEAGENT` parameter using helm chart.

The scale and soak scripts only own their test namespaces and workloads. The
caller owns cluster creation, Network Policy enablement, metrics collection,
and cluster deletion. Both scripts require `KUBECONFIG`, delete any stale test
namespace before starting, and fail if final namespace deletion fails. The
scale wrapper additionally requires `CL2_PROFILE_PATH`; Hydra normally supplies
that component-owned policy plus `CL2_MONITORS_PATH`. The workload remains
manually runnable against a developer cluster through the same interface.

Scale defaults:

- `WORKLOAD_PROFILE_ID=npa-policy-churn-v4`
- `NPA_SCALE_STABLE_TARGETS=100`
- `NPA_SCALE_TARGETS=50`
- `NPA_SCALE_BATCH_SIZE=50`
- `NPA_SCALE_CYCLES=20`
- `NPA_SCALE_CYCLE_SECONDS=60`
- `NPA_SCALE_POLICY_SETTLE_SECONDS=10`
- `NPA_SCALE_SHORT_LIVED_TARGETS=100`
- `NPA_SCALE_SHORT_LIVED_ROUNDS=20`
- `NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS=60`
- `NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS=5`

The `npa-policy-churn-v4` profile keeps 100 stable policy-selected pods active.
It first creates and deletes 50 distinct pod and NetworkPolicy identities per
policy cycle. A 10-second settle interval after the deployments become
available keeps normal policy reconciliation out of the deletion path. It then
runs 100 five-second Job pods every 60 seconds, matching the historical leak
reproduction's concurrency and rate. Two NetworkPolicies select every
short-lived pod: a default-deny policy and a control-only egress policy. Every
short-lived pod probes the healthy fixture for its full lifetime and must
observe an allowed control request on port 8081 and a denied request on port
8080 in the same probe cycle. Early allowed requests are tolerated while policy
attachment converges. Once denial is observed, a later allowed request fails
the pod. A completed pod therefore proves selective NPA enforcement before
deletion.
Each completed Job is deleted asynchronously so Kubernetes cleanup can overlap
the remainder of the interval. Before creating the next round, the workload
requires the previous round's pods to be gone. The workload fails if Job
completion, deletion, or the functional probe misses the next absolute
60-second boundary. The final policy batch remains active for the full-load
metric snapshot. Including the five functional probe pods, the default peak
test workload is 205 concurrent pods and 3,000 churn pod creations across the
run.

Soak defaults:

- `NPA_SOAK_TARGETS=20`
- `NPA_SOAK_BATCH_SIZE=5`
- `NPA_SOAK_DURATION_SECONDS=7200`
- `NPA_SOAK_CYCLE_SECONDS=300`
- `NPA_SOAK_HEALTH_INTERVAL_SECONDS=60`

#### Tests
`scripts/test/scale-soak-test.sh` validates namespace safety and active-probe failure handling without a cluster.

`scripts/test/bpf-snapshot-test.sh` validates exact eBPF activity and drain set comparisons without a cluster.

The following tests are valid to run using `run-test.sh` script, and setting the respective environment variable to true will run them:
1. Conformance Tests - `RUN_CONFORMANCE_TESTS`
2. Performance Tests - `RUN_PERFORMANCE_TESTS`


#### Conformance tests
This runs the upstream cyclonus test suite for testing network policy


#### Performance tests
This for now runs the upstream cyclonus tests and only collects the memory metrics during the run
