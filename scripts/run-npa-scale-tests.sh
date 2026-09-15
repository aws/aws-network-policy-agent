#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")"; pwd)
source "${DIR}/lib/scale-soak.sh"

NAMESPACE=${NPA_SCALE_NAMESPACE:-npa-scale}
STABLE_TARGETS=${NPA_SCALE_STABLE_TARGETS:-100}
TARGETS=${NPA_SCALE_TARGETS:-50}
BATCH_SIZE=${NPA_SCALE_BATCH_SIZE:-50}
CYCLES=${NPA_SCALE_CYCLES:-45}
CYCLE_SECONDS=${NPA_SCALE_CYCLE_SECONDS:-60}
WORKLOAD_PROFILE_ID=${WORKLOAD_PROFILE_ID:-npa-policy-churn-v1}
WORKLOAD_REPORT_PATH=${WORKLOAD_REPORT_PATH:-log/npa-scale-workload-report.json}
WORKLOAD_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NPA_TEST_NAMESPACE=$NAMESPACE
WORKLOAD_STABLE_PODS=$STABLE_TARGETS
WORKLOAD_CHURN_PODS=0
WORKLOAD_CHURN_PODS_PER_JOB=$TARGETS
WORKLOAD_CYCLE_INTERVAL_SECONDS=$CYCLE_SECONDS
WORKLOAD_DURATION_SECONDS=0
WORKLOAD_ROUNDS_REQUESTED=$CYCLES
WORKLOAD_ROUNDS_COMPLETED=0
WORKLOAD_ALLOW_PROBES=0
WORKLOAD_DENY_PROBES=0
WORKLOAD_MODE_PROBES=0
WORKLOAD_POLICY_REMOVAL_PROBES=0
WORKLOAD_POLICY_REMOVAL_STATUS=pending
WORKLOAD_STATUS=running
WORKLOAD_CLEANUP_STATUS=pending

npa_require_environment
npa_require_test_namespace "$NAMESPACE" npa-scale
npa_require_positive_integer NPA_SCALE_STABLE_TARGETS "$STABLE_TARGETS"
npa_require_positive_integer NPA_SCALE_TARGETS "$TARGETS"
npa_require_positive_integer NPA_SCALE_BATCH_SIZE "$BATCH_SIZE"
npa_require_positive_integer NPA_SCALE_CYCLES "$CYCLES"
npa_require_positive_integer NPA_SCALE_CYCLE_SECONDS "$CYCLE_SECONDS"
if [[ "$WORKLOAD_PROFILE_ID" != npa-policy-churn-v1 ]]; then
    echo "unsupported NPA scale workload profile ${WORKLOAD_PROFILE_ID}" >&2
    exit 2
fi
npa_cleanup_namespace "$NAMESPACE"
npa_create_namespace "$NAMESPACE"
trap 'npa_finalize "$NAMESPACE" "$?"' EXIT
npa_create_probe_fixture "$NAMESPACE"
npa_apply_churn "$NAMESPACE" stable "$STABLE_TARGETS" "$BATCH_SIZE"

scale_started=$(date +%s)
for ((cycle = 1; cycle <= CYCLES; cycle++)); do
    cycle_started=$(date +%s)
    run_label="scale-${cycle}"
    echo "NPA scale cycle ${cycle}/${CYCLES}: creating ${TARGETS} distinct policy identities"
    npa_apply_churn "$NAMESPACE" "$run_label" "$TARGETS" "$BATCH_SIZE"
    if ((cycle < CYCLES)); then
        npa_delete_churn "$NAMESPACE" "$run_label"
    else
        echo "Leaving final churn batch active for the full-load metric snapshot"
    fi
    npa_verify_enforcement "$NAMESPACE"
    WORKLOAD_CHURN_PODS=$((WORKLOAD_CHURN_PODS + TARGETS))
    WORKLOAD_ROUNDS_COMPLETED=$cycle
    WORKLOAD_DURATION_SECONDS=$(($(date +%s) - scale_started))
    npa_persist_state

    next_cycle=$((cycle_started + CYCLE_SECONDS))
    remaining=$((next_cycle - $(date +%s)))
    if ((remaining > 0)); then
        sleep "$remaining"
    fi
done

WORKLOAD_DURATION_SECONDS=$(($(date +%s) - scale_started))
echo "NPA scale workload completed successfully"
