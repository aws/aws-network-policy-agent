#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")"; pwd)
source "${DIR}/lib/scale-soak.sh"

NAMESPACE=${NPA_SOAK_NAMESPACE:-npa-soak}
TARGETS=${NPA_SOAK_TARGETS:-20}
BATCH_SIZE=${NPA_SOAK_BATCH_SIZE:-5}
DURATION_SECONDS=${NPA_SOAK_DURATION_SECONDS:-7200}
CYCLE_SECONDS=${NPA_SOAK_CYCLE_SECONDS:-300}
HEALTH_INTERVAL_SECONDS=${NPA_SOAK_HEALTH_INTERVAL_SECONDS:-60}
WORKLOAD_PROFILE_ID=${WORKLOAD_PROFILE_ID:-npa-functional-soak-v1}
WORKLOAD_REPORT_PATH=${WORKLOAD_REPORT_PATH:-log/npa-soak-workload-report.json}
WORKLOAD_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NPA_TEST_NAMESPACE=$NAMESPACE
WORKLOAD_STABLE_PODS=3
WORKLOAD_CHURN_PODS=0
WORKLOAD_CHURN_PODS_PER_JOB=$TARGETS
WORKLOAD_CYCLE_INTERVAL_SECONDS=$CYCLE_SECONDS
WORKLOAD_DURATION_SECONDS=0
WORKLOAD_ROUNDS_REQUESTED=$(((DURATION_SECONDS + CYCLE_SECONDS - 1) / CYCLE_SECONDS))
WORKLOAD_ROUNDS_COMPLETED=0
WORKLOAD_ALLOW_PROBES=0
WORKLOAD_DENY_PROBES=0
WORKLOAD_MODE_PROBES=0
WORKLOAD_POLICY_REMOVAL_PROBES=0
WORKLOAD_POLICY_REMOVAL_STATUS=pending
WORKLOAD_STATUS=running
WORKLOAD_CLEANUP_STATUS=pending

npa_require_environment
npa_require_test_namespace "$NAMESPACE" npa-soak
npa_require_positive_integer NPA_SOAK_TARGETS "$TARGETS"
npa_require_positive_integer NPA_SOAK_BATCH_SIZE "$BATCH_SIZE"
npa_require_positive_integer NPA_SOAK_DURATION_SECONDS "$DURATION_SECONDS"
npa_require_positive_integer NPA_SOAK_CYCLE_SECONDS "$CYCLE_SECONDS"
npa_require_positive_integer NPA_SOAK_HEALTH_INTERVAL_SECONDS "$HEALTH_INTERVAL_SECONDS"
if [[ "$WORKLOAD_PROFILE_ID" != npa-functional-soak-v1 ]]; then
    echo "unsupported NPA soak workload profile ${WORKLOAD_PROFILE_ID}" >&2
    exit 2
fi
npa_cleanup_namespace "$NAMESPACE"
npa_create_namespace "$NAMESPACE"
trap 'npa_finalize "$NAMESPACE" "$?"' EXIT
npa_create_probe_fixture "$NAMESPACE"

started_at=$(date +%s)
deadline=$((started_at + DURATION_SECONDS))
cycle=1

while (( $(date +%s) < deadline )); do
    run_label="soak-${cycle}"
    cycle_deadline=$((started_at + cycle * CYCLE_SECONDS))
    if ((cycle_deadline > deadline)); then
        cycle_deadline=$deadline
    fi
    echo "NPA soak cycle ${cycle}: creating ${TARGETS} distinct policy identities"
    npa_apply_churn "$NAMESPACE" "$run_label" "$TARGETS" "$BATCH_SIZE"

    while (( $(date +%s) < cycle_deadline && $(date +%s) < deadline )); do
        npa_verify_enforcement "$NAMESPACE"
        now=$(date +%s)
        cycle_remaining=$((cycle_deadline - now))
        test_remaining=$((deadline - now))
        remaining=$((cycle_remaining < test_remaining ? cycle_remaining : test_remaining))
        sleep_seconds=$((HEALTH_INTERVAL_SECONDS < remaining ? HEALTH_INTERVAL_SECONDS : remaining))
        if ((sleep_seconds > 0)); then
            sleep "$sleep_seconds"
        fi
    done

    npa_delete_churn "$NAMESPACE" "$run_label"
    npa_verify_enforcement "$NAMESPACE"
    WORKLOAD_CHURN_PODS=$((WORKLOAD_CHURN_PODS + TARGETS))
    WORKLOAD_ROUNDS_COMPLETED=$cycle
    WORKLOAD_DURATION_SECONDS=$(($(date +%s) - started_at))
    npa_persist_state
    cycle=$((cycle + 1))
done

WORKLOAD_DURATION_SECONDS=$(($(date +%s) - started_at))
echo "NPA soak workload completed successfully"
