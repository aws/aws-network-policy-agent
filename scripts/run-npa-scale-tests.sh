#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")"; pwd)
source "${DIR}/lib/scale-soak.sh"

NAMESPACE=${NPA_SCALE_NAMESPACE:-npa-scale}
STABLE_TARGETS=${NPA_SCALE_STABLE_TARGETS:-100}
TARGETS=${NPA_SCALE_TARGETS:-50}
BATCH_SIZE=${NPA_SCALE_BATCH_SIZE:-50}
CYCLES=${NPA_SCALE_CYCLES:-20}
CYCLE_SECONDS=${NPA_SCALE_CYCLE_SECONDS:-60}
SHORT_LIVED_TARGETS=${NPA_SCALE_SHORT_LIVED_TARGETS:-50}
SHORT_LIVED_ROUNDS=${NPA_SCALE_SHORT_LIVED_ROUNDS:-40}
SHORT_LIVED_INTERVAL_SECONDS=${NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS:-30}
SHORT_LIVED_LIFETIME_SECONDS=${NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS:-5}
WORKLOAD_PROFILE_ID=${WORKLOAD_PROFILE_ID:-npa-policy-churn-v2}
WORKLOAD_REPORT_PATH=${WORKLOAD_REPORT_PATH:-log/npa-scale-workload-report.json}
WORKLOAD_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NPA_TEST_NAMESPACE=$NAMESPACE
WORKLOAD_STABLE_PODS=$STABLE_TARGETS
WORKLOAD_CHURN_PODS=0
WORKLOAD_CHURN_PODS_PER_JOB=$((TARGETS > SHORT_LIVED_TARGETS ? TARGETS : SHORT_LIVED_TARGETS))
WORKLOAD_CYCLE_INTERVAL_SECONDS=$CYCLE_SECONDS
WORKLOAD_POLICY_ROUNDS_REQUESTED=$CYCLES
WORKLOAD_POLICY_ROUNDS_COMPLETED=0
WORKLOAD_SHORT_LIVED_PODS=0
WORKLOAD_SHORT_LIVED_PODS_PER_ROUND=$SHORT_LIVED_TARGETS
WORKLOAD_SHORT_LIVED_INTERVAL_SECONDS=$SHORT_LIVED_INTERVAL_SECONDS
WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS=0
WORKLOAD_SHORT_LIVED_ROUNDS_REQUESTED=$SHORT_LIVED_ROUNDS
WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED=0
WORKLOAD_DURATION_SECONDS=0
WORKLOAD_ROUNDS_REQUESTED=$((CYCLES + SHORT_LIVED_ROUNDS))
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
npa_require_positive_integer NPA_SCALE_SHORT_LIVED_TARGETS "$SHORT_LIVED_TARGETS"
npa_require_positive_integer NPA_SCALE_SHORT_LIVED_ROUNDS "$SHORT_LIVED_ROUNDS"
npa_require_positive_integer NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS "$SHORT_LIVED_INTERVAL_SECONDS"
npa_require_positive_integer NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS "$SHORT_LIVED_LIFETIME_SECONDS"
if [[ "$WORKLOAD_PROFILE_ID" != npa-policy-churn-v2 ]]; then
    echo "unsupported NPA scale workload profile ${WORKLOAD_PROFILE_ID}" >&2
    exit 2
fi
npa_cleanup_namespace "$NAMESPACE"
npa_create_namespace "$NAMESPACE"
trap 'npa_finalize "$NAMESPACE" "$?"' EXIT
npa_create_probe_fixture "$NAMESPACE"
npa_apply_churn "$NAMESPACE" stable "$STABLE_TARGETS" "$BATCH_SIZE"

scale_started=$(date +%s)
for ((cycle = 1; cycle < CYCLES; cycle++)); do
    cycle_started=$(date +%s)
    run_label="scale-${cycle}"
    echo "NPA scale cycle ${cycle}/${CYCLES}: creating ${TARGETS} distinct policy identities"
    npa_apply_churn "$NAMESPACE" "$run_label" "$TARGETS" "$BATCH_SIZE"
    npa_delete_churn "$NAMESPACE" "$run_label"
    npa_verify_enforcement "$NAMESPACE"
    WORKLOAD_CHURN_PODS=$((WORKLOAD_CHURN_PODS + TARGETS))
    WORKLOAD_POLICY_ROUNDS_COMPLETED=$cycle
    WORKLOAD_ROUNDS_COMPLETED=$((WORKLOAD_POLICY_ROUNDS_COMPLETED + WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED))
    WORKLOAD_DURATION_SECONDS=$(($(date +%s) - scale_started))
    npa_persist_state

    next_cycle=$((cycle_started + CYCLE_SECONDS))
    remaining=$((next_cycle - $(date +%s)))
    if ((remaining > 0)); then
        sleep "$remaining"
    fi
done

npa_apply_short_lived_policy "$NAMESPACE"
short_lived_started=$(date +%s)
for ((round = 1; round <= SHORT_LIVED_ROUNDS; round++)); do
    if ((round > 1)); then
        npa_require_short_lived_deleted "$NAMESPACE" "short-lived-$((round - 1))"
    fi
    round_started=$(date +%s)
    run_label="short-lived-${round}"
    echo "NPA short-lived churn ${round}/${SHORT_LIVED_ROUNDS}: creating ${SHORT_LIVED_TARGETS} ${SHORT_LIVED_LIFETIME_SECONDS}-second pod identities"
    npa_run_short_lived_round \
        "$NAMESPACE" \
        "$run_label" \
        "$SHORT_LIVED_TARGETS" \
        "$SHORT_LIVED_LIFETIME_SECONDS"
    npa_verify_enforcement "$NAMESPACE"
    WORKLOAD_SHORT_LIVED_PODS=$((WORKLOAD_SHORT_LIVED_PODS + SHORT_LIVED_TARGETS))
    WORKLOAD_CHURN_PODS=$((WORKLOAD_CHURN_PODS + SHORT_LIVED_TARGETS))
    WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED=$round
    WORKLOAD_ROUNDS_COMPLETED=$((WORKLOAD_POLICY_ROUNDS_COMPLETED + WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED))
    WORKLOAD_DURATION_SECONDS=$(($(date +%s) - scale_started))
    round_elapsed=$(($(date +%s) - round_started))
    if ((round_elapsed > WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS)); then
        WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS=$round_elapsed
    fi
    npa_persist_state

    next_round=$((short_lived_started + round * SHORT_LIVED_INTERVAL_SECONDS))
    remaining=$((next_round - $(date +%s)))
    if ((remaining < 0)); then
        WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS=$(($(date +%s) - round_started))
        npa_persist_state
        echo "NPA short-lived churn missed its ${SHORT_LIVED_INTERVAL_SECONDS}-second cadence in round ${round}" >&2
        exit 1
    fi
    if ((remaining > 0)); then
        sleep "$remaining"
    fi
done
npa_require_short_lived_deleted "$NAMESPACE" "short-lived-${SHORT_LIVED_ROUNDS}"

cycle=$CYCLES
run_label="scale-${cycle}"
echo "NPA scale cycle ${cycle}/${CYCLES}: creating ${TARGETS} final policy identities"
npa_apply_churn "$NAMESPACE" "$run_label" "$TARGETS" "$BATCH_SIZE"
echo "Leaving final churn batch active for the full-load metric snapshot"
npa_verify_enforcement "$NAMESPACE"
WORKLOAD_CHURN_PODS=$((WORKLOAD_CHURN_PODS + TARGETS))
WORKLOAD_POLICY_ROUNDS_COMPLETED=$CYCLES
WORKLOAD_ROUNDS_COMPLETED=$((WORKLOAD_POLICY_ROUNDS_COMPLETED + WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED))
WORKLOAD_DURATION_SECONDS=$(($(date +%s) - scale_started))
npa_persist_state
echo "NPA scale workload completed successfully"
