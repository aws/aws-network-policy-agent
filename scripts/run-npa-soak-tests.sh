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

npa_require_environment
npa_require_test_namespace "$NAMESPACE" npa-soak
npa_require_positive_integer NPA_SOAK_TARGETS "$TARGETS"
npa_require_positive_integer NPA_SOAK_BATCH_SIZE "$BATCH_SIZE"
npa_require_positive_integer NPA_SOAK_DURATION_SECONDS "$DURATION_SECONDS"
npa_require_positive_integer NPA_SOAK_CYCLE_SECONDS "$CYCLE_SECONDS"
npa_require_positive_integer NPA_SOAK_HEALTH_INTERVAL_SECONDS "$HEALTH_INTERVAL_SECONDS"
npa_cleanup_namespace "$NAMESPACE"
npa_create_namespace "$NAMESPACE"
trap 'npa_finalize "$NAMESPACE" "$?"' EXIT
npa_create_probe_fixture "$NAMESPACE"

started_at=$(date +%s)
deadline=$((started_at + DURATION_SECONDS))
cycle=1

while (( $(date +%s) < deadline )); do
    run_label="soak-${cycle}"
    cycle_deadline=$(( $(date +%s) + CYCLE_SECONDS ))
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
    cycle=$((cycle + 1))
done

echo "NPA soak workload completed successfully"
