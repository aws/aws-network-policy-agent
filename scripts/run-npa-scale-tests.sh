#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")"; pwd)
source "${DIR}/lib/scale-soak.sh"

NAMESPACE=${NPA_SCALE_NAMESPACE:-npa-scale}
TARGETS=${NPA_SCALE_TARGETS:-20}
BATCH_SIZE=${NPA_SCALE_BATCH_SIZE:-5}
CYCLES=${NPA_SCALE_CYCLES:-3}

npa_require_environment
npa_require_test_namespace "$NAMESPACE" npa-scale
npa_require_positive_integer NPA_SCALE_TARGETS "$TARGETS"
npa_require_positive_integer NPA_SCALE_BATCH_SIZE "$BATCH_SIZE"
npa_require_positive_integer NPA_SCALE_CYCLES "$CYCLES"
npa_cleanup_namespace "$NAMESPACE"
npa_create_namespace "$NAMESPACE"
trap 'npa_finalize "$NAMESPACE" "$?"' EXIT
npa_create_probe_fixture "$NAMESPACE"

for ((cycle = 1; cycle <= CYCLES; cycle++)); do
    run_label="scale-${cycle}"
    echo "NPA scale cycle ${cycle}/${CYCLES}: creating ${TARGETS} distinct policy identities"
    npa_apply_churn "$NAMESPACE" "$run_label" "$TARGETS" "$BATCH_SIZE"
    npa_delete_churn "$NAMESPACE" "$run_label"
    npa_verify_enforcement "$NAMESPACE"
done

echo "NPA scale workload completed successfully"
