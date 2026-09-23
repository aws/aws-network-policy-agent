#!/usr/bin/env bash

# Completes the policy-removal probe and deletes the workload left running by
# the NPA scale or soak script. Hydra uses this split phase to capture full-load
# BPF state before cleanup and recovery state afterwards.

set -euo pipefail

DIR=$(cd "$(dirname "$0")"; pwd)
source "${DIR}/lib/scale-soak.sh"

readonly NPA_BPF_OWNED_NAMESPACE=npa-scale-evidence

cleanup_bpf_reader_namespace() {
    if [[ -z ${KUBECONFIG:-} ]]; then
        if [[ ${NPA_REQUIRE_WORKLOAD_STATE:-false} == true ]]; then
            echo "KUBECONFIG is required to clean up NPA scale evidence" >&2
            return 1
        fi
        return 0
    fi
    npa_kubectl delete "namespace/${NPA_BPF_OWNED_NAMESPACE}" \
        --ignore-not-found=true \
        --wait=true \
        --timeout=10m
}

status=0
state_file=$(npa_state_file)
if [[ ! -f $state_file ]]; then
    if [[ ${NPA_REQUIRE_WORKLOAD_STATE:-false} == true ]]; then
        echo "NPA scale workload did not create its required state file" >&2
        status=1
    else
        echo "NPA workload did not create state; workload cleanup is a no-op"
    fi
else
    # The workload writes shell-escaped scalar assignments only.
    source "$state_file"
    : "${NPA_TEST_NAMESPACE:?NPA_TEST_NAMESPACE is missing from workload state}"

    if [[ ${WORKLOAD_CLEANUP_STATUS:-pending} == pass ]]; then
        echo "NPA workload cleanup already completed"
    else
        if [[ ${WORKLOAD_STATUS:-failed} != pass ]]; then
            status=1
        fi
        if ((status == 0)) && ! npa_validate_scale_completion; then
            status=1
        fi
        if npa_complete_cleanup "$NPA_TEST_NAMESPACE" "$status"; then
            echo "NPA workload cleanup completed"
        else
            status=$?
        fi
    fi
fi

if cleanup_bpf_reader_namespace; then
    :
else
    evidence_status=$?
    if ((status == 0)); then
        status=$evidence_status
    fi
fi

exit "$status"
