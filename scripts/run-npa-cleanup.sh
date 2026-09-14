#!/usr/bin/env bash

# Completes the policy-removal probe and deletes the workload left running by
# the NPA scale or soak script. Hydra uses this split phase to capture full-load
# BPF state before cleanup and recovery state afterwards.

set -euo pipefail

DIR=$(cd "$(dirname "$0")"; pwd)
source "${DIR}/lib/scale-soak.sh"

state_file=$(npa_state_file)
if [[ ! -f $state_file ]]; then
    echo "NPA workload state is missing at ${state_file}" >&2
    exit 1
fi

# The workload writes shell-escaped scalar assignments only.
source "$state_file"
: "${NPA_TEST_NAMESPACE:?NPA_TEST_NAMESPACE is missing from workload state}"

status=0
if [[ ${WORKLOAD_STATUS:-failed} != pass ]]; then
    status=1
fi
if npa_complete_cleanup "$NPA_TEST_NAMESPACE" "$status"; then
    :
else
    exit $?
fi

echo "NPA workload cleanup completed"
