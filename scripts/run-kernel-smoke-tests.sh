#!/bin/bash

# Runs the kernel-sensitive test suites against an existing cluster, on IPv4
# and IPv6 clusters alike, so every kernel line in the nightly matrix gets the
# same coverage (bpflatency.test's ceilings are the same on both, though its
# numbers differ by family):
#   policy.test - network policy enforcement through the agent's TC programs
#   ebpf.test   - eBPF program behavior, including the conntrack shortening of
#                 denied connections on kernels with the nf_conntrack kfuncs
#   bpflatency.test - p50/p99 of the agent's eBPF program load and probe
#                 attach for new pods, per direction, against ceilings, and
#                 logged per kernel, address family and instance type
#   restart.test - agent restarts: conntrack state survives and a deny policy
#                 holds while the agent re-attaches pods' programs
#   agentflags.test - agent flags set on aws-node, such as TCP reset on deny
#                 (changes aws-node and restores it, so it runs before strict)
#   strict.test - strict enforcement mode (mutates aws-node, so it runs last)
#
# Parameters:
# CLUSTER_NAME: name of the cluster
# KUBECONFIG: path to the cluster kubeconfig file
# REGION: defaults to us-west-2
# IP_FAMILY: defaults to IPv4
# TEST_IMAGE_REGISTRY: defaults to registry.k8s.io
# BPFLATENCY_PODS, BPFLATENCY_MAX_{LOAD,ATTACH}_{P50,P99}_MS: optional
#   bpflatency.test pod count and ceilings in ms (see its suite file)

set -euoE pipefail
DIR=$(cd "$(dirname "$0")"; pwd)
GINKGO_TEST_BUILD_DIR="$DIR/../test/build"

source "${DIR}/lib/tests.sh"

: "${IP_FAMILY:="IPv4"}"
: "${REGION:="us-west-2"}"
: "${TEST_IMAGE_REGISTRY:="registry.k8s.io"}"
: "${KUBE_CONFIG_PATH:=$KUBECONFIG}"

TEST_FAILED="false"

echo "Nodes for cluster: $CLUSTER_NAME"
kubectl get nodes -owide

echo "Making ginkgo test binaries"
(cd $DIR/.. && make build-test-binaries)

run_ginkgo_suite policy.test 15m

run_suite_restoring_agent_args ebpf.test 15m

# bpflatency's default load ceilings fit kernel 6.1 on IPv6, whose loads take
# 3-4x longer than on any other combination (see its suite file). Hold the
# others to tighter ones, about 3x their slowest mean on t3.large, unless the
# caller set them.
if [[ "${KERNEL_LINE:-}" != "6.1" || "$IP_FAMILY" != "IPv6" ]]; then
    export BPFLATENCY_MAX_LOAD_P50_MS="${BPFLATENCY_MAX_LOAD_P50_MS:-1000}"
    export BPFLATENCY_MAX_LOAD_P99_MS="${BPFLATENCY_MAX_LOAD_P99_MS:-1500}"
fi
run_ginkgo_suite bpflatency.test 10m

run_ginkgo_suite restart.test 15m

run_suite_restoring_agent_args agentflags.test 15m

enable_strict_mode

run_ginkgo_suite strict.test 15m

if [[ $TEST_FAILED == "true" ]]; then
    echo "Test run failed"
    exit 1
fi
