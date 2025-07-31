#! /bin/bash
set -Eeuox pipefail

DIR=$(cd "$(dirname "$0")"; pwd)

source ${DIR}/lib/common.sh
source ${DIR}/lib/cleanup.sh
source ${DIR}/lib/cloudwatch.sh
source ${DIR}/lib/cluster.sh
source ${DIR}/lib/network-policy.sh
source ${DIR}/lib/tests.sh

RUN_PERFORMANCE_TESTS="${RUN_PERFORMANCE_TESTS:=false}"
RUN_CONFORMANCE_TESTS="${RUN_CONFORMANCE_TESTS:=false}"
AWS_EKS_NODEAGENT_IMAGE="${AWS_EKS_NODEAGENT_IMAGE:=""}"
TEST_IMAGE_REGISTRY="${TEST_IMAGE_REGISTRY:="registry.k8s.io"}"
TEST_FAILED="false"

cleanup() {

  if [[ $RUN_PERFORMANCE_TESTS == "true" ]]; then
    uninstall_cloudwatch_agent
  fi

  delete_cluster
}

trap cleanup EXIT

check_is_installed aws
check_is_installed eksctl
check_is_installed helm

load_default_values
create_cluster

make update-node-agent-image AWS_EKS_NODEAGENT=$AWS_EKS_NODEAGENT_IMAGE IP_FAMILY=$IP_FAMILY

if [[ $RUN_PERFORMANCE_TESTS == "true" ]]; then
  echo "Runnning Performance tests"
  install_cloudwatch_agent
  run_performance_tests
elif [[ $RUN_CONFORMANCE_TESTS == "true" ]]; then
  echo "Running Conformance tests"
  run_cyclonus_tests
fi

check_path_cleanup

if [[ $TEST_FAILED == "true" ]]; then
  echo "Test run failed, check failures"
  exit 1
else
  echo "Test run succeeded"
fi