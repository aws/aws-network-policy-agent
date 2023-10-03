#! /bin/bash
set -Eeuox pipefail

DIR=$(cd "$(dirname "$0")"; pwd)

source ${DIR}/lib/cleanup.sh
source ${DIR}/lib/cloudwatch.sh
source ${DIR}/lib/cluster.sh
source ${DIR}/lib/network-policy.sh
source ${DIR}/lib/tests.sh

: "${RUN_PERFORMANCE_TESTS:=false}"
: "${RUN_CONFORMANCE_TESTS:=false}"
TEST_FAILED="false"

cleanup() {

  if [[ $RUN_PERFORMANCE_TESTS == "true" ]]; then
    uninstall_cloudwatch_agent
  fi

  delete_cluster
}

trap cleanup EXIT

load_default_values
create_cluster

build_and_push_image
make update-node-agent-image AWS_EKS_NODEAGENT=$AWS_ECR_REGISTRY/$AWS_ECR_REPO_NAME:$IMAGE_VERSION IP_FAMILY=$IP_FAMILY

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
fi
