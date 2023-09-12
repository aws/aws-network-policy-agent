#!/bin/bash

# The script runs Network Policy Cyclonus tests on a existing cluster
# Parameters to pass
# Parameters:
# CLUSTER_NAME: name of the cluster
# KUBECONFIG: path to the kubeconfig file, default ~/.kube/config
# REGION: defaults to us-west-2
# IP_FAMILY: defaults to IPv4
# ADDON_VERSION: Optional, defaults to the latest version
# ENDPOINT: Optional

set -euoE pipefail
DIR=$(cd "$(dirname "$0")"; pwd)

source ${DIR}/lib/cleanup.sh
source ${DIR}/lib/network-policy.sh
source ${DIR}/lib/tests.sh

: "${ENDPOINT_FLAG:=""}"
: "${ENDPOINT:=""}"
: "${ADDON_VERSION:=""}"
: "${IP_FAMILY:="IPv4"}"
: "${REGION:="us-west-2"}"
: "${SKIP_ADDON_INSTALLATION:="false"}"

if [[ ! -z $ENDPOINT ]]; then
    ENDPOINT_FLAG="--endpoint-url $ENDPOINT"
fi

K8S_VERSION=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION | jq -r '.cluster.version')
TEST_FAILED="false"

echo "Running Cyclonus e2e tests with the following variables
KUBECONFIG: $KUBECONFIG
CLUSTER_NAME: $CLUSTER_NAME
REGION: $REGION
IP_FAMILY: $IP_FAMILY
K8S_VERSION: $K8S_VERSION

Optional args
ENDPOINT: $ENDPOINT
ADDON_VERSION: $ADDON_VERSION"

if [[ $SKIP_ADDON_INSTALLATION == "false" ]]; then
    load_addon_details

    if [[ ! -z $ADDON_VERSION ]]; then
        install_network_policy_mao $ADDON_VERSION
    else
        install_network_policy_mao $LATEST_ADDON_VERSION
    fi
else
    echo "Skipping addons installation. Make sure you have enabled network policy support in your cluster before executing the test"
fi

run_cyclonus_tests

if [[ $TEST_FAILED == "true" ]]; then
    echo "Test run failed, check failures"
    exit 1
fi
