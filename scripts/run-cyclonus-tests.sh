#!/bin/bash

# The script runs Network Policy Cyclonus tests on a existing cluster
# Parameters:
# CLUSTER_NAME: name of the cluster
# KUBECONFIG: Set the variable to the cluster kubeconfig file path
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
: "${K8S_VERSION:=""}"
: "${TEST_IMAGE_REGISTRY:="registry.k8s.io"}"
TEST_FAILED="false"

if [[ ! -z $ENDPOINT ]]; then
    ENDPOINT_FLAG="--endpoint-url $ENDPOINT"
fi

if [[ -z $K8S_VERSION ]]; then
    K8S_VERSION=$(aws eks describe-cluster $ENDPOINT_FLAG --name $CLUSTER_NAME --region $REGION | jq -r '.cluster.version')
fi

echo "Running Cyclonus e2e tests with the following variables
CLUSTER_NAME: $CLUSTER_NAME
REGION: $REGION
IP_FAMILY: $IP_FAMILY

Optional args
ENDPOINT: $ENDPOINT
ADDON_VERSION: $ADDON_VERSION
K8S_VERSION: $K8S_VERSION
"

echo "Nodes AMI version for cluster: $CLUSTER_NAME"
kubectl get nodes -owide

PROVIDER_ID=$(kubectl get nodes -ojson | jq -r '.items[0].spec.providerID')
AMI_ID=$(aws ec2 describe-instances --instance-ids ${PROVIDER_ID##*/} --region $REGION | jq -r '.Reservations[].Instances[].ImageId')
echo "Nodes AMI ID: $AMI_ID"

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

check_path_cleanup

if [[ $TEST_FAILED == "true" ]]; then
    echo "Test run failed"
    exit 1
fi
