#!/bin/bash
# Use this script to set the aws-eks-nodeagent image on aws-node daemonset using the latest helm chart

# Parameters:
# KUBECONFIG: path to the kubeconfig file, default ~/.kube/config
# IP_FAMILY: defaults to IPv4
# AWS_EKS_NODEAGENT: node agent image

set -e
DIR=$(cd "$(dirname "$0")"; pwd)

: "${IP_FAMILY:="IPv4"}"
HELM_EXTRA_ARGS=""

source ${DIR}/lib/network-policy.sh

if [[ ! -z $AWS_EKS_NODEAGENT ]]; then
    echo "Replacing Node Agent Image in aws-vpc-cni helm chart with $AWS_EKS_NODEAGENT"
    HELM_EXTRA_ARGS+=" --set nodeAgent.image.override=$AWS_EKS_NODEAGENT"
else
    echo "Installing the latest aws-vpc-cni helm chart with default values"
fi

install_network_policy_helm

echo "Check aws-node daemonset status"
kubectl rollout status ds/aws-node -n kube-system --timeout=300s
