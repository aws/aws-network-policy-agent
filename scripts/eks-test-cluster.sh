#!/usr/bin/env bash
set -euo pipefail

REGION="${REGION:-us-west-2}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
NODES_CAPACITY="${NODES_CAPACITY:-3}"

require() {
    local name
    for name in "$@"; do
        [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 1; }
    done
}

create_cluster() {
    require CLUSTER_NAME K8S_VERSION IP_FAMILY INSTANCE_TYPE
    local ami=""
    [[ -z "${AMI_ID:-}" ]] || ami="    ami: ${AMI_ID}"

    cat >/tmp/eks-test-cluster.yaml <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${REGION}
  version: "${K8S_VERSION}"
iam:
  withOIDC: true
kubernetesNetworkConfig:
  ipFamily: ${IP_FAMILY}
autoModeConfig:
  enabled: false
addons:
  - name: vpc-cni
  - name: coredns
  - name: kube-proxy
managedNodeGroups:
  - name: ${CLUSTER_NAME}-ng
    amiFamily: AmazonLinux2023
${ami}
    instanceType: ${INSTANCE_TYPE}
    desiredCapacity: ${NODES_CAPACITY}
    minSize: 1
    maxSize: ${NODES_CAPACITY}
EOF

    eksctl create cluster -f /tmp/eks-test-cluster.yaml
    mkdir -p "$(dirname "$KUBECONFIG")"
    aws eks update-kubeconfig \
        --name "$CLUSTER_NAME" --region "$REGION" --kubeconfig "$KUBECONFIG"
}

verify_nodes() {
    require AMI_ID KERNEL_VERSION
    local nodes amis bad
    local -a instances

    nodes=$(kubectl get nodes -o json)
    mapfile -t instances < <(jq -r '.items[].spec.providerID | split("/")[-1]' <<<"$nodes")
    [[ ${#instances[@]} -gt 0 ]] || { echo "no worker nodes found" >&2; exit 1; }

    amis=$(aws ec2 describe-instances --instance-ids "${instances[@]}" --region "$REGION" \
        | jq -c '[.Reservations[].Instances[].ImageId] | unique')
    [[ $(jq length <<<"$amis") -eq 1 && $(jq -r '.[0]' <<<"$amis") == "$AMI_ID" ]] || {
        echo "expected AMI $AMI_ID, found $amis" >&2; exit 1;
    }

    bad=$(jq -r --arg expected "$KERNEL_VERSION" '
        .items[] | .status.nodeInfo.kernelVersion as $actual
        | select(($actual | sub("\\.x86_64$"; "")) != $expected)
        | "\(.metadata.name)=\($actual)"' <<<"$nodes")
    [[ -z "$bad" ]] || { echo "unexpected node kernels: $bad" >&2; exit 1; }
}

install_agent() {
    require CLUSTER_NAME NODE_AGENT_IMAGE
    cat >/tmp/eks-test-addon.yaml <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata: {name: ${CLUSTER_NAME}, region: ${REGION}}
addons:
  - name: vpc-cni
    version: latest
    configurationValues: '{"enableNetworkPolicy":"true"}'
    resolveConflicts: overwrite
EOF
    eksctl update addon -f /tmp/eks-test-addon.yaml --force
    kubectl set image daemonset/aws-node -n kube-system aws-eks-nodeagent="$NODE_AGENT_IMAGE"
    kubectl rollout status daemonset/aws-node -n kube-system --timeout=300s
}

delete_cluster() {
    require CLUSTER_NAME
    local attempt out
    for attempt in 1 2 3; do
        if eksctl delete cluster --name "$CLUSTER_NAME" --region "$REGION" --disable-nodegroup-eviction; then
            return
        fi
        if ! out=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" 2>&1); then
            grep -q ResourceNotFoundException <<<"$out" && return
            echo "describe-cluster failed: $out" >&2
        fi
        [[ $attempt -eq 3 ]] || sleep 30
    done
    echo "failed to delete $CLUSTER_NAME" >&2
    exit 1
}

case "${1:-}" in
    create) create_cluster ;;
    verify) verify_nodes ;;
    install) install_agent ;;
    delete) delete_cluster ;;
    *) echo "usage: $0 {create|verify|install|delete}" >&2; exit 2 ;;
esac
