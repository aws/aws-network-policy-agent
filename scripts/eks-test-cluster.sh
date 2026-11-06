#!/usr/bin/env bash
set -euo pipefail

REGION="${REGION:-us-west-2}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
NODES_CAPACITY="${NODES_CAPACITY:-3}"
DELETE_ATTEMPTS="${DELETE_ATTEMPTS:-3}"
tmp_config=""
trap 'rm -f "$tmp_config"' EXIT

require() {
    local name
    for name in "$@"; do
        [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 1; }
    done
}

create_cluster() {
    require CLUSTER_NAME K8S_VERSION IP_FAMILY INSTANCE_TYPE
    local state stacks ami=""
    state=$(cluster_state) || exit 1
    if [[ "$state" != NONE ]]; then
        echo "cluster $CLUSTER_NAME already exists ($state); delete it first" >&2
        exit 1
    fi
    # Re-runs reuse the name; stacks left by an earlier cleanup would block eksctl.
    stacks=$(cluster_stacks) || exit 1
    if [[ -n "$stacks" ]]; then
        echo "removing leftover stacks for $CLUSTER_NAME"
        delete_cluster || exit 1
    fi
    [[ -z "${AMI_ID:-}" ]] || ami="    ami: ${AMI_ID}"

    tmp_config=$(mktemp)
    cat >"$tmp_config" <<EOF
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

    eksctl create cluster -f "$tmp_config"
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
    tmp_config=$(mktemp)
    cat >"$tmp_config" <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata: {name: ${CLUSTER_NAME}, region: ${REGION}}
addons:
  - name: vpc-cni
    version: latest
    configurationValues: '{"enableNetworkPolicy":"true"}'
    resolveConflicts: overwrite
EOF
    eksctl update addon -f "$tmp_config" --force
    kubectl set image daemonset/aws-node -n kube-system aws-eks-nodeagent="$NODE_AGENT_IMAGE"
    kubectl rollout status daemonset/aws-node -n kube-system --timeout=300s
}

# Prints the cluster status, or NONE. Other errors fail rather than read as gone.
cluster_state() {
    local out err rc=0
    err=$(mktemp)
    out=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" \
            --query cluster.status --output text 2>"$err") || rc=$?
    if (( rc == 0 )); then
        echo "$out"
    elif grep -q ResourceNotFoundException "$err"; then
        echo NONE
        rc=0
    else
        echo "describe-cluster $CLUSTER_NAME failed: $(cat "$err")" >&2
    fi
    rm -f "$err"
    return "$rc"
}

# shellcheck disable=SC2016 # $c is a jq variable.
OWNED_BY='any(.Tags[]?; .Key == "alpha.eksctl.io/cluster-name" and .Value == $c)'

cluster_stacks_json() {
    local all
    all=$(aws cloudformation describe-stacks --region "$REGION" --output json) || return 1
    jq --arg c "$CLUSTER_NAME" "{Stacks: [.Stacks[] | select($OWNED_BY)]}" <<<"$all"
}

cluster_stacks() {
    local json
    json=$(cluster_stacks_json) || return 1
    jq -r '.Stacks[].StackName' <<<"$json"
}

# ENIs that outlive their node pin the cluster security group and fail the VPC
# stack delete. CNI only tags them when CLUSTER_NAME is set, so also match its
# aws-K8S- description in the cluster's VPC.
delete_leaked_network_resources() {
    local vpc ids id out=""
    vpc=$(aws ec2 describe-vpcs --region "$REGION" --output text \
            --filters "Name=tag:alpha.eksctl.io/cluster-name,Values=${CLUSTER_NAME}" \
            --query 'Vpcs[].VpcId') || return 1
    ids=$(aws ec2 describe-network-interfaces --region "$REGION" --output text \
            --filters "Name=tag:cluster.k8s.amazonaws.com/name,Values=${CLUSTER_NAME}" Name=status,Values=available \
            --query 'NetworkInterfaces[].NetworkInterfaceId') || return 1
    if [[ -n "$vpc" ]]; then
        ids+=" $(aws ec2 describe-network-interfaces --region "$REGION" --output text \
                --filters "Name=vpc-id,Values=$(tr -s '[:space:]' ',' <<<"$vpc" | sed 's/,$//')" \
                Name=status,Values=available "Name=description,Values=aws-K8S-*" \
                --query 'NetworkInterfaces[].NetworkInterfaceId')" || return 1
    fi
    for id in $(tr -s '[:space:]' '\n' <<<"$ids" | sort -u); do
        echo "deleting leaked ENI $id"
        out=$(aws ec2 delete-network-interface --network-interface-id "$id" --region "$REGION" 2>&1) \
            || echo "could not delete ENI $id: $out" >&2
    done
    ids=$(aws ec2 describe-security-groups --region "$REGION" --output text \
            --filters "Name=tag:aws:eks:cluster-name,Values=${CLUSTER_NAME}" \
            --query 'SecurityGroups[].GroupId') || return 1
    for id in $ids; do
        echo "deleting leftover security group $id"
        # ENI deletes take a few seconds to release the group.
        for _ in 1 2 3 4 5 6; do
            out=$(aws ec2 delete-security-group --group-id "$id" --region "$REGION" 2>&1) && continue 2
            sleep 10
        done
        echo "could not delete security group $id: $out" >&2
    done
}

# eksctl creates this outside CloudFormation, so deleting the stacks directly leaves it.
delete_oidc_provider() {
    local arns arn owner
    arns=$(aws iam list-open-id-connect-providers --output text \
            --query 'OpenIDConnectProviderList[].Arn') || return 1
    for arn in $arns; do
        [[ "$arn" == *"/oidc.eks.${REGION}.amazonaws.com/"* ]] || continue
        if ! owner=$(aws iam list-open-id-connect-provider-tags --open-id-connect-provider-arn "$arn" --output text \
                --query "Tags[?Key=='alpha.eksctl.io/cluster-name'].Value | [0]" 2>&1); then
            # Another job may have just deleted its own provider.
            grep -q NoSuchEntity <<<"$owner" && continue
            echo "listing tags for $arn failed: $owner" >&2
            return 1
        fi
        [[ "$owner" == "$CLUSTER_NAME" ]] || continue
        echo "deleting OIDC provider $arn"
        aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$arn" || return 1
    done
}

# The CloudFormation waiter can fail at once on a stack that was already
# DELETE_FAILED, so poll until it's gone.
wait_stack_gone() {
    local i status seen=""
    for (( i = 0; i < 90; i++ )); do
        if ! status=$(aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" \
                --query 'Stacks[0].StackStatus' --output text 2>&1); then
            grep -q 'does not exist' <<<"$status" && return 0
            echo "describe-stacks $1 failed: $status" >&2
            return 1
        fi
        case "$status" in
            DELETE_COMPLETE) return 0 ;;
            DELETE_IN_PROGRESS) seen=1 ;;
            DELETE_FAILED) [[ -z "$seen" ]] && (( i < 6 )) || return 1 ;;
        esac
        sleep 10
    done
    return 1
}

delete_stacks() {
    local stack failed=0
    local -a started=()
    for stack; do
        echo "deleting stack $stack"
        if aws cloudformation delete-stack --stack-name "$stack" --region "$REGION"; then
            started+=("$stack")
        else
            failed=1
        fi
    done
    for stack in ${started[@]+"${started[@]}"}; do
        wait_stack_gone "$stack" || { echo "stack $stack did not delete" >&2; failed=1; }
    done
    return "$failed"
}

# Runs once the EKS cluster is gone; fails if any of its stacks remain.
delete_leftover_stacks() {
    local stacks stack vpc_stack="eksctl-${CLUSTER_NAME}-cluster"
    local -a others=()
    stacks=$(cluster_stacks) || return 1
    [[ -n "$stacks" ]] || return 0
    delete_oidc_provider || return 1
    for stack in $stacks; do
        [[ "$stack" == "$vpc_stack" ]] || others+=("$stack")
    done
    (( ${#others[@]} == 0 )) || delete_stacks "${others[@]}" || return 1
    # After the nodegroup is gone, so ENIs it was still detaching are available.
    delete_leaked_network_resources || return 1
    grep -qx -- "$vpc_stack" <<<"$stacks" || return 0
    delete_stacks "$vpc_stack" && return 0
    # The VPC stack's ingress rules can keep the EKS cluster security group in
    # use until that stack has tried to delete once.
    delete_leaked_network_resources || return 1
    delete_stacks "$vpc_stack"
}

# Waits up to 20 minutes while the cluster is in one of the given states, then prints its state.
wait_cluster_while() {
    local state
    for _ in $(seq 40); do
        state=$(cluster_state) || return 1
        [[ " $* " == *" $state "* ]] || break
        sleep 30
    done
    echo "$state"
}

delete_cluster_once() {
    local state
    # EKS rejects deletes while a create or update is in progress.
    state=$(wait_cluster_while CREATING UPDATING PENDING) || return 1
    if [[ "$state" != NONE ]]; then
        if [[ "$state" != DELETING ]]; then
            eksctl delete cluster --name "$CLUSTER_NAME" --region "$REGION" \
                --disable-nodegroup-eviction --wait \
                || echo "eksctl delete did not finish cleanly; checking for leftovers" >&2
        fi
        state=$(wait_cluster_while DELETING) || return 1
        [[ "$state" == NONE ]] || return 1
    fi
    delete_leftover_stacks
}

delete_cluster() {
    require CLUSTER_NAME
    local attempt
    for (( attempt = 1; attempt <= DELETE_ATTEMPTS; attempt++ )); do
        delete_cluster_once && return 0
        echo "cleanup of $CLUSTER_NAME incomplete (attempt $attempt/$DELETE_ATTEMPTS)" >&2
        (( attempt == DELETE_ATTEMPTS )) || sleep 60
    done
    echo "failed to delete $CLUSTER_NAME" >&2
    return 1
}

# Prints clusters (matching the prefix regex) whose stacks make them sweepable.
sweep_candidates() {
    jq -r --arg re "$2" --arg old "$3" --arg recent "$4" '
        .Stacks[]
        | (.Tags // [] | map(select(.Key == "alpha.eksctl.io/cluster-name")) | .[0].Value) as $c
        | select($c != null and ($c | test($re)))
        | select((.StackStatus == "DELETE_FAILED" and .StackName == "eksctl-\($c)-cluster"
                    and ((.DeletionTime // .LastUpdatedTime // .CreationTime)[0:19] < $recent))
                 or (.CreationTime[0:19] < $old))
        | $c' <<<"$1" | sort -u
}

# Deletes clusters from earlier CI runs whose stacks have been DELETE_FAILED for
# SWEEP_FAILED_MIN_AGE_HOURS (so a running cleanup isn't raced) or are older than
# SWEEP_MAX_AGE_HOURS. Random order and a per-run cap keep one stuck cluster from
# blocking the rest. Dry run unless DRY_RUN=false.
sweep() {
    local max_age="${SWEEP_MAX_AGE_HOURS:-24}" failed_age="${SWEEP_FAILED_MIN_AGE_HOURS:-3}"
    local max_clusters="${SWEEP_MAX_CLUSTERS:-3}" prefixes="${SWEEP_PREFIXES:-cyclonus-pr- npa-nightly-}"
    local stacks_json clusters current name count=0 failed=0 regex="" prefix old recent
    local -a prefix_list
    read -ra prefix_list <<<"$prefixes"
    for prefix in ${prefix_list[@]+"${prefix_list[@]}"}; do
        regex+="${regex:+|}$(sed 's/[][\\.*^$+?(){}|/]/\\&/g' <<<"$prefix")"
    done
    [[ -n "$regex" ]] || { echo "SWEEP_PREFIXES is empty" >&2; return 1; }
    regex="^(${regex})"
    stacks_json=$(aws cloudformation describe-stacks --region "$REGION" --output json) \
        || { echo "listing stacks failed" >&2; return 1; }
    old=$(date -u -d "-${max_age} hours" +%Y-%m-%dT%H:%M:%S)
    recent=$(date -u -d "-${failed_age} hours" +%Y-%m-%dT%H:%M:%S)
    clusters=$(sweep_candidates "$stacks_json" "$regex" "$old" "$recent" | shuf) \
        || { echo "parsing stacks failed" >&2; return 1; }
    for name in $clusters; do
        if [[ "${DRY_RUN:-true}" == "false" ]] && (( count >= max_clusters )); then
            echo "deferring $name to the next run (limit $max_clusters)"
            continue
        fi
        if [[ "${DRY_RUN:-true}" == "false" ]]; then
            # Re-check: earlier deletes in this run can take a while.
            if ! current=$(CLUSTER_NAME="$name" cluster_stacks_json) \
                    || ! current=$(sweep_candidates "$current" "$regex" "$old" "$recent"); then
                echo "re-checking $name failed" >&2
                failed=1
                continue
            fi
            if ! grep -qx -- "$name" <<<"$current"; then
                echo "skipping $name: no longer a sweep candidate"
                continue
            fi
            count=$((count + 1))
            echo "sweeping $name"
            (CLUSTER_NAME="$name" DELETE_ATTEMPTS=1 delete_cluster) || failed=1
        else
            count=$((count + 1))
            echo "would sweep $name: $(jq -r --arg c "$name" "[.Stacks[] | select($OWNED_BY)]"' | map("\(.StackName) (\(.StackStatus))") | join(" ")' <<<"$stacks_json")"
        fi
    done
    return "$failed"
}

case "${1:-}" in
    create) create_cluster ;;
    verify) verify_nodes ;;
    install) install_agent ;;
    delete) delete_cluster ;;
    sweep) sweep ;;
    *) echo "usage: $0 {create|verify|install|delete|sweep}" >&2; exit 2 ;;
esac
