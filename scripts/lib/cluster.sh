

function load_default_values(){

    CLUSTER_NAME=network-policy-${RANDOM}
    REGION="${REGION:=us-west-2}"
    AMI_FAMILY="${AMI_FAMILY:=AmazonLinux2023}"
    NODEGROUP_TYPE="${NODEGROUP_TYPE:=linux}"
    NODES_CAPACITY="${NODES_CAPACITY:=3}"
    INSTANCE_TYPE="${INSTANCE_TYPE:=t3.large}"
    K8S_VERSION="${K8S_VERSION:=""}"
    IP_FAMILY="${IP_FAMILY:=IPv4}"
    CW_NAMESPACE="${CW_NAMESPACE:=amazon-cloudwatch}"
    CW_POLICY_ARN="${CW_POLICY_ARN:=arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy}"
    ENDPOINT_FLAG="${ENDPOINT_FLAG:=""}"
    HELM_EXTRA_ARGS="${HELM_EXTRA_ARGS:=""}"

    # If Kubernetes version is not passed then use the latest available version
    if [[ -z $K8S_VERSION ]]; then
        K8S_VERSION=$(eksctl utils describe-cluster-versions --region $REGION | jq -r '.clusterVersions[0].ClusterVersion')
    fi

}

function create_cluster(){

    cat <<EOF > eks-cluster.yaml
    apiVersion: eksctl.io/v1alpha5
    iam:
        withOIDC: true
    addons:
      - name: vpc-cni
      - name: coredns
      - name: kube-proxy
    kind: ClusterConfig
    kubernetesNetworkConfig:
        ipFamily: ${IP_FAMILY}
    managedNodeGroups:
      - amiFamily: ${AMI_FAMILY}
        desiredCapacity: ${NODES_CAPACITY}
        instanceType: ${INSTANCE_TYPE}
        labels:
            alpha.eksctl.io/cluster-name: ${CLUSTER_NAME}
            alpha.eksctl.io/nodegroup-name: ${CLUSTER_NAME}-${NODEGROUP_TYPE}-nodes
        maxSize: ${NODES_CAPACITY}
        minSize: 1
        name: ${CLUSTER_NAME}-${NODEGROUP_TYPE}
        tags:
            alpha.eksctl.io/nodegroup-name: ${CLUSTER_NAME}-${NODEGROUP_TYPE}-nodes
            alpha.eksctl.io/nodegroup-type: managed
    metadata:
        name: ${CLUSTER_NAME}
        region: ${REGION}
        version: "${K8S_VERSION}"
EOF

    eksctl create cluster -f ./eks-cluster.yaml

    echo "Nodes AMI version for cluster: $CLUSTER_NAME"
    kubectl get nodes -owide

    local providerID=$(kubectl get nodes -ojson | jq -r '.items[0].spec.providerID')
    local amiID=$(aws ec2 describe-instances --instance-ids ${providerID##*/} --region $REGION | jq -r '.Reservations[].Instances[].ImageId')
    echo "Nodes AMI ID: $amiID"
}

function delete_cluster(){

    eksctl delete cluster -f ./eks-cluster.yaml --disable-nodegroup-eviction || echo "Cluster Delete failed"
    rm -rf ./eks-cluster.yaml || echo "Cluster config file not found"
}