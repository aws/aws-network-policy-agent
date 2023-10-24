

function load_default_values(){

    CLUSTER_NAME=network-policy-${RANDOM}
    REGION="${REGION:=us-west-2}"
    AMI_FAMILY="${AMI_FAMILY:=AmazonLinux2}"
    NODEGROUP_TYPE="${NODEGROUP_TYPE:=linux}"
    NODES_CAPACITY="${NODES_CAPACITY:=3}"
    INSTANCE_TYPE="${INSTANCE_TYPE:=t3.large}"
    K8S_VERSION="${K8S_VERSION:=1.27}"
    IP_FAMILY="${IP_FAMILY:=IPv4}"
    CW_NAMESPACE="${CW_NAMESPACE:=amazon-cloudwatch}"
    CW_POLICY_ARN="${CW_POLICY_ARN:=arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy}"
    ENDPOINT_FLAG="${ENDPOINT_FLAG:=""}"
    HELM_EXTRA_ARGS="${HELM_EXTRA_ARGS:=""}"
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

}

function delete_cluster(){

    eksctl delete cluster -f ./eks-cluster.yaml || echo "Cluster Delete failed"
    rm -rf ./eks-cluster.yaml || echo "Cluster config file not found"
}