function install_cloudwatch_agent(){

    local perf_cluster_name=""
    if [[ $IP_FAMILY == "IPv4" ]]; then
        perf_cluster_name="eks-network-policy-perf-v4"
    else
        perf_cluster_name="eks-network-policy-perf-v6"
    fi

    echo "Create IAM Service Account for CW agent"
    kubectl create ns $CW_NAMESPACE

    eksctl create iamserviceaccount \
        --cluster $CLUSTER_NAME \
        --name cloudwatch-agent \
        --namespace $CW_NAMESPACE \
        --attach-policy-arn $CW_POLICY_ARN \
        --approve

    echo "Install Cloudwatch Agent DS"
    kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cwagent/cwagent-serviceaccount.yaml

    echo '{ "logs": { "metrics_collected": { "kubernetes": { "metrics_collection_interval": 30, "cluster_name": "'${perf_cluster_name}'" }},"force_flush_interval": 5 }}' | jq > cwagentconfig.json
    kubectl create cm -n $CW_NAMESPACE cwagentconfig --from-file cwagentconfig.json
    kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cwagent/cwagent-daemonset.yaml

    # Allow CW agent to startup and push initial logs
    sleep 60
}

function uninstall_cloudwatch_agent(){

    eksctl delete iamserviceaccount \
        --cluster $CLUSTER_NAME \
        --name cloudwatch-agent \
        --namespace $CW_NAMESPACE || echo " IAM Service Account role not found"

    rm -rf cwagentconfig.json || echo "CW agent config not found"
    kubectl delete namespace $CW_NAMESPACE || echo "No namespace: $CW_NAMESPACE found"
}