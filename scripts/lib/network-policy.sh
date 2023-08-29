
function install_network_policy_mao(){

    local options=" --no-cli-pager"
    if [[ ! -z $ENDPOINT_URL ]]; then
        options+=" --endpoint-url $ENDPOINT_URL"
    fi

    if [[ ! -z $CNI_ADDON_CONFIGURATION ]]; then
        options+=" --configuration $CNI_ADDON_CONFIGURATION"
    fi

    aws eks create-addon \
        --addon-name vpc-cni \
        --addon-version $CNI_ADDON_VERSION \
        --resolve-conflicts overwrite \
        --cluster-name ${CLUSTER_NAME} $options

    local status=""
    local retries=30
    local try=0
    while [[ $status != "ACTIVE" && $try -lt $retries ]]
    do
        status=$(aws eks describe-addon \
            --addon-name vpc-cni \
            --cluster-name ${CLUSTER_NAME} $options | jq -r '.addon.status')
        echo "Addon status - $status" 
        try=$((try+1))
        sleep 10
    done

    if [[ $status != "ACTIVE" ]]; then
        local err_message=$(aws eks describe-addon \
            --addon-name vpc-cni \
            --cluster-name ${CLUSTER_NAME} $options | jq -r '.addon.health')
        echo $err_message
        exit 1
    fi

    echo "Addon installed Successfully"
}

function install_network_policy_helm(){

    echo "Installing Network Policy using VPC-CNI helm chart"
    helm repo add eks https://aws.github.io/eks-charts

    if [[ $IP_FAMILY == "IPv4" ]]; then
        ENABLE_IPv4=true
        ENABLE_IPv6=false
        ENABLE_PREFIX_DELEGATION=false
    else
        ENABLE_IPv4=false
        ENABLE_IPv6=true
        ENABLE_PREFIX_DELEGATION=true
    fi

    helm upgrade --install aws-vpc-cni eks/aws-vpc-cni --wait --timeout 300 \
        --namespace kube-system \
        --set enableNetworkPolicy=true \
        --set originalMatchLabels=true \
        --set init.env.ENABLE_IPv6=$ENABLE_IPv6 \
        --set image.env.ENABLE_IPv6=$ENABLE_IPv6 \
        --set nodeAgent.enableIpv6=$ENABLE_IPv6 \
        --set image.env.ENABLE_PREFIX_DELEGATION=$ENABLE_PREFIX_DELEGATION \
        --set image.env.ENABLE_IPv4=$ENABLE_IPv4

}
