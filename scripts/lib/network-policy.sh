
function load_addon_details() {

  ADDON_NAME="vpc-cni"
  echo "loading $ADDON_NAME addon details"
  LATEST_ADDON_VERSION=$(aws eks describe-addon-versions $ENDPOINT_FLAG --addon-name $ADDON_NAME --kubernetes-version $K8S_VERSION | jq '.addons[0].addonVersions[0].addonVersion' -r)
  EXISTING_SERVICE_ACCOUNT_ROLE_ARN=$(kubectl get serviceaccount -n kube-system aws-node -o json | jq '.metadata.annotations."eks.amazonaws.com/role-arn"' -r)
}

function wait_for_addon_status() {
  local expected_status=$1
  local retry_attempt=0
  if [ "$expected_status" = "DELETED" ]; then
    while $(aws eks describe-addon $ENDPOINT_FLAG --cluster-name $CLUSTER_NAME --addon-name $ADDON_NAME --region $REGION >> /dev/null); do
      if [ $retry_attempt -ge 30 ]; then
        echo "failed to delete addon, qutting after too many attempts"
        exit 1
      fi
      echo "addon is still not deleted"
      sleep 5
      ((retry_attempt=retry_attempt+1))
    done
    echo "addon deleted"

    sleep 10
    return
  fi

  retry_attempt=0
  while true
  do
    STATUS=$(aws eks describe-addon $ENDPOINT_FLAG --cluster-name "$CLUSTER_NAME" --addon-name $ADDON_NAME --region "$REGION" | jq -r '.addon.status')
    if [ "$STATUS" = "$expected_status" ]; then
      echo "addon status matches expected status"
      return
    fi

    if [ $retry_attempt -ge 30 ]; then
      echo "failed to get desired add-on status: $STATUS, qutting after too many attempts"
      exit 1
    fi
    echo "addon status is not equal to $expected_status"
    sleep 10
    ((retry_attempt=retry_attempt+1))
  done
}

function install_network_policy_mao() {

  local addon_version=$1
  if DESCRIBE_ADDON=$(aws eks describe-addon $ENDPOINT_FLAG --cluster-name $CLUSTER_NAME --addon-name $ADDON_NAME --region $REGION); then
    local current_addon_version=$(echo "$DESCRIBE_ADDON" | jq '.addon.addonVersion' -r)
    echo "deleting the $current_addon_version"
    aws eks delete-addon $ENDPOINT_FLAG --cluster-name $CLUSTER_NAME --addon-name $ADDON_NAME --region $REGION
    wait_for_addon_status "DELETED"
  fi

  echo "Installing addon $addon_version with network policy enabled"
  
  SA_ROLE_ARN_ARG=""
  if [ "$EXISTING_SERVICE_ACCOUNT_ROLE_ARN" != "null" ]; then
     SA_ROLE_ARN_ARG="--service-account-role-arn $EXISTING_SERVICE_ACCOUNT_ROLE_ARN"
  fi

  aws eks create-addon \
    --cluster-name $CLUSTER_NAME \
    --addon-name $ADDON_NAME \
    --configuration-value '{"enableNetworkPolicy": "true"}' \
    --resolve-conflicts OVERWRITE \
    --addon-version $addon_version \
    --region $REGION $ENDPOINT_FLAG $SA_ROLE_ARN_ARG

  wait_for_addon_status "ACTIVE"
}

function install_network_policy_helm(){

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

    echo "Updating annotations and labels on existing resources"
    for kind in daemonSet clusterRole clusterRoleBinding serviceAccount; do
      echo "setting annotations and labels on $kind/aws-node"
      kubectl -n kube-system annotate --overwrite $kind aws-node meta.helm.sh/release-name=aws-vpc-cni || echo "Unable to annotate $kind/aws-node"
      kubectl -n kube-system annotate --overwrite $kind aws-node meta.helm.sh/release-namespace=kube-system || echo "Unable to annotate $kind/aws-node"
      kubectl -n kube-system label --overwrite $kind aws-node app.kubernetes.io/managed-by=Helm || echo "Unable to label $kind/aws-node"
    done

    echo "Installing/Updating the aws-vpc-cni helm chart with `enableNetworkPolicy=true`"
    helm upgrade --install aws-vpc-cni eks/aws-vpc-cni --wait --timeout 300s \
        --namespace kube-system \
        --set enableNetworkPolicy=true \
        --set originalMatchLabels=true \
        --set init.env.ENABLE_IPv6=$ENABLE_IPv6 \
        --set image.env.ENABLE_IPv6=$ENABLE_IPv6 \
        --set nodeAgent.enableIpv6=$ENABLE_IPv6 \
        --set image.env.ENABLE_PREFIX_DELEGATION=$ENABLE_PREFIX_DELEGATION \
        --set image.env.ENABLE_IPv4=$ENABLE_IPv4 $HELM_EXTRA_ARGS

}
