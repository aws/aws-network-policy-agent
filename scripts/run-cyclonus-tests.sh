#!/bin/bash

# Enhanced Network Policy Test Script with Detailed Logging
# The script runs Network Policy Cyclonus tests on a existing cluster
# Parameters:
# CLUSTER_NAME: name of the cluster
# KUBECONFIG: Set the variable to the cluster kubeconfig file path
# REGION: defaults to us-west-2
# IP_FAMILY: defaults to IPv4
# ADDON_VERSION: Optional, defaults to the latest version
# ENDPOINT: Optional
# DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE: false
# NP_CONTROLLER_ENDPOINT_CHUNK_SIZE: Optional
# AWS_EKS_NODEAGENT: Optional
# AWS_CNI_IMAGE: Optional
# AWS_CNI_IMAGE_INIT: Optional

set -euoE pipefail

# Enhanced logging function
log_step() {
    local step_name="$1"
    local step_number="$2"
    echo "=========================================="
    echo "STEP $step_number: $step_name"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
}

log_success() {
    local step_name="$1"
    local step_number="$2"
    echo "✅ SUCCESS - STEP $step_number: $step_name completed successfully"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
}

log_error() {
    local step_name="$1"
    local step_number="$2"
    local exit_code="$3"
    echo "❌ FAILED - STEP $step_number: $step_name failed with exit code $exit_code"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
}

# Function to check if TEST_FAILED was set and exit immediately
check_test_failed() {
    local step_name="$1"
    local step_number="$2"
    if [[ $TEST_FAILED == "true" ]]; then
        log_error "$step_name" "$step_number" "1"
        echo "❌ Test run failed at $step_name"
        echo "Check the logs above to identify the specific failure"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        exit 1
    fi
}

# Trap function to catch errors and provide detailed information
error_handler() {
    local exit_code=$?
    local line_number=$1
    echo ""
    echo "🚨 CRITICAL ERROR DETECTED 🚨"
    echo "=========================================="
    echo "Script failed at line: $line_number"
    echo "Exit code: $exit_code"
    echo "Last command: $BASH_COMMAND"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Current working directory: $(pwd)"
    echo "=========================================="
    
    # Show environment variables for debugging
    echo "Key Environment Variables:"
    echo "CLUSTER_NAME: ${CLUSTER_NAME:-'NOT SET'}"
    echo "REGION: ${REGION:-'NOT SET'}"
    echo "KUBECONFIG: ${KUBECONFIG:-'NOT SET'}"
    echo "IP_FAMILY: ${IP_FAMILY:-'NOT SET'}"
    echo "TEST_FAILED: ${TEST_FAILED:-'NOT SET'}"
    echo "=========================================="
    
    exit $exit_code
}

trap 'error_handler $LINENO' ERR

DIR=$(cd "$(dirname "$0")"; pwd)
GINKGO_TEST_BUILD_DIR="$DIR/../test/build"

log_step "Script Initialization" "1"
echo "Script directory: $DIR"
echo "Ginkgo test build directory: $GINKGO_TEST_BUILD_DIR"

source ${DIR}/lib/cleanup.sh
log_success "Source cleanup.sh" "1a"

source ${DIR}/lib/network-policy.sh
log_success "Source network-policy.sh" "1b"

source ${DIR}/lib/tests.sh
log_success "Source tests.sh" "1c"

log_step "Environment Variable Setup" "2"

: "${ENDPOINT_FLAG:=""}"
: "${ENDPOINT:=""}"
: "${ADDON_VERSION:=""}"
: "${IP_FAMILY:="IPv4"}"
: "${REGION:="us-west-2"}"
: "${SKIP_ADDON_INSTALLATION:="false"}"
: "${SKIP_MAKE_TEST_BINARIES:="false"}"
: "${ENABLE_STRICT_MODE:="false"}"
: "${K8S_VERSION:=""}"
: "${TEST_IMAGE_REGISTRY:="registry.k8s.io"}"
: "${PROD_IMAGE_REGISTRY:=""}"
: "${DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE:="false"}"
: "${NP_CONTROLLER_ENDPOINT_CHUNK_SIZE=""}}"
: "${KUBE_CONFIG_PATH:=$KUBECONFIG}"

echo "Environment variables set:"
echo "ENDPOINT_FLAG: $ENDPOINT_FLAG"
echo "ENDPOINT: $ENDPOINT"
echo "ADDON_VERSION: $ADDON_VERSION"
echo "IP_FAMILY: $IP_FAMILY"
echo "REGION: $REGION"
echo "SKIP_ADDON_INSTALLATION: $SKIP_ADDON_INSTALLATION"
echo "SKIP_MAKE_TEST_BINARIES: $SKIP_MAKE_TEST_BINARIES"
echo "ENABLE_STRICT_MODE: $ENABLE_STRICT_MODE"
echo "K8S_VERSION: $K8S_VERSION"
echo "TEST_IMAGE_REGISTRY: $TEST_IMAGE_REGISTRY"
echo "PROD_IMAGE_REGISTRY: $PROD_IMAGE_REGISTRY"
echo "DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE: $DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE"
echo "NP_CONTROLLER_ENDPOINT_CHUNK_SIZE: $NP_CONTROLLER_ENDPOINT_CHUNK_SIZE"
echo "KUBE_CONFIG_PATH: $KUBE_CONFIG_PATH"

TEST_FAILED="false"

log_step "Endpoint Configuration" "3"
if [[ ! -z $ENDPOINT ]]; then
    ENDPOINT_FLAG="--endpoint-url $ENDPOINT"
    echo "Endpoint flag set to: $ENDPOINT_FLAG"
else
    echo "No custom endpoint specified"
fi
log_success "Endpoint Configuration" "3"

log_step "Kubernetes Version Detection" "4"
if [[ -z $K8S_VERSION ]]; then
    echo "Detecting Kubernetes version from cluster..."
    K8S_VERSION=$(aws eks describe-cluster $ENDPOINT_FLAG --name $CLUSTER_NAME --region $REGION | jq -r '.cluster.version')
    if [[ $? -ne 0 ]]; then
        log_error "Kubernetes Version Detection" "4" "$?"
        exit 1
    fi
    echo "Detected K8S version: $K8S_VERSION"
else
    echo "Using provided K8S version: $K8S_VERSION"
fi
log_success "Kubernetes Version Detection" "4"

log_step "Test Configuration Summary" "5"
echo "Running Cyclonus e2e tests with the following variables
CLUSTER_NAME: $CLUSTER_NAME
REGION: $REGION
IP_FAMILY: $IP_FAMILY

Optional args
ENDPOINT: $ENDPOINT
ADDON_VERSION: $ADDON_VERSION
K8S_VERSION: $K8S_VERSION
"
log_success "Test Configuration Summary" "5"

log_step "Node Information Gathering" "6"
echo "Nodes AMI version for cluster: $CLUSTER_NAME"
if ! kubectl get nodes -owide; then
    log_error "Node Information Gathering - kubectl get nodes" "6" "$?"
    exit 1
fi

echo "Getting provider ID from first node..."
PROVIDER_ID=$(kubectl get nodes -ojson | jq -r '.items[0].spec.providerID')
if [[ $? -ne 0 ]] || [[ -z "$PROVIDER_ID" ]] || [[ "$PROVIDER_ID" == "null" ]]; then
    log_error "Node Information Gathering - provider ID extraction" "6" "$?"
    exit 1
fi
echo "Provider ID: $PROVIDER_ID"

echo "Getting AMI ID from EC2..."
AMI_ID=$(aws ec2 describe-instances --instance-ids ${PROVIDER_ID##*/} --region $REGION | jq -r '.Reservations[].Instances[].ImageId')
if [[ $? -ne 0 ]] || [[ -z "$AMI_ID" ]] || [[ "$AMI_ID" == "null" ]]; then
    log_error "Node Information Gathering - AMI ID extraction" "6" "$?"
    exit 1
fi
echo "Nodes AMI ID: $AMI_ID"
log_success "Node Information Gathering" "6"

log_step "Addon Installation" "7"
if [[ $SKIP_ADDON_INSTALLATION == "false" ]]; then
    echo "Loading addon details..."
    if ! load_addon_details; then
        log_error "Addon Installation - load_addon_details" "7" "$?"
        exit 1
    fi
    log_success "Load addon details" "7a"

    if [[ ! -z $ADDON_VERSION ]]; then
        echo "Installing specified addon version: $ADDON_VERSION"
        if ! install_network_policy_mao $ADDON_VERSION; then
            log_error "Addon Installation - install_network_policy_mao with version $ADDON_VERSION" "7" "$?"
            exit 1
        fi
        log_success "Install network policy MAO with specified version" "7b"
    elif [[ ! -z $LATEST_ADDON_VERSION ]]; then
        echo "Installing latest addon version: $LATEST_ADDON_VERSION"
        if ! install_network_policy_mao $LATEST_ADDON_VERSION; then
            log_error "Addon Installation - install_network_policy_mao with latest version $LATEST_ADDON_VERSION" "7" "$?"
            exit 1
        fi
        log_success "Install network policy MAO with latest version" "7c"
    else
        echo "Installing network policy using helm..."
        if ! install_network_policy_helm; then
            log_error "Addon Installation - install_network_policy_helm" "7" "$?"
            exit 1
        fi
        log_success "Install network policy helm" "7d"
    fi
else
    echo "Skipping addons installation. Make sure you have enabled network policy support in your cluster before executing the test"
fi
log_success "Addon Installation" "7"

log_step "Network Policy Controller Deployment" "8"
if [[ $DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE == "true" ]]; then
    echo "Deploying network policy controller on dataplane..."
    if ! make deploy-network-policy-controller-on-dataplane NP_CONTROLLER_IMAGE=$PROD_IMAGE_REGISTRY NP_CONTROLLER_ENDPOINT_CHUNK_SIZE=$NP_CONTROLLER_ENDPOINT_CHUNK_SIZE; then
        log_error "Network Policy Controller Deployment" "8" "$?"
        exit 1
    fi
    log_success "Deploy network policy controller on dataplane" "8"
else
    echo "Skipping network policy controller deployment on dataplane"
    log_success "Network Policy Controller Deployment (skipped)" "8"
fi

log_step "Cyclonus Tests" "9"
echo "Running cyclonus tests..."
run_cyclonus_tests
check_test_failed "Cyclonus Tests" "9"
log_success "Cyclonus Tests" "9"

log_step "Path Cleanup Check" "10"
echo "Checking path cleanup..."
check_path_cleanup
check_test_failed "Path Cleanup Check" "10"
log_success "Path Cleanup Check" "10"

log_step "Test Binaries Build" "11"
if [[ $SKIP_MAKE_TEST_BINARIES == "false" ]]; then
    echo "Making ginkgo test binaries"
    if ! (cd $DIR/../ && make build-test-binaries); then
        log_error "Test Binaries Build" "11" "$?"
        exit 1
    fi
    log_success "Make ginkgo test binaries" "11"
else
    echo "Skipping making ginkgo test binaries"
    log_success "Test Binaries Build (skipped)" "11"
fi

log_step "Ginkgo Policy Tests" "12"
echo "Running ginkgo policy tests..."
echo "Command: CGO_ENABLED=0 ginkgo -v -timeout 15m $GINKGO_TEST_BUILD_DIR/policy.test --no-color --fail-on-pending -- --cluster-kubeconfig=$KUBE_CONFIG_PATH --cluster-name=$CLUSTER_NAME --test-image-registry=$TEST_IMAGE_REGISTRY --ip-family=$IP_FAMILY"

if ! CGO_ENABLED=0 ginkgo -v -timeout 15m $GINKGO_TEST_BUILD_DIR/policy.test --no-color --fail-on-pending -- --cluster-kubeconfig=$KUBE_CONFIG_PATH --cluster-name=$CLUSTER_NAME --test-image-registry=$TEST_IMAGE_REGISTRY --ip-family=$IP_FAMILY; then
    TEST_FAILED="true"
    check_test_failed "Ginkgo Policy Tests" "12"
fi
log_success "Ginkgo Policy Tests" "12"

log_step "Strict Mode Tests" "13"
if [[ $ENABLE_STRICT_MODE == "true" ]]; then
    echo "Enable network policy strict mode"
    if ! kubectl set env daemonset aws-node -n kube-system -c aws-node NETWORK_POLICY_ENFORCING_MODE=strict; then
        log_error "Strict Mode Tests - enable strict mode" "13" "$?"
        exit 1
    fi
    log_success "Enable strict mode" "13a"
    
    echo "Check aws-node daemonset status"
    if ! kubectl rollout status ds/aws-node -n kube-system --timeout=300s; then
        log_error "Strict Mode Tests - rollout status check" "13" "$?"
        exit 1
    fi
    log_success "AWS node daemonset rollout" "13b"
    
    echo "Running strict mode tests..."
    echo "Command: CGO_ENABLED=0 ginkgo -v -timeout 15m --no-color --fail-on-pending $GINKGO_TEST_BUILD_DIR/strict.test -- --cluster-kubeconfig=$KUBE_CONFIG_PATH --cluster-name=$CLUSTER_NAME --test-image-registry=$TEST_IMAGE_REGISTRY --ip-family=$IP_FAMILY"
    
    if ! CGO_ENABLED=0 ginkgo -v -timeout 15m --no-color --fail-on-pending $GINKGO_TEST_BUILD_DIR/strict.test -- --cluster-kubeconfig=$KUBE_CONFIG_PATH --cluster-name=$CLUSTER_NAME --test-image-registry=$TEST_IMAGE_REGISTRY --ip-family=$IP_FAMILY; then
        TEST_FAILED="true"
        check_test_failed "Strict Mode Tests - ginkgo strict tests" "13"
    fi
    log_success "Ginkgo strict tests" "13c"
else
    echo "Strict mode disabled, skipping strict mode tests"
    log_success "Strict Mode Tests (skipped)" "13"
fi

log_step "Final Results" "14"
if [[ $TEST_FAILED == "true" ]]; then
    echo "❌ Test run failed"
    echo "Check the logs above to identify which specific step failed"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    exit 1
else
    echo "✅ All tests completed successfully!"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
fi
log_success "Final Results" "14"
