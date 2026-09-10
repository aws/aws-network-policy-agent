#!/usr/bin/env bash

set -euo pipefail

NPA_TEST_IMAGE="${NPA_TEST_IMAGE:-public.ecr.aws/docker/library/busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"

npa_require_environment() {
    : "${KUBECONFIG:?KUBECONFIG must identify the Hydra-created cluster}"
    command -v kubectl >/dev/null
}

npa_require_positive_integer() {
    local name=$1
    local value=$2

    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        echo "${name} must be a positive integer, got ${value}" >&2
        return 1
    fi
}

npa_require_test_namespace() {
    local namespace=$1
    local prefix=$2

    if ((${#namespace} > 63)) ||
        [[ "$namespace" != "$prefix" &&
        ! "$namespace" =~ ^${prefix}-[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
        echo "test namespace must be ${prefix} or start with ${prefix}-, got ${namespace}" >&2
        return 1
    fi
}

npa_kubectl() {
    kubectl --kubeconfig "$KUBECONFIG" "$@"
}

npa_create_namespace() {
    local namespace=$1
    npa_kubectl create namespace "$namespace" --dry-run=client -o yaml |
        npa_kubectl apply -f -
}

npa_collect_diagnostics() {
    local namespace=$1
    npa_kubectl get pods,deployments,services,networkpolicies \
        -n "$namespace" -o wide || true
    npa_kubectl get events -n "$namespace" --sort-by=.lastTimestamp || true
    npa_kubectl get pods -n kube-system -l k8s-app=aws-node -o wide || true
}

npa_cleanup_namespace() {
    local namespace=$1
    npa_kubectl delete "namespace/${namespace}" \
        --ignore-not-found=true \
        --wait=true \
        --timeout=10m
}

npa_finalize() {
    local namespace=$1
    local status=$2

    trap - EXIT
    if ((status != 0)); then
        npa_collect_diagnostics "$namespace"
    fi
    if ! npa_cleanup_namespace "$namespace"; then
        echo "failed to delete test namespace ${namespace}" >&2
        status=1
    fi
    exit "$status"
}

npa_create_probe_fixture() {
    local namespace=$1

    npa_kubectl apply -n "$namespace" -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: npa-probe-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: npa-probe-server
  template:
    metadata:
      labels:
        app: npa-probe-server
    spec:
      containers:
        - name: server
          image: ${NPA_TEST_IMAGE}
          command: ["/bin/sh", "-c", "mkdir -p /www && echo npa-ok >/www/index.html && httpd -f -p 8080 -h /www"]
---
apiVersion: v1
kind: Service
metadata:
  name: npa-probe-server
spec:
  selector:
    app: npa-probe-server
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: npa-probe-policy
spec:
  podSelector:
    matchLabels:
      app: npa-probe-server
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              npa-access: allowed
      ports:
        - protocol: TCP
          port: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: npa-allowed-client
  labels:
    npa-access: allowed
spec:
  containers:
    - name: client
      image: ${NPA_TEST_IMAGE}
      command: ["/bin/sh", "-c", "sleep 86400"]
---
apiVersion: v1
kind: Pod
metadata:
  name: npa-denied-client
  labels:
    npa-access: denied
spec:
  containers:
    - name: client
      image: ${NPA_TEST_IMAGE}
      command: ["/bin/sh", "-c", "sleep 86400"]
EOF

    npa_kubectl rollout status deployment/npa-probe-server \
        -n "$namespace" \
        --timeout=10m
    npa_kubectl wait pod/npa-allowed-client pod/npa-denied-client \
        -n "$namespace" \
        --for=condition=Ready \
        --timeout=10m
    npa_verify_enforcement "$namespace"
}

npa_verify_enforcement() {
    local namespace=$1
    local attempts=${NPA_PROBE_ATTEMPTS:-30}
    local attempt
    local denied_failure="denied network-policy probe did not prove enforcement"
    local probe_result

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if npa_kubectl exec -n "$namespace" npa-allowed-client -- \
            wget -qO- -T 3 http://npa-probe-server:8080/ |
            grep -q '^npa-ok$'; then
            break
        fi
        sleep 2
    done
    if ! npa_kubectl exec -n "$namespace" npa-allowed-client -- \
        wget -qO- -T 3 http://npa-probe-server:8080/ |
        grep -q '^npa-ok$'; then
        echo "allowed network-policy probe did not succeed" >&2
        return 1
    fi

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if ! probe_result=$(npa_kubectl exec -n "$namespace" npa-denied-client -- \
            /bin/sh -c '
                if wget -qO- -T 3 http://npa-probe-server:8080/ >/dev/null 2>&1; then
                    echo NPA_PROBE_ALLOWED
                else
                    echo NPA_PROBE_DENIED
                fi
            '); then
            denied_failure="denied network-policy probe command failed"
            sleep 2
            continue
        fi
        probe_result=${probe_result##*$'\n'}
        case "$probe_result" in
            NPA_PROBE_DENIED)
                return 0
                ;;
            NPA_PROBE_ALLOWED)
                denied_failure="denied network-policy probe unexpectedly succeeded"
                ;;
            *)
                denied_failure="denied network-policy probe returned an unexpected response"
                ;;
        esac
        if ((attempt < attempts)); then
            sleep 2
        fi
    done
    echo "$denied_failure" >&2
    return 1
}

npa_apply_churn_batch() {
    local namespace=$1
    local run_label=$2
    local start=$3
    local end=$4
    local identity

    for ((identity = start; identity <= end; identity++)); do
        local name="${run_label}-${identity}"
        npa_kubectl apply -n "$namespace" -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  labels:
    npa-test-run: ${run_label}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
        npa-test-run: ${run_label}
    spec:
      containers:
        - name: workload
          image: ${NPA_TEST_IMAGE}
          command: ["/bin/sh", "-c", "sleep 86400"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${name}
  labels:
    npa-test-run: ${run_label}
spec:
  podSelector:
    matchLabels:
      app: ${name}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
EOF
    done
}

npa_wait_for_churn() {
    local namespace=$1
    local run_label=$2

    npa_kubectl wait deployment \
        -n "$namespace" \
        -l "npa-test-run=${run_label}" \
        --for=condition=Available \
        --timeout=10m
}

npa_delete_churn() {
    local namespace=$1
    local run_label=$2

    npa_kubectl delete deployment,networkpolicy \
        -n "$namespace" \
        -l "npa-test-run=${run_label}" \
        --ignore-not-found=true \
        --wait=true \
        --timeout=10m
    npa_kubectl wait pod \
        -n "$namespace" \
        -l "npa-test-run=${run_label}" \
        --for=delete \
        --timeout=10m 2>/dev/null || true

    if npa_kubectl get pods -n "$namespace" -l "npa-test-run=${run_label}" \
        --no-headers 2>/dev/null | grep -q .; then
        echo "churn pods remain for ${run_label}" >&2
        return 1
    fi
}

npa_apply_churn() {
    local namespace=$1
    local run_label=$2
    local targets=$3
    local batch_size=$4

    local start=1
    while ((start <= targets)); do
        local end=$((start + batch_size - 1))
        end=$((end < targets ? end : targets))
        npa_apply_churn_batch "$namespace" "$run_label" "$start" "$end"
        npa_wait_for_churn "$namespace" "$run_label"
        npa_verify_enforcement "$namespace"
        start=$((end + 1))
    done
}
