#!/usr/bin/env bash

set -euo pipefail

NPA_TEST_IMAGE="${NPA_TEST_IMAGE:-public.ecr.aws/docker/library/busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
NPA_POLICY_MODE=${NPA_POLICY_MODE:-standard}

npa_require_environment() {
    : "${KUBECONFIG:?KUBECONFIG must identify the Hydra-created cluster}"
    command -v kubectl >/dev/null
    if [[ "$NPA_POLICY_MODE" != standard && "$NPA_POLICY_MODE" != strict ]]; then
        echo "NPA_POLICY_MODE must be standard or strict, got ${NPA_POLICY_MODE}" >&2
        return 1
    fi
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

npa_state_file() {
    local state_dir=${SCENARIO_STATE_DIR:-$(dirname -- "${WORKLOAD_REPORT_PATH:-log/npa-workload-report.json}")}
    printf '%s/npa-workload.state' "$state_dir"
}

npa_persist_state() {
    local state_file
    state_file=$(npa_state_file)
    mkdir -p "$(dirname -- "$state_file")"
    local temporary="${state_file}.tmp.$$"
    {
        printf 'NPA_TEST_NAMESPACE=%q\n' "${NPA_TEST_NAMESPACE:-}"
        printf 'NPA_POLICY_MODE=%q\n' "$NPA_POLICY_MODE"
        printf 'WORKLOAD_PROFILE_ID=%q\n' "${WORKLOAD_PROFILE_ID:-}"
        printf 'TEST_SCENARIO_ID=%q\n' "${TEST_SCENARIO_ID:-}"
        printf 'WORKLOAD_REPORT_PATH=%q\n' "${WORKLOAD_REPORT_PATH:-}"
        printf 'WORKLOAD_STARTED_AT=%q\n' "${WORKLOAD_STARTED_AT:-}"
        printf 'WORKLOAD_STABLE_PODS=%q\n' "${WORKLOAD_STABLE_PODS:-0}"
        printf 'WORKLOAD_CHURN_PODS=%q\n' "${WORKLOAD_CHURN_PODS:-0}"
        printf 'WORKLOAD_CHURN_PODS_PER_JOB=%q\n' "${WORKLOAD_CHURN_PODS_PER_JOB:-0}"
        printf 'WORKLOAD_BATCH_SIZE=%q\n' "${WORKLOAD_BATCH_SIZE:-0}"
        printf 'WORKLOAD_CYCLE_INTERVAL_SECONDS=%q\n' "${WORKLOAD_CYCLE_INTERVAL_SECONDS:-0}"
        printf 'WORKLOAD_POLICY_SETTLE_SECONDS=%q\n' "${WORKLOAD_POLICY_SETTLE_SECONDS:-0}"
        printf 'WORKLOAD_POLICY_ROUNDS_REQUESTED=%q\n' "${WORKLOAD_POLICY_ROUNDS_REQUESTED:-0}"
        printf 'WORKLOAD_POLICY_ROUNDS_COMPLETED=%q\n' "${WORKLOAD_POLICY_ROUNDS_COMPLETED:-0}"
        printf 'WORKLOAD_SHORT_LIVED_PODS=%q\n' "${WORKLOAD_SHORT_LIVED_PODS:-0}"
        printf 'WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS=%q\n' "${WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS:-0}"
        printf 'WORKLOAD_SHORT_LIVED_PODS_PER_ROUND=%q\n' "${WORKLOAD_SHORT_LIVED_PODS_PER_ROUND:-0}"
        printf 'WORKLOAD_SHORT_LIVED_INTERVAL_SECONDS=%q\n' "${WORKLOAD_SHORT_LIVED_INTERVAL_SECONDS:-0}"
        printf 'WORKLOAD_SHORT_LIVED_LIFETIME_SECONDS=%q\n' "${WORKLOAD_SHORT_LIVED_LIFETIME_SECONDS:-0}"
        printf 'WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS=%q\n' "${WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS:-0}"
        printf 'WORKLOAD_SHORT_LIVED_ROUNDS_REQUESTED=%q\n' "${WORKLOAD_SHORT_LIVED_ROUNDS_REQUESTED:-0}"
        printf 'WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED=%q\n' "${WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED:-0}"
        printf 'WORKLOAD_DURATION_SECONDS=%q\n' "${WORKLOAD_DURATION_SECONDS:-0}"
        printf 'WORKLOAD_ROUNDS_REQUESTED=%q\n' "${WORKLOAD_ROUNDS_REQUESTED:-0}"
        printf 'WORKLOAD_ROUNDS_COMPLETED=%q\n' "${WORKLOAD_ROUNDS_COMPLETED:-0}"
        printf 'WORKLOAD_ALLOW_PROBES=%q\n' "${WORKLOAD_ALLOW_PROBES:-0}"
        printf 'WORKLOAD_DENY_PROBES=%q\n' "${WORKLOAD_DENY_PROBES:-0}"
        printf 'WORKLOAD_MODE_PROBES=%q\n' "${WORKLOAD_MODE_PROBES:-0}"
        printf 'WORKLOAD_POLICY_REMOVAL_PROBES=%q\n' "${WORKLOAD_POLICY_REMOVAL_PROBES:-0}"
        printf 'WORKLOAD_POLICY_REMOVAL_STATUS=%q\n' "${WORKLOAD_POLICY_REMOVAL_STATUS:-unknown}"
        printf 'WORKLOAD_STATUS=%q\n' "${WORKLOAD_STATUS:-unknown}"
        printf 'WORKLOAD_CLEANUP_STATUS=%q\n' "${WORKLOAD_CLEANUP_STATUS:-unknown}"
    } >"$temporary"
    mv -f -- "$temporary" "$state_file"
}

npa_probe_policy_removal() {
    local namespace=$1
    local attempts=${NPA_PROBE_ATTEMPTS:-30}
    local attempt
    local succeeded=false

    npa_kubectl delete networkpolicy/npa-probe-policy \
        -n "$namespace" \
        --ignore-not-found=true \
        --wait=true \
        --timeout=10m

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        succeeded=false
        if npa_kubectl exec -n "$namespace" npa-denied-client -- \
            wget -qO- -T 3 http://npa-probe-server:8080/ |
            grep -q '^npa-ok$'; then
            succeeded=true
        fi
        WORKLOAD_POLICY_REMOVAL_PROBES=$((${WORKLOAD_POLICY_REMOVAL_PROBES:-0} + 1))

        if [[ "$NPA_POLICY_MODE" == standard && "$succeeded" == true ]]; then
            WORKLOAD_POLICY_REMOVAL_STATUS=pass
            return
        fi
        if [[ "$NPA_POLICY_MODE" == strict && "$succeeded" == false ]]; then
            break
        fi
        if ((attempt < attempts)); then
            sleep 2
        fi
    done

    if [[ "$NPA_POLICY_MODE" == strict && "$succeeded" == false ]]; then
        npa_kubectl apply -n "$namespace" -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: npa-cleanup-allow-server
spec:
  podSelector:
    matchLabels:
      app: npa-probe-server
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              npa-access: denied
      ports:
        - protocol: TCP
          port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: npa-cleanup-allow-client
spec:
  podSelector:
    matchLabels:
      npa-access: denied
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: npa-probe-server
      ports:
        - protocol: TCP
          port: 8080
EOF
        for ((attempt = 1; attempt <= attempts; attempt++)); do
            if npa_kubectl exec -n "$namespace" npa-denied-client -- \
                wget -qO- -T 3 http://npa-probe-server:8080/ |
                grep -q '^npa-ok$'; then
                WORKLOAD_POLICY_REMOVAL_PROBES=$((${WORKLOAD_POLICY_REMOVAL_PROBES:-0} + 1))
                WORKLOAD_POLICY_REMOVAL_STATUS=pass
                return
            fi
            WORKLOAD_POLICY_REMOVAL_PROBES=$((${WORKLOAD_POLICY_REMOVAL_PROBES:-0} + 1))
            if ((attempt < attempts)); then
                sleep 2
            fi
        done
    fi

    echo "post-policy-removal connectivity did not match ${NPA_POLICY_MODE} mode" >&2
    WORKLOAD_POLICY_REMOVAL_STATUS=failed
    return 1
}

npa_complete_cleanup() {
    local namespace=$1
    local status=$2

    if ((status == 0)) && ! npa_probe_policy_removal "$namespace"; then
        status=1
    fi
    if ! npa_cleanup_namespace "$namespace"; then
        echo "failed to delete test namespace ${namespace}" >&2
        status=1
        WORKLOAD_CLEANUP_STATUS=failed
    else
        WORKLOAD_CLEANUP_STATUS=pass
    fi
    WORKLOAD_COMPLETED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    npa_persist_state
    if [[ -n ${WORKLOAD_REPORT_PATH:-} ]] && ! npa_write_workload_report; then
        echo "failed to write NPA workload report" >&2
        status=1
    fi
    return "$status"
}

npa_finalize() {
    local namespace=$1
    local status=$2

    trap - EXIT
    if ((status != 0)); then
        WORKLOAD_STATUS=failed
        npa_collect_diagnostics "$namespace"
    else
        WORKLOAD_STATUS=pass
    fi
    npa_persist_state
    if [[ ${NPA_DEFER_CLEANUP:-false} == true ]]; then
        exit "$status"
    fi
    if npa_complete_cleanup "$namespace" "$status"; then
        :
    else
        status=$?
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
          command:
            - /bin/sh
            - -c
            - |
              mkdir -p /www-denied /www-control
              echo npa-ok >/www-denied/index.html
              echo npa-control >/www-control/index.html
              httpd -p 8080 -h /www-denied
              exec httpd -f -p 8081 -h /www-control
---
apiVersion: v1
kind: Service
metadata:
  name: npa-probe-server
spec:
  selector:
    app: npa-probe-server
  ports:
    - name: denied
      port: 8080
      targetPort: 8080
    - name: control
      port: 8081
      targetPort: 8081
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
        - podSelector:
            matchLabels:
              npa-test-phase: short-lived
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 8081
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
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: npa-unselected-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: npa-unselected-server
  template:
    metadata:
      labels:
        app: npa-unselected-server
    spec:
      containers:
        - name: server
          image: ${NPA_TEST_IMAGE}
          command: ["/bin/sh", "-c", "mkdir -p /www && echo unselected-ok >/www/index.html && httpd -f -p 8080 -h /www"]
---
apiVersion: v1
kind: Service
metadata:
  name: npa-unselected-server
spec:
  selector:
    app: npa-unselected-server
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: npa-unselected-client
spec:
  containers:
    - name: client
      image: ${NPA_TEST_IMAGE}
      command: ["/bin/sh", "-c", "sleep 86400"]
EOF

    npa_kubectl rollout status deployment/npa-probe-server \
        -n "$namespace" \
        --timeout=10m
    npa_kubectl rollout status deployment/npa-unselected-server \
        -n "$namespace" \
        --timeout=10m
    npa_kubectl wait pod/npa-allowed-client pod/npa-denied-client pod/npa-unselected-client \
        -n "$namespace" \
        --for=condition=Ready \
        --timeout=10m
    npa_verify_enforcement "$namespace"
}

npa_verify_mode() {
    local namespace=$1
    local succeeded=false
    if npa_kubectl exec -n "$namespace" npa-unselected-client -- \
        wget -qO- -T 3 http://npa-unselected-server:8080/ |
        grep -q '^unselected-ok$'; then
        succeeded=true
    fi

    if [[ "$NPA_POLICY_MODE" == standard && "$succeeded" != true ]]; then
        echo "standard mode blocked traffic between pods without policy" >&2
        return 1
    fi
    if [[ "$NPA_POLICY_MODE" == strict && "$succeeded" == true ]]; then
        echo "strict mode allowed traffic between pods without policy" >&2
        return 1
    fi
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
    WORKLOAD_ALLOW_PROBES=$((${WORKLOAD_ALLOW_PROBES:-0} + 1))

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
                WORKLOAD_DENY_PROBES=$((${WORKLOAD_DENY_PROBES:-0} + 1))
                npa_verify_mode "$namespace"
                WORKLOAD_MODE_PROBES=$((${WORKLOAD_MODE_PROBES:-0} + 1))
                return
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

npa_json_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    printf '%s' "$value"
}

npa_write_workload_report() {
    : "${WORKLOAD_REPORT_PATH:?WORKLOAD_REPORT_PATH must be set}"
    local report_dir
    report_dir=$(dirname -- "$WORKLOAD_REPORT_PATH")
    mkdir -p "$report_dir"
    local temporary="${WORKLOAD_REPORT_PATH}.tmp.$$"
    cat >"$temporary" <<EOF
{
  "schemaVersion": 1,
  "profileID": "$(npa_json_escape "${WORKLOAD_PROFILE_ID:-}")",
  "scenarioID": "$(npa_json_escape "${TEST_SCENARIO_ID:-}")",
  "policyMode": "$(npa_json_escape "$NPA_POLICY_MODE")",
  "startedAt": "$(npa_json_escape "${WORKLOAD_STARTED_AT:-}")",
  "completedAt": "$(npa_json_escape "${WORKLOAD_COMPLETED_AT:-}")",
  "stablePods": ${WORKLOAD_STABLE_PODS:-0},
  "churnPods": ${WORKLOAD_CHURN_PODS:-0},
  "churnPodsPerJob": ${WORKLOAD_CHURN_PODS_PER_JOB:-0},
  "batchSize": ${WORKLOAD_BATCH_SIZE:-0},
  "cycleIntervalSeconds": ${WORKLOAD_CYCLE_INTERVAL_SECONDS:-0},
  "policySettleSeconds": ${WORKLOAD_POLICY_SETTLE_SECONDS:-0},
  "policyRoundsRequested": ${WORKLOAD_POLICY_ROUNDS_REQUESTED:-0},
  "policyRoundsCompleted": ${WORKLOAD_POLICY_ROUNDS_COMPLETED:-0},
  "shortLivedPods": ${WORKLOAD_SHORT_LIVED_PODS:-0},
  "shortLivedPolicyAttestations": ${WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS:-0},
  "shortLivedPodsPerRound": ${WORKLOAD_SHORT_LIVED_PODS_PER_ROUND:-0},
  "shortLivedIntervalSeconds": ${WORKLOAD_SHORT_LIVED_INTERVAL_SECONDS:-0},
  "shortLivedLifetimeSeconds": ${WORKLOAD_SHORT_LIVED_LIFETIME_SECONDS:-0},
  "shortLivedMaxRoundSeconds": ${WORKLOAD_SHORT_LIVED_MAX_ROUND_SECONDS:-0},
  "shortLivedRoundsRequested": ${WORKLOAD_SHORT_LIVED_ROUNDS_REQUESTED:-0},
  "shortLivedRoundsCompleted": ${WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED:-0},
  "durationSeconds": ${WORKLOAD_DURATION_SECONDS:-0},
  "churnJobsRequested": ${WORKLOAD_ROUNDS_REQUESTED:-0},
  "churnJobsCompleted": ${WORKLOAD_ROUNDS_COMPLETED:-0},
  "allowProbes": ${WORKLOAD_ALLOW_PROBES:-0},
  "denyProbes": ${WORKLOAD_DENY_PROBES:-0},
  "modeProbes": ${WORKLOAD_MODE_PROBES:-0},
  "policyRemovalProbes": ${WORKLOAD_POLICY_REMOVAL_PROBES:-0},
  "policyRemovalStatus": "$(npa_json_escape "${WORKLOAD_POLICY_REMOVAL_STATUS:-unknown}")",
  "workloadStatus": "$(npa_json_escape "${WORKLOAD_STATUS:-unknown}")",
  "cleanupStatus": "$(npa_json_escape "${WORKLOAD_CLEANUP_STATUS:-unknown}")"
}
EOF
    mv -f -- "$temporary" "$WORKLOAD_REPORT_PATH"
}

npa_render_churn_batch() {
    local run_label=$1
    local start=$2
    local end=$3
    local identity

    for ((identity = start; identity <= end; identity++)); do
        local name="${run_label}-${identity}"
        cat <<EOF
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
---
EOF
    done
}

npa_apply_churn_batch() {
    local namespace=$1
    local run_label=$2
    local start=$3
    local end=$4

    npa_render_churn_batch "$run_label" "$start" "$end" |
        npa_kubectl apply -n "$namespace" -f -
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

npa_render_short_lived_policies() {
    cat <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: npa-short-lived-default-deny
  labels:
    npa-test-phase: short-lived
spec:
  podSelector:
    matchLabels:
      npa-test-phase: short-lived
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: npa-short-lived-policy
  labels:
    npa-test-phase: short-lived
spec:
  podSelector:
    matchLabels:
      npa-test-phase: short-lived
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: npa-probe-server
      ports:
        - protocol: TCP
          port: 8081
EOF
}

npa_render_short_lived_job() {
    local run_label=$1
    local targets=$2
    local lifetime_seconds=$3

    cat <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${run_label}
  labels:
    npa-test-phase: short-lived
    npa-test-run: ${run_label}
spec:
  parallelism: ${targets}
  completions: ${targets}
  backoffLimit: 0
  activeDeadlineSeconds: 600
  template:
    metadata:
      labels:
        npa-test-phase: short-lived
        npa-test-run: ${run_label}
    spec:
      restartPolicy: Never
      containers:
        - name: workload
          image: ${NPA_TEST_IMAGE}
          command:
            - /bin/sh
            - -c
            - |
              host="\${NPA_PROBE_SERVER_SERVICE_HOST:?missing NPA probe service host}"
              attested=0
              deadline=\$((\$(date +%s) + ${lifetime_seconds}))
              while [ "\$(date +%s)" -lt "\$deadline" ]; do
                control=\$(wget -qO- -T 1 "http://\$host:8081/" 2>/dev/null || true)
                if [ "\$control" = npa-control ]; then
                  if wget -qO- -T 1 "http://\$host:8080/" >/dev/null 2>&1; then
                    if [ "\$attested" -eq 1 ]; then
                      echo "short-lived policy denial regressed after enforcement" >&2
                      exit 1
                    fi
                  else
                    attested=1
                  fi
                fi
                sleep 1
              done
              if [ "\$attested" -ne 1 ]; then
                echo "short-lived pod never proved allowed control plus denied target" >&2
                exit 1
              fi
          resources:
            requests:
              cpu: 1m
              memory: 4Mi
EOF
}

npa_apply_short_lived_policies() {
    local namespace=$1

    npa_render_short_lived_policies |
        npa_kubectl apply -n "$namespace" -f -
}

npa_run_short_lived_round() {
    local namespace=$1
    local run_label=$2
    local targets=$3
    local lifetime_seconds=$4

    npa_render_short_lived_job "$run_label" "$targets" "$lifetime_seconds" |
        npa_kubectl apply -n "$namespace" -f -
    npa_kubectl wait "job/${run_label}" \
        -n "$namespace" \
        --for=condition=Complete \
        --timeout=10m
    npa_kubectl delete "job/${run_label}" \
        -n "$namespace" \
        --ignore-not-found=true \
        --wait=false \
        --timeout=10m
}

npa_require_short_lived_deleted() {
    local namespace=$1
    local run_label=$2
    local pods

    if ! pods=$(npa_kubectl get pods -n "$namespace" -l "npa-test-run=${run_label}" \
        --no-headers 2>/dev/null); then
        echo "failed to verify deletion for ${run_label}" >&2
        return 1
    fi
    if [[ -n $pods ]]; then
        echo "short-lived pods remain for ${run_label}" >&2
        return 1
    fi
}
