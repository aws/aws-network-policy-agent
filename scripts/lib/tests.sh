function generate_manifest_and_apply(){

    # Use Upstream images by default
    IMAGE_REPOSITORY_PARAMETER=""
    CYCLONUS_IMAGE_REPOSITORY="mfenwick100"

    if [[ $TEST_IMAGE_REGISTRY != "registry.k8s.io" ]]; then
        IMAGE_REPOSITORY_PARAMETER="- --image-repository=$TEST_IMAGE_REGISTRY"
        CYCLONUS_IMAGE_REPOSITORY=${TEST_IMAGE_REGISTRY}/networking-e2e-test-images
    fi

    local manifest
    manifest=$(mktemp)
cat <<EOF > "$manifest"
apiVersion: batch/v1
kind: Job
metadata:
  name: cyclonus
spec:
  template:
    spec:
      restartPolicy: OnFailure
      serviceAccount: cyclonus
      containers:
        - name: cyclonus
          imagePullPolicy: Always
          image: ${CYCLONUS_IMAGE_REPOSITORY}/cyclonus:v0.5.4
          command:
            - ./cyclonus
            - generate
            - --retries=2
            ${IMAGE_REPOSITORY_PARAMETER}
EOF
    kubectl_retry apply -n netpol -f "$manifest"
    rm -f "$manifest"
}

function run_cyclonus_tests(){

    TIMEOUT=$((5 * 60 * 60))  # 5 hours timeout in seconds
    START_TIME=$(date +%s)

    # Applied rather than created, so a retried call or a reused cluster doesn't fail on AlreadyExists.
    local setup
    setup=$(mktemp)
    {
      kubectl create ns netpol --dry-run=client -o yaml
      echo "---"
      kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=netpol:cyclonus --dry-run=client -o yaml
      echo "---"
      kubectl create sa cyclonus -n netpol --dry-run=client -o yaml
    } > "$setup"
    kubectl_retry apply -f "$setup"
    rm -f "$setup"

    generate_manifest_and_apply

    echo "Executing cyclonus suite"

    while true; do
      if ! STATUS=$(kubectl_retry get job.batch/cyclonus -n netpol  -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}'); then
        echo "Could not read the cyclonus job status. Marking the run failed."
        TEST_FAILED=true
        break
      fi

      if [ "$STATUS" == "True" ]; then
        echo "Job cyclonus has failed. Exiting."
        break
      fi

      CURRENT_TIME=$(date +%s)
      ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
      if [ "$ELAPSED_TIME" -ge "$TIMEOUT" ]; then
          echo "Timeout reached (5 hours). Exiting."
          break
      fi

      kubectl wait --for=condition=complete job.batch/cyclonus -n netpol --timeout=60s > /dev/null 2>&1 && break
    done

    local have_results=true
    if kubectl_retry logs -n netpol job/cyclonus > ${DIR}/results.log.tmp; then
      mv ${DIR}/results.log.tmp ${DIR}/results.log
    else
      echo "Could not fetch the cyclonus job logs. Marking the run failed."
      rm -f ${DIR}/results.log.tmp
      have_results=false
      TEST_FAILED=true
    fi

    if [[ $have_results == "true" ]]; then
      cat ${DIR}/results.log

      echo "Verify results against expected"
      python3 ${DIR}/lib/verify_test_results.py -f ${DIR}/results.log -ip $IP_FAMILY || TEST_FAILED=true
    fi

    # Diagnostics and cleanup are best-effort so they can't discard a finished result.
    kubectl_retry get pods -A -owide || echo "warn: could not list pods"
    kubectl_retry delete clusterrolebinding cyclonus --ignore-not-found || echo "warn: could not delete clusterrolebinding cyclonus"
    kubectl_retry delete ns netpol x y z --ignore-not-found || echo "warn: could not delete the cyclonus namespaces"
}

function run_performance_tests(){
    run_cyclonus_tests
}

# Runs a prebuilt ginkgo suite binary (test/build/*.test) against the cluster.
# Records any failure in TEST_FAILED (instead of aborting) so the remaining
# suites still run. Callers must initialize TEST_FAILED="false".
function run_ginkgo_suite(){
    local suite_binary="$1"
    local timeout="${2:-15m}"
    : "${GINKGO_TEST_BUILD_DIR:?run_ginkgo_suite requires GINKGO_TEST_BUILD_DIR}"
    : "${CLUSTER_NAME:?run_ginkgo_suite requires CLUSTER_NAME}"
    : "${KUBE_CONFIG_PATH:?run_ginkgo_suite requires KUBE_CONFIG_PATH}"
    : "${IP_FAMILY:?run_ginkgo_suite requires IP_FAMILY}"
    # registry.k8s.io is the scripts' default for cyclonus, which pulls upstream images. The
    # ginkgo suites need the networking-e2e-test-images mirror (busybox is not on
    # registry.k8s.io), so for that default they use the framework's own registry.
    local registry_flag=()
    if [[ -n "${TEST_IMAGE_REGISTRY:-}" && "$TEST_IMAGE_REGISTRY" != "registry.k8s.io" ]]; then
        registry_flag=(--test-image-registry="$TEST_IMAGE_REGISTRY")
    else
        echo "TEST_IMAGE_REGISTRY is ${TEST_IMAGE_REGISTRY:-unset}; using the test framework's default registry"
    fi
    echo "Running ${suite_binary} (timeout ${timeout})"
    CGO_ENABLED=0 ginkgo -v -timeout "$timeout" --no-color --fail-on-pending \
        "$GINKGO_TEST_BUILD_DIR/$suite_binary" -- \
        --cluster-kubeconfig="$KUBE_CONFIG_PATH" \
        --cluster-name="$CLUSTER_NAME" \
        ${registry_flag[@]+"${registry_flag[@]}"} \
        --ip-family="$IP_FAMILY" || TEST_FAILED="true"
}

# Switches the aws-node daemonset to strict network policy enforcement and
# waits for the rollout. Mutates cluster state, so run the strict suite last.
function enable_strict_mode(){
    echo "Enable network policy strict mode"
    kubectl set env daemonset aws-node -n kube-system -c aws-node NETWORK_POLICY_ENFORCING_MODE=strict

    echo "Check aws-node daemonset status"
    kubectl rollout status ds/aws-node -n kube-system --timeout=300s
}

# Runs the agentflags suite, whose specs change the agent's args on the aws-node
# daemonset and put them back when they finish. A run killed or timed out before
# then leaves them changed for every suite after it, so this saves the args first
# and restores them after the suite, or on exit if the script stops mid-suite.
# Run it after the suites that expect the stock agent, and before strict mode.
function run_agent_flags_suite(){
    local timeout="${1:-15m}"
    AGENT_ARGS_BEFORE_FLAGS_SUITE=$(kubectl get daemonset aws-node -n kube-system \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="aws-eks-nodeagent")].args}')
    trap restore_agent_args EXIT

    run_ginkgo_suite agentflags.test "$timeout"

    restore_agent_args
    trap - EXIT
}

function restore_agent_args(){
    echo "Restore the agent args saved before the agentflags suite"
    kubectl patch daemonset aws-node -n kube-system --type=strategic -p \
        "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"aws-eks-nodeagent\",\"args\":${AGENT_ARGS_BEFORE_FLAGS_SUITE}}]}}}}"

    echo "Check aws-node daemonset status"
    kubectl rollout status ds/aws-node -n kube-system --timeout=300s
}
