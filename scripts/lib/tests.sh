function generate_manifest_and_apply(){

    # Use Upstream images by default
    IMAGE_REPOSITORY_PARAMETER=""
    CYCLONUS_IMAGE_REPOSITORY="mfenwick100"

    if [[ $TEST_IMAGE_REGISTRY != "registry.k8s.io" ]]; then
        IMAGE_REPOSITORY_PARAMETER="- --image-repository=$TEST_IMAGE_REGISTRY"
        CYCLONUS_IMAGE_REPOSITORY=${TEST_IMAGE_REGISTRY}/networking-e2e-test-images
    fi

cat <<EOF | kubectl apply -n netpol -f -
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
}

function dump_cyclonus_diagnostics(){
    local reason="${1:-diagnostics}"
    echo "==== cyclonus diagnostics: ${reason} ===="

    echo "---- kubectl get pods -A -owide ----"
    kubectl get pods -A -owide || true

    echo "---- kubectl get events -n netpol --sort-by=.lastTimestamp ----"
    kubectl get events -n netpol --sort-by=.lastTimestamp || true

    echo "---- kubectl describe job/cyclonus -n netpol ----"
    kubectl describe job/cyclonus -n netpol || true

    echo "---- kubectl describe pods -n netpol (cyclonus) ----"
    kubectl describe pods -n netpol -l job-name=cyclonus || true

    echo "---- kubectl get pods -n kube-system -l k8s-app=aws-node -owide ----"
    kubectl get pods -n kube-system -l k8s-app=aws-node -owide || true

    echo "---- aws-node restartCounts per container ----"
    kubectl get pods -n kube-system -l k8s-app=aws-node \
        -o jsonpath='{range .items[*]}{.spec.nodeName}{"\t"}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.name}={.restartCount},{end}{"\n"}{end}' || true

    echo "---- kubectl describe pods -n kube-system -l k8s-app=aws-node ----"
    kubectl describe pods -n kube-system -l k8s-app=aws-node || true

    echo "---- kubectl logs -n kube-system -l k8s-app=aws-node -c aws-eks-nodeagent --tail=200 ----"
    kubectl logs -n kube-system -l k8s-app=aws-node -c aws-eks-nodeagent --tail=200 --prefix=true || true

    echo "---- kubectl logs -n kube-system -l k8s-app=aws-node -c aws-node --tail=200 ----"
    kubectl logs -n kube-system -l k8s-app=aws-node -c aws-node --tail=200 --prefix=true || true

    echo "==== end diagnostics ===="
}

function wait_for_cyclonus_pod_running(){
    local pod_timeout=${1:-300}
    local start=$(date +%s)
    echo "Waiting up to ${pod_timeout}s for the cyclonus pod to reach Running..."

    while true; do
        local pod_json
        pod_json=$(kubectl get pods -n netpol -l job-name=cyclonus -o json 2>/dev/null || echo '{"items":[]}')
        local phase
        phase=$(echo "$pod_json" | jq -r '.items[0].status.phase // "Missing"')

        if [ "$phase" = "Running" ] || [ "$phase" = "Succeeded" ]; then
            echo "cyclonus pod reached phase=${phase}"
            return 0
        fi

        local now=$(date +%s)
        local elapsed=$((now - start))
        if [ "$elapsed" -ge "$pod_timeout" ]; then
            local waiting_reason
            waiting_reason=$(echo "$pod_json" | jq -r '.items[0].status.containerStatuses[0].state.waiting.reason // "unknown"')
            echo "cyclonus pod did not reach Running within ${pod_timeout}s (phase=${phase} waiting=${waiting_reason})"
            dump_cyclonus_diagnostics "cyclonus pod stuck (phase=${phase} waiting=${waiting_reason})"
            return 1
        fi

        sleep 5
    done
}

function run_cyclonus_tests(){

    TIMEOUT=$((5 * 60 * 60))  # 5 hours timeout in seconds
    POD_START_TIMEOUT=${CYCLONUS_POD_START_TIMEOUT:-300}
    START_TIME=$(date +%s)

    kubectl create ns netpol
    kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=netpol:cyclonus
    kubectl create sa cyclonus -n netpol

    generate_manifest_and_apply

    if ! wait_for_cyclonus_pod_running "$POD_START_TIMEOUT"; then
        echo "cyclonus pod failed to start; marking test failed and skipping the 5h wait"
        TEST_FAILED=true
        kubectl delete clusterrolebinding cyclonus || true
        kubectl delete ns netpol x y z --ignore-not-found=true || true
        return 0
    fi

    echo "Executing cyclonus suite"

    while true; do
      STATUS=$(kubectl get job.batch/cyclonus -n netpol  -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}')
      if [ "$STATUS" == "True" ]; then
        echo "Job cyclonus has failed. Exiting."
        break
      fi

      CURRENT_TIME=$(date +%s)
      ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
      if [ "$ELAPSED_TIME" -ge "$TIMEOUT" ]; then
          echo "Timeout reached (5 hours). Exiting."
          dump_cyclonus_diagnostics "job timeout"
          TEST_FAILED=true
          break
      fi

      kubectl wait --for=condition=complete job.batch/cyclonus -n netpol --timeout=60s > /dev/null 2>&1 && break
    done

    kubectl logs -n netpol job/cyclonus > ${DIR}/results.log 2>&1 || echo "warning: kubectl logs failed; results.log may be empty"
    kubectl get pods -A -owide || true

    # Cleanup after test finishes
    kubectl delete clusterrolebinding cyclonus || true
    kubectl delete ns netpol x y z --ignore-not-found=true || true

    cat ${DIR}/results.log || true

    echo "Verify results against expected"
    python3 ${DIR}/lib/verify_test_results.py -f ${DIR}/results.log -ip $IP_FAMILY || TEST_FAILED=true
}

function run_performance_tests(){
    run_cyclonus_tests
}
