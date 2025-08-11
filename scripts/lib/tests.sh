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

function run_cyclonus_tests(){

    TIMEOUT=$((5 * 60 * 60))  # 5 hours timeout in seconds
    START_TIME=$(date +%s)

    kubectl create ns netpol
    kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=netpol:cyclonus
    kubectl create sa cyclonus -n netpol

    generate_manifest_and_apply

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
          break
      fi

      kubectl wait --for=condition=complete job.batch/cyclonus -n netpol --timeout=60s > /dev/null 2>&1 && break
    done

    kubectl logs -n netpol job/cyclonus > ${DIR}/results.log
    kubectl get pods -A -owide

    # Cleanup after test finishes
    kubectl delete clusterrolebinding cyclonus
    kubectl delete ns netpol x y z

    cat ${DIR}/results.log

    echo "Verify results against expected"
    python3 ${DIR}/lib/verify_test_results.py -f ${DIR}/results.log -ip $IP_FAMILY || TEST_FAILED=true
}

function run_performance_tests(){
    run_cyclonus_tests
}
