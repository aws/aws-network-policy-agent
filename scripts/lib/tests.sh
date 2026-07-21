function generate_manifest_and_apply(){

    # Use Upstream images by default
    # NOTE: policy-assistant is the successor to cyclonus from kubernetes-sigs/network-policy-api
    # The image should be published to registry.k8s.io/networking-e2e-test-images/policy-assistant
    # If the image is not yet available, it can be built from source using the kubernetes-sigs/network-policy-api repository
    IMAGE_REPOSITORY_PARAMETER=""
    POLICY_ASSISTANT_IMAGE_REPOSITORY="registry.k8s.io/networking-e2e-test-images"

    if [[ $TEST_IMAGE_REGISTRY != "registry.k8s.io" ]]; then
        IMAGE_REPOSITORY_PARAMETER="- --image-repository=$TEST_IMAGE_REGISTRY"
        POLICY_ASSISTANT_IMAGE_REPOSITORY=${TEST_IMAGE_REGISTRY}/networking-e2e-test-images
    fi

cat <<EOF | kubectl apply -n netpol -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: policy-assistant
spec:
  template:
    spec:
      restartPolicy: OnFailure
      serviceAccount: policy-assistant
      containers:
        - name: policy-assistant
          imagePullPolicy: Always
          image: ${POLICY_ASSISTANT_IMAGE_REPOSITORY}/policy-assistant:latest
          command:
            - ./policy-assistant
            - generate
            - --retries=2
            ${IMAGE_REPOSITORY_PARAMETER}
EOF
}

function run_policy_assistant_tests(){

    TIMEOUT=$((5 * 60 * 60))  # 5 hours timeout in seconds
    START_TIME=$(date +%s)

    kubectl create ns netpol
    kubectl create clusterrolebinding policy-assistant --clusterrole=cluster-admin --serviceaccount=netpol:policy-assistant
    kubectl create sa policy-assistant -n netpol

    generate_manifest_and_apply

    echo "Executing policy-assistant suite"

    while true; do
      STATUS=$(kubectl get job.batch/policy-assistant -n netpol  -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}')
      if [ "$STATUS" == "True" ]; then
        echo "Job policy-assistant has failed. Exiting."
        break
      fi

      CURRENT_TIME=$(date +%s)
      ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
      if [ "$ELAPSED_TIME" -ge "$TIMEOUT" ]; then
          echo "Timeout reached (5 hours). Exiting."
          break
      fi

      kubectl wait --for=condition=complete job.batch/policy-assistant -n netpol --timeout=60s > /dev/null 2>&1 && break
    done

    kubectl logs -n netpol job/policy-assistant > ${DIR}/results.log
    kubectl get pods -A -owide

    # Cleanup after test finishes
    kubectl delete clusterrolebinding policy-assistant
    kubectl delete ns netpol x y z

    cat ${DIR}/results.log

    echo "Verify results against expected"
    python3 ${DIR}/lib/verify_test_results.py -f ${DIR}/results.log -ip $IP_FAMILY || TEST_FAILED=true
}

function run_performance_tests(){
    run_policy_assistant_tests
}

# Backwards compatibility alias
function run_cyclonus_tests(){
    run_policy_assistant_tests
}
