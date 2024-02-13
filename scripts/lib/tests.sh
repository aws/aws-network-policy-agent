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
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccount: cyclonus
      containers:
        - name: cyclonus
          imagePullPolicy: Always
          image: ${CYCLONUS_IMAGE_REPOSITORY}/cyclonus:v0.5.4
          command:
            - ./cyclonus
            - generate
            - --retries=2
            - --verbosity=debug
            ${IMAGE_REPOSITORY_PARAMETER}
EOF
}

function run_cyclonus_tests(){

    kubectl create ns netpol
    kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=netpol:cyclonus
    kubectl create sa cyclonus -n netpol

    generate_manifest_and_apply

    echo "Executing cyclonus suite"
    kubectl wait --for=condition=complete --timeout=300m -n netpol job.batch/cyclonus || echo "Job timed out after 4 hrs"
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
