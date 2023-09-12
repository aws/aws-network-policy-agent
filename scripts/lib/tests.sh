function run_cyclonus_tests(){

    kubectl create ns netpol
    kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=netpol:cyclonus
    kubectl create sa cyclonus -n netpol
    kubectl apply -f ${DIR}/test/cyclonus-config.yaml -n netpol

    echo "Executing cyclonus suite"
    kubectl wait --for=condition=complete --timeout=240m -n netpol job.batch/cyclonus || echo "Job timed out after 4 hrs"
    kubectl logs -n netpol job/cyclonus > ${DIR}/results.log

    # Cleanup after test finishes
    kubectl delete clusterrolebinding cyclonus
    kubectl delete ns netpol

    cat ${DIR}/results.log

    echo "Verify results against expected"
    python3 ${DIR}/lib/verify_test_results.py -f ${DIR}/results.log -ip $IP_FAMILY || (echo "Cyclonus tests have failed" && TEST_FAILED=true)
}

function run_performance_tests(){
    run_cyclonus_tests
}
