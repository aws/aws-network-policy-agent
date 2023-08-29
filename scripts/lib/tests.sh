function run_cyclonus_tests(){

    kubectl create ns $NETWORK_POLICY_NS
    kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=$NETWORK_POLICY_NS:cyclonus
    kubectl create sa cyclonus -n $NETWORK_POLICY_NS

    kubectl apply -f ${DIR}/test/cyclonus-config.yaml -n $NETWORK_POLICY_NS

    kubectl wait --for=condition=complete --timeout=240m -n $NETWORK_POLICY_NS job.batch/cyclonus || echo "Job timed out after 4 hrs"
    kubectl logs -n $NETWORK_POLICY_NS job/cyclonus > ${DIR}/results.log

}

function run_performance_tests(){
    run_cyclonus_tests
}
