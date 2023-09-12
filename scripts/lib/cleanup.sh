
function check_path_cleanup(){

    local worker_nodes=$(kubectl get nodes -o custom-columns=NAME:.metadata.name --no-headers)
    for node in $worker_nodes
    do
        export NODE=$node
        envsubst '$NODE' < ${DIR}/test/check-cleanup-pod.yaml > ${DIR}/test/check-cleanup-pod-$node.yaml
        kubectl apply -f ${DIR}/test/check-cleanup-pod-$node.yaml -n default
        rm -rf ${DIR}/test/check-cleanup-pod-$node.yaml
    done
    sleep 20

    for node in $worker_nodes
    do
        if [[ $(kubectl get pods -n default $node -ojsonpath="{.status.phase}") == "Failed" ]]; then
            echo "BPF files not cleaned up on $node"
            kubectl logs $node -n default
            TEST_FAILED=true
        else
            echo "BPF files were cleaned up from the node $node"
        fi
        kubectl delete pods $node -n default
    done

}