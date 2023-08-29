
function check_path_cleanup(){

    local worker_nodes=$(kubectl get nodes -o custom-columns=NAME:.metadata.name --no-headers)
    for node in $worker_nodes
    do
        export NODE=$node
        envsubst '$NODE' < ${DIR}/test/check-cleanup-pod.yaml > ${DIR}/test/check-cleanup-pod-$node.yaml
        kubectl apply -f ${DIR}/test/check-cleanup-pod-$node.yaml
        rm -rf ${DIR}/test/check-cleanup-pod-$node.yaml
    done
    sleep 20

    for node in $worker_nodes
    do
        if [[ $(kubectl get pods $node -ojsonpath="{.status.phase}") == "Failed" ]]; then
            echo "BPF files not cleaned up on $node.. $(kubectl logs $node)"
            exit 1
        fi
        kubectl delete pods $node
    done

    echo "BPF files were cleaned up from the nodes"
}