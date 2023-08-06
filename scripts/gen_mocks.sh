# Note: Put all external mocks in the ./mock directory
#       The mocks specific to this project go alongside the original package

MOCKGEN=${MOCKGEN:-~/go/bin/mockgen}

$MOCKGEN -package=mock_client -destination=./mocks/controller-runtime/client/client_mocks.go sigs.k8s.io/controller-runtime/pkg/client Client
#$MOCKGEN -package=mock_ebpf_client -destination=./pkg/ebpf/bpf_client.go  github.com/achevuru/aws-network-policy-agent/pkg/ebpf bpfClient
