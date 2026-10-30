## Test Agent

This test agent package contains binaries to run the e2e tests

### check-bpf-cleanup-agent

This agent mounts the host file system and checks if the files under `program` and `maps` are cleaned up after finishing the tests

### check-bpf-load-agent

This agent loads the network policy agent's ingress BPF objects (the regular one and the ct-deny one) on the node's kernel and prints which ones load, and whether the kernel has the nf_conntrack kfuncs the ct-deny object needs. It reads the objects from the running agent's container through `/proc/<pid>/root`, so it needs a privileged pod with `hostPID` and the host's bpffs mounted at `/sys/fs/bpf`. `test/integration/ebpf/ingress_object_load_test.go` runs it on every node.
