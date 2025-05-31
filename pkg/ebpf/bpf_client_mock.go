package ebpf

import (
	"sync"
)

// NewMockBpfClient is an exported helper for tests that returns a mock implementation of BpfClient.
// This function is intended for use in tests in other packages.
func NewMockBpfClient() BpfClient {
	return &bpfClient{
		policyEndpointeBPFContext: new(sync.Map),
		IngressPodToProgMap:       new(sync.Map),
		EgressPodToProgMap:        new(sync.Map),
		IngressProgToPodsMap:      new(sync.Map),
		EgressProgToPodsMap:       new(sync.Map),
		GlobalMaps:                new(sync.Map),
		nodeIP:                    "127.0.0.1",
		enableIPv6:                false,
		hostMask:                  "/32",
	}
}
