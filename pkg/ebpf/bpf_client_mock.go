package ebpf

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"
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

type MockBpfClient struct{}

func (m *MockBpfClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string) error {
	return nil
}

func (m *MockBpfClient) UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []EbpfFirewallRules, egressFirewallRules []EbpfFirewallRules) error {
	return nil
}

func (m *MockBpfClient) UpdatePodStateEbpfMaps(podIdentifier string, state int, updateIngress bool, updateEgress bool) error {
	return nil
}

func (m *MockBpfClient) IsEBPFProbeAttached(podName string, podNamespace string) (bool, bool) {
	return false, false
}

func (m *MockBpfClient) IsFirstPodInPodIdentifier(podIdentifier string) bool {
	return false
}
func (m *MockBpfClient) GetIngressPodToProgMap() *sync.Map {
	return nil
}
func (m *MockBpfClient) GetEgressPodToProgMap() *sync.Map {
	return nil
}
func (m *MockBpfClient) GetIngressProgToPodsMap() *sync.Map {
	return nil
}
func (m *MockBpfClient) GetEgressProgToPodsMap() *sync.Map {
	return nil
}

func (m *MockBpfClient) DeletePodFromIngressProgPodCaches(podName string, podNamespace string) {
}

func (m *MockBpfClient) DeletePodFromEgressProgPodCaches(podName string, podNamespace string) {
}

func (m *MockBpfClient) ReAttachEbpfProbes() error {
	return nil
}

func (m *MockBpfClient) DeleteBPFProgramAndMaps(podIdentifier string) error {
	return nil
}

func (m *MockBpfClient) GetDeletePodIdentifierLockMap() *sync.Map {
	return nil
}
