package ebpf

import (
	"sync"

	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"k8s.io/apimachinery/pkg/types"
)

// NewMockBpfClient is an exported helper for tests that returns a mock implementation of BpfClient.
// This function is intended for use in tests in other packages.
func NewMockBpfClient() *bpfClient {
	return &bpfClient{
		policyEndpointeBPFContext:       new(sync.Map),
		ingressPodToProgMap:             new(sync.Map),
		egressPodToProgMap:              new(sync.Map),
		ingressProgToPodsMap:            new(sync.Map),
		egressProgToPodsMap:             new(sync.Map),
		globalMaps:                      new(sync.Map),
		hostMask:                        "/32",
		clusterPolicyIngressInMemoryMap: new(sync.Map),
		clusterPolicyEgressInMemoryMap:  new(sync.Map),
	}
}

type MockBpfClient struct {
	CallLog []string

	// Injected errors for failure-path tests. Zero values preserve the
	// original success-path behavior, so existing tests continue to pass.
	UpdateEbpfMapsErr              error
	UpdateClusterPolicyEbpfMapsErr error
	UpdatePodStateEbpfMapsErr      error
}

func (m *MockBpfClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, numInterfaces int) error {
	m.CallLog = append(m.CallLog, "AttacheBPFProbes")
	return nil
}

func (m *MockBpfClient) DeleteBPFProbes(pod types.NamespacedName, podIdentifier string) error {
	m.CallLog = append(m.CallLog, "DeleteBPFProbes")
	return nil
}

func (m *MockBpfClient) UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error {
	m.CallLog = append(m.CallLog, "UpdateEbpfMaps")
	return m.UpdateEbpfMapsErr
}

func (m *MockBpfClient) UpdateClusterPolicyEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error {
	m.CallLog = append(m.CallLog, "UpdateClusterPolicyEbpfMaps")
	return m.UpdateClusterPolicyEbpfMapsErr
}

func (m *MockBpfClient) UpdatePodStateEbpfMaps(podIdentifier string, key int, state int, updateIngress bool, updateEgress bool) error {
	m.CallLog = append(m.CallLog, "UpdatePodStateEbpfMaps")
	return m.UpdatePodStateEbpfMapsErr
}

func (m *MockBpfClient) IsFirstPodInPodIdentifier(podIdentifier string) bool {
	m.CallLog = append(m.CallLog, "IsFirstPodInPodIdentifier")
	return false
}

func (m *MockBpfClient) ReAttachEbpfProbes() error {
	m.CallLog = append(m.CallLog, "ReAttachEbpfProbes")
	return nil
}

func (m *MockBpfClient) GetNetworkPolicyMode() string {
	return "standard"
}

func (m *MockBpfClient) CreatePodStateEbpfEntryIfNotExists(podIdentifier string, key int, state int) error {
	m.CallLog = append(m.CallLog, "CreatePodStateEbpfEntryIfNotExists")
	return nil
}

func (m *MockBpfClient) ClearDeletedPod(podNamespacedName string) {
	m.CallLog = append(m.CallLog, "ClearDeletedPod")
}
