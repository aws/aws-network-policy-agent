package ebpf

import (
	"context"
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

type MockBpfClient struct{}

func (m *MockBpfClient) AttacheBPFProbes(ctx context.Context, pod types.NamespacedName, podIdentifier string, numInterfaces int) error {
	return nil
}

func (m *MockBpfClient) DeleteBPFProbes(ctx context.Context, pod types.NamespacedName, podIdentifier string) error {
	return nil
}

func (m *MockBpfClient) UpdateEbpfMaps(ctx context.Context, podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error {
	return nil
}

func (m *MockBpfClient) UpdateClusterPolicyEbpfMaps(ctx context.Context, podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error {
	return nil
}

func (m *MockBpfClient) UpdatePodStateEbpfMaps(ctx context.Context, podIdentifier string, key int, state int, updateIngress bool, updateEgress bool) error {
	return nil
}

func (m *MockBpfClient) IsFirstPodInPodIdentifier(ctx context.Context, podIdentifier string) bool {
	return false
}

func (m *MockBpfClient) ReAttachEbpfProbes() error {
	return nil
}

func (m *MockBpfClient) GetNetworkPolicyMode() string {
	return "standard"
}

func (m *MockBpfClient) CreatePodStateEbpfEntryIfNotExists(ctx context.Context, podIdentifier string, key int, state int) error {
	return nil
}
