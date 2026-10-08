package ebpf

import (
	"fmt"
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
	UpdateEbpfMapsErr                     error
	UpdateClusterPolicyEbpfMapsErr        error
	UpdatePodStateEbpfMapsErr             error
	CreatePodStateEbpfEntryIfNotExistsErr error

	// Captured args from the most recent UpdateEbpfMaps call.
	LastIngressRules []fwrp.EbpfFirewallRules
	LastEgressRules  []fwrp.EbpfFirewallRules

	// Captured args from the most recent UpdateClusterPolicyEbpfMaps call, so tests can
	// assert that the rules were actually cleared and not just that the call happened.
	LastClusterPolicyIngressRules []fwrp.EbpfFirewallRules
	LastClusterPolicyEgressRules  []fwrp.EbpfFirewallRules

	// podIdentifiers whose probes are detached. Empty by default so HasBPFContext reports
	// true, preserving the original success-path behavior. Also fails every map write for
	// that identifier, the way the real client's context lookup does.
	PodIdentifiersWithoutBPFContext map[string]bool

	// Empty means "standard", preserving the original behavior.
	NetworkPolicyMode string

	// Per-identifier failures for UpdateClusterPolicyEbpfMaps, so a test can make one pod
	// identifier's map writes fail every time while every other identifier succeeds.
	UpdateClusterPolicyEbpfMapsErrFor map[string]error

	// Per-identifier call records. The Last* fields above retain only the most recent
	// call, which cannot distinguish outcomes when one reconcile programs several
	// identifiers.
	ClusterPolicyIngressByIdentifier map[string][]fwrp.EbpfFirewallRules
	ClusterPolicyEgressByIdentifier  map[string][]fwrp.EbpfFirewallRules
	IngressByIdentifier              map[string][]fwrp.EbpfFirewallRules
	EgressByIdentifier               map[string][]fwrp.EbpfFirewallRules
	PodStateByIdentifier             map[PodStateKey]int

	// Entries the eBPF map already holds, which survive Reset because they model map
	// contents rather than recorded calls. CreatePodStateEbpfEntryIfNotExists uses
	// BPF_NOEXIST, so it must not overwrite one.
	podStateSeeded map[PodStateKey]bool
}

// PodStateKey identifies one entry of the pod-state map. POD_STATE_MAP_KEY holds the
// namespaced-policy verdict and CLUSTER_POLICY_POD_STATE_MAP_KEY the cluster-policy one,
// so one identifier has an independent state under each.
type PodStateKey struct {
	PodIdentifier string
	MapKey        int
}

// Reset clears every recorded call so a test can establish steady state through a first
// reconcile and then assert only on what a later reconcile did.
func (m *MockBpfClient) Reset() {
	m.CallLog = nil
	m.LastIngressRules = nil
	m.LastEgressRules = nil
	m.LastClusterPolicyIngressRules = nil
	m.LastClusterPolicyEgressRules = nil
	m.ClusterPolicyIngressByIdentifier = nil
	m.ClusterPolicyEgressByIdentifier = nil
	m.IngressByIdentifier = nil
	m.EgressByIdentifier = nil
	m.PodStateByIdentifier = nil
}

func recordRules(dst *map[string][]fwrp.EbpfFirewallRules, podIdentifier string, rules []fwrp.EbpfFirewallRules) {
	if *dst == nil {
		*dst = map[string][]fwrp.EbpfFirewallRules{}
	}
	(*dst)[podIdentifier] = rules
}

func (m *MockBpfClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, numInterfaces int) error {
	m.CallLog = append(m.CallLog, "AttacheBPFProbes")
	return nil
}

func (m *MockBpfClient) DeleteBPFProbes(pod types.NamespacedName, podIdentifier string) error {
	m.CallLog = append(m.CallLog, "DeleteBPFProbes")
	return nil
}

// ForgetIdentifier drops everything the mock holds for an identifier, modelling
// deleteBPFProbes destroying its maps. DeleteBPFProbes does not call it: production only
// destroys the context when the identifier's last pod leaves the node, and the mock has no
// notion of a shared program FD, so tests decide when an identifier is really gone.
func (m *MockBpfClient) ForgetIdentifier(podIdentifier string) {
	delete(m.PodIdentifiersWithoutBPFContext, podIdentifier)
	for k := range m.podStateSeeded {
		if k.PodIdentifier == podIdentifier {
			delete(m.podStateSeeded, k)
		}
	}
	for k := range m.PodStateByIdentifier {
		if k.PodIdentifier == podIdentifier {
			delete(m.PodStateByIdentifier, k)
		}
	}
}

func (m *MockBpfClient) UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error {
	m.CallLog = append(m.CallLog, "UpdateEbpfMaps")
	if err := m.contextErr(podIdentifier); err != nil {
		return err
	}
	m.LastIngressRules = ingressFirewallRules
	m.LastEgressRules = egressFirewallRules
	recordRules(&m.IngressByIdentifier, podIdentifier, ingressFirewallRules)
	recordRules(&m.EgressByIdentifier, podIdentifier, egressFirewallRules)
	return m.UpdateEbpfMapsErr
}

func (m *MockBpfClient) UpdateClusterPolicyEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error {
	m.CallLog = append(m.CallLog, "UpdateClusterPolicyEbpfMaps")
	if err := m.contextErr(podIdentifier); err != nil {
		return err
	}
	if err := m.UpdateClusterPolicyEbpfMapsErrFor[podIdentifier]; err != nil {
		return err
	}
	m.LastClusterPolicyIngressRules = ingressFirewallRules
	m.LastClusterPolicyEgressRules = egressFirewallRules
	recordRules(&m.ClusterPolicyIngressByIdentifier, podIdentifier, ingressFirewallRules)
	recordRules(&m.ClusterPolicyEgressByIdentifier, podIdentifier, egressFirewallRules)
	return m.UpdateClusterPolicyEbpfMapsErr
}

func (m *MockBpfClient) UpdatePodStateEbpfMaps(podIdentifier string, key int, state int, updateIngress bool, updateEgress bool) error {
	m.CallLog = append(m.CallLog, "UpdatePodStateEbpfMaps")
	if err := m.contextErr(podIdentifier); err != nil {
		return err
	}
	m.recordPodState(podIdentifier, key, state)
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
	if m.NetworkPolicyMode == "" {
		return "standard"
	}
	return m.NetworkPolicyMode
}

func (m *MockBpfClient) CreatePodStateEbpfEntryIfNotExists(podIdentifier string, key int, state int) error {
	m.CallLog = append(m.CallLog, "CreatePodStateEbpfEntryIfNotExists")
	if err := m.contextErr(podIdentifier); err != nil {
		return err
	}
	if !m.podStateSeeded[PodStateKey{PodIdentifier: podIdentifier, MapKey: key}] {
		m.recordPodState(podIdentifier, key, state)
	}
	return m.CreatePodStateEbpfEntryIfNotExistsErr
}

func (m *MockBpfClient) ClearDeletedPod(podNamespacedName string) {
	m.CallLog = append(m.CallLog, "ClearDeletedPod")
}

func (m *MockBpfClient) HasBPFContext(podIdentifier string) bool {
	return !m.PodIdentifiersWithoutBPFContext[podIdentifier]
}

func (m *MockBpfClient) recordPodState(podIdentifier string, key int, state int) {
	if m.PodStateByIdentifier == nil {
		m.PodStateByIdentifier = map[PodStateKey]int{}
	}
	if m.podStateSeeded == nil {
		m.podStateSeeded = map[PodStateKey]bool{}
	}
	k := PodStateKey{PodIdentifier: podIdentifier, MapKey: key}
	m.PodStateByIdentifier[k] = state
	m.podStateSeeded[k] = true
}

// contextErr reproduces the real client's context lookup, which every map write performs
// before touching a map and which fails once the probes are detached. Without it the mock
// is more forgiving than production and cannot reproduce cleanup failures.
func (m *MockBpfClient) contextErr(podIdentifier string) error {
	if m.PodIdentifiersWithoutBPFContext[podIdentifier] {
		return fmt.Errorf("no bpf context registered for pod %s", podIdentifier)
	}
	return nil
}
