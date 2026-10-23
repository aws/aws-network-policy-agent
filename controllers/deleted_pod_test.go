package controllers

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
)

type podAttachErrorClient struct {
	ebpf.MockBpfClient
	deletedPod  types.NamespacedName
	attachCalls []types.NamespacedName
}

func (m *podAttachErrorClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, numInterfaces int, podConfirmedLive bool) (bool, error) {
	m.attachCalls = append(m.attachCalls, pod)
	if pod == m.deletedPod {
		return false, ebpf.ErrPodDeleted
	}
	return m.MockBpfClient.AttacheBPFProbes(pod, podIdentifier, numInterfaces, podConfirmedLive)
}

type recordingDNSProxy struct {
	proxymanager.ProxyManagerMock
	addedPods []types.NamespacedName
}

func (p *recordingDNSProxy) AddDNSRedirectionRulesForPod(pod npatypes.Pod, podIdentifier string) error {
	p.addedPods = append(p.addedPods, pod.NamespacedName)
	return nil
}

func TestConfigureBPFProbes_DeletedPod(t *testing.T) {
	deletedPod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-deleted", Namespace: "default"}}
	livePod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-live", Namespace: "default"}}
	podIdentifier := utils.GetPodIdentifier(deletedPod.Name, deletedPod.Namespace)

	t.Cleanup(func() { filter.DeletePolicyEndpointDomains(podIdentifier) })
	bpf := &podAttachErrorClient{deletedPod: deletedPod.NamespacedName}
	proxy := &recordingDNSProxy{}
	egressRules := []fwrp.EbpfFirewallRules{{DomainName: "example.com"}}

	r := NewPolicyEndpointsReconciler(nil, "", bpf, false, proxy)
	err := r.configureeBPFProbes(t.Context(), podIdentifier, []npatypes.Pod{deletedPod, livePod}, nil, egressRules)

	assert.NoError(t, err)
	assert.Equal(t, []types.NamespacedName{deletedPod.NamespacedName, livePod.NamespacedName}, bpf.attachCalls)
	assert.Equal(t, []types.NamespacedName{livePod.NamespacedName}, proxy.addedPods)
}
