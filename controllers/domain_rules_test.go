package controllers

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/assert"
)

var (
	ipRule     = fwrp.EbpfFirewallRules{IPCidr: "192.0.2.0/24"}
	domainRule = fwrp.EbpfFirewallRules{DomainName: "example.com", Action: "Accept"}
)

func TestUpdateeBPFMaps_DomainRulesStayOutOfIPMaps(t *testing.T) {
	mock := &ebpf.MockBpfClient{}
	r := &PolicyEndpointsReconciler{ebpfClient: mock}
	assert.NoError(t, r.updateeBPFMaps("app@ns", nil, []fwrp.EbpfFirewallRules{ipRule, domainRule}, ebpf.POLICIES_APPLIED))
	assert.Equal(t, []fwrp.EbpfFirewallRules{ipRule}, mock.LastEgressRules)
}

func TestUpdateClusterPolicyBPFMaps_DomainRulesStayOutOfIPMaps(t *testing.T) {
	mock := &ebpf.MockBpfClient{}
	r := &ClusterPolicyEndpointsReconciler{ebpfClient: mock}
	assert.NoError(t, r.updateClusterPolicyBPFMaps("app@ns", nil, []fwrp.EbpfFirewallRules{domainRule}))
	assert.Empty(t, mock.LastClusterPolicyEgressRules)
	// Domain rules alone still count as cluster policy rules for the pod state.
	assert.Equal(t, ebpf.POLICIES_APPLIED, mock.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: "app@ns", MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}])
}
