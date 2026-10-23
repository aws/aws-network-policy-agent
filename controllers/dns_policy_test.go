package controllers

import (
	"context"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These tests pin when DNS policy applies: with a proxy manager (IPv4 clusters) the controllers use
// Auto's handling of domainName entries; with a nil proxy manager (IPv6 clusters, where DNS policy is
// not supported yet) they keep skipping domainName entries as before DNS policy support.

func domainPolicyEndpoint() *policyk8sawsv1.PolicyEndpoint {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	return &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "domains-abcde", Namespace: "ns"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "domains", Namespace: "ns"},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyk8sawsv1.EndpointInfo{
				{
					DomainName: "aws.com",
					Ports:      []policyk8sawsv1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
			},
		},
	}
}

func TestDerivePolicyEndpointDomainRules(t *testing.T) {
	pe := domainPolicyEndpoint()
	podIdentifier := "client@ns"

	for _, tc := range []struct {
		name               string
		proxyManager       proxymanager.ProxyManager
		wantEgressRules    []fwrp.EbpfFirewallRules
		wantEgressIsolated bool
	}{
		{
			name:               "DNS policy inactive skips the domain entry and isolates egress",
			proxyManager:       nil,
			wantEgressRules:    nil,
			wantEgressIsolated: true,
		},
		{
			name:         "DNS policy active adds the domain entry as a namespace tier rule",
			proxyManager: &proxymanager.ProxyManagerMock{},
			wantEgressRules: []fwrp.EbpfFirewallRules{{
				Priority:   utils.PE_PRIORITY*10 + 1,
				DomainName: "aws.com",
				L4Info:     pe.Spec.Egress[0].Ports,
			}},
			wantEgressIsolated: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mock_client.NewMockClient(ctrl)
			mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: pe.Name, Namespace: pe.Namespace}, gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, currentPE *policyk8sawsv1.PolicyEndpoint, opts ...client.GetOption) error {
					*currentPE = *pe
					return nil
				},
			).AnyTimes()

			r := NewPolicyEndpointsReconciler(mockClient, "", &ebpf.MockBpfClient{}, false, tc.proxyManager)
			r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{pe.Name})

			_, egressRules, _, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(), podIdentifier, pe.Namespace, pe.Name, false)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantEgressRules, egressRules)
			assert.Equal(t, tc.wantEgressIsolated, isEgressIsolated)
		})
	}
}

// An egress entry with neither a CIDR nor a domain name matches nothing. It is skipped whether or not
// DNS policy is active, so it never reaches the firewall rule processor as an empty CIDR.
func TestDeriveEgressRules_SkipsEntryWithoutCIDROrDomain(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	ports := []policyk8sawsv1.Port{{Protocol: &protocolTCP, Port: &port443}}
	podIdentifier := "client@ns"

	pe := &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-peer-abcde", Namespace: "ns"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "empty-peer", Namespace: "ns"},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyk8sawsv1.EndpointInfo{
				{Ports: ports},
				{CIDR: "10.0.0.0/8", Ports: ports},
			},
		},
	}
	for _, tc := range []struct {
		name         string
		proxyManager proxymanager.ProxyManager
	}{
		{name: "DNS policy inactive", proxyManager: nil},
		{name: "DNS policy active", proxyManager: &proxymanager.ProxyManagerMock{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mock_client.NewMockClient(ctrl)
			mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
					*obj.(*policyk8sawsv1.PolicyEndpoint) = *pe
					return nil
				},
			).AnyTimes()

			peReconciler := NewPolicyEndpointsReconciler(mockClient, "", &ebpf.MockBpfClient{}, false, tc.proxyManager)
			peReconciler.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{pe.Name})
			_, egressRules, _, _, err := peReconciler.deriveIngressAndEgressFirewallRules(context.Background(), podIdentifier, pe.Namespace, pe.Name, false)
			assert.NoError(t, err)
			assert.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: "10.0.0.0/8", L4Info: ports}}, egressRules)

		})
	}
}

func TestConfigureBPFProbes_DNSPolicyInactiveLeavesDomainStoreUntouched(t *testing.T) {
	pod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "client", Namespace: "ns"}}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	egressRules := []fwrp.EbpfFirewallRules{{IPCidr: "10.0.0.0/8"}}

	pe := NewPolicyEndpointsReconciler(nil, "", &ebpf.MockBpfClient{}, false, nil)
	assert.NoError(t, pe.configureeBPFProbes(context.Background(), podIdentifier, []npatypes.Pod{pod}, nil, egressRules))

	assert.False(t, filter.HasAnyDomainRules(podIdentifier))
}

// recordingDomainProxy records DNS redirection removals.
type recordingDomainProxy struct {
	proxymanager.ProxyManagerMock
	removedPods []types.NamespacedName
}

func (p *recordingDomainProxy) RemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	p.removedPods = append(p.removedPods, pod)
	return nil
}

func TestCleanupPod_PolicyEndpointDomainRules(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	namespace := "pe-cleanup"
	cleanedUpPE := "deleted-abcde"
	remainingPE := "remaining-abcde"

	remainingDomainPE := policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: remainingPE, Namespace: namespace},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "remaining", Namespace: namespace},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyk8sawsv1.EndpointInfo{{
				DomainName: "aws.com",
				Ports:      []policyk8sawsv1.Port{{Protocol: &protocolTCP, Port: &port443}},
			}},
		},
	}
	remainingIPPE := policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: remainingPE, Namespace: namespace},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "remaining", Namespace: namespace},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyk8sawsv1.EndpointInfo{{
				CIDR:  "10.0.0.0/8",
				Ports: []policyk8sawsv1.Port{{Protocol: &protocolTCP, Port: &port443}},
			}},
		},
	}

	for _, tc := range []struct {
		name            string
		remaining       *policyk8sawsv1.PolicyEndpoint
		wantDomains     bool
		wantRemovedPods int
	}{
		{name: "no policy left removes domains and redirection", remaining: nil, wantDomains: false, wantRemovedPods: 1},
		{name: "remaining policy with a domain keeps the domains", remaining: &remainingDomainPE, wantDomains: true, wantRemovedPods: 0},
		{name: "remaining policy without a domain removes domains and redirection", remaining: &remainingIPPE, wantDomains: false, wantRemovedPods: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetPod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "client", Namespace: namespace}}
			podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)
			t.Cleanup(func() { filter.DeletePolicyEndpointDomains(podIdentifier) })
			assert.NoError(t, filter.SetPolicyEndpointDomains(podIdentifier, []fwrp.EbpfFirewallRules{{DomainName: "deleted.example.com."}}))

			ctrl := gomock.NewController(t)
			mockClient := mock_client.NewMockClient(ctrl)
			proxy := &recordingDomainProxy{}
			r := NewPolicyEndpointsReconciler(mockClient, "1.1.1.1", &ebpf.MockBpfClient{}, false, proxy)
			if tc.remaining != nil {
				remaining := tc.remaining
				r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{remaining.Name})
				mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: remaining.Name, Namespace: namespace}, gomock.Any()).DoAndReturn(
					func(ctx context.Context, key types.NamespacedName, currentPE *policyk8sawsv1.PolicyEndpoint, opts ...client.GetOption) error {
						*currentPE = *remaining
						return nil
					},
				).AnyTimes()
			} else {
				// the deleted endpoint is the only one left in the map; the delete flow skips it
				r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{cleanedUpPE})
			}

			assert.NoError(t, r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true))

			assert.Equal(t, tc.wantDomains, filter.HasPolicyEndpointDomains(podIdentifier))
			assert.Equal(t, tc.wantDomains, filter.HasAnyDomainRules(podIdentifier))
			if tc.wantDomains {
				ipFilter, ok := filter.GetIPFilter(podIdentifier)
				assert.True(t, ok)
				allowed, _ := ipFilter.IsAllowed("aws.com.")
				assert.True(t, allowed)
				allowed, _ = ipFilter.IsAllowed("deleted.example.com.")
				assert.False(t, allowed)
			}
			assert.Len(t, proxy.removedPods, tc.wantRemovedPods)
		})
	}
}
