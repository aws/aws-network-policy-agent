package controllers

import (
	"context"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/go-logr/logr"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestDeriveIngressAndEgressFirewallRules(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	var port80 int32 = 80

	type policyendpointGetCall struct {
		peRef types.NamespacedName
		pe    *policyendpoint.PolicyEndpoint
		err   error
	}

	type want struct {
		ingressRules      []ebpf.EbpfFirewallRules
		egressRules       []ebpf.EbpfFirewallRules
		isIngressIsolated bool
		isEgressIsolated  bool
	}

	ingressAndEgressPolicy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			Ingress: []policyendpoint.EndpointInfo{
				{
					CIDR: "1.1.1.1/32",
					Ports: []policyendpoint.Port{
						{
							Port:     &port80,
							Protocol: &protocolTCP,
						},
					},
				},
			},
			Egress: []policyendpoint.EndpointInfo{
				{
					CIDR: "2.2.2.2/32",
					Ports: []policyendpoint.Port{
						{
							Port:     &port80,
							Protocol: &protocolUDP,
						},
					},
				},
			},
		},
	}

	ingressRulesOnlyPolicy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeIngress,
				networking.PolicyTypeEgress,
			},
			Ingress: []policyendpoint.EndpointInfo{
				{
					CIDR: "1.1.1.1/32",
					Ports: []policyendpoint.Port{
						{
							Port:     &port80,
							Protocol: &protocolTCP,
						},
					},
				},
			},
		},
	}

	egressRulesOnlyPolicy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeIngress,
				networking.PolicyTypeEgress,
			},
			Egress: []policyendpoint.EndpointInfo{
				{
					CIDR: "2.2.2.2/32",
					Ports: []policyendpoint.Port{
						{
							Port:     &port80,
							Protocol: &protocolUDP,
						},
					},
				},
			},
		},
	}

	denyAll_ingress_policy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "denyAll",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "denyAll",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeIngress,
			},
		},
	}

	denyAll_egress_policy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "denyAll",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "denyAll",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeEgress,
			},
		},
	}

	tests := []struct {
		name                  string
		podIdentifier         string
		resourceNamespace     string
		policyEndpointName    string
		policyendpointGetCall []policyendpointGetCall
		want                  want
		wantErr               error
	}{
		{
			name:               "Ingress and Egress Policy",
			podIdentifier:      "foo-bar",
			resourceNamespace:  "bar",
			policyEndpointName: "foo",
			policyendpointGetCall: []policyendpointGetCall{
				{
					peRef: types.NamespacedName{
						Name:      "foo",
						Namespace: "bar",
					},
					pe: &ingressAndEgressPolicy,
				},
			},
			want: want{
				ingressRules: []ebpf.EbpfFirewallRules{
					{
						IPCidr: "1.1.1.1/32",
						L4Info: []policyendpoint.Port{
							{
								Protocol: &protocolTCP,
								Port:     &port80,
							},
						},
					},
				},
				egressRules: []ebpf.EbpfFirewallRules{
					{
						IPCidr: "2.2.2.2/32",
						L4Info: []policyendpoint.Port{
							{
								Protocol: &protocolUDP,
								Port:     &port80,
							},
						},
					},
				},
				isIngressIsolated: false,
				isEgressIsolated:  false,
			},
			wantErr: nil,
		},

		{
			name:               "Ingress Only Policy",
			podIdentifier:      "foo-bar",
			resourceNamespace:  "bar",
			policyEndpointName: "foo",
			policyendpointGetCall: []policyendpointGetCall{
				{
					peRef: types.NamespacedName{
						Name:      "foo",
						Namespace: "bar",
					},
					pe: &ingressRulesOnlyPolicy,
				},
			},
			want: want{
				ingressRules: []ebpf.EbpfFirewallRules{
					{
						IPCidr: "1.1.1.1/32",
						L4Info: []policyendpoint.Port{
							{
								Protocol: &protocolTCP,
								Port:     &port80,
							},
						},
					},
				},
				isIngressIsolated: false,
				isEgressIsolated:  true,
			},
			wantErr: nil,
		},

		{
			name:               "Egress Only Policy",
			podIdentifier:      "foo-bar",
			resourceNamespace:  "bar",
			policyEndpointName: "foo",
			policyendpointGetCall: []policyendpointGetCall{
				{
					peRef: types.NamespacedName{
						Name:      "foo",
						Namespace: "bar",
					},
					pe: &egressRulesOnlyPolicy,
				},
			},
			want: want{
				egressRules: []ebpf.EbpfFirewallRules{
					{
						IPCidr: "2.2.2.2/32",
						L4Info: []policyendpoint.Port{
							{
								Protocol: &protocolUDP,
								Port:     &port80,
							},
						},
					},
				},
				isIngressIsolated: true,
				isEgressIsolated:  false,
			},
			wantErr: nil,
		},

		{
			name:               "Deny All Ingress",
			podIdentifier:      "denyAll-bar",
			resourceNamespace:  "bar",
			policyEndpointName: "denyAll",
			policyendpointGetCall: []policyendpointGetCall{
				{
					peRef: types.NamespacedName{
						Name:      "denyAll",
						Namespace: "bar",
					},
					pe: &denyAll_ingress_policy,
				},
			},
			want: want{
				isIngressIsolated: true,
				isEgressIsolated:  false,
			},
			wantErr: nil,
		},

		{
			name:               "Deny All Egress",
			podIdentifier:      "denyAll-bar",
			resourceNamespace:  "bar",
			policyEndpointName: "denyAll",
			policyendpointGetCall: []policyendpointGetCall{
				{
					peRef: types.NamespacedName{
						Name:      "denyAll",
						Namespace: "bar",
					},
					pe: &denyAll_egress_policy,
				},
			},
			want: want{
				isIngressIsolated: false,
				isEgressIsolated:  true,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler, _ := NewPolicyEndpointsReconciler(mockClient, logr.New(&log.NullLogSink{}),
			false, false, false, false)
		var policyEndpointsList []string
		policyEndpointsList = append(policyEndpointsList, tt.policyEndpointName)
		policyEndpointReconciler.podIdentifierToPolicyEndpointMap.Store(tt.podIdentifier, policyEndpointsList)
		for _, item := range tt.policyendpointGetCall {
			call := item
			mockClient.EXPECT().Get(gomock.Any(), call.peRef, gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
					if call.pe != nil {
						*currentPE = *call.pe
					}
					return call.err
				},
			).AnyTimes()
		}

		t.Run(tt.name, func(t *testing.T) {
			gotIngressRules, gotEgressRules, gotIsIngressIsolated, gotIsEgressIsolated, gotError := policyEndpointReconciler.deriveIngressAndEgressFirewallRules(context.Background(),
				tt.podIdentifier, tt.resourceNamespace)
			assert.Equal(t, tt.want.ingressRules, gotIngressRules)
			assert.Equal(t, tt.want.egressRules, gotEgressRules)
			assert.Equal(t, tt.want.isIngressIsolated, gotIsIngressIsolated)
			assert.Equal(t, tt.want.isEgressIsolated, gotIsEgressIsolated)
			assert.Equal(t, tt.wantErr, gotError)
		})
	}
}

func TestDeriveTargetPods(t *testing.T) {
	type want struct {
		activePods        []types.NamespacedName
		podsToBeCleanedUp []types.NamespacedName
	}

	samplePolicyEndpoint := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodSelectorEndpoints: []policyendpoint.PodEndpoint{
				{
					HostIP:    "1.1.1.1",
					PodIP:     "10.1.1.1",
					Name:      "foo1",
					Namespace: "bar",
				},
			},
		},
	}

	noMatchingPods := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodSelectorEndpoints: []policyendpoint.PodEndpoint{
				{
					HostIP:    "2.2.2.1",
					PodIP:     "10.1.1.1",
					Name:      "foo1",
					Namespace: "bar",
				},
			},
		},
	}

	policyEndpointUpdate := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodSelectorEndpoints: []policyendpoint.PodEndpoint{
				{
					HostIP:    "1.1.1.1",
					PodIP:     "10.1.1.1",
					Name:      "foo2",
					Namespace: "bar",
				},
			},
		},
	}

	samplePods := []types.NamespacedName{
		{
			Name:      "foo1",
			Namespace: "bar",
		},
	}

	ipv6NodePolicyEndpoint := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodSelectorEndpoints: []policyendpoint.PodEndpoint{
				{
					HostIP:    "2001:db8::1",
					PodIP:     "2001:db8::2",
					Name:      "foo1",
					Namespace: "bar",
				},
			},
		},
	}

	tests := []struct {
		name           string
		policyendpoint policyendpoint.PolicyEndpoint
		parentPEList   []string
		currentPods    []types.NamespacedName //Current set of active pods against this policy
		nodeIP         string                 //Default: 1.1.1.1
		want           want
	}{
		{
			name:           "Matching Local pods",
			policyendpoint: samplePolicyEndpoint,
			parentPEList:   []string{samplePolicyEndpoint.Name},
			want: want{
				activePods: []types.NamespacedName{
					{
						Name:      "foo1",
						Namespace: "bar",
					},
				},
			},
		},
		{
			name:           "No Matching Local pods",
			policyendpoint: noMatchingPods,
			want:           want{},
		},
		{
			name:           "Derive Old pods to be cleaned up",
			policyendpoint: policyEndpointUpdate,
			parentPEList:   []string{policyEndpointUpdate.Name},
			currentPods:    samplePods,
			want: want{
				activePods: []types.NamespacedName{
					{
						Name:      "foo2",
						Namespace: "bar",
					},
				},
				podsToBeCleanedUp: []types.NamespacedName{
					{
						Name:      "foo1",
						Namespace: "bar",
					},
				},
			},
		},
		{
			name:           "Matching Local pods on IPv6 node",
			policyendpoint: ipv6NodePolicyEndpoint,
			parentPEList:   []string{ipv6NodePolicyEndpoint.Name},
			nodeIP:         "2001:db8:0:0:0:0:0:1",
			want: want{
				activePods: []types.NamespacedName{
					{
						Name:      "foo1",
						Namespace: "bar",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := PolicyEndpointsReconciler{
			k8sClient: mockClient,
			log:       logr.New(&log.NullLogSink{}),
			nodeIP:    tt.nodeIP,
		}
		if tt.nodeIP == "" {
			policyEndpointReconciler.nodeIP = "1.1.1.1"
		}

		if tt.currentPods != nil {
			policyEndpointReconciler.policyEndpointSelectorMap.Store(tt.policyendpoint.ObjectMeta.Name+tt.policyendpoint.ObjectMeta.Namespace,
				tt.currentPods)
		}

		t.Run(tt.name, func(t *testing.T) {
			gotActivePods, _, gotPodsToBeCleanedUp := policyEndpointReconciler.deriveTargetPods(context.Background(),
				&tt.policyendpoint, tt.parentPEList)
			assert.Equal(t, tt.want.activePods, gotActivePods)
			assert.Equal(t, tt.want.podsToBeCleanedUp, gotPodsToBeCleanedUp)
		})
	}
}

func TestAddCatchAllEntry(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	sampleFirewallRules := []ebpf.EbpfFirewallRules{
		{
			IPCidr: "1.1.1.1/32",
			L4Info: []policyendpoint.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	catchAllFirewallRule := ebpf.EbpfFirewallRules{
		IPCidr: "0.0.0.0/0",
	}

	var sampleFirewallRulesWithCatchAllEntry []ebpf.EbpfFirewallRules
	sampleFirewallRulesWithCatchAllEntry = append(sampleFirewallRulesWithCatchAllEntry, sampleFirewallRules...)
	sampleFirewallRulesWithCatchAllEntry = append(sampleFirewallRulesWithCatchAllEntry, catchAllFirewallRule)

	tests := []struct {
		name          string
		firewallRules []ebpf.EbpfFirewallRules
		want          []ebpf.EbpfFirewallRules
	}{
		{
			name:          "Append Catch All Entry",
			firewallRules: sampleFirewallRules,
			want:          sampleFirewallRulesWithCatchAllEntry,
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := PolicyEndpointsReconciler{
			k8sClient: mockClient,
			log:       logr.New(&log.NullLogSink{}),
		}

		t.Run(tt.name, func(t *testing.T) {
			policyEndpointReconciler.addCatchAllEntry(context.Background(),
				&tt.firewallRules)
			assert.Equal(t, tt.want, sampleFirewallRulesWithCatchAllEntry)
		})
	}
}

func TestDeriveDefaultPodIsolation(t *testing.T) {
	type want struct {
		isIngressIsolated bool
		isEgressIsolated  bool
	}

	ingressIsolated := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeIngress,
			},
		},
	}

	egressIsolated := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeEgress,
			},
		},
	}

	ingressAndEgressIsolated := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			PodIsolation: []networking.PolicyType{
				networking.PolicyTypeIngress,
				networking.PolicyTypeEgress,
			},
		},
	}

	tests := []struct {
		name             string
		policyendpoint   policyendpoint.PolicyEndpoint
		ingressRuleCount int
		egressRuleCount  int
		want             want
	}{
		{
			name:             "Ingress Isolated",
			policyendpoint:   ingressIsolated,
			ingressRuleCount: 0,
			egressRuleCount:  0,
			want: want{
				isIngressIsolated: true,
				isEgressIsolated:  false,
			},
		},

		{
			name:             "Egress Isolated",
			policyendpoint:   egressIsolated,
			ingressRuleCount: 0,
			egressRuleCount:  0,
			want: want{
				isIngressIsolated: false,
				isEgressIsolated:  true,
			},
		},

		{
			name:             "Ingress and Egress Isolated",
			policyendpoint:   ingressAndEgressIsolated,
			ingressRuleCount: 0,
			egressRuleCount:  0,
			want: want{
				isIngressIsolated: true,
				isEgressIsolated:  true,
			},
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := PolicyEndpointsReconciler{
			k8sClient: mockClient,
			log:       logr.New(&log.NullLogSink{}),
		}

		t.Run(tt.name, func(t *testing.T) {
			gotIsIngressIsolated, gotIsEgressIsolated := policyEndpointReconciler.deriveDefaultPodIsolation(context.Background(),
				&tt.policyendpoint, tt.ingressRuleCount, tt.egressRuleCount)
			assert.Equal(t, tt.want.isIngressIsolated, gotIsIngressIsolated)
			assert.Equal(t, tt.want.isEgressIsolated, gotIsEgressIsolated)
		})
	}
}
