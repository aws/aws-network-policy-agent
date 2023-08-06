package controllers

import (
	"context"
	policyendpoint "github.com/achevuru/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/achevuru/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/achevuru/aws-network-policy-agent/pkg/ebpf"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"testing"
)

/*
// PolicyEndpointsReconciler reconciles a PolicyEndpoints object
type PolicyEndpointsReconciler struct {
	k8sClient client.Client
	scheme    *runtime.Scheme
	//Primary IP of EC2 instance
	nodeIP string
	// Maps PolicyEndpoint resource to it's eBPF context
	policyEndpointeBPFContext sync.Map
	// Maps pod Identifier to list of PolicyEndpoint resources
	podIdentifierToPolicyEndpointMap sync.Map
	// Mutex for operations on PodIdentifierToPolicyEndpointMap
	podIdentifierToPolicyEndpointMapMutex sync.Mutex
	// Maps PolicyEndpoint resource with a list of local pods
	policyEndpointSelectorMap sync.Map
	//BPF Client instance
	ebpfClient ebpf.BpfClient

	//Logger
	log logr.Logger
}

*/

func TestDeriveIngressAndEgressFirewallRules(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	intOrStrPort80 := intstr.FromInt(int(port80))

	type policyendpointGetCall struct {
		peRef types.NamespacedName
		pe    *policyendpoint.PolicyEndpoint
		err   error
	}

	type want struct {
		ingressRules []ebpf.EbpfFirewallRules
		egressRules  []ebpf.EbpfFirewallRules
	}

	policyEndpoint_foo := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sample_pe",
			Namespace: "ns",
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: metav1.LabelSelector{},
			PolicyRef: policyendpoint.PolicyReference{
				Name:      "foo",
				Namespace: "bar",
			},
			Ingress: []policyendpoint.EndpointInfo{
				{
					CIDR: "1.1.1.1/32",
					Ports: []policyendpoint.Port{
						{
							Port:     &intOrStrPort80,
							Protocol: &protocolTCP,
						},
					},
				},
			},
			Egress: []policyendpoint.EndpointInfo{
				{
					CIDR: "2.2.2.3/32",
					Ports: []policyendpoint.Port{
						{
							Port:     &intOrStrPort80,
							Protocol: &protocolUDP,
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name                  string
		podIdentifier         string
		resourceNamespace     string
		policyendpointGetCall []policyendpointGetCall
		want                  want
		wantErr               error
	}{
		{
			name:              "Single PE resource",
			podIdentifier:     "foo",
			resourceNamespace: "bar",
			policyendpointGetCall: []policyendpointGetCall{
				{
					peRef: types.NamespacedName{
						Name:      "allow-ingress",
						Namespace: "ing",
					},
					pe: &policyEndpoint_foo,
				},
			},
			want: want{
				ingressRules: []ebpf.EbpfFirewallRules{
					{
						IPCidr: "1.1.1.1/32",
						L4Info: []policyendpoint.Port{
							{
								Protocol: &protocolTCP,
								Port:     &intOrStrPort80,
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
								Port:     &intOrStrPort80,
							},
						},
					},
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler, _ := NewPolicyEndpointsReconciler(mockClient, logr.New(&log.NullLogSink{}),
			false, false, false)
		currentPE := &policyendpoint.PolicyEndpoint{}
		for _, item := range tt.policyendpointGetCall {
			call := item
			mockClient.EXPECT().Get(gomock.Any(), call.peRef, gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, policyendpoint *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
					if call.pe != nil {
						*currentPE = *call.pe
					}
					return call.err
				},
			).AnyTimes()
		}

		t.Run(tt.name, func(t *testing.T) {
			gotIngressRules, gotEgressRules, _, _, _ := policyEndpointReconciler.deriveIngressAndEgressFirewallRules(gomock.AnythingOfType(),
				tt.args.podIdentifier, tt.args.resourceNamespace)
			assert.Equal(t, tt.want.ingressRules, gotIngressRules)
			assert.Equal(t, tt.want.egressRules, gotEgressRules)
		})
	}
}
