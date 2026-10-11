package controllers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/golang/mock/gomock"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestPolicyEndpointReconcile(t *testing.T) {
	namespace := "my-namespace"
	p1N1 := policyendpoint.PodEndpoint{
		HostIP:    "1.1.1.1",
		PodIP:     "10.1.1.1",
		Name:      "deployment1rs-1",
		Namespace: namespace,
	}
	p2N1 := policyendpoint.PodEndpoint{
		HostIP:    "1.1.1.1",
		PodIP:     "10.1.1.2",
		Name:      "deployment1rs-2",
		Namespace: namespace,
	}

	nodeIp := "1.1.1.1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Reconcile call for Create PolicyEndpoint with PodEndpoint local to Node", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, nodeIp, &ebpf.MockBpfClient{}, false)

		policyEndpoint := getPolicyEndpoint("allow-all-egress", "my-namespace", []policyendpoint.PodEndpoint{p1N1, p2N1})

		mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{
			Name:      policyEndpoint.GetName(),
			Namespace: policyEndpoint.GetNamespace(),
		}, gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
				*currentPE = policyEndpoint
				return nil
			},
		).AnyTimes()

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
				*list = policyendpoint.PolicyEndpointList{
					Items: []policyendpoint.PolicyEndpoint{policyEndpoint},
				}
				return nil
			},
		).AnyTimes()

		_, err := policyEndpointReconciler.Reconcile(context.TODO(), controllerruntime.Request{
			NamespacedName: types.NamespacedName{
				Name:      policyEndpoint.GetName(),
				Namespace: policyEndpoint.GetNamespace(),
			},
		})

		assert.Nil(t, err)
		val, ok := policyEndpointReconciler.networkPolicyToPodIdentifierMap.Load("allow-all-egress")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "deployment1rs@my-namespace"))

		val, ok = policyEndpointReconciler.podIdentifierToPolicyEndpointMap.Load("deployment1rs@my-namespace")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "allow-all-egress-abcd"))

		val, ok = policyEndpointReconciler.policyEndpointSelectorMap.Load("allow-all-egress-abcdmy-namespace")
		assert.True(t, ok)
		assert.Equal(t, 2, len(val.([]npatypes.Pod)))
	})

	t.Run("Reconcile for Create and Delete PE", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, nodeIp, &ebpf.MockBpfClient{}, false)

		policyEndpoint := getPolicyEndpoint("allow-all-egress", "my-namespace", []policyendpoint.PodEndpoint{p1N1, p2N1})

		mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{
			Name:      policyEndpoint.GetName(),
			Namespace: policyEndpoint.GetNamespace(),
		}, gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
				*currentPE = policyEndpoint
				return nil
			},
		).MaxTimes(3)

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
				*list = policyendpoint.PolicyEndpointList{
					Items: []policyendpoint.PolicyEndpoint{policyEndpoint},
				}
				return nil
			},
		).MaxTimes(1)

		_, err := policyEndpointReconciler.Reconcile(context.TODO(), controllerruntime.Request{
			NamespacedName: types.NamespacedName{
				Name:      policyEndpoint.GetName(),
				Namespace: policyEndpoint.GetNamespace(),
			},
		})

		assert.Nil(t, err)
		val, ok := policyEndpointReconciler.networkPolicyToPodIdentifierMap.Load("allow-all-egress")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "deployment1rs@my-namespace"))

		val, ok = policyEndpointReconciler.podIdentifierToPolicyEndpointMap.Load("deployment1rs@my-namespace")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "allow-all-egress-abcd"))

		val, ok = policyEndpointReconciler.policyEndpointSelectorMap.Load("allow-all-egress-abcdmy-namespace")
		assert.True(t, ok)
		assert.Equal(t, 2, len(val.([]npatypes.Pod)))

		mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{
			Name:      policyEndpoint.GetName(),
			Namespace: policyEndpoint.GetNamespace(),
		}, gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
				return apierrors.NewNotFound(schema.GroupResource{Group: networking.SchemeGroupVersion.Group, Resource: ""}, "")
			},
		).AnyTimes()

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
				*list = policyendpoint.PolicyEndpointList{}
				return nil
			},
		).AnyTimes()

		_, err = policyEndpointReconciler.Reconcile(context.TODO(), controllerruntime.Request{
			NamespacedName: types.NamespacedName{
				Name:      policyEndpoint.GetName(),
				Namespace: policyEndpoint.GetNamespace(),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, 0, sizeOfSyncMap(&policyEndpointReconciler.networkPolicyToPodIdentifierMap))
		assert.Equal(t, 0, sizeOfSyncMap(&policyEndpointReconciler.podIdentifierToPolicyEndpointMap))
		assert.Equal(t, 0, sizeOfSyncMap(&policyEndpointReconciler.policyEndpointSelectorMap))

	})
}

func getPolicyEndpoint(npName string, namespace string, podEndpoints []policyendpoint.PodEndpoint) policyendpoint.PolicyEndpoint {
	return policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      npName + "-abcd",
			Namespace: namespace,
		},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector:          &metav1.LabelSelector{},
			PodSelectorEndpoints: podEndpoints,
			PolicyRef: policyendpoint.PolicyReference{
				Name:      npName,
				Namespace: namespace,
			},
			Egress: []policyendpoint.EndpointInfo{},
		},
	}
}

func sizeOfSyncMap(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

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
		ingressRules      []fwrp.EbpfFirewallRules
		egressRules       []fwrp.EbpfFirewallRules
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
				ingressRules: []fwrp.EbpfFirewallRules{
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
				egressRules: []fwrp.EbpfFirewallRules{
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
				ingressRules: []fwrp.EbpfFirewallRules{
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
				egressRules: []fwrp.EbpfFirewallRules{
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
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil, false)
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
				tt.podIdentifier, tt.resourceNamespace, tt.policyEndpointName, false)
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
		activePods        []npatypes.Pod
		podsToBeCleanedUp []npatypes.Pod
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

	hostNetworkPolicyEndpoint := policyendpoint.PolicyEndpoint{
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
					PodIP:     "1.1.1.1", // PodIP == HostIP indicates hostNetwork pod
					Name:      "hostnetwork-pod",
					Namespace: "bar",
				},
			},
		},
	}

	mixedPolicyEndpoint := policyendpoint.PolicyEndpoint{
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
					Name:      "regular-pod",
					Namespace: "bar",
				},
				{
					HostIP:    "1.1.1.1",
					PodIP:     "1.1.1.1", // hostNetwork pod
					Name:      "hostnetwork-pod",
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
				activePods: []npatypes.Pod{
					{
						NamespacedName: types.NamespacedName{
							Name:      "foo1",
							Namespace: "bar",
						},
						PodIP: "10.1.1.1",
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
				activePods: []npatypes.Pod{
					{
						NamespacedName: types.NamespacedName{
							Name:      "foo2",
							Namespace: "bar",
						},
						PodIP: "10.1.1.1",
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
				activePods: []npatypes.Pod{
					{
						NamespacedName: types.NamespacedName{
							Name:      "foo1",
							Namespace: "bar",
						},
						PodIP: "2001:db8::2",
					},
				},
			},
		},
		{
			name:           "Exclude hostNetwork pod (PodIP == HostIP)",
			policyendpoint: hostNetworkPolicyEndpoint,
			parentPEList:   []string{hostNetworkPolicyEndpoint.Name},
			want: want{
				activePods: nil,
			},
		},
		{
			name:           "Mixed regular and hostNetwork pods",
			policyendpoint: mixedPolicyEndpoint,
			parentPEList:   []string{mixedPolicyEndpoint.Name},
			want: want{
				activePods: []npatypes.Pod{
					{
						NamespacedName: types.NamespacedName{
							Name:      "regular-pod",
							Namespace: "bar",
						},
						PodIP: "10.1.1.1",
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
			gotActivePods, _ := policyEndpointReconciler.deriveTargetPods(context.Background(),
				&tt.policyendpoint, tt.parentPEList)
			assert.Equal(t, tt.want.activePods, gotActivePods)
		})
	}
}

func TestAddCatchAllEntry(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	sampleFirewallRules := []fwrp.EbpfFirewallRules{
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

	catchAllFirewallRule := fwrp.EbpfFirewallRules{
		IPCidr: "0.0.0.0/0",
	}

	var sampleFirewallRulesWithCatchAllEntry []fwrp.EbpfFirewallRules
	sampleFirewallRulesWithCatchAllEntry = append(sampleFirewallRulesWithCatchAllEntry, sampleFirewallRules...)
	sampleFirewallRulesWithCatchAllEntry = append(sampleFirewallRulesWithCatchAllEntry, catchAllFirewallRule)

	tests := []struct {
		name          string
		firewallRules []fwrp.EbpfFirewallRules
		want          []fwrp.EbpfFirewallRules
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
		}

		t.Run(tt.name, func(t *testing.T) {
			policyEndpointReconciler.addCatchAllEntry(&tt.firewallRules)
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
		}

		t.Run(tt.name, func(t *testing.T) {
			gotIsIngressIsolated, gotIsEgressIsolated := policyEndpointReconciler.deriveDefaultPodIsolation(
				&tt.policyendpoint, tt.ingressRuleCount, tt.egressRuleCount)
			assert.Equal(t, tt.want.isIngressIsolated, gotIsIngressIsolated)
			assert.Equal(t, tt.want.isEgressIsolated, gotIsEgressIsolated)
		})
	}
}

func TestArePoliciesAvailableInLocalCache(t *testing.T) {
	type want struct {
		activePoliciesAvailable bool
	}

	tests := []struct {
		name               string
		podIdentifier      string
		policyEndpointName []string
		want               want
	}{
		{
			name:               "Active policies present against the PodIdentifier",
			podIdentifier:      "foo-bar",
			policyEndpointName: []string{"foo", "bar"},
			want: want{
				activePoliciesAvailable: true,
			},
		},

		{
			name:          "No Active policies present against the PodIdentifier",
			podIdentifier: "foo-bar",
			want: want{
				activePoliciesAvailable: false,
			},
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil, false)
		var policyEndpointsList []string
		policyEndpointsList = append(policyEndpointsList, tt.policyEndpointName...)
		policyEndpointReconciler.podIdentifierToPolicyEndpointMap.Store(tt.podIdentifier, policyEndpointsList)

		t.Run(tt.name, func(t *testing.T) {
			activePoliciesAvailable := policyEndpointReconciler.ArePoliciesAvailableInLocalCache(tt.podIdentifier)
			assert.Equal(t, tt.want.activePoliciesAvailable, activePoliciesAvailable)
		})
	}
}

func TestDeriveFireWallRulesPerPodIdentifier(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	var port80 int32 = 80

	type policyendpointGetCall struct {
		peRef types.NamespacedName
		pe    *policyendpoint.PolicyEndpoint
		err   error
	}

	type want struct {
		ingressRules      []fwrp.EbpfFirewallRules
		egressRules       []fwrp.EbpfFirewallRules
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
				ingressRules: []fwrp.EbpfFirewallRules{
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
				egressRules: []fwrp.EbpfFirewallRules{
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
				ingressRules: []fwrp.EbpfFirewallRules{
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
				egressRules: []fwrp.EbpfFirewallRules{
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
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil, false)
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
			gotIngressRules, gotEgressRules, gotError := policyEndpointReconciler.DeriveFireWallRulesPerPodIdentifier(tt.podIdentifier, tt.resourceNamespace)
			assert.Equal(t, tt.want.ingressRules, gotIngressRules)
			assert.Equal(t, tt.want.egressRules, gotEgressRules)
			assert.Equal(t, tt.wantErr, gotError)
		})
	}
}

// failClosedTestCase is the table row for fail-closed tests of the bpf-map update wrappers.
type failClosedTestCase struct {
	name           string   // human-readable test case name
	ruleMapErr     error    // error injected on the bpf-client rule-map write; nil = succeed
	podStateErr    error    // error injected on the bpf-client pod-state write; nil = succeed
	createEntryErr error    // error injected on the bpf-client createIfNotExists seed; nil = succeed
	wantErr        error    // expected error, matched with errors.Is; nil = no error
	wantCalls      []string // expected ordered sequence of bpf-client method names
}

// runFailClosedTable runs each case as a subtest. invoke wires the variant-specific mock field, builds the reconciler, and calls the function under test.
func runFailClosedTable(t *testing.T, tests []failClosedTestCase, invoke func(mock *ebpf.MockBpfClient, tt failClosedTestCase) error) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &ebpf.MockBpfClient{
				UpdatePodStateEbpfMapsErr:             tt.podStateErr,
				CreatePodStateEbpfEntryIfNotExistsErr: tt.createEntryErr,
			}
			err := invoke(mock, tt)

			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantCalls, mock.CallLog)
		})
	}
}

// TestUpdateeBPFMaps_FailClosed verifies that updateeBPFMaps surfaces
// errors from the bpf client and short-circuits the pod-state write when
// the rule-map write fails. wantCalls asserts both the set and the order
// of bpf-client calls.
func TestUpdateeBPFMaps_FailClosed(t *testing.T) {
	ruleMapErr := errors.New("rule map write failed")
	podStateErr := errors.New("pod state write failed")
	createEntryErr := errors.New("create entry failed")

	tests := []failClosedTestCase{
		{
			name:       "rule-map failure short-circuits before pod-state",
			ruleMapErr: ruleMapErr,
			wantErr:    ruleMapErr,
			wantCalls:  []string{"UpdateEbpfMaps"},
		},
		{
			name:        "pod-state failure surfaces",
			podStateErr: podStateErr,
			wantErr:     podStateErr,
			wantCalls:   []string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps"},
		},
		{
			name:           "createIfNotExists seed failure surfaces",
			createEntryErr: createEntryErr,
			wantErr:        createEntryErr,
			wantCalls:      []string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
		},
		{
			name:      "happy path returns nil and runs the full sequence",
			wantCalls: []string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
		},
	}

	runFailClosedTable(t, tests, func(mock *ebpf.MockBpfClient, tt failClosedTestCase) error {
		mock.UpdateEbpfMapsErr = tt.ruleMapErr
		r := &PolicyEndpointsReconciler{ebpfClient: mock}
		return r.updateeBPFMaps("test-pod-id", nil, nil, ebpf.POLICIES_APPLIED)
	})
}

// TestUpdateClusterPolicyBPFMaps_FailClosed mirrors TestUpdateeBPFMaps_FailClosed
// for the ClusterPolicyEndpointsReconciler path: a cluster-policy rule-map
// failure must short-circuit before pod-state runs, and either failure must
// surface to the caller.
func TestUpdateClusterPolicyBPFMaps_FailClosed(t *testing.T) {
	ruleMapErr := errors.New("cluster rule map write failed")
	podStateErr := errors.New("cluster pod state write failed")
	createEntryErr := errors.New("cluster create entry failed")

	tests := []failClosedTestCase{
		{
			name:       "cluster rule-map failure short-circuits before pod-state",
			ruleMapErr: ruleMapErr,
			wantErr:    ruleMapErr,
			wantCalls:  []string{"UpdateClusterPolicyEbpfMaps"},
		},
		{
			name:        "cluster pod-state failure surfaces",
			podStateErr: podStateErr,
			wantErr:     podStateErr,
			wantCalls:   []string{"UpdateClusterPolicyEbpfMaps", "UpdatePodStateEbpfMaps"},
		},
		{
			name:           "createIfNotExists seed failure surfaces",
			createEntryErr: createEntryErr,
			wantErr:        createEntryErr,
			wantCalls:      []string{"UpdateClusterPolicyEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
		},
		{
			name:      "happy path returns nil and runs the full sequence",
			wantCalls: []string{"UpdateClusterPolicyEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
		},
	}

	runFailClosedTable(t, tests, func(mock *ebpf.MockBpfClient, tt failClosedTestCase) error {
		mock.UpdateClusterPolicyEbpfMapsErr = tt.ruleMapErr
		r := &ClusterPolicyEndpointsReconciler{ebpfClient: mock}
		return r.updateClusterPolicyBPFMaps("test-pod-id", nil, nil)
	})
}

// Regression test for the asymmetric catch-all bug in cleanupPod (issue #591):
// after cleaning up one of N Ingress-only NPs selecting a pod, the egress rules
// written to the bpf client must still contain the 0.0.0.0/0 catch-all so that
// egress_map stays consistent with pod_state=POLICIES_APPLIED.
func TestCleanupPod_PreservesCatchAllOnRemainingPolicy(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	namespace := "my-namespace"
	podIdentifier := "deployment1rs@my-namespace"
	cleanedUpPE := "ingress-1-abcd"
	remainingPE := "ingress-2-abcd"

	remainingPolicy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: remainingPE, Namespace: namespace},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef:   policyendpoint.PolicyReference{Name: "ingress-2", Namespace: namespace},
			Ingress: []policyendpoint.EndpointInfo{
				{
					CIDR:  "10.0.0.0/24",
					Ports: []policyendpoint.Port{{Port: &port80, Protocol: &protocolTCP}},
				},
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{}
	r := NewPolicyEndpointsReconciler(mockClient, "1.1.1.1", mockBpf, false)
	r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{remainingPE})

	mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: remainingPE, Namespace: namespace}, gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = remainingPolicy
			return nil
		},
	).AnyTimes()

	targetPod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: "deployment1rs-1", Namespace: namespace},
		PodIP:          "10.1.1.1",
	}

	err := r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true)
	assert.NoError(t, err)

	catchAll := fwrp.EbpfFirewallRules{IPCidr: "0.0.0.0/0"}
	assert.Contains(t, mockBpf.LastEgressRules, catchAll)
	assert.NotContains(t, mockBpf.LastIngressRules, catchAll)
	assert.NotEmpty(t, mockBpf.LastIngressRules)
}

// Symmetric variant of TestCleanupPod_PreservesCatchAllOnRemainingPolicy:
// after cleaning up one of N Egress-only NPs selecting a pod, the ingress rules
// written to the bpf client must contain the 0.0.0.0/0 catch-all so that
// ingress_map stays consistent with pod_state=POLICIES_APPLIED.
func TestCleanupPod_EgressOnlyAddsIngressCatchAll(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	namespace := "my-namespace"
	podIdentifier := "deployment1rs@my-namespace"
	cleanedUpPE := "egress-1-abcd"
	remainingPE := "egress-2-abcd"

	remainingPolicy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: remainingPE, Namespace: namespace},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef:   policyendpoint.PolicyReference{Name: "egress-2", Namespace: namespace},
			Egress: []policyendpoint.EndpointInfo{
				{
					CIDR:  "10.0.0.0/24",
					Ports: []policyendpoint.Port{{Port: &port80, Protocol: &protocolTCP}},
				},
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{}
	r := NewPolicyEndpointsReconciler(mockClient, "1.1.1.1", mockBpf, false)
	r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{remainingPE})

	mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: remainingPE, Namespace: namespace}, gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = remainingPolicy
			return nil
		},
	).AnyTimes()

	targetPod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: "deployment1rs-1", Namespace: namespace},
		PodIP:          "10.1.1.1",
	}

	err := r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true)
	assert.NoError(t, err)

	catchAll := fwrp.EbpfFirewallRules{IPCidr: "0.0.0.0/0"}
	assert.Contains(t, mockBpf.LastIngressRules, catchAll)
	assert.NotContains(t, mockBpf.LastEgressRules, catchAll)
	assert.NotEmpty(t, mockBpf.LastEgressRules)
}

// When the remaining PolicyEndpoint has BOTH ingress and egress rules,
// neither side should get a 0.0.0.0/0 catch-all appended on cleanup —
// the existing rule sets are non-empty so the dataplane will not drop traffic.
func TestCleanupPod_BothDirectionsActiveNoCatchAll(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	namespace := "my-namespace"
	podIdentifier := "deployment1rs@my-namespace"
	cleanedUpPE := "ingress-1-abcd"
	remainingPE := "mixed-2-abcd"

	remainingPolicy := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: remainingPE, Namespace: namespace},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef:   policyendpoint.PolicyReference{Name: "mixed-2", Namespace: namespace},
			Ingress: []policyendpoint.EndpointInfo{
				{
					CIDR:  "10.0.0.0/24",
					Ports: []policyendpoint.Port{{Port: &port80, Protocol: &protocolTCP}},
				},
			},
			Egress: []policyendpoint.EndpointInfo{
				{
					CIDR:  "10.0.1.0/24",
					Ports: []policyendpoint.Port{{Port: &port80, Protocol: &protocolTCP}},
				},
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{}
	r := NewPolicyEndpointsReconciler(mockClient, "1.1.1.1", mockBpf, false)
	r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{remainingPE})

	mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: remainingPE, Namespace: namespace}, gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = remainingPolicy
			return nil
		},
	).AnyTimes()

	targetPod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: "deployment1rs-1", Namespace: namespace},
		PodIP:          "10.1.1.1",
	}

	err := r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true)
	assert.NoError(t, err)

	catchAll := fwrp.EbpfFirewallRules{IPCidr: "0.0.0.0/0"}
	assert.NotContains(t, mockBpf.LastIngressRules, catchAll)
	assert.NotContains(t, mockBpf.LastEgressRules, catchAll)
	assert.NotEmpty(t, mockBpf.LastIngressRules)
	assert.NotEmpty(t, mockBpf.LastEgressRules)
}

// Regression test for #686: a map write failure must return an error so the
// PolicyEndpoint is requeued.
func TestPolicyEndpointReconcile_MapUpdateFailureRequeues(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	localPod := policyendpoint.PodEndpoint{
		HostIP:    policyendpoint.NetworkAddress(nodeIP),
		PodIP:     "10.1.1.1",
		Name:      "deployment1rs-1",
		Namespace: namespace,
	}

	enomem := errors.New("unable to update map: cannot allocate memory")

	tests := []struct {
		name             string
		updateEbpfMapErr error
		wantErr          bool
	}{
		{
			name:             "map write failure surfaces so the item is requeued",
			updateEbpfMapErr: enomem,
			wantErr:          true,
		},
		{
			name:    "successful map write still reports success",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mock_client.NewMockClient(ctrl)
			mockBpf := &ebpf.MockBpfClient{UpdateEbpfMapsErr: tt.updateEbpfMapErr}
			r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

			pe := getPolicyEndpoint("allow-all-egress", namespace, []policyendpoint.PodEndpoint{localPod})

			mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
					*currentPE = pe
					return nil
				},
			).AnyTimes()

			mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
				func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
					*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
					return nil
				},
			).AnyTimes()

			_, err := r.Reconcile(context.TODO(), controllerruntime.Request{
				NamespacedName: types.NamespacedName{Name: pe.GetName(), Namespace: pe.GetNamespace()},
			})

			if tt.wantErr {
				require.Error(t, err, "map write failure must surface as a reconcile error so the item is requeued")
				assert.ErrorIs(t, err, tt.updateEbpfMapErr, "the underlying map-write error must be preserved for diagnosis")
				assert.Contains(t, err.Error(), "deployment1rs@"+namespace)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// A failure on one pod identifier must not skip the others.
func TestPolicyEndpointReconcile_MapUpdateFailureAttemptsAllPodIdentifiers(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"

	// Two distinct pod identifiers on this node: deployment1rs and deployment2rs.
	pods := []policyendpoint.PodEndpoint{
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.1", Name: "deployment1rs-1", Namespace: namespace},
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.2", Name: "deployment2rs-1", Namespace: namespace},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{UpdateEbpfMapsErr: errors.New("cannot allocate memory")}
	r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

	pe := getPolicyEndpoint("allow-all-egress", namespace, pods)

	mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = pe
			return nil
		},
	).AnyTimes()

	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
			*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
			return nil
		},
	).AnyTimes()

	_, err := r.Reconcile(context.TODO(), controllerruntime.Request{
		NamespacedName: types.NamespacedName{Name: pe.GetName(), Namespace: pe.GetNamespace()},
	})

	require.Error(t, err)

	updateCalls := 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateEbpfMaps" {
			updateCalls++
		}
	}
	assert.Equal(t, 2, updateCalls, "both pod identifiers must be attempted despite the first failing")
}

// getPolicyEndpointWithTriggerTime is getPolicyEndpoint with the
// last-change-trigger-time annotation set.
func getPolicyEndpointWithTriggerTime(npName, namespace string, podEndpoints []policyendpoint.PodEndpoint) policyendpoint.PolicyEndpoint {
	pe := getPolicyEndpoint(npName, namespace, podEndpoints)
	pe.Annotations = map[string]string{
		LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano),
	}
	return pe
}

// A failed reconcile records no latency and leaves the annotation for the retry,
// which then records it.
func TestPolicyEndpointReconcile_FailedProgrammingRecordsNoLatency(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	localPod := policyendpoint.PodEndpoint{
		HostIP:    policyendpoint.NetworkAddress(nodeIP),
		PodIP:     "10.1.1.1",
		Name:      "deployment1rs-1",
		Namespace: namespace,
	}

	newReconciler := func(t *testing.T, injected error) (*PolicyEndpointsReconciler, policyendpoint.PolicyEndpoint) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		mockClient := mock_client.NewMockClient(ctrl)
		r := NewPolicyEndpointsReconciler(mockClient, nodeIP, &ebpf.MockBpfClient{UpdateEbpfMapsErr: injected}, false)
		// Latency is only observed for trigger times after trackerStartTime.
		r.trackerStartTime = time.Now().Add(-time.Minute)
		pe := getPolicyEndpointWithTriggerTime("allow-all-egress", namespace, []policyendpoint.PodEndpoint{localPod})

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
				*currentPE = pe
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
				*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
				return nil
			},
		).AnyTimes()
		return r, pe
	}

	t.Run("successful programming records one sample", func(t *testing.T) {
		r, pe := newReconciler(t, nil)
		before := histSampleCount(t, policyProgrammingLatency)
		require.NoError(t, r.reconcilePolicyEndpoint(context.TODO(), &pe))
		assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before)
	})

	t.Run("failed programming records nothing and leaves the annotation for the requeue", func(t *testing.T) {
		injected := errors.New("unable to update map: cannot allocate memory")
		r, pe := newReconciler(t, injected)

		before := histSampleCount(t, policyProgrammingLatency)
		err := r.reconcilePolicyEndpoint(context.TODO(), &pe)
		require.Error(t, err)
		assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
			"a failed programming attempt must not record E2E latency")

		// Requeue with the map write now succeeding.
		r.ebpfClient.(*ebpf.MockBpfClient).UpdateEbpfMapsErr = nil
		require.NoError(t, r.reconcilePolicyEndpoint(context.TODO(), &pe))
		assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
			"the requeue that succeeds must record the true E2E latency")
	})
}

// Attach failures must not skip the map update shared by the identifier's pods.
func TestConfigureeBPFProbes_AttachFailureMatrix(t *testing.T) {
	const namespace = "my-namespace"
	const podIdentifier = "deployment1rs@" + namespace
	attachErr := errors.New("failed to find host veth: Pod might have been deleted")

	pod := func(name string) npatypes.Pod {
		return npatypes.Pod{NamespacedName: types.NamespacedName{Name: name, Namespace: namespace}}
	}
	siblings := []npatypes.Pod{pod("deployment1rs-1"), pod("deployment1rs-2")}

	tests := []struct {
		name string
		// failPods are the pods whose AttacheBPFProbes returns an error.
		failPods []string
		// skipPods return ErrProbeAttachSkipped.
		skipPods []string
		// noContext means no eBPF context is registered for the identifier.
		noContext bool
		// updateErr injects a shared-map-write failure alongside the attach ones.
		updateErr    error
		targetPods   []npatypes.Pod
		wantErr      error
		wantAlsoErr  bool
		wantErrNames string
		wantAttaches int
		wantUpdates  int
		why          string
	}{
		{
			name:         "one sibling fails, context live: the shared write must still run",
			failPods:     []string{"deployment1rs-1"},
			wantErrNames: "my-namespace/deployment1rs-1",
			targetPods:   siblings,
			wantErr:      attachErr,
			wantAttaches: 2,
			wantUpdates:  1,
			why:          "healthy siblings must receive the new rules rather than enforce stale ones",
		},
		{
			name:         "every sibling fails but a context is live: the write can still land",
			failPods:     []string{"deployment1rs-1", "deployment1rs-2"},
			targetPods:   siblings,
			wantErr:      attachErr,
			wantAttaches: 2,
			wantUpdates:  1,
			why:          "a context registered by an earlier reconcile still has maps worth updating",
		},
		{
			name:         "every sibling fails and no context exists: skip the futile write",
			failPods:     []string{"deployment1rs-1", "deployment1rs-2"},
			noContext:    true,
			targetPods:   siblings,
			wantErr:      attachErr,
			wantAttaches: 2,
			wantUpdates:  0,
			why:          "UpdateEbpfMaps would return no-bpf-context and misattribute the attach failure in sdkAPIErr",
		},
		{
			name:         "every pod deliberately skipped and no context: success, no write",
			skipPods:     []string{"deployment1rs-1", "deployment1rs-2"},
			noContext:    true,
			targetPods:   siblings,
			wantAttaches: 2,
			wantUpdates:  0,
			why:          "a deliberate skip must not requeue, and with no context there is nothing to write",
		},
		{
			name:     "a departed pod is not a programming failure: skip, report success",
			failPods: nil,
			// Deleted pods attach with nil and leave no context: not an error.
			noContext:    true,
			targetPods:   siblings,
			wantAttaches: 2,
			wantUpdates:  0,
			why:          "a pod whose CNI DEL already ran must not be counted as a programming failure",
		},
		{
			name:         "attach and map write both fail: both errors survive",
			failPods:     []string{"deployment1rs-1"},
			updateErr:    errors.New("unable to update map: cannot allocate memory"),
			targetPods:   siblings,
			wantErr:      attachErr,
			wantAlsoErr:  true,
			wantAttaches: 2,
			wantUpdates:  1,
			why:          "the attach error names the pod; the map error names the cause; triage needs both",
		},
		{
			name: "no pod of this identifier: nothing to attach and nothing to write",
			targetPods: []npatypes.Pod{
				{NamespacedName: types.NamespacedName{Name: "other-rs-1", Namespace: "other-ns"}},
			},
			noContext:    true,
			wantAttaches: 0,
			wantUpdates:  0,
			why:          "unreachable from the sole caller, since podIdentifiers derives from targetPods; kept as a defensive guard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBpf := &ebpf.MockBpfClient{UpdateEbpfMapsErr: tt.updateErr}
			if len(tt.failPods) > 0 || len(tt.skipPods) > 0 {
				mockBpf.AttacheBPFProbesErrByPod = map[string]error{}
				for _, n := range tt.failPods {
					mockBpf.AttacheBPFProbesErrByPod[namespace+"/"+n] = attachErr
				}
				for _, n := range tt.skipPods {
					mockBpf.AttacheBPFProbesErrByPod[namespace+"/"+n] = fmt.Errorf(
						"%w: multiNIC enabled and interface count is unknown", ebpf.ErrProbeAttachSkipped)
				}
			}
			if tt.noContext {
				mockBpf.PodIdentifiersWithoutBPFContext = map[string]bool{podIdentifier: true}
			}
			r := &PolicyEndpointsReconciler{ebpfClient: mockBpf}

			programmed, err := r.configureeBPFProbes(context.TODO(), podIdentifier, tt.targetPods, nil, nil)

			if tt.wantErr != nil {
				require.Error(t, err, "the failing pod must be reported so it is retried")
				assert.ErrorIs(t, err, tt.wantErr)
				if tt.wantErrNames != "" {
					assert.Contains(t, err.Error(), tt.wantErrNames)
				}
				if tt.wantAlsoErr {
					assert.ErrorIs(t, err, tt.updateErr,
						"errors.Join must keep the map-write cause alongside the attach error")
				}
			} else {
				require.NoError(t, err)
			}

			attaches, updates := 0, 0
			for _, c := range mockBpf.CallLog {
				switch c {
				case "AttacheBPFProbes":
					attaches++
				case "UpdateEbpfMaps":
					updates++
				}
			}
			assert.Equal(t, tt.wantAttaches, attaches, "attach attempts")
			assert.Equal(t, tt.wantUpdates, updates, "shared map writes: %s", tt.why)
			assert.Equal(t, tt.wantUpdates == 1 && tt.updateErr == nil, programmed,
				"programmed must report whether the shared map write happened")
		})
	}
}

// ErrProbeAttachSkipped must not become a reconcile error.
func TestConfigureeBPFProbes_SkippedAttachIsNotAProgrammingFailure(t *testing.T) {
	namespace := "my-namespace"
	podIdentifier := "deployment1rs@" + namespace

	skipped := fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	mockBpf := &ebpf.MockBpfClient{
		AttacheBPFProbesErrByPod: map[string]error{
			namespace + "/deployment1rs-1": skipped,
			namespace + "/deployment1rs-2": skipped,
		},
	}
	r := &PolicyEndpointsReconciler{ebpfClient: mockBpf}

	targetPods := []npatypes.Pod{
		{NamespacedName: types.NamespacedName{Name: "deployment1rs-1", Namespace: namespace}},
		{NamespacedName: types.NamespacedName{Name: "deployment1rs-2", Namespace: namespace}},
	}

	programmed, err := r.configureeBPFProbes(context.TODO(), podIdentifier, targetPods, nil, nil)
	require.NoError(t, err, "a deliberate skip must not become a programming failure that requeues forever")
	assert.True(t, programmed, "a live context means the shared map write happened")

	updates := 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateEbpfMaps" {
			updates++
		}
	}
	assert.Equal(t, 1, updates, "a context from an earlier reconcile still has maps worth updating")
}

// A rule-derivation abort must keep errors accumulated from earlier identifiers.
func TestPolicyEndpointReconcile_DeriveAbortCarriesAccumulatedError(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	deriveErr := errors.New("etcdserver: request timed out")
	enomem := errors.New("unable to update map: cannot allocate memory")
	badPE := "poisoned-pe-abcd"

	attempt := func(t *testing.T) (error, []string) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{UpdateEbpfMapsErr: enomem}
		r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

		pe := getPolicyEndpoint("allow-all-egress", namespace, []policyendpoint.PodEndpoint{
			{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.1", Name: "deployment1rs-1", Namespace: namespace},
			{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.2", Name: "deployment2rs-1", Namespace: namespace},
		})
		r.podIdentifierToPolicyEndpointMap.Store("deployment1rs@"+namespace, []string{badPE})
		r.podIdentifierToPolicyEndpointMap.Store("deployment2rs@"+namespace, []string{pe.GetName()})

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
				if key.Name == badPE {
					return deriveErr
				}
				*currentPE = pe
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
				*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
				return nil
			},
		).AnyTimes()

		err := r.reconcilePolicyEndpoint(context.TODO(), &pe)
		return err, mockBpf.CallLog
	}

	// Map order is random: retry until the failing write ran before the abort.
	for i := 0; i < 200; i++ {
		err, callLog := attempt(t)
		require.Error(t, err)

		attempted := false
		for _, c := range callLog {
			if c == "UpdateEbpfMaps" {
				attempted = true
			}
		}
		if !attempted {
			continue // derive identifier came first; try again
		}

		assert.ErrorIs(t, err, deriveErr, "the derive failure must surface")
		assert.ErrorIs(t, err, enomem,
			"the earlier identifier's map-write cause must not be discarded by the derive abort")
		assert.Contains(t, err.Error(), "deployment2rs@"+namespace,
			"the accumulated error names the identifier whose map write failed")
		return
	}
	t.Fatal("map iteration never scheduled the map-write identifier first in 200 attempts; with two identifiers this is unreachable, so the fixture has changed")
}

// A reconcile that programmed nothing records no latency, and the later one that
// does program records it.
func TestPolicyEndpointReconcile_SkippedReconcileDoesNotClaimLatency(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	podIdentifier := "deployment1rs@" + namespace

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	skipped := fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	mockBpf := &ebpf.MockBpfClient{
		AttacheBPFProbesErrByPod:        map[string]error{namespace + "/deployment1rs-1": skipped},
		PodIdentifiersWithoutBPFContext: map[string]bool{podIdentifier: true},
	}
	r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)
	r.trackerStartTime = time.Now().Add(-time.Minute)

	pe := getPolicyEndpointWithTriggerTime("allow-all-egress", namespace, []policyendpoint.PodEndpoint{
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.1", Name: "deployment1rs-1", Namespace: namespace},
	})

	mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = pe
			return nil
		},
	).AnyTimes()
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
			*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
			return nil
		},
	).AnyTimes()

	before := histSampleCount(t, policyProgrammingLatency)

	// Pass 1: skipped, no context. Nothing programmed.
	require.NoError(t, r.reconcilePolicyEndpoint(context.TODO(), &pe),
		"a deliberate skip must not requeue")
	writes := 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateEbpfMaps" {
			writes++
		}
	}
	require.Equal(t, 0, writes, "fixture precondition: nothing was written")
	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"a reconcile that programmed nothing must not record a latency sample")

	// Pass 2: the CNI ADD has landed, so the context exists and the attach works.
	mockBpf.PodIdentifiersWithoutBPFContext = nil
	mockBpf.AttacheBPFProbesErrByPod = nil
	mockBpf.CallLog = nil
	require.NoError(t, r.reconcilePolicyEndpoint(context.TODO(), &pe))
	writes = 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateEbpfMaps" {
			writes++
		}
	}
	require.Equal(t, 1, writes, "fixture precondition: the real write happened")
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
		"the reconcile that actually programmed must record the sample, which requires the skipped pass to have left the annotation unconsumed")
}

// A rule-derivation failure stops the loop; the requeue programs the rest.
func TestPolicyEndpointReconcile_DeriveFailureAbortsRemainingIdentifiers(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	deriveErr := errors.New("etcdserver: request timed out")
	badPE := "poisoned-pe-abcd"

	attempt := func(t *testing.T) (error, int) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}
		r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

		pe := getPolicyEndpoint("allow-all-egress", namespace, []policyendpoint.PodEndpoint{
			{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.1", Name: "deployment1rs-1", Namespace: namespace},
			{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.2", Name: "deployment2rs-1", Namespace: namespace},
		})
		r.podIdentifierToPolicyEndpointMap.Store("deployment1rs@"+namespace, []string{badPE})
		r.podIdentifierToPolicyEndpointMap.Store("deployment2rs@"+namespace, []string{pe.GetName()})

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
				if key.Name == badPE {
					return deriveErr
				}
				*currentPE = pe
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
				*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
				return nil
			},
		).AnyTimes()

		err := r.reconcilePolicyEndpoint(context.TODO(), &pe)
		writes := 0
		for _, c := range mockBpf.CallLog {
			if c == "UpdateEbpfMaps" {
				writes++
			}
		}
		return err, writes
	}

	// Map order is random: only the poisoned identifier going first tells abort
	// from continue.
	for i := 0; i < 200; i++ {
		err, writes := attempt(t)
		require.Error(t, err)
		assert.ErrorIs(t, err, deriveErr)
		if writes == 0 {
			return // poisoned identifier went first and the loop aborted
		}
	}
	t.Fatal("map iteration never scheduled the poisoned identifier first in 200 attempts; with two identifiers this is unreachable, so the fixture has changed")
}

// Latency is recorded when at least one identifier was programmed.
func TestPolicyEndpointReconcile_LatencyRecordedWhenAnyIdentifierProgrammed(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	skipped := fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	// deployment1rs is skipped with no context; deployment2rs programs normally.
	mockBpf := &ebpf.MockBpfClient{
		AttacheBPFProbesErrByPod:        map[string]error{namespace + "/deployment1rs-1": skipped},
		PodIdentifiersWithoutBPFContext: map[string]bool{"deployment1rs@" + namespace: true},
	}
	r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)
	r.trackerStartTime = time.Now().Add(-time.Minute)

	pe := getPolicyEndpointWithTriggerTime("allow-all-egress", namespace, []policyendpoint.PodEndpoint{
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.1", Name: "deployment1rs-1", Namespace: namespace},
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.2", Name: "deployment2rs-1", Namespace: namespace},
	})

	mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = pe
			return nil
		},
	).AnyTimes()
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
			*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
			return nil
		},
	).AnyTimes()

	before := histSampleCount(t, policyProgrammingLatency)
	require.NoError(t, r.reconcilePolicyEndpoint(context.TODO(), &pe))

	writes := 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateEbpfMaps" {
			writes++
		}
	}
	require.Equal(t, 1, writes, "fixture precondition: exactly one identifier programmed")
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
		"a reconcile that programmed at least one identifier must record a sample even though another was skipped")
}

// A PolicyEndpoint with no local pods still records latency, as before.
func TestPolicyEndpointReconcile_NoLocalIdentifiersStillRecords(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{}
	r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)
	r.trackerStartTime = time.Now().Add(-time.Minute)

	// Every pod is on a different node, so podIdentifiers is empty.
	pe := getPolicyEndpointWithTriggerTime("allow-all-egress", namespace, []policyendpoint.PodEndpoint{
		{HostIP: policyendpoint.NetworkAddress("9.9.9.9"), PodIP: "10.9.9.1", Name: "elsewhere-1", Namespace: namespace},
	})

	mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = pe
			return nil
		},
	).AnyTimes()
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
			*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
			return nil
		},
	).AnyTimes()

	before := histSampleCount(t, policyProgrammingLatency)
	require.NoError(t, r.reconcilePolicyEndpoint(context.TODO(), &pe))

	for _, c := range mockBpf.CallLog {
		require.NotEqual(t, "UpdateEbpfMaps", c, "fixture precondition: no local identifier to program")
	}
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
		"a PolicyEndpoint with no local pod identifiers keeps the pre-change behaviour and records a sample")
}

// An attach failure suppresses latency even when the map write succeeded, and
// both identifiers' errors are returned.
func TestPolicyEndpointReconcile_AttachFailureWithLiveContextSuppressesLatency(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	errOne := errors.New("failed to find link enif00d1e2c3d4: Link not found")
	errTwo := errors.New("failed to find link enifaabbccdd: Link not found")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{
		AttacheBPFProbesErrByPod: map[string]error{
			namespace + "/deployment1rs-1": errOne,
			namespace + "/deployment2rs-1": errTwo,
		},
	}
	r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)
	r.trackerStartTime = time.Now().Add(-time.Minute)

	pe := getPolicyEndpointWithTriggerTime("allow-all-egress", namespace, []policyendpoint.PodEndpoint{
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.1", Name: "deployment1rs-1", Namespace: namespace},
		{HostIP: policyendpoint.NetworkAddress(nodeIP), PodIP: "10.1.1.2", Name: "deployment2rs-1", Namespace: namespace},
	})

	mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = pe
			return nil
		},
	).AnyTimes()
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
			*list = policyendpoint.PolicyEndpointList{Items: []policyendpoint.PolicyEndpoint{pe}}
			return nil
		},
	).AnyTimes()

	before := histSampleCount(t, policyProgrammingLatency)
	err := r.reconcilePolicyEndpoint(context.TODO(), &pe)

	require.Error(t, err, "the attach failures must surface so the item is requeued")

	writes := 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateEbpfMaps" {
			writes++
		}
	}
	require.Equal(t, 2, writes, "fixture precondition: the map write lands despite the attach failures")

	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"a reconcile returning an error must not record a latency sample even though the map write landed")

	// Both distinct causes must survive the loop's errors.Join.
	assert.ErrorIs(t, err, errOne, "the first identifier's cause must survive the Join")
	assert.ErrorIs(t, err, errTwo, "the second identifier's cause must survive the Join")
}
