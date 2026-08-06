package controllers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
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

// Shared fixture for the selector-narrowing scenario (the design's bug
// condition). Used by TestCleanupPodStaleDataplane and by the task 3.4
// fix-checking tests below so every variant exercises the exact same setup and
// only the MockBpfClient configuration differs.
const (
	narrowingNamespace     = "my-namespace"
	narrowingNodeIP        = "1.1.1.1"
	narrowingParentNP      = "allow-all-egress"
	narrowingPodName       = "deployment1rs-1"
	narrowingPodIdentifier = "deployment1rs@my-namespace"
)

// runSelectorNarrowingReconcile drives one Reconcile over the selector-narrowing
// scenario: the PolicyEndpoint no longer selects any local pod
// (PodSelectorEndpoints is empty) while the controller caches still hold the old
// pod and its podIdentifier. deriveTargetPodsForParentNP() drops the
// podIdentifier from podIdentifierToPolicyEndpointMap before cleanupPod() runs,
// so cleanupPod() takes the "no policies remain" path.
//
// mockBpf is supplied by the caller so each test can configure
// PodIdentifiersWithoutBPFContext / NetworkPolicyMode and then assert on the
// recorded calls.
func runSelectorNarrowingReconcile(t *testing.T, mockBpf *ebpf.MockBpfClient) (*PolicyEndpointsReconciler, error) {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockClient := mock_client.NewMockClient(ctrl)
	r := NewPolicyEndpointsReconciler(mockClient, narrowingNodeIP, mockBpf, false)

	// PolicyEndpoint after the podSelector narrowing: no local pod is selected
	// anymore, so PodSelectorEndpoints is empty.
	narrowedPE := getPolicyEndpoint(narrowingParentNP, narrowingNamespace, []policyendpoint.PodEndpoint{})

	stalePod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: narrowingPodName, Namespace: narrowingNamespace},
		PodIP:          "10.1.1.1",
	}

	// Controller caches still reflect the pre-narrowing state.
	r.policyEndpointSelectorMap.Store(utils.GetPolicyEndpointIdentifier(narrowedPE.Name, narrowingNamespace),
		[]npatypes.Pod{stalePod})
	r.podIdentifierToPolicyEndpointMap.Store(narrowingPodIdentifier, []string{narrowedPE.Name})
	r.networkPolicyToPodIdentifierMap.Store(narrowingParentNP, []string{narrowingPodIdentifier})

	mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{
		Name:      narrowedPE.GetName(),
		Namespace: narrowedPE.GetNamespace(),
	}, gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
			*currentPE = narrowedPE
			return nil
		},
	).AnyTimes()

	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyendpoint.PolicyEndpointList, opts ...*client.ListOptions) error {
			*list = policyendpoint.PolicyEndpointList{
				Items: []policyendpoint.PolicyEndpoint{narrowedPE},
			}
			return nil
		},
	).AnyTimes()

	_, err := r.Reconcile(context.TODO(), controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Name:      narrowedPE.GetName(),
			Namespace: narrowedPE.GetNamespace(),
		},
	})
	return r, err
}

// TestCleanupPodStaleDataplane reproduces the selector-narrowing scenario: a
// NetworkPolicy's podSelector is narrowed so the local pod is no longer selected
// (PolicyEndpoint.Spec.PodSelectorEndpoints becomes empty) while the controller
// caches still hold the pod and its podIdentifier.
//
// This is the bug condition from the design doc:
//
//	NOT exists(podIdentifierToPolicyEndpointMap[podIdentifier]) AND ebpfClient.HasBPFContext(podIdentifier) == true
//
// The assertions below encode the EXPECTED behavior (design `expectedBehavior`):
// the dataplane is cleaned to the mode's default state with empty rule sets.
//
// **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
func TestCleanupPodStaleDataplane(t *testing.T) {
	podIdentifier := narrowingPodIdentifier

	mockBpf := &ebpf.MockBpfClient{}
	r, err := runSelectorNarrowingReconcile(t, mockBpf)

	assert.NoError(t, err)

	// Bug condition precondition 1: the control plane cache no longer tracks any
	// PolicyEndpoint for this podIdentifier.
	_, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier)
	assert.False(t, ok, "podIdentifierToPolicyEndpointMap should no longer track the deselected podIdentifier")
	assert.Equal(t, 0, sizeOfSyncMap(&r.networkPolicyToPodIdentifierMap))

	// Bug condition precondition 2: the dataplane is still programmed for it.
	assert.True(t, mockBpf.HasBPFContext(podIdentifier))

	// Expected behavior: a full map update with empty rule sets, pod state reset
	// to the standard-mode default (DEFAULT_ALLOW).
	assert.Contains(t, mockBpf.CallLog, "UpdateEbpfMaps",
		"stale dataplane must be cleared via UpdateEbpfMaps when no policies remain")
	assert.Contains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps",
		"pod state must be reset when no policies remain")
	assert.Equal(t, ebpf.POD_STATE_MAP_KEY, mockBpf.LastPodStateKey)
	assert.Equal(t, ebpf.DEFAULT_ALLOW, mockBpf.LastPodState)
	assert.Empty(t, mockBpf.LastIngressRules)
	assert.Empty(t, mockBpf.LastEgressRules)

	// Task 3.4 fix checking, standard mode. Companion assertions that pin down
	// HOW the default state was reached: the no-policies-remain branch must reuse
	// the existing updateeBPFMaps() path end to end, in order, and nothing else
	// may touch the bpf client during this reconcile.
	t.Run("reuses the full updateeBPFMaps sequence", func(t *testing.T) {
		assert.Equal(t,
			[]string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
			mockBpf.CallLog)
	})

	// DEFAULT_ALLOW above is only meaningful if the mode under test really is
	// standard - otherwise the assertion would pass vacuously.
	t.Run("standard mode drives the DEFAULT_ALLOW selection", func(t *testing.T) {
		assert.Equal(t, "standard", r.GeteBPFClient().GetNetworkPolicyMode())
		assert.False(t, utils.IsStrictMode(r.GeteBPFClient().GetNetworkPolicyMode()))
	})
}

// TestCleanupPodStaleDataplaneWithoutBPFContextIsNoOp is task 3.4 test 2: the
// same selector-narrowing scenario, but the pod no longer holds an eBPF context
// (it is already gone from the node). The no-policies-remain branch must bail out
// before touching any map and must not report an error.
//
// **Validates: Requirements 2.4**
func TestCleanupPodStaleDataplaneWithoutBPFContextIsNoOp(t *testing.T) {
	mockBpf := &ebpf.MockBpfClient{
		PodIdentifiersWithoutBPFContext: map[string]bool{narrowingPodIdentifier: true},
	}
	r, err := runSelectorNarrowingReconcile(t, mockBpf)

	assert.NoError(t, err)

	// Same control-plane precondition as TestCleanupPodStaleDataplane: the cache
	// entry is gone. Only the dataplane side of the bug condition differs.
	_, ok := r.podIdentifierToPolicyEndpointMap.Load(narrowingPodIdentifier)
	assert.False(t, ok, "podIdentifierToPolicyEndpointMap should no longer track the deselected podIdentifier")
	assert.False(t, mockBpf.HasBPFContext(narrowingPodIdentifier))

	assert.NotContains(t, mockBpf.CallLog, "UpdateEbpfMaps",
		"no map update expected when the pod has no eBPF context")
	assert.NotContains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps",
		"no pod state update expected when the pod has no eBPF context")
	assert.Empty(t, mockBpf.CallLog, "cleanup must be a complete no-op")
}

// TestCleanupPodStaleDataplaneStrictMode is task 3.4 test 3: identical to
// TestCleanupPodStaleDataplane except the agent runs in strict mode, so the
// stale dataplane must be reset to DEFAULT_DENY instead of DEFAULT_ALLOW.
//
// **Validates: Requirements 2.1, 2.2, 2.5**
func TestCleanupPodStaleDataplaneStrictMode(t *testing.T) {
	mockBpf := &ebpf.MockBpfClient{NetworkPolicyMode: "strict"}
	r, err := runSelectorNarrowingReconcile(t, mockBpf)

	assert.NoError(t, err)
	assert.True(t, utils.IsStrictMode(r.GeteBPFClient().GetNetworkPolicyMode()))

	_, ok := r.podIdentifierToPolicyEndpointMap.Load(narrowingPodIdentifier)
	assert.False(t, ok, "podIdentifierToPolicyEndpointMap should no longer track the deselected podIdentifier")
	assert.Equal(t, 0, sizeOfSyncMap(&r.networkPolicyToPodIdentifierMap))
	assert.True(t, mockBpf.HasBPFContext(narrowingPodIdentifier))

	assert.Contains(t, mockBpf.CallLog, "UpdateEbpfMaps",
		"stale dataplane must be cleared via UpdateEbpfMaps when no policies remain")
	assert.Contains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps",
		"pod state must be reset when no policies remain")
	assert.Equal(t, ebpf.POD_STATE_MAP_KEY, mockBpf.LastPodStateKey)
	assert.Equal(t, ebpf.DEFAULT_DENY, mockBpf.LastPodState,
		"strict mode must fall back to DEFAULT_DENY, not DEFAULT_ALLOW")
	assert.Empty(t, mockBpf.LastIngressRules)
	assert.Empty(t, mockBpf.LastEgressRules)
}

// --- Property 2: Preservation ------------------------------------------------
//
// Baseline observed on UNFIXED code. These assertions are a snapshot of the
// current behavior of cleanupPod() for inputs where isBugCondition(X) is FALSE,
// i.e. everything the fix in task 3.3 must leave untouched:
//
//	(a) podIdentifier IS still present in podIdentifierToPolicyEndpointMap
//	    -> rules are re-derived from the remaining PolicyEndpoints, a
//	       0.0.0.0/0 catch-all is appended to whichever direction has no
//	       active policy, and pod state stays at POLICIES_APPLIED.
//	(b) podIdentifier is ABSENT from the map AND HasBPFContext() == false
//	    -> complete no-op: err == nil and CallLog records no map updates.
//
// Go has no built-in property-based testing framework, so the property is
// approximated by exhaustive combinatorial enumeration over the input space:
//
//	remaining PE count {1, 2} x isolation {none, ingress-only, egress-only, both}
//	x HasBPFContext {true, false}
//
// The HasBPFContext dimension is a structural invariant check for case (a):
// the value must not influence the outcome, because the guard in cleanupPod()
// takes the cache-present path before HasBPFContext() is ever consulted.

// peIsolationShape describes how a remaining PolicyEndpoint is built for the
// preservation matrix.
type peIsolationShape string

const (
	// shapeNone: rules on both directions, no PodIsolation.
	shapeNone peIsolationShape = "none"
	// shapeIngressOnly: ingress isolation only, no rules.
	shapeIngressOnly peIsolationShape = "ingress-only"
	// shapeEgressOnly: egress isolation only, no rules.
	shapeEgressOnly peIsolationShape = "egress-only"
	// shapeBoth: ingress and egress isolation, no rules.
	shapeBoth peIsolationShape = "both"
)

// buildRemainingPE builds one of the four isolation shapes above.
func buildRemainingPE(name, parentNP, namespace string, shape peIsolationShape) policyendpoint.PolicyEndpoint {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	pe := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyendpoint.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef:   policyendpoint.PolicyReference{Name: parentNP, Namespace: namespace},
		},
	}

	switch shape {
	case shapeNone:
		pe.Spec.Ingress = []policyendpoint.EndpointInfo{
			{CIDR: "10.0.0.0/24", Ports: []policyendpoint.Port{{Port: &port80, Protocol: &protocolTCP}}},
		}
		pe.Spec.Egress = []policyendpoint.EndpointInfo{
			{CIDR: "10.0.1.0/24", Ports: []policyendpoint.Port{{Port: &port80, Protocol: &protocolTCP}}},
		}
	case shapeIngressOnly:
		pe.Spec.PodIsolation = []networking.PolicyType{networking.PolicyTypeIngress}
	case shapeEgressOnly:
		pe.Spec.PodIsolation = []networking.PolicyType{networking.PolicyTypeEgress}
	case shapeBoth:
		pe.Spec.PodIsolation = []networking.PolicyType{networking.PolicyTypeIngress, networking.PolicyTypeEgress}
	}
	return pe
}

type preservationCombo struct {
	peCount       int
	shape         peIsolationShape
	hasBPFContext bool
}

// preservationCombos enumerates the full 2 x 4 x 2 input space.
func preservationCombos() []preservationCombo {
	var combos []preservationCombo
	for _, peCount := range []int{1, 2} {
		for _, shape := range []peIsolationShape{shapeNone, shapeIngressOnly, shapeEgressOnly, shapeBoth} {
			for _, hasBPFContext := range []bool{true, false} {
				combos = append(combos, preservationCombo{peCount: peCount, shape: shape, hasBPFContext: hasBPFContext})
			}
		}
	}
	return combos
}

// wantRuleCounts returns the observed ingress/egress rule-set sizes and whether
// each direction carries the 0.0.0.0/0 catch-all, for a given combo.
func wantRuleCounts(c preservationCombo) (wantIngress, wantEgress int, ingressCatchAll, egressCatchAll bool) {
	switch c.shape {
	case shapeNone:
		// One ingress and one egress rule per remaining PE; both directions
		// active so no catch-all is appended.
		return c.peCount, c.peCount, false, false
	case shapeIngressOnly:
		// Ingress isolated -> no ingress rules, no ingress catch-all.
		// Egress has no active policy -> catch-all appended.
		return 0, 1, false, true
	case shapeEgressOnly:
		return 1, 0, true, false
	default: // shapeBoth
		// Both directions isolated -> both rule sets stay empty.
		return 0, 0, false, false
	}
}

// TestCleanupPodPreservationProperty freezes the baseline behavior of
// cleanupPod() for all non-bug-condition inputs (Property 2: Preservation).
//
// **Validates: Requirements 2.4, 3.1, 3.2, 3.3, 3.4, 3.6, 3.7, 3.8**
func TestCleanupPodPreservationProperty(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	podIdentifier := "deployment1rs@my-namespace"
	cleanedUpPE := "cleaned-np-abcd"
	catchAll := fwrp.EbpfFirewallRules{IPCidr: "0.0.0.0/0"}

	targetPod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: "deployment1rs-1", Namespace: namespace},
		PodIP:          "10.1.1.1",
	}

	// Case (a): the podIdentifier is still tracked in
	// podIdentifierToPolicyEndpointMap. Rules are re-derived, catch-all entries
	// are appended where a direction has no active policy, and pod state stays
	// at POLICIES_APPLIED - independent of HasBPFContext.
	for _, combo := range preservationCombos() {
		c := combo
		name := fmt.Sprintf("cache-present/pe=%d/isolation=%s/hasBPFContext=%t", c.peCount, c.shape, c.hasBPFContext)
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mock_client.NewMockClient(ctrl)
			mockBpf := &ebpf.MockBpfClient{}
			if !c.hasBPFContext {
				mockBpf.PodIdentifiersWithoutBPFContext = map[string]bool{podIdentifier: true}
			}
			r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

			var remainingPEs []string
			for i := 0; i < c.peCount; i++ {
				parentNP := fmt.Sprintf("remaining-%d", i)
				peName := parentNP + "-abcd"
				pe := buildRemainingPE(peName, parentNP, namespace, c.shape)
				remainingPEs = append(remainingPEs, peName)

				mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: peName, Namespace: namespace}, gomock.Any()).DoAndReturn(
					func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
						*currentPE = pe
						return nil
					},
				).AnyTimes()
			}
			r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, remainingPEs)

			err := r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true)
			assert.NoError(t, err)

			// Observed baseline: the existing update path runs end to end.
			assert.Equal(t,
				[]string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
				mockBpf.CallLog)
			assert.Equal(t, ebpf.POD_STATE_MAP_KEY, mockBpf.LastPodStateKey)
			assert.Equal(t, ebpf.POLICIES_APPLIED, mockBpf.LastPodState,
				"pod state must stay at POLICIES_APPLIED while any PolicyEndpoint remains")

			wantIngress, wantEgress, ingressCatchAll, egressCatchAll := wantRuleCounts(c)
			assert.Len(t, mockBpf.LastIngressRules, wantIngress)
			assert.Len(t, mockBpf.LastEgressRules, wantEgress)
			if ingressCatchAll {
				assert.Contains(t, mockBpf.LastIngressRules, catchAll)
			} else {
				assert.NotContains(t, mockBpf.LastIngressRules, catchAll)
			}
			if egressCatchAll {
				assert.Contains(t, mockBpf.LastEgressRules, catchAll)
			} else {
				assert.NotContains(t, mockBpf.LastEgressRules, catchAll)
			}

			// The podIdentifier entry itself is untouched by cleanupPod().
			val, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier)
			assert.True(t, ok)
			assert.Equal(t, remainingPEs, val.([]string))
		})
	}

	// Case (b): the podIdentifier is absent from the map AND the pod no longer
	// holds an eBPF context. Observed baseline is a complete no-op.
	// HasBPFContext == true with an absent podIdentifier is the bug condition
	// (Property 1) and is deliberately excluded here.
	for _, combo := range preservationCombos() {
		c := combo
		if c.hasBPFContext {
			continue
		}
		name := fmt.Sprintf("cache-absent-no-bpf-context/pe=%d/isolation=%s", c.peCount, c.shape)
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mock_client.NewMockClient(ctrl)
			mockBpf := &ebpf.MockBpfClient{
				PodIdentifiersWithoutBPFContext: map[string]bool{podIdentifier: true},
			}
			r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

			// Nothing is stored in podIdentifierToPolicyEndpointMap: the entry
			// was already removed by deriveTargetPodsForParentNP().
			mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			err := r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true)
			assert.NoError(t, err)

			assert.Empty(t, mockBpf.CallLog, "no-op expected when the pod has no eBPF context")
			assert.NotContains(t, mockBpf.CallLog, "UpdateEbpfMaps")
			assert.NotContains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps")
			assert.False(t, mockBpf.HasBPFContext(podIdentifier))
		})
	}

	// Mock default-mode regression from the controller's point of view: an
	// unconfigured MockBpfClient still reports standard mode, so the
	// DEFAULT_ALLOW / DEFAULT_DENY selection in cleanupPod() keeps its current
	// behavior. The mock-level equivalent lives in
	// pkg/ebpf/bpf_client_mock_behavior_test.go:TestMockBpfClientGetNetworkPolicyModeBehavior.
	t.Run("mock defaults to standard network policy mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		r := NewPolicyEndpointsReconciler(mock_client.NewMockClient(ctrl), nodeIP, &ebpf.MockBpfClient{}, false)
		assert.Equal(t, "standard", r.GeteBPFClient().GetNetworkPolicyMode())
		assert.False(t, utils.IsStrictMode(r.GeteBPFClient().GetNetworkPolicyMode()))
	})
}

// --- Task 3.5: property-based / combinatorial enumeration --------------------
//
// Property 1 is enumerated over the network-policy-mode dimension below.
// Property 2 (preservation) is already enumerated exhaustively over
// remaining PE count {1, 2} x isolation {none, ingress-only, egress-only, both}
// x HasBPFContext {true, false} by TestCleanupPodPreservationProperty above, so
// it is not repeated here. What that matrix does NOT reach is the
// cache-present-but-no-active-policy path, which is the only input where the
// original inner branch and the new no-policies-remain branch produce the same
// pod state - that gap is closed by
// TestCleanupPodGuardNeverEntersNoPoliciesRemainBranch below.

// networkPolicyModeCombos enumerates the mode dimension of Property 1. The
// mixed casing pins down that utils.IsStrictMode() is case-insensitive, and the
// empty value pins down the mock's fallback to standard mode.
func networkPolicyModeCombos() []string {
	return []string{"", "standard", "Strict", "strict"}
}

// wantDefaultPodState derives the expected pod state from utils.IsStrictMode()
// itself rather than from a per-string lookup table, so the expectation cannot
// drift away from the production decision the fix makes.
func wantDefaultPodState(effectiveMode string) int {
	if utils.IsStrictMode(effectiveMode) {
		return ebpf.DEFAULT_DENY
	}
	return ebpf.DEFAULT_ALLOW
}

// TestCleanupPodStaleDataplaneModeProperty enumerates Property 1 (bug
// condition) over NetworkPolicyMode ∈ {"", "standard", "Strict", "strict"} with
// HasBPFContext == true. For every mode the stale dataplane must be reset to the
// state utils.IsStrictMode() dictates, with empty ingress/egress rule sets.
//
// **Validates: Requirements 2.2, 2.5**
func TestCleanupPodStaleDataplaneModeProperty(t *testing.T) {
	for _, mode := range networkPolicyModeCombos() {
		mode := mode
		t.Run(fmt.Sprintf("mode=%q", mode), func(t *testing.T) {
			mockBpf := &ebpf.MockBpfClient{NetworkPolicyMode: mode}
			r, err := runSelectorNarrowingReconcile(t, mockBpf)
			assert.NoError(t, err)

			// Bug condition holds: cache entry gone, dataplane still programmed.
			_, ok := r.podIdentifierToPolicyEndpointMap.Load(narrowingPodIdentifier)
			assert.False(t, ok, "podIdentifierToPolicyEndpointMap should no longer track the deselected podIdentifier")
			assert.True(t, mockBpf.HasBPFContext(narrowingPodIdentifier))

			effectiveMode := r.GeteBPFClient().GetNetworkPolicyMode()
			wantState := wantDefaultPodState(effectiveMode)

			assert.Equal(t,
				[]string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
				mockBpf.CallLog)
			assert.Equal(t, ebpf.POD_STATE_MAP_KEY, mockBpf.LastPodStateKey)
			assert.Equal(t, wantState, mockBpf.LastPodState,
				"pod state must follow utils.IsStrictMode(%q)", effectiveMode)
			assert.Empty(t, mockBpf.LastIngressRules)
			assert.Empty(t, mockBpf.LastEgressRules)
		})
	}
}

// TestCleanupPodGuardNeverEntersNoPoliciesRemainBranch is the structural guard
// invariant: whenever the podIdentifier IS present in
// podIdentifierToPolicyEndpointMap, the new no-policies-remain branch must never
// run, no matter what HasBPFContext() would answer.
//
// The remaining PolicyEndpoint here carries no rules and no PodIsolation, so the
// original inner branch also lands on DEFAULT_ALLOW / DEFAULT_DENY. Pod state
// alone therefore cannot tell the two paths apart - HasBPFContext == false is
// what discriminates them: the new branch would short-circuit to a complete
// no-op, while the cache-present path must still push a full map update. The
// combos where remaining policies keep the pod at POLICIES_APPLIED are already
// enumerated by TestCleanupPodPreservationProperty.
//
// **Validates: Requirements 3.1, 3.2, 3.8**
func TestCleanupPodGuardNeverEntersNoPoliciesRemainBranch(t *testing.T) {
	namespace := "my-namespace"
	nodeIP := "1.1.1.1"
	podIdentifier := "deployment1rs@my-namespace"
	cleanedUpPE := "cleaned-np-abcd"

	targetPod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: "deployment1rs-1", Namespace: namespace},
		PodIP:          "10.1.1.1",
	}

	for _, peCount := range []int{1, 2} {
		for _, hasBPFContext := range []bool{true, false} {
			for _, mode := range networkPolicyModeCombos() {
				peCount, hasBPFContext, mode := peCount, hasBPFContext, mode
				name := fmt.Sprintf("pe=%d/hasBPFContext=%t/mode=%q", peCount, hasBPFContext, mode)
				t.Run(name, func(t *testing.T) {
					ctrl := gomock.NewController(t)
					defer ctrl.Finish()

					mockClient := mock_client.NewMockClient(ctrl)
					mockBpf := &ebpf.MockBpfClient{NetworkPolicyMode: mode}
					if !hasBPFContext {
						mockBpf.PodIdentifiersWithoutBPFContext = map[string]bool{podIdentifier: true}
					}
					r := NewPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf, false)

					var remainingPEs []string
					for i := 0; i < peCount; i++ {
						parentNP := fmt.Sprintf("empty-%d", i)
						peName := parentNP + "-abcd"
						// No rules and no PodIsolation: the cache-present path
						// resolves to "no active policies".
						pe := policyendpoint.PolicyEndpoint{
							ObjectMeta: metav1.ObjectMeta{Name: peName, Namespace: namespace},
							Spec: policyendpoint.PolicyEndpointSpec{
								PodSelector: &metav1.LabelSelector{},
								PolicyRef:   policyendpoint.PolicyReference{Name: parentNP, Namespace: namespace},
							},
						}
						remainingPEs = append(remainingPEs, peName)

						mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: peName, Namespace: namespace}, gomock.Any()).DoAndReturn(
							func(ctx context.Context, key types.NamespacedName, currentPE *policyendpoint.PolicyEndpoint, opts ...client.GetOption) error {
								*currentPE = pe
								return nil
							},
						).AnyTimes()
					}
					r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, remainingPEs)

					err := r.cleanupPod(context.Background(), targetPod, cleanedUpPE, true)
					assert.NoError(t, err)

					// Path signature of the cache-present branch: the full update
					// sequence ran even when HasBPFContext() is false, so the new
					// no-policies-remain branch was never entered.
					assert.Equal(t,
						[]string{"UpdateEbpfMaps", "UpdatePodStateEbpfMaps", "CreatePodStateEbpfEntryIfNotExists"},
						mockBpf.CallLog)
					assert.Equal(t, ebpf.POD_STATE_MAP_KEY, mockBpf.LastPodStateKey)
					assert.Equal(t, wantDefaultPodState(r.GeteBPFClient().GetNetworkPolicyMode()), mockBpf.LastPodState)
					assert.Empty(t, mockBpf.LastIngressRules)
					assert.Empty(t, mockBpf.LastEgressRules)

					// The cache entry itself is untouched by cleanupPod().
					val, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier)
					assert.True(t, ok)
					assert.Equal(t, remainingPEs, val.([]string))
				})
			}
		}
	}
}
