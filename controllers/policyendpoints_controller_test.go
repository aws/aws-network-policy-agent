package controllers

import (
	"context"
	"sync"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
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
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, nodeIp, &ebpf.MockBpfClient{})

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
		assert.True(t, lo.Contains(val.([]string), "deployment1rs-my-namespace"))

		val, ok = policyEndpointReconciler.podIdentifierToPolicyEndpointMap.Load("deployment1rs-my-namespace")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "allow-all-egress-abcd"))

		val, ok = policyEndpointReconciler.policyEndpointSelectorMap.Load("allow-all-egress-abcdmy-namespace")
		assert.True(t, ok)
		assert.Equal(t, 2, len(val.([]types.NamespacedName)))
	})

	t.Run("Reconcile for Create and Delete PE", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, nodeIp, &ebpf.MockBpfClient{})

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
		assert.True(t, lo.Contains(val.([]string), "deployment1rs-my-namespace"))

		val, ok = policyEndpointReconciler.podIdentifierToPolicyEndpointMap.Load("deployment1rs-my-namespace")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "allow-all-egress-abcd"))

		val, ok = policyEndpointReconciler.policyEndpointSelectorMap.Load("allow-all-egress-abcdmy-namespace")
		assert.True(t, ok)
		assert.Equal(t, 2, len(val.([]types.NamespacedName)))

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

func TestIsProgFdShared(t *testing.T) {
	type want struct {
		isProgFdShared bool
	}
	podToProgFd := map[string]int{
		"pod1A": 2,
		"pod2A": 2,
		"pod1B": 15,
	}
	tests := []struct {
		name         string
		podName      string
		podNamespace string
		want         want
		wantErr      error
	}{
		{
			name:         "ProgFD Shared",
			podName:      "pod1",
			podNamespace: "A",

			want: want{
				isProgFdShared: true,
			},
			wantErr: nil,
		},
		{
			name:         "ProgFD Not Shared",
			podName:      "pod1",
			podNamespace: "B",
			want: want{
				isProgFdShared: false,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil)
		policyEndpointReconciler.ebpfClient = ebpf.NewMockBpfClient()
		for pod, progFd := range podToProgFd {
			policyEndpointReconciler.ebpfClient.GetIngressPodToProgMap().Store(pod, progFd)
			currentPodSet, _ := policyEndpointReconciler.ebpfClient.GetIngressProgToPodsMap().LoadOrStore(progFd, make(map[string]struct{}))
			currentPodSet.(map[string]struct{})[pod] = struct{}{}
		}

		t.Run(tt.name, func(t *testing.T) {
			isProgFdShared, _ := policyEndpointReconciler.IsProgFdShared(tt.podName, tt.podNamespace)
			assert.Equal(t, tt.want.isProgFdShared, isProgFdShared)
		})
	}
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
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil)
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
		}

		t.Run(tt.name, func(t *testing.T) {
			gotIsIngressIsolated, gotIsEgressIsolated := policyEndpointReconciler.deriveDefaultPodIsolation(context.Background(),
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
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil)
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
		policyEndpointReconciler := NewPolicyEndpointsReconciler(mockClient, "", nil)
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
