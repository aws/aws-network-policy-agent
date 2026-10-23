// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package rpc

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRunRPCHandler_NoExistingSocket(t *testing.T) {
	testSocketPath := "/tmp/test-rpc-handler.sock"
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath, nil)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestRunRPCHandler_StaleSocketCleanup(t *testing.T) {
	testSocketPath := "/tmp/temp-rpc-handler.sock"

	// Create a stale socket file
	file, err := os.Create(testSocketPath)
	if err != nil {
		t.Fatalf("Failed to create stale socket file: %v", err)
	}
	file.Close()
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath, nil)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestEnforceNpToPod_AttachesAsConfirmedLive(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// A CNI ADD proves the pod exists, so its attach must clear any stale
	// deleted-pod marker under the identifier lock instead of being skipped.
	assert.Equal(t, "AttacheBPFProbes", mockBpfClient.CallLog[0])
	assert.True(t, mockBpfClient.LastAttachPodConfirmedLive)
}

func TestEnforceNpToPod_NilClusterPolicyReconciler_ReturnsError(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: nil,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_NilClusterPolicyEBPFClient_ReturnsError(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil)
	// clusterReconciler with nil eBPF client
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", nil)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_OneReconcilerReady_ReturnsError(t *testing.T) {
	// Reverse case: clusterPolicyReconciler is ready but policyReconciler is nil
	mockBpfClient := &ebpf.MockBpfClient{}
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        nil,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, err.Error(), "One of the policy reconcilers is not ready")
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_BothReconcilersNil_ReturnsSuccess(t *testing.T) {
	s := &server{
		policyReconciler:        nil,
		clusterPolicyReconciler: nil,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestEnforceNpToPod_NoPolicies_UpdatesBothPodStateMaps(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// With no policies and AttacheBPFProbes reporting no first pod,
	// the "no active policies" branch fires and calls UpdatePodStateEbpfMaps twice:
	// once for POD_STATE_MAP_KEY and once for CLUSTER_POLICY_POD_STATE_MAP_KEY
	updateCount := 0
	for _, call := range mockBpfClient.CallLog {
		if call == "UpdatePodStateEbpfMaps" {
			updateCount++
		}
	}
	assert.Equal(t, 2, updateCount, "should update both pod state map and cluster policy pod state map")
}

// TestEnforceNpToPod_FailsClosedOnPodStateError verifies that EnforceNpToPod
// returns an error rather than a success reply when the pod-state map write
// fails on the no-cached-policies path that seeds default-allow/default-deny.
// Both reconcilers are wired so the readiness check passes and execution
// reaches UpdatePodStateEbpfMaps.
func TestEnforceNpToPod_FailsClosedOnPodStateError(t *testing.T) {
	injected := errors.New("simulated pod state write failure")
	mockBpfClient := &ebpf.MockBpfClient{
		UpdatePodStateEbpfMapsErr: injected,
	}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})

	assert.ErrorIs(t, err, injected)
	assert.Nil(t, resp, "rpc must not return a success reply when the pod-state write fails")
}

// reconcilerWithCachedPolicy returns a PolicyEndpoints reconciler whose local
// cache knows an egress policy for the "nginx" podIdentifier in "default",
// populated the same way production does it: by reconciling a PolicyEndpoint
// that selects a pod of that identifier on this node.
func reconcilerWithCachedPolicy(t *testing.T, ebpfClient *ebpf.MockBpfClient) *controllers.PolicyEndpointsReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	assert.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	pe := &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "np-x-abcde", Namespace: "default"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "np-x", Namespace: "default"},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "nginx-old123", Namespace: "default", PodIP: "10.0.0.5", HostIP: "10.0.0.1"},
			},
			Egress: []policyk8sawsv1.EndpointInfo{{CIDR: "10.1.0.0/16"}},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pe).Build()
	reconciler := controllers.NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", ebpfClient, false, nil)
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pe.Name, Namespace: pe.Namespace}})
	require.NoError(t, err)
	assert.True(t, reconciler.ArePoliciesAvailableInLocalCache("nginx@default"), "precondition: policy cached")
	return reconciler
}

// When AttacheBPFProbes reports the first pod of the identifier, the CNI ADD
// programs its freshly loaded maps and marks the pod POLICIES_APPLIED; later
// pods share maps that are already programmed.
func TestEnforceNpToPod_CachedPolicies_ProgramsMapsOnlyForFirstPod(t *testing.T) {
	for _, tt := range []struct {
		name        string
		firstPod    bool
		wantProgram bool
	}{
		{name: "first pod of the identifier", firstPod: true, wantProgram: true},
		{name: "later pod of the identifier", firstPod: false, wantProgram: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mockBpfClient := &ebpf.MockBpfClient{}
			reconciler := reconcilerWithCachedPolicy(t, mockBpfClient)
			mockBpfClient.Reset()
			mockBpfClient.AttachFirstPodInPodIdentifier = tt.firstPod
			s := &server{
				policyReconciler:        reconciler,
				clusterPolicyReconciler: controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient),
			}

			resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
				K8S_POD_NAME:        "nginx-new456",
				K8S_POD_NAMESPACE:   "default",
				NETWORK_POLICY_MODE: "standard",
				InterfaceCount:      1,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.Success)

			if !tt.wantProgram {
				assert.NotContains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
				assert.Empty(t, mockBpfClient.PodStateByIdentifier)
				return
			}
			assert.Contains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
			assert.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: "10.1.0.0/16"}}, mockBpfClient.LastEgressRules)
			assert.Equal(t, map[ebpf.PodStateKey]int{
				{PodIdentifier: "nginx@default", MapKey: ebpf.POD_STATE_MAP_KEY}:                ebpf.POLICIES_APPLIED,
				{PodIdentifier: "nginx@default", MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}: ebpf.DEFAULT_ALLOW,
			}, mockBpfClient.PodStateByIdentifier)
		})
	}
}

// Only a cluster policy selects the pod: the ADD must still program the cluster
// policy maps and mark the cluster-policy key POLICIES_APPLIED, while the
// namespaced-policy key goes to the mode default.
func TestEnforceNpToPod_CachedClusterPolicyOnly_ProgramsClusterPolicyMaps(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-x-abcde"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "cnp-x"},
			Tier:      policyk8sawsv1.AdminTier,
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "nginx-old123", Namespace: "default", PodIP: "10.0.0.5", HostIP: "10.0.0.1"},
			},
			Egress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "10.1.0.0/16", Action: "Deny"}},
		},
	}
	mockBpfClient := &ebpf.MockBpfClient{}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cpe).Build()
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(k8sClient, "10.0.0.1", mockBpfClient)
	_, err := clusterReconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: cpe.Name}})
	require.NoError(t, err)
	require.True(t, clusterReconciler.ArePoliciesAvailableInLocalCache("nginx@default"), "precondition: cluster policy cached")

	mockBpfClient.Reset()
	mockBpfClient.AttachFirstPodInPodIdentifier = true
	s := &server{
		policyReconciler:        controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil),
		clusterPolicyReconciler: clusterReconciler,
	}
	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-new456",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotContains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
	assert.Contains(t, mockBpfClient.CallLog, "UpdateClusterPolicyEbpfMaps")
	assert.Equal(t, map[ebpf.PodStateKey]int{
		{PodIdentifier: "nginx@default", MapKey: ebpf.POD_STATE_MAP_KEY}:                ebpf.DEFAULT_ALLOW,
		{PodIdentifier: "nginx@default", MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}: ebpf.POLICIES_APPLIED,
	}, mockBpfClient.PodStateByIdentifier)
}

// recordingProxy records the pods whose DNS redirection is force-removed; the removal fails with err when set.
type recordingProxy struct {
	proxymanager.ProxyManagerMock
	removedPods []types.NamespacedName
	err         error
}

func (p *recordingProxy) ForceRemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	p.removedPods = append(p.removedPods, pod)
	return p.err
}

func TestDeletePodNp_DNSPolicy(t *testing.T) {
	pod := types.NamespacedName{Name: "nginx-abc123", Namespace: "default"}
	removalErr := errors.New("simulated nftables failure")
	for _, tc := range []struct {
		name         string
		proxy        *recordingProxy
		wantRemovals []types.NamespacedName
		wantErr      error
	}{
		{name: "DNS policy inactive", proxy: nil},
		{name: "DNS policy active removes the pod's DNS redirection", proxy: &recordingProxy{}, wantRemovals: []types.NamespacedName{pod}},
		{
			name:         "a failed DNS redirection removal fails the request",
			proxy:        &recordingProxy{err: removalErr},
			wantRemovals: []types.NamespacedName{pod},
			wantErr:      removalErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockBpfClient := &ebpf.MockBpfClient{}
			s := &server{policyReconciler: controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false, nil)}
			if tc.proxy != nil {
				s.proxymanager = tc.proxy
			}

			resp, err := s.DeletePodNp(context.Background(), &rpc.DeleteNpRequest{K8S_POD_NAME: pod.Name, K8S_POD_NAMESPACE: pod.Namespace})
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.False(t, resp.Success)
			} else {
				assert.NoError(t, err)
				assert.True(t, resp.Success)
			}
			assert.Equal(t, []string{"DeleteBPFProbes"}, mockBpfClient.CallLog)
			if tc.proxy != nil {
				assert.Equal(t, tc.wantRemovals, tc.proxy.removedPods)
			}
		})
	}
}
