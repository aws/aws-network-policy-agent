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
	"fmt"
	"os"
	"testing"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRunRPCHandler_NoExistingSocket(t *testing.T) {
	testSocketPath := "/tmp/test-rpc-handler.sock"
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath)
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

	errCh, err := RunRPCHandler(nil, nil, testSocketPath)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestEnforceNpToPod_AttachesAsConfirmedLive(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
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
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)

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
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
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
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
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

	assert.Equal(t, map[ebpf.PodStateKey]int{
		{PodIdentifier: "nginx@default", MapKey: ebpf.POD_STATE_MAP_KEY}:                ebpf.DEFAULT_ALLOW,
		{PodIdentifier: "nginx@default", MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}: ebpf.DEFAULT_ALLOW,
	}, mockBpfClient.PodStateByIdentifier)
}

// TestEnforceNpToPod_FailsClosedOnPodStateError verifies that EnforceNpToPod
// returns an error rather than a success reply when the pod-state map write
// fails on the no-cached-policies path that seeds default-allow/default-deny.
// Both reconcilers are wired so the readiness check passes and execution
// reaches UpdatePodStateEbpfMaps.
func TestEnforceNpToPod_FailsClosedOnPodStateError(t *testing.T) {
	injected := errors.New("simulated pod state write failure")
	mockBpfClient := &ebpf.MockBpfClient{
		SetPodStateBaselineErr: injected,
	}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
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
	reconciler := controllers.NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", ebpfClient, false)
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
		policyReconciler:        controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false),
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

// racingBpfClient runs onBaselineWrite once, after the policy cache check and before the
// default allow/deny write, to simulate a reconcile landing in between.
type racingBpfClient struct {
	*ebpf.MockBpfClient
	onBaselineWrite func()
}

func (c *racingBpfClient) SetPodStateBaseline(podIdentifier string, key int, state int, since uint64) error {
	if hook := c.onBaselineWrite; hook != nil && key == ebpf.POD_STATE_MAP_KEY {
		c.onBaselineWrite = nil
		hook()
	}
	return c.MockBpfClient.SetPodStateBaseline(podIdentifier, key, state, since)
}

// denyIngressPE selects client-one on hostIP, which shares the client@demo identifier with client-two.
func denyIngressPE(hostIP string) *policyk8sawsv1.PolicyEndpoint {
	return &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "default-deny-ingress-abcde", Namespace: "demo"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "default-deny-ingress", Namespace: "demo"},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeIngress},
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "client-one", Namespace: "demo", PodIP: "10.0.0.5", HostIP: policyk8sawsv1.NetworkAddress(hostIP)},
			},
		},
	}
}

var (
	clientDemoPodState   = ebpf.PodStateKey{PodIdentifier: "client@demo", MapKey: ebpf.POD_STATE_MAP_KEY}
	clientDemoCPPodState = ebpf.PodStateKey{PodIdentifier: "client@demo", MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}
)

func addClientTwo(t *testing.T, s *server, mode string) {
	t.Helper()
	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME: "client-two", K8S_POD_NAMESPACE: "demo", NETWORK_POLICY_MODE: mode, InterfaceCount: 1,
	})
	require.NoError(t, err)
	require.True(t, resp.Success)
}

func newPEServer(t *testing.T, c ebpf.BpfClient, objs ...client.Object) (*server, *controllers.PolicyEndpointsReconciler) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	r := controllers.NewPolicyEndpointsReconciler(fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(), "10.0.0.1", c, false)
	return &server{policyReconciler: r, clusterPolicyReconciler: controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", c)}, r
}

func reconcilePE(t *testing.T, r *controllers.PolicyEndpointsReconciler, pe *policyk8sawsv1.PolicyEndpoint) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pe.Name, Namespace: pe.Namespace}})
	require.NoError(t, err)
}

// A reconcile between the cache check and the default write must keep POLICIES_APPLIED.
func TestEnforceNpToPod_ReconcileBetweenCacheCheckAndBaselineWrite(t *testing.T) {
	for _, sharedMaps := range []bool{false, true} {
		t.Run(fmt.Sprintf("sharedMaps=%t", sharedMaps), func(t *testing.T) {
			pe := denyIngressPE("10.0.0.1")
			c := &racingBpfClient{MockBpfClient: &ebpf.MockBpfClient{}}
			s, r := newPEServer(t, c, pe)
			if sharedMaps {
				require.NoError(t, c.CreatePodStateEbpfEntryIfNotExists("client@demo", ebpf.POD_STATE_MAP_KEY, ebpf.DEFAULT_ALLOW))
			}
			c.onBaselineWrite = func() {
				reconcilePE(t, r, pe)
				got, written := c.PodStateByIdentifier[clientDemoPodState]
				require.True(t, written && got == ebpf.POLICIES_APPLIED, "precondition: reconcile applied the policy")
			}

			addClientTwo(t, s, "standard")
			require.Nil(t, c.onBaselineWrite, "the hook ran")
			assert.Equal(t, ebpf.POLICIES_APPLIED, c.PodStateByIdentifier[clientDemoPodState])
			ingress, programmed := c.IngressByIdentifier["client@demo"]
			assert.True(t, programmed, "ingress map programmed")
			assert.Empty(t, ingress, "default deny: no ingress rules")
		})
	}
}

// A policy selecting only remote pods programs nothing locally, so the default must still be written.
func TestEnforceNpToPod_PolicyBecameKnownForRemotePodOnly_SeedsBaseline(t *testing.T) {
	pe := denyIngressPE("10.0.0.2")
	c := &racingBpfClient{MockBpfClient: &ebpf.MockBpfClient{}}
	s, r := newPEServer(t, c, pe)
	c.onBaselineWrite = func() {
		reconcilePE(t, r, pe)
		require.True(t, r.ArePoliciesAvailableInLocalCache("client@demo"), "precondition: policy cached")
		_, written := c.PodStateByIdentifier[clientDemoPodState]
		require.False(t, written, "precondition: nothing programmed on this node")
	}

	addClientTwo(t, s, "standard")
	require.Nil(t, c.onBaselineWrite, "the hook ran")
	got, written := c.PodStateByIdentifier[clientDemoPodState]
	assert.True(t, written, "baseline seeded")
	assert.Equal(t, ebpf.DEFAULT_ALLOW, got)
}

// With no policy, the default still overwrites stale state, e.g. after a mode switch or a
// policy deleted while the agent was down.
func TestEnforceNpToPod_NoPolicyKnown_BaselineOverwrites(t *testing.T) {
	for _, tt := range []struct {
		name     string
		existing int
		mode     string
		want     int
	}{
		{name: "strict to standard", existing: ebpf.DEFAULT_DENY, mode: "standard", want: ebpf.DEFAULT_ALLOW},
		{name: "standard to strict", existing: ebpf.DEFAULT_ALLOW, mode: "strict", want: ebpf.DEFAULT_DENY},
		{name: "orphaned POLICIES_APPLIED", existing: ebpf.POLICIES_APPLIED, mode: "standard", want: ebpf.DEFAULT_ALLOW},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &ebpf.MockBpfClient{}
			s, _ := newPEServer(t, c)
			require.NoError(t, c.CreatePodStateEbpfEntryIfNotExists("client@demo", ebpf.POD_STATE_MAP_KEY, tt.existing))
			require.NoError(t, c.CreatePodStateEbpfEntryIfNotExists("client@demo", ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, ebpf.POLICIES_APPLIED))

			addClientTwo(t, s, tt.mode)
			assert.Equal(t, tt.want, c.PodStateByIdentifier[clientDemoPodState])
			assert.Equal(t, ebpf.DEFAULT_ALLOW, c.PodStateByIdentifier[clientDemoCPPodState])
		})
	}
}

// Same race for cluster policies.
func TestEnforceNpToPod_ClusterPolicyReconcileBetweenCacheCheckAndBaselineWrite(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-x-abcde"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "cnp-x"},
			Tier:      policyk8sawsv1.AdminTier,
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "client-one", Namespace: "demo", PodIP: "10.0.0.5", HostIP: "10.0.0.1"},
			},
			Egress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "10.1.0.0/16", Action: "Deny"}},
		},
	}
	c := &racingBpfClient{MockBpfClient: &ebpf.MockBpfClient{}}
	cr := controllers.NewClusterPolicyEndpointsReconciler(fake.NewClientBuilder().WithScheme(scheme).WithObjects(cpe).Build(), "10.0.0.1", c)
	s := &server{policyReconciler: controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", c, false), clusterPolicyReconciler: cr}
	c.onBaselineWrite = func() {
		_, err := cr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: cpe.Name}})
		require.NoError(t, err)
		require.Equal(t, ebpf.POLICIES_APPLIED, c.PodStateByIdentifier[clientDemoCPPodState], "precondition: reconcile applied the cluster policy")
	}

	addClientTwo(t, s, "standard")
	require.Nil(t, c.onBaselineWrite, "the hook ran")
	assert.Equal(t, ebpf.POLICIES_APPLIED, c.PodStateByIdentifier[clientDemoCPPodState])
	assert.Equal(t, ebpf.DEFAULT_ALLOW, c.PodStateByIdentifier[clientDemoPodState])
}

// A remote-only policy appearing in the window must not stop the default from fixing stale state.
func TestEnforceNpToPod_RemoteOnlyPolicyInWindow_StaleEntryOverwritten(t *testing.T) {
	for _, tt := range []struct {
		name     string
		existing int
		mode     string
		want     int
	}{
		{name: "orphaned POLICIES_APPLIED, standard", existing: ebpf.POLICIES_APPLIED, mode: "standard", want: ebpf.DEFAULT_ALLOW},
		{name: "orphaned POLICIES_APPLIED, strict", existing: ebpf.POLICIES_APPLIED, mode: "strict", want: ebpf.DEFAULT_DENY},
		{name: "strict baseline left, now standard", existing: ebpf.DEFAULT_DENY, mode: "standard", want: ebpf.DEFAULT_ALLOW},
		{name: "standard baseline left, now strict", existing: ebpf.DEFAULT_ALLOW, mode: "strict", want: ebpf.DEFAULT_DENY},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pe := denyIngressPE("10.0.0.2")
			c := &racingBpfClient{MockBpfClient: &ebpf.MockBpfClient{}}
			s, r := newPEServer(t, c, pe)
			require.NoError(t, c.CreatePodStateEbpfEntryIfNotExists("client@demo", ebpf.POD_STATE_MAP_KEY, tt.existing))
			c.onBaselineWrite = func() {
				reconcilePE(t, r, pe)
				require.True(t, r.ArePoliciesAvailableInLocalCache("client@demo"), "precondition: policy cached")
			}

			addClientTwo(t, s, tt.mode)
			require.Nil(t, c.onBaselineWrite, "the hook ran")
			assert.Equal(t, tt.want, c.PodStateByIdentifier[clientDemoPodState])
		})
	}
}

// Same as above for cluster policies.
func TestEnforceNpToPod_RemoteOnlyClusterPolicyInWindow_StaleEntryOverwritten(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-x-abcde"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "cnp-x"},
			Tier:      policyk8sawsv1.AdminTier,
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "client-one", Namespace: "demo", PodIP: "10.0.0.5", HostIP: "10.0.0.2"},
			},
			Egress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "10.1.0.0/16", Action: "Deny"}},
		},
	}
	c := &racingBpfClient{MockBpfClient: &ebpf.MockBpfClient{}}
	cr := controllers.NewClusterPolicyEndpointsReconciler(fake.NewClientBuilder().WithScheme(scheme).WithObjects(cpe).Build(), "10.0.0.1", c)
	s := &server{policyReconciler: controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", c, false), clusterPolicyReconciler: cr}
	require.NoError(t, c.CreatePodStateEbpfEntryIfNotExists("client@demo", ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, ebpf.POLICIES_APPLIED))
	c.onBaselineWrite = func() {
		_, err := cr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: cpe.Name}})
		require.NoError(t, err)
		require.True(t, cr.ArePoliciesAvailableInLocalCache("client@demo"), "precondition: cluster policy cached")
	}

	addClientTwo(t, s, "standard")
	require.Nil(t, c.onBaselineWrite, "the hook ran")
	assert.Equal(t, ebpf.DEFAULT_ALLOW, c.PodStateByIdentifier[clientDemoCPPodState])
}
