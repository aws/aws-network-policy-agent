package controllers

import (
	"context"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestReconcileClusterPolicyEndpoint_StalePodIdentifiersClearedFromEbpf(t *testing.T) {
	nodeIP := "192.168.70.108"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("stale pod identifiers have eBPF maps cleared on label removal", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		podName := "nginx-abc123"
		podNamespace := "np-target"
		podIdentifier := "nginx@np-target"
		cpeName := "isolate-dark-corner-t7p5w"
		parentCNP := "isolate-dark-corner"

		// Simulate prior state: pod was previously targeted by this CPE
		reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpeName})
		reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
		reconciler.ClusterPolicyEndpointSelectorMap.Store(cpeName, []npatypes.Pod{
			{NamespacedName: types.NamespacedName{Name: podName, Namespace: podNamespace}, PodIP: "192.168.95.108"},
		})

		// CPE after label removal: still exists but podSelectorEndpoints is empty
		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name: cpeName,
			},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.ClusterPolicyReference{
					Name: parentCNP,
				},
				Priority:             10,
				Tier:                 policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{},
				Ingress: []policyk8sawsv1.ClusterEndpointInfo{
					{CIDR: "192.168.90.89", Action: "Deny"},
					{CIDR: "192.168.71.43", Action: "Deny"},
				},
			},
		}

		// Mock: List returns the CPE (it still exists after label removal)
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{
					Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe},
				}
				return nil
			},
		).AnyTimes()

		// Mock: Get for the CPE (used by cleanupClusterPolicyPod if it runs)
		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if cpObj, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*cpObj = *cpe
				}
				return nil
			},
		).AnyTimes()

		err := reconciler.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
		assert.Nil(t, err)

		// Verify: stale pod identifier removed from lookup map
		_, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
		assert.False(t, ok, "stale pod identifier should be removed from podIdentifierToClusterPolicyEndpointMap")

		// Verify: clusterNetworkPolicyToPodIdentifierMap cleared (no targets left)
		_, ok = reconciler.clusterNetworkPolicyToPodIdentifierMap.Load(parentCNP)
		assert.False(t, ok, "clusterNetworkPolicyToPodIdentifierMap should be cleared when no targets remain")

		// Verify: eBPF maps were explicitly cleared via UpdateClusterPolicyEbpfMaps
		assert.Contains(t, mockBpf.CallLog, "UpdateClusterPolicyEbpfMaps",
			"UpdateClusterPolicyEbpfMaps should be called to clear stale eBPF entries")

		// Verify: the clear passed empty rules (not a re-derive of the old Deny rules)
		assert.Empty(t, mockBpf.LastClusterPolicyIngressRules,
			"stale cleanup should clear ingress rules, not reprogram them")
		assert.Empty(t, mockBpf.LastClusterPolicyEgressRules,
			"stale cleanup should clear egress rules, not reprogram them")

		// Verify: pod state was reset to DEFAULT_ALLOW via UpdatePodStateEbpfMaps
		assert.Contains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps",
			"UpdatePodStateEbpfMaps should be called to reset pod state to DEFAULT_ALLOW")
	})

	t.Run("stale pod with no eBPF context is skipped, not errored", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		podIdentifier := "nginx@np-target"
		// The pod's probes were already detached (last pod of the identifier left the node),
		// so there is no eBPF context to update. This must be a no-op, not a failing reconcile.
		mockBpf := &ebpf.MockBpfClient{
			PodIdentifiersWithoutBPFContext: map[string]bool{podIdentifier: true},
		}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		cpeName := "isolate-dark-corner-t7p5w"
		parentCNP := "isolate-dark-corner"

		reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpeName})
		reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
		reconciler.ClusterPolicyEndpointSelectorMap.Store(cpeName, []npatypes.Pod{
			{NamespacedName: types.NamespacedName{Name: "nginx-abc123", Namespace: "np-target"}, PodIP: "192.168.95.108"},
		})

		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: cpeName},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef:            policyk8sawsv1.ClusterPolicyReference{Name: parentCNP},
				Priority:             10,
				Tier:                 policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{},
				Ingress: []policyk8sawsv1.ClusterEndpointInfo{
					{CIDR: "192.168.90.89", Action: "Deny"},
				},
			},
		}

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe}}
				return nil
			},
		).AnyTimes()

		err := reconciler.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
		assert.Nil(t, err, "reconcile should not error when the stale pod has no eBPF context to clear")

		// No eBPF map update should have been attempted for the context-less pod.
		assert.NotContains(t, mockBpf.CallLog, "UpdateClusterPolicyEbpfMaps",
			"UpdateClusterPolicyEbpfMaps must not be called when there is no eBPF context")
	})

	t.Run("sibling CPE of the same CNP does not keep stale rules alive", func(t *testing.T) {
		// A parent CNP sliced into two CPEs. When the parent stops selecting the pod, every
		// one of its CPEs must be removed from the stale identifier's entry. Leaving a sibling
		// CPE behind would keep the entry alive and let cleanup re-derive the parent's Deny
		// rules instead of clearing them.
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		podIdentifier := "nginx@np-target"
		cpeA := "isolate-dark-corner-aaaaa"
		cpeB := "isolate-dark-corner-bbbbb"
		parentCNP := "isolate-dark-corner"

		// Prior state: identifier holds BOTH CPEs of the same parent CNP.
		reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpeA, cpeB})
		reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
		reconciler.ClusterPolicyEndpointSelectorMap.Store(cpeA, []npatypes.Pod{
			{NamespacedName: types.NamespacedName{Name: "nginx-abc123", Namespace: "np-target"}, PodIP: "192.168.95.108"},
		})

		// After label removal both CPEs of the CNP still exist but select no pods on this node.
		makeCPE := func(name string) policyk8sawsv1.ClusterPolicyEndpoint {
			return policyk8sawsv1.ClusterPolicyEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
					PolicyRef:            policyk8sawsv1.ClusterPolicyReference{Name: parentCNP},
					Priority:             10,
					Tier:                 policyk8sawsv1.AdminTier,
					PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{},
					Ingress: []policyk8sawsv1.ClusterEndpointInfo{
						{CIDR: "192.168.90.89", Action: "Deny"},
					},
				},
			}
		}
		cpeAObj := makeCPE(cpeA)

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{makeCPE(cpeA), makeCPE(cpeB)}}
				return nil
			},
		).AnyTimes()

		err := reconciler.reconcileClusterPolicyEndpoint(context.TODO(), &cpeAObj)
		assert.Nil(t, err)

		// The whole entry must be gone — no sibling CPE left behind.
		_, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
		assert.False(t, ok, "all CPEs of the parent CNP should be removed for the stale identifier")

		// And the eBPF rules must have been cleared (empty), not re-derived from the sibling CPE.
		assert.Contains(t, mockBpf.CallLog, "UpdateClusterPolicyEbpfMaps")
		assert.Empty(t, mockBpf.LastClusterPolicyIngressRules,
			"sibling CPE must not re-supply Deny rules for a stale identifier")
	})

	t.Run("active pod identifiers keep rules applied when there are no stale identifiers", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		podName := "nginx-abc123"
		podNamespace := "np-target"
		podIdentifier := "nginx@np-target"
		cpeName := "isolate-dark-corner-t7p5w"
		parentCNP := "isolate-dark-corner"

		// CPE with the pod still targeted (label still present)
		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name: cpeName,
			},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.ClusterPolicyReference{
					Name: parentCNP,
				},
				Priority: 10,
				Tier:     policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
					{
						HostIP:    policyk8sawsv1.NetworkAddress(nodeIP),
						PodIP:     "192.168.95.108",
						Name:      podName,
						Namespace: podNamespace,
					},
				},
				Ingress: []policyk8sawsv1.ClusterEndpointInfo{
					{CIDR: "192.168.90.89", Action: "Deny"},
				},
			},
		}

		// Pre-populate: pod was already a target in prior reconcile
		reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpeName})
		reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
		reconciler.ClusterPolicyEndpointSelectorMap.Store(cpeName, []npatypes.Pod{
			{NamespacedName: types.NamespacedName{Name: podName, Namespace: podNamespace}, PodIP: "192.168.95.108"},
		})

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{
					Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe},
				}
				return nil
			},
		).AnyTimes()

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if cpObj, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*cpObj = *cpe
				}
				return nil
			},
		).AnyTimes()

		err := reconciler.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
		assert.Nil(t, err)

		// Pod is still a target — should remain in the map
		_, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
		assert.True(t, ok, "active pod identifier should remain in podIdentifierToClusterPolicyEndpointMap")

		// eBPF maps should be updated (rules applied), not cleared
		assert.Contains(t, mockBpf.CallLog, "UpdateClusterPolicyEbpfMaps")
		assert.Contains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps")
	})
}

func TestCleanUpClusterPolicyEndpoint_StalePodIdentifiersCleanedUp(t *testing.T) {
	nodeIP := "192.168.70.108"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("stale identifiers removed from map during delete flow", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		podIdentifier := "nginx@np-target"
		cpeName := "isolate-dark-corner-t7p5w"
		parentCNP := "isolate-dark-corner"

		// Simulate prior state
		reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpeName})
		reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
		reconciler.ClusterPolicyEndpointSelectorMap.Store(cpeName, []npatypes.Pod{
			{NamespacedName: types.NamespacedName{Name: "nginx-abc123", Namespace: "np-target"}, PodIP: "192.168.95.108"},
		})

		// CPE is being deleted — List returns empty (no sibling CPEs)
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{}}
				return nil
			},
		).AnyTimes()

		err := reconciler.cleanUpClusterPolicyEndpoint(context.TODO(), controllerruntime.Request{
			NamespacedName: types.NamespacedName{Name: cpeName},
		})
		assert.Nil(t, err)

		// Verify cleanup
		_, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
		assert.False(t, ok, "pod identifier should be removed during delete cleanup")

		selectorMapSize := 0
		reconciler.ClusterPolicyEndpointSelectorMap.Range(func(_, _ any) bool {
			selectorMapSize++
			return true
		})
		assert.Equal(t, 0, selectorMapSize, "ClusterPolicyEndpointSelectorMap should be empty after cleanup")
	})
}
