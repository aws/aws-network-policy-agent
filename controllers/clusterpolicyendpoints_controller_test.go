package controllers

import (
	"context"
	"sync"
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

		// Verify: pod state was reset to DEFAULT_ALLOW via UpdatePodStateEbpfMaps
		assert.Contains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps",
			"UpdatePodStateEbpfMaps should be called to reset pod state to DEFAULT_ALLOW")
	})

	t.Run("no eBPF calls when there are no stale identifiers", func(t *testing.T) {
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

func sizeOfSyncMapCluster(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
