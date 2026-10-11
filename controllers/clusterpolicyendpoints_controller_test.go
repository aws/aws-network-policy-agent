package controllers

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("truncated CPE name still triggers stale cleanup", func(t *testing.T) {
		// For CNP names >= 58 chars GenerateName truncates the CPE base, so the write
		// key must be derived from the CPE name (same as the reader) rather than
		// Spec.PolicyRef.Name — else stale cleanup silently re-derives Deny rules.
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		parentCNP := "restrict-egress-from-payment-service-to-external-endpoints-prod"
		cpeName := "restrict-egress-from-payment-service-to-external-endpoints-abcde"
		podName := "nginx-abc123"
		podNamespace := "np-target"
		podIdentifier := "nginx@np-target"

		var currentCPE *policyk8sawsv1.ClusterPolicyEndpoint
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*currentCPE}}
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if cpObj, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*cpObj = *currentCPE
				}
				return nil
			},
		).AnyTimes()

		// Reconcile #1: pod selected — writes clusterNetworkPolicyToPodIdentifierMap.
		currentCPE = &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: cpeName},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: parentCNP},
				Priority:  10,
				Tier:      policyk8sawsv1.AdminTier,
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
		err := reconciler.reconcileClusterPolicyEndpoint(context.TODO(), currentCPE)
		assert.Nil(t, err)

		// Reconcile #2: label removed — CPE still exists but selects no pods.
		currentCPE = &policyk8sawsv1.ClusterPolicyEndpoint{
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
		mockBpf.CallLog = nil
		mockBpf.LastClusterPolicyIngressRules = nil
		err = reconciler.reconcileClusterPolicyEndpoint(context.TODO(), currentCPE)
		assert.Nil(t, err)

		_, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
		assert.False(t, ok, "stale identifier should be removed even when the CPE name is truncated")

		// Rule count is what distinguishes "clear" from "re-derive" — both branches call
		// UpdateClusterPolicyEbpfMaps.
		assert.Contains(t, mockBpf.CallLog, "UpdateClusterPolicyEbpfMaps")
		assert.Empty(t, mockBpf.LastClusterPolicyIngressRules,
			"Deny rules must be cleared, not re-derived")

		_, ok = reconciler.clusterNetworkPolicyToPodIdentifierMap.Load(utils.GetParentNPNameFromPEName(cpeName))
		assert.False(t, ok)
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

	// When the deleted CPE has siblings under the same parent, the sibling names are in
	// parentCPEList but the deleted CPE's name isn't — so the scrub loop in
	// deriveTargetPodsForParentCNP wouldn't remove it. Its dangling name keeps the
	// identifier entry alive and defeats the HasBPFContext guard: cleanupClusterPolicyPod
	// takes the "sibling still applies" branch and calls UpdateClusterPolicyEbpfMaps on
	// a detached context. cleanUpClusterPolicyEndpoint must scrub resourceName from every
	// affected identifier explicitly.
	t.Run("deleted CPE removed from identifier map when siblings exist", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}

		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		podIdentifier := "nginx@np-target"
		deletedCPE := "isolate-dark-corner-t7p5w"
		siblingCPE := "isolate-dark-corner-x9k4m"
		parentCNP := "isolate-dark-corner"

		reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{deletedCPE, siblingCPE})
		reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
		reconciler.ClusterPolicyEndpointSelectorMap.Store(deletedCPE, []npatypes.Pod{
			{NamespacedName: types.NamespacedName{Name: "nginx-abc123", Namespace: "np-target"}, PodIP: "192.168.95.108"},
		})

		// List returns only the sibling — the deleted CPE is gone from etcd.
		siblingObj := policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: siblingCPE},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef:            policyk8sawsv1.ClusterPolicyReference{Name: parentCNP},
				Priority:             10,
				Tier:                 policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{}, // sibling selects nothing on this node
			},
		}
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{siblingObj}}
				return nil
			},
		).AnyTimes()

		err := reconciler.cleanUpClusterPolicyEndpoint(context.TODO(), controllerruntime.Request{
			NamespacedName: types.NamespacedName{Name: deletedCPE},
		})
		assert.Nil(t, err)

		// deletedCPE must be gone from the identifier's list.
		if v, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
			assert.NotContains(t, v.([]string), deletedCPE,
				"deleted CPE must not linger in podIdentifierToClusterPolicyEndpointMap when siblings exist")
		}
	})
}

// A transient k8sClient.List failure must NOT be treated as "no CPEs left". The old code
// swallowed the error and returned nil, indistinguishable from an empty result, and the
// caller would then scrub map state and clear eBPF Deny rules — opening traffic on a
// transient API error. Reconcile must surface the error so controller-runtime requeues.
func TestReconcileClusterPolicyEndpoint_TransientListErrorDoesNotClearEbpf(t *testing.T) {
	nodeIP := "192.168.70.108"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{}

	reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

	podIdentifier := "nginx@np-target"
	cpeName := "isolate-dark-corner-t7p5w"
	parentCNP := "isolate-dark-corner"

	reconciler.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpeName})
	reconciler.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNP, []string{podIdentifier})
	reconciler.ClusterPolicyEndpointSelectorMap.Store(cpeName, []npatypes.Pod{
		{NamespacedName: types.NamespacedName{Name: "nginx-abc123", Namespace: "np-target"}, PodIP: "192.168.95.108"},
	})

	listErr := errors.New("etcdserver: request timed out")
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).
		Return(listErr).AnyTimes()

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

	err := reconciler.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
	assert.ErrorIs(t, err, listErr, "reconcile must surface List failure so controller-runtime requeues")

	// eBPF state MUST be untouched — no Deny-rule clear, no pod-state flip.
	assert.NotContains(t, mockBpf.CallLog, "UpdateClusterPolicyEbpfMaps",
		"eBPF maps must not be cleared on a transient List failure")
	assert.NotContains(t, mockBpf.CallLog, "UpdatePodStateEbpfMaps",
		"pod state must not be reset on a transient List failure")

	// Lookup maps must be untouched — nothing scrubbed, nothing deleted.
	pes, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
	if assert.True(t, ok, "podIdentifierToClusterPolicyEndpointMap entry must not be scrubbed on List error") {
		assert.Equal(t, []string{cpeName}, pes)
	}
	pids, ok := reconciler.clusterNetworkPolicyToPodIdentifierMap.Load(parentCNP)
	if assert.True(t, ok, "clusterNetworkPolicyToPodIdentifierMap entry must not be deleted on List error") {
		assert.Equal(t, []string{podIdentifier}, pids)
	}
}

// Regression test for #686 on the ClusterPolicyEndpoint path.
func TestReconcileClusterPolicyEndpoint_MapUpdateFailureRequeues(t *testing.T) {
	nodeIP := "192.168.70.108"

	enomem := errors.New("unable to update map: cannot allocate memory")

	tests := []struct {
		name        string
		injectErr   error
		wantErr     bool
		wantLatency bool
	}{
		{
			name:      "cluster map write failure surfaces so the item is requeued",
			injectErr: enomem,
			wantErr:   true,
		},
		{
			name:        "successful cluster map write reports success and records latency",
			wantErr:     false,
			wantLatency: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mock_client.NewMockClient(ctrl)
			mockBpf := &ebpf.MockBpfClient{UpdateClusterPolicyEbpfMapsErr: tt.injectErr}
			reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)
			// Latency is only observed for trigger times after trackerStartTime.
			reconciler.trackerStartTime = time.Now().Add(-time.Minute)

			cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "isolate-everything-t7p5w",
					Annotations: map[string]string{
						LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano),
					},
				},
				Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
					PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "isolate-everything"},
					Priority:  10,
					Tier:      policyk8sawsv1.AdminTier,
					PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
						{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: "np-target"},
						{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.109", Name: "redis-def456", Namespace: "np-target"},
					},
					Ingress: []policyk8sawsv1.ClusterEndpointInfo{
						{CIDR: "192.168.90.89", Action: "Deny"},
					},
				},
			}

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

			before := histSampleCount(t, clusterPolicyProgrammingLatency)
			// Call Reconcile so the error return to the workqueue is covered.
			_, err := reconciler.Reconcile(context.TODO(), controllerruntime.Request{
				NamespacedName: types.NamespacedName{Name: cpe.Name},
			})

			if tt.wantErr {
				require.Error(t, err, "cluster map write failure must surface so the item is requeued")
				assert.ErrorIs(t, err, tt.injectErr, "the underlying map-write error must be preserved")
				assert.Contains(t, err.Error(), "nginx@np-target")

				updates := 0
				for _, c := range mockBpf.CallLog {
					if c == "UpdateClusterPolicyEbpfMaps" {
						updates++
					}
				}
				assert.Equal(t, 2, updates, "both pod identifiers must be attempted despite the first failing")
			} else {
				require.NoError(t, err)
			}

			// A failed attempt records no latency and leaves the annotation for the retry.
			got := histSampleCount(t, clusterPolicyProgrammingLatency) - before
			if tt.wantLatency {
				assert.Equal(t, uint64(1), got, "a successful reconcile must record E2E latency")
			} else {
				assert.Equal(t, uint64(0), got, "a failed reconcile must not record E2E latency")
			}
		})
	}
}

// Cluster-policy version of TestConfigureeBPFProbes_AttachFailureMatrix.
func TestConfigureClusterPolicyBPFProbes_AttachFailureMatrix(t *testing.T) {
	const namespace = "np-target"
	const podIdentifier = "nginx@" + namespace
	attachErr := errors.New("failed to find host veth: Pod might have been deleted")

	pod := func(name string) npatypes.Pod {
		return npatypes.Pod{NamespacedName: types.NamespacedName{Name: name, Namespace: namespace}}
	}
	siblings := []npatypes.Pod{pod("nginx-abc123"), pod("nginx-def456")}

	tests := []struct {
		name      string
		failPods  []string
		noContext bool
		// targetPods overrides the default pair of sibling pods.
		targetPods   []npatypes.Pod
		updateErr    error
		wantErr      error
		wantAlsoErr  bool
		wantErrNames string
		wantAttaches int
		wantUpdates  int
		why          string
	}{
		{
			name:         "one sibling fails, context live: the shared write must still run",
			failPods:     []string{"nginx-abc123"},
			wantErrNames: "np-target/nginx-abc123",
			wantErr:      attachErr,
			wantAttaches: 2,
			wantUpdates:  1,
			why:          "healthy siblings must receive the new rules",
		},
		{
			// A live context is still updated when every attach fails.
			name:         "every sibling fails but a context is live: the write can still land",
			failPods:     []string{"nginx-abc123", "nginx-def456"},
			wantErr:      attachErr,
			wantAttaches: 2,
			wantUpdates:  1,
			why:          "a context registered by an earlier reconcile still has maps worth updating",
		},
		{
			name:         "every sibling fails and no context exists: skip the futile write",
			failPods:     []string{"nginx-abc123", "nginx-def456"},
			noContext:    true,
			wantErr:      attachErr,
			wantAttaches: 2,
			wantUpdates:  0,
			why:          "the write would return no-bpf-context and misattribute the attach failure",
		},
		{
			name:         "a departed pod is not a programming failure: skip, report success",
			noContext:    true,
			wantAttaches: 2,
			wantUpdates:  0,
			why:          "a pod whose CNI DEL already ran must not be counted as a programming failure",
		},
		{
			// Pods of other identifiers are ignored.
			name: "no pod of this identifier: nothing to attach and nothing to write",
			targetPods: []npatypes.Pod{
				{NamespacedName: types.NamespacedName{Name: "other-rs-1", Namespace: "other-ns"}},
			},
			noContext:    true,
			wantAttaches: 0,
			wantUpdates:  0,
			why:          "unreachable from the sole caller, since targetPodIdentifiers derives from targetPods; kept as a defensive guard",
		},
		{
			name:         "attach and map write both fail: both errors survive",
			failPods:     []string{"nginx-abc123"},
			updateErr:    errors.New("unable to update map: cannot allocate memory"),
			wantErr:      attachErr,
			wantAlsoErr:  true,
			wantAttaches: 2,
			wantUpdates:  1,
			why:          "errors.Join must keep both causes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBpf := &ebpf.MockBpfClient{UpdateClusterPolicyEbpfMapsErr: tt.updateErr}
			if len(tt.failPods) > 0 {
				mockBpf.AttacheBPFProbesErrByPod = map[string]error{}
				for _, n := range tt.failPods {
					mockBpf.AttacheBPFProbesErrByPod[namespace+"/"+n] = attachErr
				}
			}
			if tt.noContext {
				mockBpf.PodIdentifiersWithoutBPFContext = map[string]bool{podIdentifier: true}
			}
			r := &ClusterPolicyEndpointsReconciler{ebpfClient: mockBpf}

			pods := tt.targetPods
			if pods == nil {
				pods = siblings
			}
			programmed, err := r.configureClusterPolicyBPFProbes(podIdentifier, pods, nil, nil)

			if tt.wantErr != nil {
				require.Error(t, err)
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
				case "UpdateClusterPolicyEbpfMaps":
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
func TestConfigureClusterPolicyBPFProbes_SkippedAttachIsNotAProgrammingFailure(t *testing.T) {
	namespace := "np-target"
	podIdentifier := "nginx@" + namespace

	skipped := fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	mockBpf := &ebpf.MockBpfClient{
		AttacheBPFProbesErrByPod: map[string]error{
			namespace + "/nginx-abc123": skipped,
			namespace + "/nginx-def456": skipped,
		},
	}
	r := &ClusterPolicyEndpointsReconciler{ebpfClient: mockBpf}

	targetPods := []npatypes.Pod{
		{NamespacedName: types.NamespacedName{Name: "nginx-abc123", Namespace: namespace}},
		{NamespacedName: types.NamespacedName{Name: "nginx-def456", Namespace: namespace}},
	}

	programmed, err := r.configureClusterPolicyBPFProbes(podIdentifier, targetPods, nil, nil)
	require.NoError(t, err, "a deliberate skip must not become a programming failure that requeues forever")
	assert.True(t, programmed, "a live context means the shared map write happened")

	updates := 0
	for _, c := range mockBpf.CallLog {
		if c == "UpdateClusterPolicyEbpfMaps" {
			updates++
		}
	}
	assert.Equal(t, 1, updates, "a context from an earlier reconcile still has maps worth updating")
}

// A rule-derivation abort must keep errors accumulated from earlier identifiers.
func TestReconcileClusterPolicyEndpoint_DeriveAbortCarriesAccumulatedError(t *testing.T) {
	nodeIP := "192.168.70.108"
	namespace := "np-target"
	deriveErr := errors.New("etcdserver: request timed out")
	enomem := errors.New("unable to update map: cannot allocate memory")
	badCPE := "poisoned-cpe-abcd"
	cpeName := "isolate-everything-t7p5w"

	attempt := func(t *testing.T) (error, []string) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{UpdateClusterPolicyEbpfMapsErr: enomem}
		r := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: cpeName},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "isolate-everything"},
				Priority:  10,
				Tier:      policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
					{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: namespace},
					{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.109", Name: "redis-def456", Namespace: namespace},
				},
				Ingress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "192.168.90.89", Action: "Deny"}},
			},
		}
		r.podIdentifierToClusterPolicyEndpointMap.Store("nginx@"+namespace, []string{badCPE})
		r.podIdentifierToClusterPolicyEndpointMap.Store("redis@"+namespace, []string{cpeName})

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if key.Name == badCPE {
					return deriveErr
				}
				if cpObj, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*cpObj = *cpe
				}
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe}}
				return nil
			},
		).AnyTimes()

		return r.reconcileClusterPolicyEndpoint(context.TODO(), cpe), mockBpf.CallLog
	}

	for i := 0; i < 200; i++ {
		err, callLog := attempt(t)
		require.Error(t, err)

		attempted := false
		for _, c := range callLog {
			if c == "UpdateClusterPolicyEbpfMaps" {
				attempted = true
			}
		}
		if !attempted {
			continue
		}
		assert.ErrorIs(t, err, deriveErr, "the derive failure must surface")
		assert.ErrorIs(t, err, enomem,
			"the earlier identifier's map-write cause must not be discarded by the derive abort")
		assert.Contains(t, err.Error(), "redis@"+namespace)
		return
	}
	t.Fatal("map iteration never scheduled the map-write identifier first in 200 attempts; with two identifiers this is unreachable, so the fixture has changed")
}

// Latency suppression rules on the cluster-policy path.
func TestReconcileClusterPolicyEndpoint_LatencySuppressionMirrorsPE(t *testing.T) {
	nodeIP := "192.168.70.108"
	namespace := "np-target"
	skipped := fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)

	newCPE := func(pods []policyk8sawsv1.PodEndpoint) *policyk8sawsv1.ClusterPolicyEndpoint {
		return &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name: "isolate-everything-t7p5w",
				Annotations: map[string]string{
					LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano),
				},
			},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef:            policyk8sawsv1.ClusterPolicyReference{Name: "isolate-everything"},
				Priority:             10,
				Tier:                 policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: pods,
				Ingress:              []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "192.168.90.89", Action: "Deny"}},
			},
		}
	}

	run := func(t *testing.T, mockBpf *ebpf.MockBpfClient, cpe *policyk8sawsv1.ClusterPolicyEndpoint) (uint64, int) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockClient := mock_client.NewMockClient(ctrl)
		r := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)
		r.trackerStartTime = time.Now().Add(-time.Minute)

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if o, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*o = *cpe
				}
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe}}
				return nil
			},
		).AnyTimes()

		before := histSampleCount(t, clusterPolicyProgrammingLatency)
		require.NoError(t, r.reconcileClusterPolicyEndpoint(context.TODO(), cpe))
		writes := 0
		for _, c := range mockBpf.CallLog {
			if c == "UpdateClusterPolicyEbpfMaps" {
				writes++
			}
		}
		return histSampleCount(t, clusterPolicyProgrammingLatency) - before, writes
	}

	t.Run("every identifier skipped and no context: no sample", func(t *testing.T) {
		cpe := newCPE([]policyk8sawsv1.PodEndpoint{
			{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: namespace},
		})
		samples, writes := run(t, &ebpf.MockBpfClient{
			AttacheBPFProbesErrByPod:        map[string]error{namespace + "/nginx-abc123": skipped},
			PodIdentifiersWithoutBPFContext: map[string]bool{"nginx@" + namespace: true},
		}, cpe)
		require.Equal(t, 0, writes, "fixture precondition: nothing written")
		assert.Equal(t, uint64(0), samples, "a reconcile that programmed nothing must not record a sample")
	})

	t.Run("one skipped, one programmed: sample recorded", func(t *testing.T) {
		cpe := newCPE([]policyk8sawsv1.PodEndpoint{
			{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: namespace},
			{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.109", Name: "redis-def456", Namespace: namespace},
		})
		samples, writes := run(t, &ebpf.MockBpfClient{
			AttacheBPFProbesErrByPod:        map[string]error{namespace + "/nginx-abc123": skipped},
			PodIdentifiersWithoutBPFContext: map[string]bool{"nginx@" + namespace: true},
		}, cpe)
		require.Equal(t, 1, writes, "fixture precondition: exactly one identifier programmed")
		assert.Equal(t, uint64(1), samples, "programming one identifier is enough to record")
	})

	t.Run("attach failure with a live context: programmed but error, no sample", func(t *testing.T) {
		// Attach error with a live context: the map write lands but latency is not
		// recorded.
		attachFail := errors.New("failed to find link enifaabbccdd: Link not found")
		cpe := newCPE([]policyk8sawsv1.PodEndpoint{
			{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: namespace},
		})
		mockBpf := &ebpf.MockBpfClient{
			AttacheBPFProbesErrByPod: map[string]error{namespace + "/nginx-abc123": attachFail},
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockClient := mock_client.NewMockClient(ctrl)
		r := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)
		r.trackerStartTime = time.Now().Add(-time.Minute)
		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if o, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*o = *cpe
				}
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe}}
				return nil
			},
		).AnyTimes()

		before := histSampleCount(t, clusterPolicyProgrammingLatency)
		err := r.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
		require.Error(t, err)
		assert.ErrorIs(t, err, attachFail)

		writes := 0
		for _, c := range mockBpf.CallLog {
			if c == "UpdateClusterPolicyEbpfMaps" {
				writes++
			}
		}
		require.Equal(t, 1, writes, "fixture precondition: the map write lands despite the attach failure")
		assert.Equal(t, uint64(0), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
			"a reconcile returning an error must not record a sample even though the map write landed")
	})

	t.Run("no local identifiers: pre-change behaviour, sample recorded", func(t *testing.T) {
		cpe := newCPE([]policyk8sawsv1.PodEndpoint{
			{HostIP: policyk8sawsv1.NetworkAddress("9.9.9.9"), PodIP: "192.168.99.9", Name: "elsewhere-1", Namespace: namespace},
		})
		samples, writes := run(t, &ebpf.MockBpfClient{}, cpe)
		require.Equal(t, 0, writes, "fixture precondition: no local identifier")
		assert.Equal(t, uint64(1), samples, "an empty identifier set keeps the pre-change behaviour")
	})
}

// A rule-derivation failure stops the loop; the requeue programs the rest.
func TestReconcileClusterPolicyEndpoint_DeriveFailureAbortsRemainingIdentifiers(t *testing.T) {
	nodeIP := "192.168.70.108"
	namespace := "np-target"
	deriveErr := errors.New("etcdserver: request timed out")
	badCPE := "poisoned-cpe-abcd"
	cpeName := "isolate-everything-t7p5w"

	attempt := func(t *testing.T) (error, int) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockClient := mock_client.NewMockClient(ctrl)
		mockBpf := &ebpf.MockBpfClient{}
		r := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: cpeName},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "isolate-everything"},
				Priority:  10,
				Tier:      policyk8sawsv1.AdminTier,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
					{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: namespace},
					{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.109", Name: "redis-def456", Namespace: namespace},
				},
				Ingress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "192.168.90.89", Action: "Deny"}},
			},
		}
		r.podIdentifierToClusterPolicyEndpointMap.Store("nginx@"+namespace, []string{badCPE})
		r.podIdentifierToClusterPolicyEndpointMap.Store("redis@"+namespace, []string{cpeName})

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
				if key.Name == badCPE {
					return deriveErr
				}
				if o, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
					*o = *cpe
				}
				return nil
			},
		).AnyTimes()
		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
				*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe}}
				return nil
			},
		).AnyTimes()

		err := r.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
		writes := 0
		for _, c := range mockBpf.CallLog {
			if c == "UpdateClusterPolicyEbpfMaps" {
				writes++
			}
		}
		return err, writes
	}

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

// Errors from different identifiers are all returned.
func TestReconcileClusterPolicyEndpoint_AccumulatesDistinctCauses(t *testing.T) {
	nodeIP := "192.168.70.108"
	namespace := "np-target"
	errNginx := errors.New("veth gone for nginx")
	errRedis := errors.New("veth gone for redis")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{
		AttacheBPFProbesErrByPod: map[string]error{
			namespace + "/nginx-abc123": errNginx,
			namespace + "/redis-def456": errRedis,
		},
	}
	r := NewClusterPolicyEndpointsReconciler(mockClient, nodeIP, mockBpf)

	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "isolate-everything-t7p5w"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "isolate-everything"},
			Priority:  10,
			Tier:      policyk8sawsv1.AdminTier,
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.108", Name: "nginx-abc123", Namespace: namespace},
				{HostIP: policyk8sawsv1.NetworkAddress(nodeIP), PodIP: "192.168.95.109", Name: "redis-def456", Namespace: namespace},
			},
			Ingress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "192.168.90.89", Action: "Deny"}},
		},
	}
	mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
			if o, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
				*o = *cpe
			}
			return nil
		},
	).AnyTimes()
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
		func(ctx context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, opts ...client.ListOption) error {
			*list = policyk8sawsv1.ClusterPolicyEndpointList{Items: []policyk8sawsv1.ClusterPolicyEndpoint{*cpe}}
			return nil
		},
	).AnyTimes()

	err := r.reconcileClusterPolicyEndpoint(context.TODO(), cpe)
	require.Error(t, err)
	assert.ErrorIs(t, err, errNginx, "the first identifier's cause must survive the Join")
	assert.ErrorIs(t, err, errRedis, "the second identifier's cause must survive the Join")
}
