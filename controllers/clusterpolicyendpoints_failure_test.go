package controllers

import (
	"context"
	"errors"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// The cluster-policy counterparts of the cases in policyendpoints_failure_test.go. The two
// controllers share this failure-handling model, so each fix lands on both; these pin the
// cluster half so the pair cannot drift.
//
// Cluster policy rules carry an explicit Action, so a skipped map write here can leave a pod
// without a Deny that was meant to apply -- the same defect as on the namespaced path, with a
// fail-open rather than a fail-stale outcome.

// TestClusterPolicySlices_AttachFailureHandling covers configureClusterPolicyBPFProbes.
// GetPodIdentifier strips the last name segment, so replicas of one workload share an
// identifier and the single pair of eBPF maps behind it. One replica failing to attach must
// not stop the others from attaching, nor stop the shared maps from being written.
func TestClusterPolicySlices_AttachFailureHandling(t *testing.T) {
	attachFailed := errors.New("failed to find link enif00112233")

	// web-aaa and web-bbb share the identifier "web@<ns>". web-aaa is listed first, so the
	// pre-fix code returned on its failure before ever reaching web-bbb.
	web := identifierOf("web-aaa")
	podA := types.NamespacedName{Name: "web-aaa", Namespace: fixtureNamespace}
	podB := types.NamespacedName{Name: "web-bbb", Namespace: fixtureNamespace}

	newFixture := func(t *testing.T) *cpeFixture {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("web-bbb", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		return fx
	}

	t.Run("a replica's attach failure does not stop its co-located sibling", func(t *testing.T) {
		fx := newFixture(t)
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{podA: attachFailed}

		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), attachFailed,
			"the attach failure must be returned so the request requeues")

		assert.False(t, fx.bpf.AttachedPods[podA])
		assert.True(t, fx.bpf.AttachedPods[podB],
			"the loop must continue past the failing replica to the one that can attach")
	})

	t.Run("the shared identifier is still programmed for the replica that attached", func(t *testing.T) {
		fx := newFixture(t)
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{podA: attachFailed}

		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), attachFailed)

		// Skipping the map write would leave web-bbb without this CNP's Deny for as long as
		// web-aaa stays broken.
		assert.Contains(t, fx.clusterPolicyRules(web), "Deny 192.168.90.1/32",
			"the identifier's maps must be written for the replica that did attach")
		state, ok := fx.clusterPolicyState(web)
		require.True(t, ok, "cluster pod_state must be programmed alongside the rules")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("a recovered attach is retried and clears the error", func(t *testing.T) {
		fx := newFixture(t)
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{podA: attachFailed}
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), attachFailed)

		fx.bpf.AttacheBPFProbesErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.True(t, fx.bpf.AttachedPods[podA], "the retry must attach the pod that failed before")
	})

	t.Run("every failing replica is reported, not just the first", func(t *testing.T) {
		fx := newFixture(t)
		otherFailure := errors.New("interface count is unknown")
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{
			podA: attachFailed,
			podB: otherFailure,
		}

		err := fx.reconcile("cnp-1-aaaaa")
		// Both must survive the errors.Join chain, which is what %w rather than %v buys.
		require.ErrorIs(t, err, attachFailed)
		require.ErrorIs(t, err, otherFailure)
	})
}

// TestClusterPolicySlices_DeleteFlowProgrammingFailure covers the delete path when the call
// that updates the pods the parent still selects fails while there is nothing to clean up, so
// failedCleanups is empty. The departing CPE's selector entry must be removed rather than
// written as an empty set: nothing is owed a retry, and the entry is keyed by a CPE that no
// longer exists.
func TestClusterPolicySlices_DeleteFlowProgrammingFailure(t *testing.T) {
	writeFailed := errors.New("cluster policy map write failed")
	resident := identifierOf("resident-aaa")

	// Two slices of cnp-1 both select resident-aaa, so deleting one leaves the pod selected by
	// the sibling: it is a target pod, never a pod to clean up.
	fx := newCPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}},
		sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 2,
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.2/32")}},
	)
	fx.reconcileAll()
	fx.reset()

	// cnp-1-aaaaa goes away and resident's map write fails, so updateErr is set while
	// cleanupErr is not.
	fx.deleteSlice("cnp-1-aaaaa")
	fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{resident: writeFailed}
	require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed,
		"the failure must be returned so the request requeues")

	_, tracked := fx.r.ClusterPolicyEndpointSelectorMap.Load("cnp-1-aaaaa")
	assert.False(t, tracked,
		"with no failed cleanups to retry, the deleted CPE's entry must be removed, not stored empty")

	// The retry succeeds and leaves nothing behind for the departed slice.
	fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
	fx.reset()
	require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
	_, tracked = fx.r.ClusterPolicyEndpointSelectorMap.Load("cnp-1-aaaaa")
	assert.False(t, tracked)
}

// TestClusterPolicySlices_PriorPodsDedupedByIdentity covers deriveTargetPodsForParentCNP
// reading a parent's prior pods from every one of its slices. A StatefulSet pod keeps its name
// across recreation but not its address, so the same pod can be recorded under two slices with
// different PodIPs. Deduping on the whole struct would keep both copies, and
// GetPodListToBeCleanedUp matches on NamespacedName, so the pod would be cleaned up twice.
func TestClusterPolicySlices_PriorPodsDedupedByIdentity(t *testing.T) {
	fx := newCPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods:    []podRef{localPod("other-aaa", "10.1.1.9")},
			ingress: []ruleRef{deny("192.168.90.1/32")}},
		sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 2,
			pods:    []podRef{localPod("other-aaa", "10.1.1.9")},
			ingress: []ruleRef{deny("192.168.90.2/32")}},
	)

	// web-0 is no longer selected by either slice, but both still record it from the
	// reconciles that did -- each with the address it had at the time.
	web0 := types.NamespacedName{Name: "web-0", Namespace: fixtureNamespace}
	for name, ip := range map[string]string{"cnp-1-aaaaa": "10.1.1.5", "cnp-1-bbbbb": "10.1.1.7"} {
		fx.r.ClusterPolicyEndpointSelectorMap.Store(name,
			[]npatypes.Pod{{NamespacedName: web0, PodIP: policyk8sawsv1.NetworkAddress(ip)}})
	}

	_, _, podsToBeCleanedUp, _, _, err := fx.r.deriveTargetPodsForParentCNP(
		context.TODO(), "cnp-1", "cnp-1-aaaaa")
	require.NoError(t, err)

	assert.Len(t, podsToBeCleanedUp, 1,
		"a pod recorded under two slices with different IPs is one pod, and is cleaned up once")
	if len(podsToBeCleanedUp) > 0 {
		assert.Equal(t, web0, podsToBeCleanedUp[0].NamespacedName)
	}
}
