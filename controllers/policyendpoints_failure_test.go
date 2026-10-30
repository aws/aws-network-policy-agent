package controllers

import (
	"context"
	"errors"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// These cases cover the failure-handling model ported from the cluster-policy path
// (PR #692) to the namespaced PolicyEndpoint controller:
//
//   - Programming runs whether or not cleanup succeeded, so a failing cleanup for one
//     identifier does not hold back the pods the policy still selects.
//   - The pods whose cleanup failed are committed alongside the programmed pods, so the
//     retry derives them as stale again and repeats only those.
//   - A per-identifier derive/programming error records and continues instead of aborting
//     the loop, and is returned so the request requeues.
//
// Namespaced NetworkPolicy rules are allow-only; isolation comes from Spec.PodIsolation,
// which these fixtures leave unset, so cleanup re-derives with an allow-all entry.

// stuckPECleanup seeds two local pods of one parent policy, then makes stuck-aaa's map
// writes fail and drops it from the policy while resident-aaa stays. Reconciling the slice
// then runs cleanup for stuck, which fails, while resident stays programmed.
func stuckPECleanup(t *testing.T, writeFailed error) (*peFixture, string, string) {
	t.Helper()
	stuck, resident := identifierOf("stuck-aaa"), identifierOf("resident-aaa")
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	fx.reconcileAll()
	fx.reset()

	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{stuck: writeFailed}
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	return fx, stuck, resident
}

func TestPolicySlices_CleanupFailureHandling(t *testing.T) {
	writeFailed := errors.New("map write failed")

	t.Run("a failing cleanup does not block programming the pods still selected", func(t *testing.T) {
		fx, stuck, resident := stuckPECleanup(t, writeFailed)

		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		// resident is still selected and must be programmed in the same pass the cleanup failed.
		state, ok := fx.podState(resident)
		require.True(t, ok, "the still-selected identifier must be programmed despite the cleanup failure")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		assert.Contains(t, fx.ingressCIDRs(resident), "192.168.90.1/32")
		_ = stuck
	})

	t.Run("a failed cleanup is retried and then stops being retried once it succeeds", func(t *testing.T) {
		fx, stuck, _ := stuckPECleanup(t, writeFailed)
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		// The write recovers. The retry cleans stuck up and clears its rules.
		fx.bpf.UpdateEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		fx.assertRulesCleared(stuck)

		// Nothing left to retry: a further reconcile does not touch stuck again.
		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.NotContains(t, fx.bpf.IngressByIdentifier, stuck, "nothing left to retry")
	})

	t.Run("a failed cleanup whose identifier is selected again is programmed, not cleared", func(t *testing.T) {
		fx, stuck, _ := stuckPECleanup(t, writeFailed)
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		// A new pod of the same workload lands on the node and is selected again.
		fx.bpf.UpdateEbpfMapsErrFor = nil
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("stuck-bbb", "10.1.1.5"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.Contains(t, fx.ingressCIDRs(stuck), "192.168.90.1/32")

		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.Contains(t, fx.ingressCIDRs(stuck), "192.168.90.1/32",
			"the old pod's cleanup must not clear the identifier later")
	})

	t.Run("a failed cleanup whose pod then leaves the node stops being retried", func(t *testing.T) {
		fx, stuck, _ := stuckPECleanup(t, writeFailed)
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		// The pod leaves the node: its probes are detached, so cleanup is a no-op and the
		// reconcile succeeds. The retry must not keep trying to write stuck.
		fx.detachContext(stuck)
		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		fx.bpf.UpdateEbpfMapsErrFor = nil
		fx.bpf.ForgetIdentifier(stuck)
		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.NotContains(t, fx.bpf.IngressByIdentifier, stuck,
			"a departed pod is not cleaned up again once its workload returns")
	})

	t.Run("a failed cleanup for an identifier a second policy still selects is retried", func(t *testing.T) {
		stuck, resident := identifierOf("stuck-aaa"), identifierOf("resident-aaa")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		// np-1 stops selecting stuck; its cleanup recompute (from np-2) fails.
		fx.bpf.UpdateEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		// On recovery the retry recomputes stuck from the policy that still selects it.
		fx.bpf.UpdateEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.Equal(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(stuck),
			"only the policy that still selects the pod contributes rules")
		_ = resident
	})

	t.Run("a programming failure for one identifier does not stop another, and requeues", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})

		// web's programming write fails; api must still be programmed and the error returned.
		fx.bpf.UpdateEbpfMapsErrFor = map[string]error{web: writeFailed}
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		state, ok := fx.podState(api)
		require.True(t, ok, "a programming failure for one identifier must not abort the loop")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		assert.Contains(t, fx.ingressCIDRs(api), "192.168.90.1/32")
	})
}

func TestPolicySlices_DeleteFlowFailureHandling(t *testing.T) {
	writeFailed := errors.New("map write failed")

	t.Run("deleting a PE whose cleanup keeps failing is retried until it succeeds", func(t *testing.T) {
		fx, stuck, resident := stuckPECleanup(t, writeFailed)
		// Reach the stuck state through a normal reconcile first.
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), writeFailed)

		// Now the slice is deleted while stuck's cleanup still fails.
		fx.deleteSlice("np-1-aaaaa")
		fx.reset()
		require.ErrorIs(t, fx.reconcileDeleted("np-1-aaaaa"), writeFailed)

		// On recovery the retry finishes stuck's cleanup; resident is not needlessly retried.
		fx.bpf.UpdateEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		fx.assertRulesCleared(stuck)
		_ = resident
	})
}

// TestPolicySlices_AttachFailureHandling covers configureeBPFProbes. GetPodIdentifier strips
// the last name segment, so replicas of one workload share an identifier and the single pair
// of eBPF maps behind it. One replica failing to attach must therefore not stop the others
// from attaching, nor stop the shared maps from being written for the ones that did -- or a
// policy update silently fails to land for healthy replicas.
func TestPolicySlices_AttachFailureHandling(t *testing.T) {
	attachFailed := errors.New("failed to find link enif00112233")

	// web-aaa and web-bbb share the identifier "web@<ns>". web-aaa is listed first, so the
	// pre-fix code returned on its failure before ever reaching web-bbb.
	web := identifierOf("web-aaa")
	podA := types.NamespacedName{Name: "web-aaa", Namespace: fixtureNamespace}
	podB := types.NamespacedName{Name: "web-bbb", Namespace: fixtureNamespace}

	newFixture := func(t *testing.T) *peFixture {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("web-bbb", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		return fx
	}

	t.Run("a replica's attach failure does not stop its co-located sibling", func(t *testing.T) {
		fx := newFixture(t)
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{podA: attachFailed}

		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), attachFailed,
			"the attach failure must be returned so the request requeues")

		assert.False(t, fx.bpf.AttachedPods[podA])
		assert.True(t, fx.bpf.AttachedPods[podB],
			"the loop must continue past the failing replica to the one that can attach")
	})

	t.Run("the shared identifier is still programmed for the replica that attached", func(t *testing.T) {
		fx := newFixture(t)
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{podA: attachFailed}

		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), attachFailed)

		// Skipping the map write would leave web-bbb on whatever the maps held before, so a
		// policy change would not reach it for as long as web-aaa stays broken.
		assert.Contains(t, fx.ingressCIDRs(web), "192.168.90.1/32",
			"the identifier's maps must be written for the replica that did attach")
		state, ok := fx.podState(web)
		require.True(t, ok, "pod_state must be programmed alongside the rules")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("a recovered attach is retried and clears the error", func(t *testing.T) {
		fx := newFixture(t)
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{podA: attachFailed}
		require.ErrorIs(t, fx.reconcile("np-1-aaaaa"), attachFailed)

		fx.bpf.AttacheBPFProbesErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.True(t, fx.bpf.AttachedPods[podA], "the retry must attach the pod that failed before")
	})

	t.Run("every failing replica is reported, not just the first", func(t *testing.T) {
		fx := newFixture(t)
		otherFailure := errors.New("interface count is unknown")
		fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{
			podA: attachFailed,
			podB: otherFailure,
		}

		err := fx.reconcile("np-1-aaaaa")
		// Both must survive the errors.Join chain, which is what %w rather than %v buys.
		require.ErrorIs(t, err, attachFailed)
		require.ErrorIs(t, err, otherFailure)
	})
}

// TestPolicySlices_DeleteFlowProgrammingFailure covers the delete path when the call that
// updates the pods the parent still selects fails while there is nothing to clean up, so
// failedCleanups is empty. The departing PE's selector entry must be removed rather than
// written as an empty set: nothing is owed a retry, and the entry is keyed by a PE that no
// longer exists.
func TestPolicySlices_DeleteFlowProgrammingFailure(t *testing.T) {
	writeFailed := errors.New("map write failed")
	resident := identifierOf("resident-aaa")

	// Two slices of np-1 both select resident-aaa, so deleting one leaves the pod selected by
	// the sibling: it is a target pod, never a pod to clean up.
	fx := newPEFixture(t)
	slices := []sliceSpec{
		{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.2/32")}},
	}
	fx.setSlices(slices...)
	fx.reconcileAll()
	fx.reset()

	// np-1-aaaaa goes away and resident's map write fails, so updateErr is set while
	// cleanupErr is not.
	fx.deleteSlice("np-1-aaaaa")
	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{resident: writeFailed}
	require.ErrorIs(t, fx.reconcileDeleted("np-1-aaaaa"), writeFailed,
		"the failure must be returned so the request requeues")

	departed := utils.GetPolicyEndpointIdentifier("np-1-aaaaa", fixtureNamespace)
	_, tracked := fx.r.policyEndpointSelectorMap.Load(departed)
	assert.False(t, tracked,
		"with no failed cleanups to retry, the deleted PE's entry must be removed, not stored empty")

	// The retry succeeds and leaves nothing behind for the departed slice.
	fx.bpf.UpdateEbpfMapsErrFor = nil
	fx.reset()
	require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
	_, tracked = fx.r.policyEndpointSelectorMap.Load(departed)
	assert.False(t, tracked)
}

// TestPolicySlices_PriorPodsDedupedByIdentity covers deriveTargetPodsForParentNP reading a
// parent's prior pods from every one of its slices. A StatefulSet pod keeps its name across
// recreation but not its address, so the same pod can be recorded under two slices with
// different PodIPs. Deduping on the whole struct would keep both copies, and
// getPodListToBeCleanedUp matches on NamespacedName, so the pod would be cleaned up twice.
func TestPolicySlices_PriorPodsDedupedByIdentity(t *testing.T) {
	fx := newPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("other-aaa", "10.1.1.9")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		sliceSpec{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{localPod("other-aaa", "10.1.1.9")},
			ingress: []ruleRef{allow("192.168.90.2/32")}},
	)

	// web-0 is no longer selected by either slice, but both still record it from the
	// reconciles that did -- each with the address it had at the time.
	web0 := types.NamespacedName{Name: "web-0", Namespace: fixtureNamespace}
	for name, ip := range map[string]string{"np-1-aaaaa": "10.1.1.5", "np-1-bbbbb": "10.1.1.7"} {
		fx.r.policyEndpointSelectorMap.Store(
			utils.GetPolicyEndpointIdentifier(name, fixtureNamespace),
			[]npatypes.Pod{{NamespacedName: web0, PodIP: policyk8sawsv1.NetworkAddress(ip)}})
	}

	_, _, podsToBeCleanedUp, _, _, err := fx.r.deriveTargetPodsForParentNP(
		context.TODO(), "np-1", fixtureNamespace, "np-1-aaaaa")
	require.NoError(t, err)

	assert.Len(t, podsToBeCleanedUp, 1,
		"a pod recorded under two slices with different IPs is one pod, and is cleaned up once")
	if len(podsToBeCleanedUp) > 0 {
		assert.Equal(t, web0, podsToBeCleanedUp[0].NamespacedName)
	}
}
