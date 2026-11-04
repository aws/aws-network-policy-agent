package controllers

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// Guards for behaviour that was previously only exercised incidentally: each case below
// fails if the one line it covers is reverted or deleted.

// TestPolicySlices_SiblingSelectorEntriesAreUnioned covers the prior-pod lookup in
// deriveTargetPodsForParentNP reading every slice of the parent rather than only the
// reconciled one.
//
// A policy re-sliced in a single update can present a brand new slice to the reconciler
// first. That slice has no selector entry of its own, so a pod dropped in the same update is
// only discoverable under a sibling's entry -- reduce the lookup to resourceName and the pod
// keeps its enforcement with nothing left to ever clean it up.
func TestPolicySlices_SiblingSelectorEntriesAreUnioned(t *testing.T) {
	gone := identifierOf("gone-aaa")
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("gone-aaa", "10.1.1.1"), localPod("stays-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	fx.reconcileAll()
	fx.reset()

	// gone-aaa is deselected and a new sibling slice appears in the same update.
	fx.setSlices(
		sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("stays-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		sliceSpec{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{localPod("stays-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.2/32")}},
	)

	// The new slice is reconciled first, before it has a selector entry of its own.
	require.NoError(t, fx.reconcile("np-1-bbbbb"))

	state, ok := fx.podState(gone)
	require.True(t, ok,
		"the deselected pod is only reachable through the sibling slice's selector entry, so it must still be cleaned up")
	assert.Equal(t, ebpf.DEFAULT_ALLOW, state,
		"no policy selects the deselected pod anymore, so it must be back on its baseline")
}

// TestPolicySlices_DepartingSliceEntryHoldsOnlyFailedCleanups covers the selector-map write
// at the end of cleanUpPolicyEndpoint, on the path the delete-flow tests never reach: a
// sibling slice of the same parent survives the delete.
//
// While a cleanup is owed the departing slice's entry must hold exactly the pods that failed,
// not the full set it held before, and once the retry succeeds the entry must go. Dropping
// the write leaves the pre-delete set behind for good.
func TestPolicySlices_DepartingSliceEntryHoldsOnlyFailedCleanups(t *testing.T) {
	writeFailed := errors.New("map write failed")
	stuck, other := identifierOf("stuck-aaa"), identifierOf("other-aaa")
	departing := utils.GetPolicyEndpointIdentifier("np-1-aaaaa", fixtureNamespace)

	fx := newPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("other-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		sliceSpec{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{localPod("other-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.2/32")}},
	)
	fx.reconcileAll()

	// Both pods start out recorded under the departing slice.
	before := selectorEntry(t, fx, departing)
	require.ElementsMatch(t, []string{stuck, other}, identifiersOf(before))

	// np-1-aaaaa is deleted while np-1-bbbbb remains, and stuck's cleanup fails.
	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{stuck: writeFailed}
	fx.deleteSlice("np-1-aaaaa")
	fx.reset()
	require.ErrorIs(t, fx.reconcileDeleted("np-1-aaaaa"), writeFailed)

	owed := selectorEntry(t, fx, departing)
	assert.ElementsMatch(t, []string{stuck}, identifiersOf(owed),
		"the departing slice's entry must be narrowed to the pods still owed a cleanup")

	// On recovery the retry repeats only that pod, and the entry is removed.
	fx.bpf.UpdateEbpfMapsErrFor = nil
	fx.reset()
	require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
	fx.assertRulesCleared(stuck)
	_, stillTracked := fx.r.policyEndpointSelectorMap.Load(departing)
	assert.False(t, stillTracked,
		"with nothing left owed, the departing slice must not keep an entry")
}

// TestPolicySlices_DeriveErrorDoesNotAbortRemainingIdentifiers covers the record-and-continue
// on a rule-derivation failure in reconcilePolicyEndpoint, and the podIdentifier context the
// error carries.
//
// Two identifiers each additionally track a slice of another policy whose read fails, so both
// derivations fail in the same pass. Returning on the first would surface one failure; the
// joined error must name both, which also makes the assertion independent of map iteration
// order.
func TestPolicySlices_DeriveErrorDoesNotAbortRemainingIdentifiers(t *testing.T) {
	apiFailed := errors.New("injected API failure")
	web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
	fx := newPEFixture(t)

	// Give each identifier a slice of its own from a different parent.
	fx.setSlices(sliceSpec{name: "np-9-aaaaa", parent: "np-9",
		pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.91.1/32")}})
	fx.reconcileAll()
	fx.setSlices(sliceSpec{name: "np-8-aaaaa", parent: "np-8",
		pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.92.1/32")}})
	fx.reconcileAll()

	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	require.NoError(t, fx.reconcile("np-1-aaaaa"))

	// Now both of those other slices become unreadable.
	fx.getErr = map[string]error{"np-9-aaaaa": apiFailed, "np-8-aaaaa": apiFailed}
	fx.reset()

	err := fx.reconcile("np-1-aaaaa")
	require.Error(t, err, "a derive failure must requeue the request")
	assert.Contains(t, err.Error(), web,
		"the error must name every identifier whose derivation failed")
	assert.Contains(t, err.Error(), api,
		"a failure for one identifier must not stop the loop reaching the next")
}

// TestPolicySlices_LatencyObservedAfterFailedCleanup is the namespaced counterpart of
// TestClusterPolicySlices_LatencyObservedAfterFailedCleanup. A pass that does not land the
// change records nothing and leaves the trigger time unconsumed, so the retry that does land
// it reports the full time including the retry delay.
func TestPolicySlices_LatencyObservedAfterFailedCleanup(t *testing.T) {
	stuck := identifierOf("stuck-aaa")
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	fx.reconcileAll()

	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{stuck: errors.New("map write failed")}
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	pe := fx.store["np-1-aaaaa"]
	pe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["np-1-aaaaa"] = pe

	before := histSampleCount(t, policyProgrammingLatency)
	require.Error(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"a failed pass must not record a sample")

	fx.bpf.UpdateEbpfMapsErrFor = nil
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
		"the retry that succeeds must record the change it finally applied")
}

// TestPolicySlices_TeardownLatencyOnlyForRealTeardowns covers the guard on
// policyTearDownLatency. Every node reconciles every PE, so observing unconditionally adds a
// series per PE name per node -- and GenerateName means those names are never reused and the
// series are never removed. A pass that tore nothing down, or failed, must not record.
func TestPolicySlices_TeardownLatencyOnlyForRealTeardowns(t *testing.T) {
	t.Run("a delete with nothing to tear down records no sample", func(t *testing.T) {
		fx := newPEFixture(t)
		// Nothing was ever reconciled, so the deleted slice has no pods recorded.
		before := teardownSampleCount(t, "np-empty-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-empty-aaaaa"))
		assert.Equal(t, uint64(0), teardownSampleCount(t, "np-empty-aaaaa")-before,
			"an empty delete pass is not a teardown measurement")
	})

	t.Run("a failed delete records no sample, and the retry that succeeds does", func(t *testing.T) {
		writeFailed := errors.New("map write failed")
		stuck := identifierOf("stuck-aaa")
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-2-aaaaa", parent: "np-2",
			pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()

		fx.bpf.UpdateEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.deleteSlice("np-2-aaaaa")
		before := teardownSampleCount(t, "np-2-aaaaa")
		require.ErrorIs(t, fx.reconcileDeleted("np-2-aaaaa"), writeFailed)
		assert.Equal(t, uint64(0), teardownSampleCount(t, "np-2-aaaaa")-before,
			"a failed teardown must not be measured as one")

		fx.bpf.UpdateEbpfMapsErrFor = nil
		require.NoError(t, fx.reconcileDeleted("np-2-aaaaa"))
		assert.Equal(t, uint64(1), teardownSampleCount(t, "np-2-aaaaa")-before,
			"the pass that actually tore the policy down must be measured")
	})
}

// selectorEntry reads one PolicyEndpoint's recorded pods, failing if it has none.
func selectorEntry(t *testing.T, fx *peFixture, policyEndpointIdentifier string) []npatypes.Pod {
	t.Helper()
	v, ok := fx.r.policyEndpointSelectorMap.Load(policyEndpointIdentifier)
	require.True(t, ok, "expected a selector entry for %s", policyEndpointIdentifier)
	return v.([]npatypes.Pod)
}

// identifiersOf returns the distinct identifiers of pods. The recorded set is the parent's
// target pods, which are accumulated per slice without deduping, so a pod named by two
// slices of the same parent appears twice.
func identifiersOf(pods []npatypes.Pod) []string {
	seen := map[string]bool{}
	var out []string
	for _, pod := range pods {
		id := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// teardownSampleCount reads the teardown summary for one PolicyEndpoint name. Reading creates
// the child if absent, which is harmless here: the assertions compare sample counts, and an
// unobserved child reports zero.
func teardownSampleCount(t *testing.T, peName string) uint64 {
	t.Helper()
	obs, err := policyTearDownLatency.GetMetricWithLabelValues(peName, fixtureNamespace)
	require.NoError(t, err)
	m := &dto.Metric{}
	require.NoError(t, obs.(prometheus.Metric).Write(m))
	return m.GetSummary().GetSampleCount()
}

// TestTrackFailedCleanups covers the shared helper both reconcilers commit through.
func TestTrackFailedCleanups(t *testing.T) {
	pod := func(name string) npatypes.Pod {
		return npatypes.Pod{NamespacedName: nsName(name)}
	}
	targets := []npatypes.Pod{pod("web-aaa")}
	failed := []npatypes.Pod{pod("stuck-aaa")}

	t.Run("failed cleanups join the tracked set and contribute their identifiers", func(t *testing.T) {
		ids := map[string]bool{identifierOf("web-aaa"): true}
		pods, tracked := trackFailedCleanups(targets, failed, ids)

		assert.ElementsMatch(t, []string{identifierOf("web-aaa"), identifierOf("stuck-aaa")}, identifiersOf(pods))
		assert.True(t, tracked[identifierOf("stuck-aaa")],
			"the failed pod's identifier must be committed so the retry derives it as stale again")
		assert.True(t, tracked[identifierOf("web-aaa")])
	})

	t.Run("the caller's identifier map is not mutated", func(t *testing.T) {
		ids := map[string]bool{identifierOf("web-aaa"): true}
		_, _ = trackFailedCleanups(targets, failed, ids)

		assert.Len(t, ids, 1, "the caller's identifier map must not gain the failed identifiers")
	})

	t.Run("the caller's target slice is not written through", func(t *testing.T) {
		// Spare capacity is what makes a bare append write into the caller's own array, so
		// asserting on len alone would never catch it: park a sentinel past len and check it
		// survives.
		withSpare := make([]npatypes.Pod, 2, 4)
		withSpare[0], withSpare[1] = pod("web-aaa"), pod("sentinel-aaa")
		caller := withSpare[:1]

		_, _ = trackFailedCleanups(caller, failed, nil)

		assert.Equal(t, "sentinel-aaa", withSpare[1].Name,
			"the helper must clone before appending, or it overwrites what the caller still holds past len")
	})

	t.Run("a nil identifier map is usable", func(t *testing.T) {
		_, tracked := trackFailedCleanups(nil, failed, nil)
		assert.True(t, tracked[identifierOf("stuck-aaa")])
	})
}

// TestAttachProbesForIdentifier covers the shared attach loop. Replicas of one workload share
// an identifier and the single pair of eBPF maps behind it, so one replica failing must not
// stop its co-located siblings.
func TestAttachProbesForIdentifier(t *testing.T) {
	podIdentifier := identifierOf("web-aaa")
	pods := []npatypes.Pod{
		{NamespacedName: nsName("web-aaa")},
		{NamespacedName: nsName("web-bbb")},
		{NamespacedName: nsName("other-aaa")},
	}

	t.Run("attaches every pod of the identifier and skips the rest", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		_, attachErr := attachProbesForIdentifier(bpf, podIdentifier, pods)
		require.NoError(t, attachErr)

		assert.True(t, bpf.AttachedPods[nsName("web-aaa")])
		assert.True(t, bpf.AttachedPods[nsName("web-bbb")])
		assert.False(t, bpf.AttachedPods[nsName("other-aaa")],
			"a pod of another identifier must not be attached under this one")
	})

	t.Run("a failing replica does not stop its siblings, and is reported", func(t *testing.T) {
		attachFailed := errors.New("attach failed")
		bpf := &ebpf.MockBpfClient{
			AttacheBPFProbesErrFor: map[types.NamespacedName]error{nsName("web-aaa"): attachFailed},
		}

		_, err := attachProbesForIdentifier(bpf, podIdentifier, pods)
		require.ErrorIs(t, err, attachFailed)
		assert.True(t, bpf.AttachedPods[nsName("web-bbb")],
			"the co-located replica shares the maps and must still be attached")
		assert.True(t, strings.Contains(err.Error(), "web-aaa"),
			"the error must name the pod that failed")
	})
}

func nsName(name string) types.NamespacedName {
	return types.NamespacedName{Name: name, Namespace: fixtureNamespace}
}
