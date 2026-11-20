package controllers

import (
	"context"
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

// TestPolicySlices_NewSliceFindsPodsDeselectedInTheSameUpdate covers the prior-pod lookup being
// per parent policy rather than per slice.
//
// A policy re-sliced in a single update can present a brand new slice to the reconciler
// first. A pod dropped in the same update was recorded only under the parent's earlier
// reconcile, so a lookup keyed by the reconciled slice would miss it and the pod would keep
// its enforcement with nothing left to ever clean it up.
func TestPolicySlices_NewSliceFindsPodsDeselectedInTheSameUpdate(t *testing.T) {
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

	// The new slice is reconciled first, before any reconcile has recorded it.
	require.NoError(t, fx.reconcile("np-1-bbbbb"))

	state, ok := fx.podState(gone)
	require.True(t, ok,
		"the deselected pod is only known from the parent's earlier reconcile, so it must still be cleaned up")
	assert.Equal(t, ebpf.DEFAULT_ALLOW, state,
		"no policy selects the deselected pod anymore, so it must be back on its baseline")
}

// TestPolicySlices_FailedCleanupIsRetriedUntilItSucceeds covers a slice delete whose cleanup
// fails for one identifier while a sibling slice of the same parent survives. The failed
// identifier stays queued and is programmed by the next pass; the parent's record no longer
// lists the deleted slice either way.
func TestPolicySlices_FailedCleanupIsRetriedUntilItSucceeds(t *testing.T) {
	writeFailed := errors.New("map write failed")
	stuck, other := identifierOf("stuck-aaa"), identifierOf("other-aaa")

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
	require.ElementsMatch(t, []string{stuck, other}, fx.r.localIdentifiers(fixtureNamespace, "np-1"))

	// np-1-aaaaa is deleted while np-1-bbbbb remains, and stuck's cleanup fails.
	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{stuck: writeFailed}
	fx.deleteSlice("np-1-aaaaa")
	fx.reset()
	require.ErrorIs(t, fx.reconcileDeleted("np-1-aaaaa"), writeFailed)
	assert.Equal(t, []string{other}, fx.r.localIdentifiers(fixtureNamespace, "np-1"),
		"the parent's record reflects its surviving slice even while a cleanup is owed")
	assert.Equal(t, []string{"np-1-bbbbb"}, fx.identifierSlices(other))
	assert.Equal(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(other), "the failure for stuck does not hold back other")

	// On recovery the queued identifier is programmed by the next pass, and only it.
	fx.bpf.UpdateEbpfMapsErrFor = nil
	fx.reset()
	require.NoError(t, fx.r.drainProgramming(context.TODO()))
	fx.assertRulesCleared(stuck)
	assert.NotContains(t, fx.bpf.IngressByIdentifier, other)
}

// TestPolicySlices_DeriveErrorDoesNotAbortRemainingIdentifiers covers one identifier's failed
// rule derivation not stopping the programming of the others, and the podIdentifier context the
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
// series are never removed. A pass that queued nothing to program must not record.
func TestPolicySlices_TeardownLatencyOnlyForRealTeardowns(t *testing.T) {
	t.Run("a delete with nothing to tear down records no sample", func(t *testing.T) {
		fx := newPEFixture(t)
		// Nothing was ever reconciled, so the deleted slice has no pods recorded.
		before := teardownSampleCount(t, "np-empty-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-empty-aaaaa"))
		assert.Equal(t, uint64(0), teardownSampleCount(t, "np-empty-aaaaa")-before,
			"an empty delete pass is not a teardown measurement")
	})

	t.Run("a delete records one sample once programming applies it, retries included", func(t *testing.T) {
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
			"the teardown is not applied until its identifier is programmed")

		fx.bpf.UpdateEbpfMapsErrFor = nil
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		assert.Equal(t, uint64(1), teardownSampleCount(t, "np-2-aaaaa")-before,
			"the retry that applies the teardown records it")
		fx.assertRulesCleared(stuck)

		require.NoError(t, fx.reconcileDeleted("np-2-aaaaa"))
		assert.Equal(t, uint64(1), teardownSampleCount(t, "np-2-aaaaa")-before,
			"a repeat with nothing left to queue is not another measurement")
	})
}

// TestPolicySlices_SetupLatencyEndsWhenEveryIdentifierIsProgrammed covers what
// policySetupLatency measures: from the reconcile of a PolicyEndpoint until every pod
// identifier it queued on this node is programmed.
func TestPolicySlices_SetupLatencyEndsWhenEveryIdentifierIsProgrammed(t *testing.T) {
	writeFailed := errors.New("map write failed")
	web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: "np-3-aaaaa", parent: "np-3",
		pods:    []podRef{localPod("web-aaa", "10.1.1.2"), localPod("api-aaa", "10.1.1.3")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})

	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{api: writeFailed}
	before := setupSampleCount(t, "np-3-aaaaa")
	require.ErrorIs(t, fx.reconcile("np-3-aaaaa"), writeFailed)
	assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(web), "web is programmed")
	assert.Equal(t, uint64(0), setupSampleCount(t, "np-3-aaaaa")-before,
		"api is not programmed yet, so the PolicyEndpoint is not applied")

	fx.bpf.UpdateEbpfMapsErrFor = nil
	require.NoError(t, fx.r.drainProgramming(context.TODO()))
	assert.Equal(t, uint64(1), setupSampleCount(t, "np-3-aaaaa")-before,
		"the retry that programs the last identifier records the sample")
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

func teardownSampleCount(t *testing.T, peName string) uint64 {
	return summarySampleCount(t, policyTearDownLatency, peName)
}

func setupSampleCount(t *testing.T, peName string) uint64 {
	return summarySampleCount(t, policySetupLatency, peName)
}

// summarySampleCount reads a latency summary for one PolicyEndpoint name. Reading creates the
// child if absent, which is harmless here: the assertions compare sample counts, and an
// unobserved child reports zero.
func summarySampleCount(t *testing.T, summary *prometheus.SummaryVec, peName string) uint64 {
	t.Helper()
	obs, err := summary.GetMetricWithLabelValues(peName, fixtureNamespace)
	require.NoError(t, err)
	m := &dto.Metric{}
	require.NoError(t, obs.(prometheus.Metric).Write(m))
	return m.GetSummary().GetSampleCount()
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
