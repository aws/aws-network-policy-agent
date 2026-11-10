package controllers

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// The #686 fix: a failed eBPF map write must reach controller-runtime so the
// reconcile is retried. Before this change reconcilePolicyEndpoint returned
// nil, the reconcile was recorded as a success, and nothing on the node ever
// retried the write.
func TestReconcilePolicyEndpoint_MapWriteFailurePropagates(t *testing.T) {
	fx := newPEFixture(t)
	fx.bpf.UpdateEbpfMapsErr = fmt.Errorf("ingress map write: %w",
		fmt.Errorf("unable to update map: %w", unix.ENOMEM))
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})

	err := fx.reconcile("np-1-aaaaa")

	require.Error(t, err, "a failed map write must not be reported as a successful reconcile")
	assert.ErrorIs(t, err, unix.ENOMEM, "the errno must survive to the reconciler")
	assert.Contains(t, err.Error(), identifierOf("nginx-aaa"),
		"the failing identifier must be named by value, not just the word podIdentifier")
}

// A skip that no retry can resolve must not be reported as a failure, or the
// pod would fail every reconcile for the life of the node.
func TestReconcilePolicyEndpoint_ProbeAttachSkipIsNotAFailure(t *testing.T) {
	fx := newPEFixture(t)
	fx.bpf.AttacheBPFProbesErr = fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})

	assert.NoError(t, fx.reconcile("np-1-aaaaa"))
}

// Every other identifier must still be programmed when one fails, so a single
// bad write cannot leave the rest of the node's policy unapplied.
func TestReconcilePolicyEndpoint_OneFailingIdentifierDoesNotBlockTheRest(t *testing.T) {
	fx := newPEFixture(t)
	failing := identifierOf("web-aaa")
	healthy := identifierOf("api-aaa")
	require.NotEqual(t, failing, healthy, "the two pods must map to distinct identifiers")
	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{
		failing: errors.New("unable to update map: cannot allocate memory"),
	}
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods: []podRef{
			localPod("web-aaa", "10.1.1.1"),
			localPod("api-aaa", "10.1.1.2"),
		},
		ingress: []ruleRef{allow("192.168.90.1/32")}})

	err := fx.reconcile("np-1-aaaaa")

	require.Error(t, err)
	assert.ErrorContains(t, err, failing, "the failing identifier must be named")
	// Asserted both ways so map iteration order cannot decide the result: the healthy
	// identifier is programmed and the failing one is not, whichever ran first.
	assert.Contains(t, fx.bpf.IngressByIdentifier, healthy,
		"the healthy identifier must still be programmed")
	assert.NotContains(t, fx.bpf.IngressByIdentifier, failing,
		"the failing identifier must not be recorded as programmed")
}

// A skipped pod must not hide a real failure. configureeBPFProbes joins the per-pod attach
// errors with the map-write error, and errors.Is matches when any arm of a join carries
// ErrProbeAttachSkipped, so before skips were tracked separately one skipped pod turned an
// ENOMEM map write into a Warn and a nil return, and nothing retried it. That is the #686
// bug reached through the skip path.
func TestReconcilePolicyEndpoint_SkipDoesNotMaskMapWriteFailure(t *testing.T) {
	fx := newPEFixture(t)
	skipped := localPod("web-aaa", "10.1.1.1")
	fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{
		{Name: skipped.name, Namespace: fixtureNamespace}: fmt.Errorf(
			"%w: multiNIC enabled and interface count is unknown", ebpf.ErrProbeAttachSkipped),
	}
	fx.bpf.UpdateEbpfMapsErr = fmt.Errorf("ingress map write: %w",
		fmt.Errorf("unable to update map: %w", unix.ENOMEM))
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{skipped, localPod("api-aaa", "10.1.1.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})

	err := fx.reconcile("np-1-aaaaa")

	require.Error(t, err, "a skipped pod must not absorb the map-write failure")
	assert.ErrorIs(t, err, unix.ENOMEM, "the errno must still reach the reconciler")
	assert.NotErrorIs(t, err, ebpf.ErrProbeAttachSkipped,
		"the skip must not travel in the returned error, or errors.Is would mask the failure")
}

// The same masking on the cluster path, where a swallowed failure can leave a required
// Deny rule unapplied.
func TestReconcileClusterPolicyEndpoint_SkipDoesNotMaskMapWriteFailure(t *testing.T) {
	fx := newCPEFixture(t)
	skipped := localPod("web-aaa", "10.1.1.1")
	fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{
		{Name: skipped.name, Namespace: fixtureNamespace}: fmt.Errorf(
			"%w: multiNIC enabled and interface count is unknown", ebpf.ErrProbeAttachSkipped),
	}
	fx.bpf.UpdateClusterPolicyEbpfMapsErr = fmt.Errorf("ingress map write: %w",
		fmt.Errorf("unable to update map: %w", unix.ENOMEM))
	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{skipped, localPod("api-aaa", "10.1.1.2")},
		ingress: []ruleRef{deny("192.168.90.1/32")}})

	err := fx.reconcile("cnp-1-aaaaa")

	require.Error(t, err, "a skipped pod must not absorb the map-write failure")
	assert.ErrorIs(t, err, unix.ENOMEM, "the errno must still reach the reconciler")
	assert.NotErrorIs(t, err, ebpf.ErrProbeAttachSkipped,
		"the skip must not travel in the returned error, or errors.Is would mask the failure")
}

// A PolicyEndpoint with no local pods implements nothing on this node, so the pass consumes
// the trigger without a sample. Leaving it unconsumed lets a later resync, or a sibling slice
// that later gains a local pod, report the age of the original annotation as programming
// latency. This is the case the plain "programmed > 0" gate could not tell apart from a
// skipped or failed pass.
func TestReconcilePolicyEndpoint_NoLocalWorkConsumesTriggerWithoutSample(t *testing.T) {
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{remotePod("nginx-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	pe := fx.store["np-1-aaaaa"]
	pe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["np-1-aaaaa"] = pe

	before := histSampleCount(t, policyProgrammingLatency)
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"nothing on this node implements the change, so there is no latency to report")

	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"the trigger was consumed, so a resync of the same annotation records nothing")
}

// A pass where every attach was skipped programmed nothing, so it must record no
// latency sample and must leave the trigger time for the pass that does program.
func TestReconcilePolicyEndpoint_AllSkippedRecordsNoLatency(t *testing.T) {
	fx := newPEFixture(t)
	fx.bpf.AttacheBPFProbesErr = fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	// Every attach was skipped, so no probes exist for the identifier. Without this the mock
	// reports a context the skipped pod never created, the map write succeeds, and the pass
	// looks like real programming.
	fx.bpf.PodIdentifiersWithoutBPFContext = map[string]bool{identifierOf("nginx-aaa"): true}
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	pe := fx.store["np-1-aaaaa"]
	pe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["np-1-aaaaa"] = pe

	before := histSampleCount(t, policyProgrammingLatency)
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"a pass that programmed nothing must not record a sample")

	fx.bpf.AttacheBPFProbesErr = nil
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
		"the pass that programs the change must still record it")
}

func TestReconcileClusterPolicyEndpoint_AllSkippedRecordsNoLatency(t *testing.T) {
	fx := newCPEFixture(t)
	fx.bpf.AttacheBPFProbesErr = fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
	// See the PolicyEndpoint case: a fully skipped identifier has no probes on the node.
	fx.bpf.PodIdentifiersWithoutBPFContext = map[string]bool{identifierOf("nginx-aaa"): true}
	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
		ingress: []ruleRef{deny("192.168.90.1/32")}})
	cpe := fx.store["cnp-1-aaaaa"]
	cpe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["cnp-1-aaaaa"] = cpe

	before := histSampleCount(t, clusterPolicyProgrammingLatency)
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
		"a pass that programmed nothing must not record a sample")

	fx.bpf.AttacheBPFProbesErr = nil
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Equal(t, uint64(1), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
		"the pass that programs the change must still record it")
}

// A pass with no local work consumes the trigger, so a later pass that does program must not
// measure from the original annotation. Reconciling the same PE twice cannot show this,
// because the duplicate-trigger check returns early regardless of the first pass's outcome.
// Giving a sibling slice of the same parent a local pod is what separates the two: if the
// first pass had deferred instead of consumed, this second pass would program and report the
// age of a change it did not implement.
func TestReconcilePolicyEndpoint_NoLocalWorkConsumesSoASiblingCannotMeasureIt(t *testing.T) {
	fx := newPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{remotePod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		sliceSpec{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{remotePod("web-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
	)
	stamp := time.Now().Format(time.RFC3339Nano)
	pe := fx.store["np-1-aaaaa"]
	pe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: stamp}
	fx.store["np-1-aaaaa"] = pe

	before := histSampleCount(t, policyProgrammingLatency)
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	require.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"no local pod, so there is no programming latency to report")

	// The sibling slice gains a local pod. The parent's target set now has local work, but
	// this PE's annotation still refers to the earlier change.
	fx.setSlices(
		sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{remotePod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		sliceSpec{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
	)
	pe = fx.store["np-1-aaaaa"]
	pe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: stamp}
	fx.store["np-1-aaaaa"] = pe

	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, policyProgrammingLatency)-before,
		"the trigger was consumed by the no-work pass, so this one must not measure it")
}

// One failing identifier must not stop the others, and the assertion must not depend on which
// identifier the reconcile happened to reach first. A single fixture lets map iteration order
// decide, so this builds a fresh one each time.
func TestReconcilePolicyEndpoint_OneFailingIdentifierIsOrderIndependent(t *testing.T) {
	const runs = 50
	failing := identifierOf("web-aaa")
	healthy := identifierOf("api-aaa")
	require.NotEqual(t, failing, healthy, "the two pods must map to distinct identifiers")

	for i := 0; i < runs; i++ {
		fx := newPEFixture(t)
		fx.bpf.UpdateEbpfMapsErrFor = map[string]error{
			failing: errors.New("unable to update map: cannot allocate memory"),
		}
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods: []podRef{
				localPod("web-aaa", "10.1.1.1"),
				localPod("api-aaa", "10.1.1.2"),
			},
			ingress: []ruleRef{allow("192.168.90.1/32")}})

		err := fx.reconcile("np-1-aaaaa")

		require.Errorf(t, err, "run %d: the failing identifier must surface", i)
		assert.Containsf(t, fx.bpf.IngressByIdentifier, healthy,
			"run %d: the healthy identifier must be programmed whichever ran first", i)
	}
}

// Cleanup writes are programming. A pass whose only work was cleanup leaves the target loop
// empty, so counting just programmed identifiers would drop its sample, including the
// cleanup-only retry that finally lands. cleanupPod has two writing arms and both must count.
func TestReconcilePolicyEndpoint_CleanupOnlyPassRecordsLatency(t *testing.T) {
	tests := []struct {
		name          string
		otherSelector bool // a sibling policy still selects the pod
	}{
		{name: "baseline restore, nothing selects the pod any more"},
		{name: "remaining policies still select the pod", otherSelector: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newPEFixture(t)
			web := types.NamespacedName{Name: "web-aaa", Namespace: fixtureNamespace}
			identifier := identifierOf("web-aaa")

			// The slice recorded the pod on an earlier reconcile, and no longer selects it,
			// so this reconcile derives it as cleanup with nothing left to program.
			fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{},
				ingress: []ruleRef{allow("192.168.90.1/32")}})
			fx.r.policyEndpointSelectorMap.Store(fx.request("np-1-aaaaa", "np-1"),
				[]npatypes.Pod{{NamespacedName: web, PodIP: "10.1.1.1"}})
			if tt.otherSelector {
				fx.r.podIdentifierToPolicyEndpointMap.Store(identifier, refsOf("np-2", "np-2-aaaaa"))
			}

			pe := fx.store["np-1-aaaaa"]
			pe.Annotations = map[string]string{
				LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
			fx.store["np-1-aaaaa"] = pe

			before := histSampleCount(t, policyProgrammingLatency)
			require.NoError(t, fx.reconcile("np-1-aaaaa"))
			assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before,
				"cleanup wrote a map, so the pass landed the change and must be measured")
		})
	}
}

// The cluster path has the same accounting, where a cleanup-only pass still wrote maps.
func TestReconcileClusterPolicyEndpoint_CleanupOnlyPassRecordsLatency(t *testing.T) {
	fx := newCPEFixture(t)
	web := types.NamespacedName{Name: "web-aaa", Namespace: fixtureNamespace}

	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{},
		ingress: []ruleRef{deny("192.168.90.1/32")}})
	fx.r.ClusterPolicyEndpointSelectorMap.Store(cpeRequest("cnp-1-aaaaa", "cnp-1"),
		[]npatypes.Pod{{NamespacedName: web, PodIP: "10.1.1.1"}})

	cpe := fx.store["cnp-1-aaaaa"]
	cpe.Annotations = map[string]string{
		LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["cnp-1-aaaaa"] = cpe

	before := histSampleCount(t, clusterPolicyProgrammingLatency)
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Equal(t, uint64(1), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
		"cleanup wrote a map, so the pass landed the change and must be measured")
}
