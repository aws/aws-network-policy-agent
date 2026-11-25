package controllers

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// The #686 fix: a failed eBPF map write must be returned so the write is retried; a
// pass recorded as a success leaves nothing on the node to ever retry it.
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

// A skipped pod must not hide a real failure. A programming pass joins the per-pod attach
// errors with the map-write error, and errors.Is matches when any arm of a join carries
// ErrProbeAttachSkipped, so a skip carried in the error would turn an ENOMEM map write into
// a Warn and a nil return, and nothing would retry it. That is the #686
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

// Cleanup writes are programming. A change whose only work was cleanup selects nothing, so
// counting just selected identifiers would drop its sample, including the cleanup-only retry
// that finally lands. Both the baseline write and the remaining-policies write must count.
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
			fx.r.networkPolicyToLocalPodsMap.Store(utils.GetNetworkPolicyIdentifier("np-1", fixtureNamespace),
				map[string][]npatypes.Pod{identifier: {{NamespacedName: web, PodIP: "10.1.1.1"}}})
			fx.bpf.AttachIdentifier(identifier)
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
	fx.r.clusterNetworkPolicyToLocalPodsMap.Store("cnp-1",
		map[string][]npatypes.Pod{identifierOf("web-aaa"): {{NamespacedName: web, PodIP: "10.1.1.1"}}})
	fx.bpf.AttachIdentifier(identifierOf("web-aaa"))

	cpe := fx.store["cnp-1-aaaaa"]
	cpe.Annotations = map[string]string{
		LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["cnp-1-aaaaa"] = cpe

	before := histSampleCount(t, clusterPolicyProgrammingLatency)
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Equal(t, uint64(1), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
		"cleanup wrote a map, so the pass landed the change and must be measured")
}

// A policy that selects a workload only through its replica on another node still applies to
// the replica here, which shares the identifier's maps. When the policy stops selecting the
// workload, the identifier is not reprogrammed: during a rollout NPC can drop the last old
// replica before it lists the new pod, and reprogramming would reset a new pod that CNI ADD
// programmed with the policy's rules to the baseline until NPC lists it. The refs are pruned,
// so the next pass for the identifier drops the policy's rules.
func TestReconcilePolicyEndpoint_DroppingARemoteOnlySelectionDoesNotReprogramTheLocalReplica(t *testing.T) {
	web := identifierOf("web-aaa")
	fx := newPEFixture(t)
	// The local replica was attached by its CNI ADD; NPC lists only the remote one.
	fx.bpf.AttachIdentifier(web)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{remotePod("web-bbb", "10.2.2.2")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Empty(t, fx.bpf.IngressByIdentifier[web], "a policy that selects no pod here does not program the identifier")

	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods:    []podRef{},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	fx.reset()
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	assert.Empty(t, fx.bpf.CallLog, "nothing is written for an identifier the policy never selected a pod of here")
	assert.Empty(t, fx.identifierRefs(web), "the policy's refs for the identifier are gone")
}

func TestReconcileClusterPolicyEndpoint_DroppingARemoteOnlySelectionDoesNotReprogramTheLocalReplica(t *testing.T) {
	web := identifierOf("web-aaa")
	fx := newCPEFixture(t)
	fx.bpf.AttachIdentifier(web)
	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{remotePod("web-bbb", "10.2.2.2")},
		ingress: []ruleRef{deny("192.168.90.1/32")}})
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Empty(t, fx.bpf.ClusterPolicyIngressByIdentifier[web], "a policy that selects no pod here does not program the identifier")

	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{},
		ingress: []ruleRef{deny("192.168.90.1/32")}})
	fx.reset()
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Empty(t, fx.bpf.CallLog, "nothing is written for an identifier the policy never selected a pod of here")
	assert.Empty(t, fx.identifierRefs(web), "the policy's refs for the identifier are gone")
}

// During a rollout NPC can remove the last old replica of db from a policy before it lists the
// new pod. A pass reads the state as it is when it runs, so only a pass that runs between the
// two updates writes db without the policy, with any number of workers. The second subtest is
// what a backlog buys: db's pass runs after both updates and writes the policy once.
func TestProgramIdentifier_RolloutIntervalIsWrittenOnlyByAPassInsideIt(t *testing.T) {
	db := identifierOf("db-0")
	withPods := func(pods ...podRef) sliceSpec {
		return sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: pods, ingress: []ruleRef{allow("192.168.90.1/32")}}
	}
	setUp := func(t *testing.T) (*peFixture, func() error) {
		fx := newPEFixture(t)
		fx.setSlices(withPods(localPod("db-0", "10.1.1.10")))
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		require.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(db))
		stage1 := func() error { return fx.r.reconcile(context.TODO(), fx.request("np-1-aaaaa", "np-1")) }
		return fx, stage1
	}
	assertState := func(t *testing.T, fx *peFixture, want int) {
		t.Helper()
		state, ok := fx.podState(db)
		require.True(t, ok)
		assert.Equal(t, want, state)
	}

	t.Run("a pass between the updates writes the baseline", func(t *testing.T) {
		fx, stage1 := setUp(t)
		fx.setSlices(withPods())
		require.NoError(t, stage1())
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		fx.assertRulesCleared(db)
		assertState(t, fx, DEFAULT_ALLOW)

		fx.setSlices(withPods(localPod("db-0", "10.1.1.20")))
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(db))
		assertState(t, fx, POLICIES_APPLIED)
	})

	t.Run("a pass after both updates writes only the policy", func(t *testing.T) {
		fx, stage1 := setUp(t)
		fx.setSlices(withPods())
		require.NoError(t, stage1())
		fx.setSlices(withPods(localPod("db-0", "10.1.1.20")))
		require.NoError(t, stage1())

		fx.reset()
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		assert.Equal(t, 1, lo.Count(fx.bpf.CallLog, "UpdatePodStateEbpfMaps"), "one pass, one pod-state write")
		assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(db))
		assertState(t, fx, POLICIES_APPLIED)
	})
}

// A pass reads an identifier's refs, then attaches its first pod, which is when the identifier's
// eBPF context appears. A reconcile that stops selecting the identifier while that attach runs
// sees no selected pods here and no context yet. It must still queue the identifier, or the pass
// writes the rules of the slice it read and nothing rewrites them. The slices carry no trigger
// annotation, as for a policy that predates an agent restart, so no E2E sample holds the
// identifier either.
func TestProgramIdentifier_DeselectionDuringFirstAttachIsRewritten(t *testing.T) {
	db := identifierOf("db-0")
	selecting := []podRef{localPod("db-0", "10.1.1.10")}
	deselected := []podRef{localPod("web-0", "10.1.1.20")}
	// deselectDuringAttach runs reconcileAgain once, while db's first pod is attaching.
	deselectDuringAttach := func(bpf *ebpf.MockBpfClient, reconcileAgain func()) {
		done := false
		bpf.BeforeAttach = func(_ types.NamespacedName, podIdentifier string) {
			if podIdentifier == db && !done {
				done = true
				reconcileAgain()
			}
		}
	}

	t.Run("network policy", func(t *testing.T) {
		fx := newPEFixture(t)
		spec := sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: selecting, ingress: []ruleRef{allow("192.168.90.1/32")}}
		fx.setSlices(spec)
		stage1 := func() { require.NoError(t, fx.r.reconcile(context.TODO(), fx.request("np-1-aaaaa", "np-1"))) }
		stage1()
		require.False(t, fx.bpf.HasBPFContext(db))
		deselectDuringAttach(fx.bpf, func() {
			spec.pods = deselected
			fx.setSlices(spec)
			stage1()
		})
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		fx.assertRulesCleared(db)
	})

	t.Run("cluster network policy", func(t *testing.T) {
		fx := newCPEFixture(t)
		spec := sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: selecting, ingress: []ruleRef{deny("192.168.90.1/32")}}
		fx.setSlices(spec)
		stage1 := func() { require.NoError(t, fx.r.reconcile(context.TODO(), cpeRequest("cnp-1-aaaaa", "cnp-1"))) }
		stage1()
		require.False(t, fx.bpf.HasBPFContext(db))
		deselectDuringAttach(fx.bpf, func() {
			spec.pods = deselected
			fx.setSlices(spec)
			stage1()
		})
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		fx.assertClusterPolicyRulesCleared(db)
	})
}

// A live PolicyEndpoint that selects a pod but carries no rules and no isolation still puts the
// pod in the applied state with an allow-all entry in each direction. Only an identifier no live
// PolicyEndpoint selects goes to the baseline, which in strict mode is deny.
func TestProgramIdentifier_EmptyLivePolicyEndpointAllowsEverythingInStrictMode(t *testing.T) {
	web := identifierOf("web-aaa")
	fx := newPEFixture(t)
	fx.bpf.NetworkPolicyMode = string(utils.Strict)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods: []podRef{localPod("web-aaa", "10.1.1.1")}})

	require.NoError(t, fx.reconcile("np-1-aaaaa"))

	state, ok := fx.podState(web)
	require.True(t, ok)
	assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	assert.Equal(t, []string{"0.0.0.0/0"}, fx.ingressCIDRs(web))
	assert.Equal(t, []string{"0.0.0.0/0"}, fx.egressCIDRs(web))

	fx.deleteSlice("np-1-aaaaa")
	require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
	state, _ = fx.podState(web)
	assert.Equal(t, ebpf.DEFAULT_DENY, state, "with no live PolicyEndpoint the pod returns to the strict-mode baseline")
}

// linkedFixtures returns a PolicyEndpoint and a ClusterPolicyEndpoint fixture that share one BPF
// client, with their programmers linked as main links them. The client reports an attach that
// creates an identifier's programs, as the real one does.
func linkedFixtures(t *testing.T) (*peFixture, *cpeFixture) {
	pfx, cfx := newPEFixture(t), newCPEFixture(t)
	cfx.bpf = pfx.bpf
	cfx.r.ebpfClient = pfx.bpf
	pfx.bpf.ReportFirstAttach = true
	LinkProgrammers(pfx.r, cfx.r)
	return pfx, cfx
}

// drainBoth runs both programmers until neither has work, as their workers would.
func drainBoth(t *testing.T, pfx *peFixture, cfx *cpeFixture) {
	t.Helper()
	for i := 0; pfx.r.programQueue.Len() > 0 || cfx.r.programQueue.Len() > 0; i++ {
		require.Less(t, i, 10, "the programmers keep queueing each other")
		require.NoError(t, pfx.r.drainProgramming(context.TODO()))
		require.NoError(t, cfx.r.drainProgramming(context.TODO()))
	}
}

// A policy that selects an identifier only through a replica on another node does not queue it,
// yet its rules apply to the identifier's replicas here. When the other controller's pass creates
// the identifier's programs, both policy types' maps are new, so that pass queues the
// identifier on the other programmer, which writes its policy.
func TestProgramIdentifier_CreatingProgramsQueuesThePeerProgrammer(t *testing.T) {
	db := identifierOf("db-0")

	t.Run("network policy pass creates them", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		cfx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny("192.168.90.9/32")}})
		require.NoError(t, cfx.reconcile("cnp-1-aaaaa"))
		require.False(t, pfx.bpf.HasBPFContext(db))

		pfx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, pfx.r.reconcile(context.TODO(), pfx.request("np-1-aaaaa", "np-1")))
		drainBoth(t, pfx, cfx)

		assert.Equal(t, []string{"192.168.90.1/32"}, pfx.ingressCIDRs(db))
		assert.Equal(t, []string{"Deny 192.168.90.9/32"}, cfx.clusterPolicyRules(db),
			"the cluster policy's Deny reaches the identifier whose programs the network policy pass created")
	})

	t.Run("cluster network policy pass creates them", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		pfx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, pfx.reconcile("np-1-aaaaa"))
		require.False(t, pfx.bpf.HasBPFContext(db))

		cfx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny("192.168.90.9/32")}})
		require.NoError(t, cfx.r.reconcile(context.TODO(), cpeRequest("cnp-1-aaaaa", "cnp-1")))
		drainBoth(t, pfx, cfx)

		assert.Equal(t, []string{"Deny 192.168.90.9/32"}, cfx.clusterPolicyRules(db))
		assert.Equal(t, []string{"192.168.90.1/32"}, pfx.ingressCIDRs(db),
			"the network policy reaches the identifier whose programs the cluster policy pass created")
		state, ok := pfx.podState(db)
		require.True(t, ok)
		assert.Equal(t, POLICIES_APPLIED, state)
	})

	t.Run("the peer is queued even when the creating pass's write fails", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		cfx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny("192.168.90.9/32")}})
		require.NoError(t, cfx.reconcile("cnp-1-aaaaa"))

		writeFailed := errors.New("map write failed")
		pfx.bpf.UpdateEbpfMapsErrFor = map[string]error{db: writeFailed}
		pfx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, pfx.r.reconcile(context.TODO(), pfx.request("np-1-aaaaa", "np-1")))
		require.ErrorIs(t, pfx.r.drainProgramming(context.TODO()), writeFailed)

		require.NoError(t, cfx.r.drainProgramming(context.TODO()))
		assert.Equal(t, []string{"Deny 192.168.90.9/32"}, cfx.clusterPolicyRules(db), "the peer programs its plane")

		pfx.bpf.UpdateEbpfMapsErrFor = nil
		drainBoth(t, pfx, cfx)
		assert.Equal(t, []string{"192.168.90.1/32"}, pfx.ingressCIDRs(db), "the creating programmer's retry lands")
	})

	t.Run("the peer is queued even when the creating cluster policy pass's write fails", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		pfx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, pfx.reconcile("np-1-aaaaa"))

		writeFailed := errors.New("map write failed")
		cfx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{db: writeFailed}
		cfx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny("192.168.90.9/32")}})
		require.NoError(t, cfx.r.reconcile(context.TODO(), cpeRequest("cnp-1-aaaaa", "cnp-1")))
		require.ErrorIs(t, cfx.r.drainProgramming(context.TODO()), writeFailed)

		require.NoError(t, pfx.r.drainProgramming(context.TODO()))
		assert.Equal(t, []string{"192.168.90.1/32"}, pfx.ingressCIDRs(db), "the peer programs its plane")

		cfx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		drainBoth(t, pfx, cfx)
		assert.Equal(t, []string{"Deny 192.168.90.9/32"}, cfx.clusterPolicyRules(db), "the creating programmer's retry lands")
	})
}

// A slice-deletion record outlives the programs it was written for: the identifier's last pod
// leaves, the programs go, the record stays. When the other controller's pass later creates new
// programs and queues this programmer, the record describes maps that no longer exist, so this
// programmer's pass writes the policy it would have left out. A CNI ADD that finds the new
// programs in place does not rewrite them.
func TestProgramIdentifier_NewProgramsDropDeletionRecordsOfEarlierOnes(t *testing.T) {
	db := identifierOf("db-0")
	// nonFirstCNIAdd models a later pod's CNI ADD: its attach finds the programs in place, so it
	// writes nothing.
	nonFirstCNIAdd := func(t *testing.T, pfx *peFixture) {
		created, err := pfx.bpf.AttacheBPFProbes(types.NamespacedName{Name: "db-3", Namespace: fixtureNamespace}, db, 1, true)
		require.NoError(t, err)
		require.False(t, created)
	}

	t.Run("network policy record, cluster network policy pass creates the programs", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		pfx.setSlices(np1a, np1b)
		pfx.reconcileAll()
		drainBoth(t, pfx, cfx)
		pfx.deleteSlice("np-1-aaaaa")
		require.NoError(t, pfx.reconcileDeleted("np-1-aaaaa"))
		pfx.assertRulesCleared(db)
		pfx.detachContext(db)

		cfx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{deny("192.168.90.9/32")}})
		require.NoError(t, cfx.r.reconcile(context.TODO(), cpeRequest("cnp-1-aaaaa", "cnp-1")))
		drainBoth(t, pfx, cfx)
		nonFirstCNIAdd(t, pfx)

		assert.Equal(t, []string{np1bCIDR}, pfx.ingressCIDRs(db), "np-1, which still selects db-2, is written to the new programs")
	})

	t.Run("cluster network policy record, network policy pass creates the programs", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		cfx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny(np1bCIDR)}},
		)
		cfx.reconcileAll()
		drainBoth(t, pfx, cfx)
		cfx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, cfx.reconcileDeleted("cnp-1-aaaaa"))
		cfx.assertClusterPolicyRulesCleared(db)
		cfx.detachContext(db)

		pfx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, pfx.r.reconcile(context.TODO(), pfx.request("np-1-aaaaa", "np-1")))
		drainBoth(t, pfx, cfx)
		nonFirstCNIAdd(t, pfx)

		assert.Equal(t, []string{"Deny " + np1bCIDR}, cfx.clusterPolicyRules(db), "cnp-1's Deny, for db-2, is written to the new programs")
	})

	t.Run("a record made while the new programs are being created is kept", func(t *testing.T) {
		pfx, cfx := linkedFixtures(t)
		pfx.setSlices(np1a, np1b)
		pfx.reconcileAll()
		drainBoth(t, pfx, cfx)
		pfx.detachContext(db)

		// np-1-aaaaa's deletion is reconciled while the cluster policy pass attaches db-1, so it
		// is recorded for the new programs.
		done := false
		pfx.bpf.BeforeAttach = func(pod types.NamespacedName, _ string) {
			if pod.Name != "db-1" || done {
				return
			}
			done = true
			pfx.setSlices(np1b)
			require.NoError(t, pfx.r.reconcile(context.TODO(), pfx.request("np-1-aaaaa", "np-1")))
		}
		cfx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1,
			pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{deny("192.168.90.9/32")}})
		require.NoError(t, cfx.r.reconcile(context.TODO(), cpeRequest("cnp-1-aaaaa", "cnp-1")))
		drainBoth(t, pfx, cfx)

		require.True(t, done)
		pfx.assertRulesCleared(db)
	})
}
