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
	assert.Contains(t, err.Error(), "podIdentifier", "the failing identifier must be named")
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
	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{
		identifierOf("web-aaa"): errors.New("unable to update map: cannot allocate memory"),
	}
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
		pods: []podRef{
			localPod("web-aaa", "10.1.1.1"),
			localPod("api-aaa", "10.1.1.2"),
		},
		ingress: []ruleRef{allow("192.168.90.1/32")}})

	err := fx.reconcile("np-1-aaaaa")

	require.Error(t, err)
	assert.Contains(t, fx.bpf.IngressByIdentifier, identifierOf("api-aaa"),
		"the healthy identifier must still be programmed")
}

// A pass where every attach was skipped programmed nothing, so it must record no
// latency sample and must leave the trigger time for the pass that does program.
func TestReconcilePolicyEndpoint_AllSkippedRecordsNoLatency(t *testing.T) {
	fx := newPEFixture(t)
	fx.bpf.AttacheBPFProbesErr = fmt.Errorf("%w: multiNIC enabled and interface count is unknown",
		ebpf.ErrProbeAttachSkipped)
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
