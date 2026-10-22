package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reconcilers attach pods from PolicyEndpoint caches, which can still list pods
// already deleted from this node, so they must not claim the pod is live: only a
// CNI ADD may override a deleted-pod marker.
func TestReconcilers_AttachWithoutConfirmingPodLive(t *testing.T) {
	t.Run("PolicyEndpoint", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-a-1", parent: "np-a", pods: []podRef{localPod("app-1", "10.0.0.5")}, egress: []ruleRef{allow("10.1.0.0/16")}})
		fx.reconcileAll()
		require.Contains(t, fx.bpf.CallLog, "AttacheBPFProbes")
		assert.False(t, fx.bpf.LastAttachPodConfirmedLive)
	})
	t.Run("ClusterPolicyEndpoint", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-a-1", parent: "cnp-a", pods: []podRef{localPod("app-1", "10.0.0.5")}, egress: []ruleRef{deny("10.1.0.0/16")}})
		fx.reconcileAll()
		require.Contains(t, fx.bpf.CallLog, "AttacheBPFProbes")
		assert.False(t, fx.bpf.LastAttachPodConfirmedLive)
	})
}
