package controllers

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// These tests pin what a slice deletion does: an identifier's maps are written from the slices
// that are live once the deletion is reconciled, as for any other change. A policy that still
// selects the identifier's pods, on this node or another, keeps its rules there, whichever of
// its slices is deleted and in whichever order the slices are reconciled. Deleting a slice gives
// the same maps as updating it to list none of the identifier's pods here.

// Each slice carries its own rule, so the CIDRs show which slices an identifier's rules came from.
const (
	np1aCIDR = "192.168.90.1/32"
	np1bCIDR = "192.168.90.3/32"
	np2aCIDR = "192.168.90.2/32"
)

var (
	np1a = sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{allow(np1aCIDR)}}
	np1b = sliceSpec{name: "np-1-bbbbb", parent: "np-1", pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{allow(np1bCIDR)}}
	np2a = sliceSpec{name: "np-2-aaaaa", parent: "np-2", pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{allow(np2aCIDR)}}

	cnp1a = sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}}
	cnp1b = sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny(np1bCIDR)}}
)

// dbFixture: np-1 selects db-0 on this node through np-1-aaaaa and db-2 on another node through
// np-1-bbbbb, plus any extra slices. db-0 and db-1 share the identifier db.
func dbFixture(t *testing.T, extra ...sliceSpec) (*peFixture, string) {
	t.Helper()
	fx := newPEFixture(t)
	fx.setSlices(append([]sliceSpec{np1a, np1b}, extra...)...)
	fx.reconcileAll()
	db := identifierOf("db-0")
	require.Subset(t, fx.ingressCIDRs(db), []string{np1aCIDR, np1bCIDR})
	return fx, db
}

func dbClusterFixture(t *testing.T) (*cpeFixture, string) {
	t.Helper()
	fx := newCPEFixture(t)
	fx.setSlices(cnp1a, cnp1b)
	fx.reconcileAll()
	db := identifierOf("db-0")
	require.ElementsMatch(t, []string{"Deny " + np1aCIDR, "Deny " + np1bCIDR}, fx.clusterPolicyRules(db))
	return fx, db
}

func TestPolicySlices_SliceDeletionKeepsAPolicyThatStillSelectsTheIdentifier(t *testing.T) {
	t.Run("deleting the slice that lists the pod here", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		assert.Equal(t, []string{np1bCIDR}, fx.ingressCIDRs(db), "np-1 still selects db-2")
	})

	t.Run("updating it to list none of the pods here gives the same maps", func(t *testing.T) {
		fx, db := dbFixture(t)
		updated := np1a
		updated.pods = nil
		fx.setSlices(updated, np1b)
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.ElementsMatch(t, []string{np1aCIDR, np1bCIDR}, fx.ingressCIDRs(db), "np-1 still selects db-2, with both slices' rules")
	})

	t.Run("deleting the policy's last slices returns the identifier to the baseline", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		fx.deleteSlice("np-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		require.NoError(t, fx.reconcileDeleted("np-1-bbbbb"))
		fx.assertRulesCleared(db)
		state, ok := fx.podState(db)
		require.True(t, ok)
		assert.Equal(t, DEFAULT_ALLOW, state)
	})

	t.Run("deleting the policy's slices one reconcile at a time returns the identifier to the baseline", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		require.Equal(t, []string{np1bCIDR}, fx.ingressCIDRs(db), "np-1 selects db only on another node now")
		fx.deleteSlice("np-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("np-1-bbbbb"))
		fx.assertRulesCleared(db)
		state, ok := fx.podState(db)
		require.True(t, ok)
		assert.Equal(t, DEFAULT_ALLOW, state)
	})

	t.Run("another policy selecting a pod here is unaffected", func(t *testing.T) {
		fx, db := dbFixture(t, np2a)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		assert.ElementsMatch(t, []string{np1bCIDR, np2aCIDR}, fx.ingressCIDRs(db))
	})
}

func TestClusterPolicySlices_SliceDeletionKeepsAPolicyThatStillSelectsTheIdentifier(t *testing.T) {
	fx, db := dbClusterFixture(t)
	fx.deleteSlice("cnp-1-aaaaa")
	require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
	assert.Equal(t, []string{"Deny " + np1bCIDR}, fx.clusterPolicyRules(db), "cnp-1 still selects db-2")

	fx.deleteSlice("cnp-1-bbbbb")
	require.NoError(t, fx.reconcileDeleted("cnp-1-bbbbb"))
	fx.assertClusterPolicyRulesCleared(db)
	state, ok := fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: db, MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}]
	require.True(t, ok)
	assert.Equal(t, DEFAULT_ALLOW, state)
}

// The informer can show a slice gone and a sibling changed at once, and either request can be
// reconciled first. Both orders give the maps of the live slices. np-1-aaaaa lists db-0 and is
// deleted; np-1-bbbbb lists web-0 here, db-2 and web-1 elsewhere, and stops listing web-0.
func TestPolicySlices_SliceDeletionGivesTheSameMapsInEitherOrder(t *testing.T) {
	webCIDR := "192.168.90.6/32"
	a := sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{allow(np1aCIDR)}}
	b := sliceSpec{name: "np-1-bbbbb", parent: "np-1", ingress: []ruleRef{allow(webCIDR)},
		pods: []podRef{localPod("web-0", "10.1.1.30"), remotePod("db-2", "10.1.2.12"), remotePod("web-1", "10.1.2.31")}}
	bUpdated := b
	bUpdated.pods = []podRef{remotePod("db-2", "10.1.2.12"), remotePod("web-1", "10.1.2.31")}
	for _, siblingFirst := range []bool{false, true} {
		name := "deletion first"
		if siblingFirst {
			name = "sibling first"
		}
		t.Run(name, func(t *testing.T) {
			fx := newPEFixture(t)
			db, web := identifierOf("db-0"), identifierOf("web-0")
			fx.setSlices(a, b)
			fx.reconcileAll()

			fx.setSlices(bUpdated)
			if siblingFirst {
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
			}
			assert.Equal(t, []string{webCIDR}, fx.ingressCIDRs(db))
			assert.Equal(t, []string{webCIDR}, fx.ingressCIDRs(web))
		})
	}
}

func TestClusterPolicySlices_SliceDeletionGivesTheSameMapsInEitherOrder(t *testing.T) {
	webCIDR := "192.168.90.6/32"
	a := sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}}
	b := sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, ingress: []ruleRef{deny(webCIDR)},
		pods: []podRef{localPod("web-0", "10.1.1.30"), remotePod("db-2", "10.1.2.12"), remotePod("web-1", "10.1.2.31")}}
	bUpdated := b
	bUpdated.pods = []podRef{remotePod("db-2", "10.1.2.12"), remotePod("web-1", "10.1.2.31")}
	for _, siblingFirst := range []bool{false, true} {
		name := "deletion first"
		if siblingFirst {
			name = "sibling first"
		}
		t.Run(name, func(t *testing.T) {
			fx := newCPEFixture(t)
			db, web := identifierOf("db-0"), identifierOf("web-0")
			fx.setSlices(a, b)
			fx.reconcileAll()

			fx.setSlices(bUpdated)
			if siblingFirst {
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
			}
			assert.Equal(t, []string{"Deny " + webCIDR}, fx.clusterPolicyRules(db))
			assert.Equal(t, []string{"Deny " + webCIDR}, fx.clusterPolicyRules(web))
		})
	}
}

// A sibling's reconcile programs db for np-1-aaaaa before np-1-aaaaa's own reconcile runs. When
// np-1-aaaaa is deleted before that, either order gives the maps of the live slices.
func TestPolicySlices_DeletingASliceNeverReconciledGivesTheLiveSlicesMaps(t *testing.T) {
	for _, siblingFirst := range []bool{false, true} {
		name := "deletion first"
		if siblingFirst {
			name = "sibling first"
		}
		t.Run(name, func(t *testing.T) {
			fx := newPEFixture(t)
			db := identifierOf("db-0")
			fx.setSlices(np1a, np1b)
			require.NoError(t, fx.reconcile("np-1-bbbbb"))
			require.Contains(t, fx.ingressCIDRs(db), np1aCIDR)

			fx.deleteSlice("np-1-aaaaa")
			if siblingFirst {
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
			}
			assert.Equal(t, []string{np1bCIDR}, fx.ingressCIDRs(db))
		})
	}
}

func TestClusterPolicySlices_DeletingASliceNeverReconciledGivesTheLiveSlicesMaps(t *testing.T) {
	for _, siblingFirst := range []bool{false, true} {
		name := "deletion first"
		if siblingFirst {
			name = "sibling first"
		}
		t.Run(name, func(t *testing.T) {
			fx := newCPEFixture(t)
			db := identifierOf("db-0")
			fx.setSlices(cnp1a, cnp1b)
			require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
			require.Contains(t, fx.clusterPolicyRules(db), "Deny "+np1aCIDR)

			fx.deleteSlice("cnp-1-aaaaa")
			if siblingFirst {
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
			}
			assert.Equal(t, []string{"Deny " + np1bCIDR}, fx.clusterPolicyRules(db))
		})
	}
}

// A pod whose attach is skipped holds latency measurements that no pass finishes. Once the
// policy stops selecting it, a last pass retires them, so they don't outlive the identifier.
func TestPolicySlices_DeselectedIdentifierWithSkippedAttachRetiresItsMeasurements(t *testing.T) {
	fx := newPEFixture(t)
	skipped := identifierOf("skip-aaa")
	fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{
		{Name: "skip-aaa", Namespace: fixtureNamespace}: ebpf.ErrProbeAttachSkipped,
	}
	fx.setSlices(sliceSpec{name: "np-9-aaaaa", parent: "np-9", pods: []podRef{localPod("skip-aaa", "10.1.1.20")}, ingress: []ruleRef{allow(np1aCIDR)}})
	require.NoError(t, fx.reconcile("np-9-aaaaa"))
	require.False(t, fx.bpf.HasBPFContext(skipped))
	require.NotEmpty(t, fx.r.programmingLatency.pending[skipped], "the skipped pass leaves its measurement pending")

	fx.setSlices(sliceSpec{name: "np-9-aaaaa", parent: "np-9", pods: []podRef{remotePod("skip-bbb", "10.1.2.20")}, ingress: []ruleRef{allow(np1aCIDR)}})
	require.NoError(t, fx.reconcile("np-9-aaaaa"))
	assert.Empty(t, fx.r.programmingLatency.pending[skipped])
}
