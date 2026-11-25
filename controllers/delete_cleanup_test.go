package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// These tests pin down the cleanup a slice deletion does. Once a policy no longer selects any
// of an identifier's pods on this node, deleting the slice writes the identifier without that
// policy's rules, even though the policy still selects the identifier's pods on other nodes.
// Any later write of the identifier includes the policy again. A StatefulSet whose pods share
// an identifier but not their labels relies on it: db-1 must not keep a policy that selected
// only db-0 once db-0 has left the node.

// Each slice carries its own rule, so the CIDRs show which slices an identifier's rules came from.
const (
	np1aCIDR = "192.168.90.1/32"
	np1bCIDR = "192.168.90.3/32"
	np2aCIDR = "192.168.90.2/32"
	np2bCIDR = "192.168.90.4/32"
)

var (
	np1a = sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{allow(np1aCIDR)}}
	np1b = sliceSpec{name: "np-1-bbbbb", parent: "np-1", pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{allow(np1bCIDR)}}
	np2a = sliceSpec{name: "np-2-aaaaa", parent: "np-2", pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{allow(np2aCIDR)}}
	np2b = sliceSpec{name: "np-2-bbbbb", parent: "np-2", pods: []podRef{remotePod("db-3", "10.1.2.13")}, ingress: []ruleRef{allow(np2bCIDR)}}
)

// dbFixture: np-1 selects db-0 on this node through np-1-aaaaa and db-2 on another node through
// np-1-bbbbb, plus any extra slices. db-0 and db-1 share the identifier db; db-1 stays on this
// node throughout.
func dbFixture(t *testing.T, extra ...sliceSpec) (*peFixture, string) {
	t.Helper()
	fx := newPEFixture(t)
	fx.setSlices(append([]sliceSpec{np1a, np1b}, extra...)...)
	fx.reconcileAll()
	db := identifierOf("db-0")
	require.Contains(t, fx.ingressCIDRs(db), np1aCIDR)
	return fx, db
}

func TestPolicySlices_SliceDeletionLeavesThePolicyOutOfAnIdentifierItLeftHere(t *testing.T) {
	t.Run("the deletion writes the identifier without the policy", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		fx.assertRulesCleared(db)
		state, ok := fx.podState(db)
		require.True(t, ok)
		assert.Equal(t, DEFAULT_ALLOW, state, "no other policy applies, so the identifier is at the baseline")
	})

	t.Run("a retry of a failed write still leaves the policy out", func(t *testing.T) {
		fx, db := dbFixture(t)
		writeFailed := errors.New("map write failed")
		fx.bpf.UpdateEbpfMapsErrFor = map[string]error{db: writeFailed}
		fx.deleteSlice("np-1-aaaaa")
		require.ErrorIs(t, fx.reconcileDeleted("np-1-aaaaa"), writeFailed)

		fx.bpf.UpdateEbpfMapsErrFor = nil
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		fx.assertRulesCleared(db)
	})

	t.Run("an update that stops selecting the pods here keeps the policy", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: []podRef{remotePod("db-0", "10.1.2.10")}, ingress: []ruleRef{allow(np1aCIDR)}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1", pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{allow(np1bCIDR)}},
		)
		require.NoError(t, fx.reconcile("np-1-aaaaa"))
		assert.ElementsMatch(t, []string{np1aCIDR, np1bCIDR}, fx.ingressCIDRs(db))
	})

	t.Run("a later reconcile that writes the identifier puts the policy back", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		fx.assertRulesCleared(db)

		fx.setSlices(np1b, np2a)
		require.NoError(t, fx.reconcile("np-2-aaaaa"))
		assert.ElementsMatch(t, []string{np1bCIDR, np2aCIDR}, fx.ingressCIDRs(db))
	})

	t.Run("a CNI ADD writes the policy back, and later passes keep it", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		ingress, _, err := fx.r.DeriveFireWallRulesPerPodIdentifier(db, fixtureNamespace)
		require.NoError(t, err)
		assert.Equal(t, []string{np1bCIDR}, cidrsOf(ingress))

		fx.r.programQueue.Add(db)
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		assert.Equal(t, []string{np1bCIDR}, fx.ingressCIDRs(db))
	})

	t.Run("another policy's deletion leaves only that policy out", func(t *testing.T) {
		fx, db := dbFixture(t, np2a, np2b)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		require.ElementsMatch(t, []string{np2aCIDR, np2bCIDR}, fx.ingressCIDRs(db))

		fx.deleteSlice("np-2-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-2-aaaaa"))
		assert.Equal(t, []string{np1bCIDR}, fx.ingressCIDRs(db), "the last cleanup decides which policy is left out")
	})
}

func TestClusterPolicySlices_SliceDeletionLeavesThePolicyOutOfAnIdentifierItLeftHere(t *testing.T) {
	db := identifierOf("db-0")
	fx := newCPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}},
		sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny(np1bCIDR)}},
	)
	fx.reconcileAll()
	require.ElementsMatch(t, []string{np1aCIDR, np1bCIDR}, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[db]))

	fx.deleteSlice("cnp-1-aaaaa")
	require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
	assert.Empty(t, fx.bpf.ClusterPolicyIngressByIdentifier[db])
	state, ok := fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: db, MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}]
	require.True(t, ok)
	assert.Equal(t, DEFAULT_ALLOW, state)

	ingress, _, err := fx.r.DeriveClusterPolicyFireWallRulesPerPodIdentifier(context.TODO(), db)
	require.NoError(t, err)
	assert.Equal(t, []string{np1bCIDR}, cidrsOf(ingress), "a CNI ADD writes the policy back")
}

// The record lives only as long as it can matter, so it does not grow with identifiers that
// come and go.
func TestPolicySlices_SliceDeletionRecordIsBounded(t *testing.T) {
	recorded := func(fx *peFixture, podIdentifier string) bool {
		_, ok := fx.r.deleteCleanups.byIdentifier.Load(podIdentifier)
		return ok
	}

	t.Run("dropped once the policy selects none of the identifier's pods", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		require.True(t, recorded(fx, db))

		fx.deleteSlice("np-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("np-1-bbbbb"))
		assert.False(t, recorded(fx, db))
	})

	t.Run("dropped once the identifier has nothing left on this node", func(t *testing.T) {
		fx, db := dbFixture(t)
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		require.True(t, recorded(fx, db))

		fx.detachContext(db)
		fx.r.programQueue.Add(db)
		require.NoError(t, fx.r.drainProgramming(context.TODO()))
		assert.False(t, recorded(fx, db))
	})
}

// The informer can show slice A gone by the time slice B's update is reconciled. B's reconcile
// must not use up what A's deletion needs: whichever is reconciled first, A's deletion leaves
// the policy out of db, as it does today, where each slice keeps its own record of the pods it
// selected until its own deletion is reconciled.
func TestPolicySlices_SliceDeletionCleanupSurvivesASiblingReconciledFirst(t *testing.T) {
	for _, siblingFirst := range []bool{false, true} {
		name := "deletion first"
		if siblingFirst {
			name = "sibling first"
		}
		t.Run(name, func(t *testing.T) {
			fx, db := dbFixture(t)
			updated := np1b
			updated.ingress = []ruleRef{allow(np1bCIDR), allow("192.168.90.5/32")}
			fx.setSlices(updated)
			if siblingFirst {
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
			}
			fx.assertRulesCleared(db)
		})
	}
}

func TestClusterPolicySlices_SliceDeletionCleanupSurvivesASiblingReconciledFirst(t *testing.T) {
	cnp1a := sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}}
	cnp1b := sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny(np1bCIDR)}}
	for _, siblingFirst := range []bool{false, true} {
		name := "deletion first"
		if siblingFirst {
			name = "sibling first"
		}
		t.Run(name, func(t *testing.T) {
			db := identifierOf("db-0")
			fx := newCPEFixture(t)
			fx.setSlices(cnp1a, cnp1b)
			fx.reconcileAll()
			require.ElementsMatch(t, []string{np1aCIDR, np1bCIDR}, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[db]))

			updated := cnp1b
			updated.ingress = []ruleRef{deny(np1bCIDR), deny("192.168.90.5/32")}
			fx.setSlices(updated)
			if siblingFirst {
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
			}
			assert.Empty(t, fx.bpf.ClusterPolicyIngressByIdentifier[db])
		})
	}
}

// A sibling's reconcile scans the whole policy, so it programs db with the policy's rules for
// db-0 before np-1-aaaaa, which lists db-0, is ever reconciled. If np-1-aaaaa is then deleted
// and a sibling reconciles first, the policy no longer records db-0 here, and np-1-aaaaa's
// deletion has only what the first scan recorded for it to go on.
func TestPolicySlices_SliceDeletionCleanupCoversASliceNeverReconciled(t *testing.T) {
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
			require.Contains(t, fx.ingressCIDRs(db), np1aCIDR, "the sibling programs the pods of a slice not yet reconciled")

			fx.deleteSlice("np-1-aaaaa")
			if siblingFirst {
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
			}
			fx.assertRulesCleared(db)
		})
	}
}

func TestClusterPolicySlices_SliceDeletionCleanupCoversASliceNeverReconciled(t *testing.T) {
	cnp1a := sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}}
	cnp1b := sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny(np1bCIDR)}}
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
			require.Contains(t, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[db]), np1aCIDR,
				"the sibling programs the pods of a slice not yet reconciled")

			fx.deleteSlice("cnp-1-aaaaa")
			if siblingFirst {
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
			}
			fx.assertClusterPolicyRulesCleared(db)
		})
	}
}

// A slice's deletion cleans up every identifier its policy selected here when the slice was last
// seen, not only the ones the slice itself listed, as today's per-slice selector entries hold
// the policy's whole local pod set. np-1-aaaaa lists db-0 and np-1-bbbbb lists web-0; the
// informer shows np-1-aaaaa gone and np-1-bbbbb no longer listing web-0 at once. Whichever is
// reconciled first, the deletion leaves np-1 out of both identifiers.
func TestPolicySlices_SliceDeletionCleansUpThePolicysLocalPodsAsLastSeen(t *testing.T) {
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
			require.ElementsMatch(t, []string{np1aCIDR, webCIDR}, fx.ingressCIDRs(web))

			fx.setSlices(bUpdated)
			if siblingFirst {
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
				require.NoError(t, fx.reconcile("np-1-bbbbb"))
			}
			fx.assertRulesCleared(db)
			fx.assertRulesCleared(web)
		})
	}
}

func TestClusterPolicySlices_SliceDeletionCleansUpThePolicysLocalPodsAsLastSeen(t *testing.T) {
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
			require.ElementsMatch(t, []string{np1aCIDR, webCIDR}, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[web]))

			fx.setSlices(bUpdated)
			if siblingFirst {
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
			} else {
				require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
				require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
			}
			fx.assertClusterPolicyRulesCleared(db)
			fx.assertClusterPolicyRulesCleared(web)
		})
	}
}

// A slice deleted and recreated under the same name before its own reconcile is reconciled once,
// as live. Its earlier incarnation selected api-0 here, and a sibling's reconcile in between
// kept the policy on api, which the policy then still selected on another node. When the policy
// stops selecting api anywhere, the recreated slice's reconcile must still rewrite api from what
// the slice recorded, or api keeps rules no policy applies.
func TestPolicySlices_RecreatedSliceRewritesWhatItsEarlierIncarnationSelected(t *testing.T) {
	api := identifierOf("api-0")
	a := sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: []podRef{localPod("api-0", "10.1.1.30")}, ingress: []ruleRef{allow(np1aCIDR)}}
	b := sliceSpec{name: "np-1-bbbbb", parent: "np-1", pods: []podRef{remotePod("api-2", "10.1.2.32")}, ingress: []ruleRef{allow(np1bCIDR)}}
	fx := newPEFixture(t)
	fx.setSlices(a, b)
	fx.reconcileAll()
	require.ElementsMatch(t, []string{np1aCIDR, np1bCIDR}, fx.ingressCIDRs(api))

	fx.setSlices(b)
	require.NoError(t, fx.reconcile("np-1-bbbbb"))
	require.Equal(t, []string{np1bCIDR}, fx.ingressCIDRs(api), "the policy still selects api on another node")

	recreated := a
	recreated.pods = nil
	bUpdated := b
	bUpdated.pods = nil
	fx.setSlices(recreated, bUpdated)
	require.NoError(t, fx.reconcile("np-1-aaaaa"))
	require.NoError(t, fx.reconcile("np-1-bbbbb"))
	fx.assertRulesCleared(api)
	state, ok := fx.podState(api)
	require.True(t, ok)
	assert.Equal(t, DEFAULT_ALLOW, state)
}

func TestClusterPolicySlices_RecreatedSliceRewritesWhatItsEarlierIncarnationSelected(t *testing.T) {
	api := identifierOf("api-0")
	a := sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("api-0", "10.1.1.30")}, ingress: []ruleRef{deny(np1aCIDR)}}
	b := sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("api-2", "10.1.2.32")}, ingress: []ruleRef{deny(np1bCIDR)}}
	fx := newCPEFixture(t)
	fx.setSlices(a, b)
	fx.reconcileAll()
	require.ElementsMatch(t, []string{np1aCIDR, np1bCIDR}, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[api]))

	fx.setSlices(b)
	require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
	require.Equal(t, []string{np1bCIDR}, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[api]), "the policy still selects api on another node")

	recreated := a
	recreated.pods = nil
	bUpdated := b
	bUpdated.pods = nil
	fx.setSlices(recreated, bUpdated)
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
	fx.assertClusterPolicyRulesCleared(api)
}

// A pass that finds no programs because an attach failed keeps the slice-deletion record for its
// retry. db's programs are gone and np-2 selects db-1 here; the deletion pass's attach of db-1
// fails, and the retry, once it attaches, must still leave np-1 out.
func TestPolicySlices_SliceDeletionRecordSurvivesAFailedAttach(t *testing.T) {
	np2 := sliceSpec{name: "np-2-aaaaa", parent: "np-2", pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{allow(np2aCIDR)}}
	fx, db := dbFixture(t, np2)
	fx.detachContext(db)
	attachFailed := errors.New("attach failed")
	fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{{Name: "db-1", Namespace: fixtureNamespace}: attachFailed}
	fx.deleteSlice("np-1-aaaaa")
	require.ErrorIs(t, fx.reconcileDeleted("np-1-aaaaa"), attachFailed)

	fx.bpf.AttacheBPFProbesErrFor = nil
	require.NoError(t, fx.r.drainProgramming(context.TODO()))
	assert.Equal(t, []string{np2aCIDR}, fx.ingressCIDRs(db), "the retry still leaves np-1 out")
}

func TestClusterPolicySlices_SliceDeletionRecordSurvivesAFailedAttach(t *testing.T) {
	db := identifierOf("db-0")
	fx := newCPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 1, pods: []podRef{localPod("db-0", "10.1.1.10")}, ingress: []ruleRef{deny(np1aCIDR)}},
		sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 1, pods: []podRef{remotePod("db-2", "10.1.2.12")}, ingress: []ruleRef{deny(np1bCIDR)}},
		sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2", priority: 1, pods: []podRef{localPod("db-1", "10.1.1.11")}, ingress: []ruleRef{deny(np2aCIDR)}},
	)
	fx.reconcileAll()
	fx.detachContext(db)
	attachFailed := errors.New("attach failed")
	fx.bpf.AttacheBPFProbesErrFor = map[types.NamespacedName]error{{Name: "db-1", Namespace: fixtureNamespace}: attachFailed}
	fx.deleteSlice("cnp-1-aaaaa")
	require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), attachFailed)

	fx.bpf.AttacheBPFProbesErrFor = nil
	require.NoError(t, fx.r.drainProgramming(context.TODO()))
	assert.Equal(t, []string{np2aCIDR}, cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[db]), "the retry still leaves cnp-1 out")
}

// Deleting a policy's last slices leaves nothing to leave out: the policy selects the
// identifier nowhere, so no record is kept for it.
func TestPolicySlices_LastSliceDeletionKeepsNoRecord(t *testing.T) {
	fx, db := dbFixture(t)
	fx.deleteSlice("np-1-aaaaa")
	fx.deleteSlice("np-1-bbbbb")
	require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
	require.NoError(t, fx.reconcileDeleted("np-1-bbbbb"))
	fx.assertRulesCleared(db)
	_, recorded := fx.r.deleteCleanups.byIdentifier.Load(db)
	assert.False(t, recorded)
	remaining := 0
	fx.r.sliceLocalIdentifiers.Range(func(any, any) bool { remaining++; return true })
	assert.Zero(t, remaining, "a slice's own record goes once its deletion is reconciled")
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
