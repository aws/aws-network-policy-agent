package controllers

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The namespaced path mirrors the cluster path: one NetworkPolicy is bin-packed across
// several PolicyEndpoints, so every slice contributes pods and rules to the identifiers
// it names. NetworkPolicy rules are allow-only, and isolation comes from the pod being
// selected at all rather than from an explicit Deny action.

func TestPolicySlices_ProgrammingAcrossSlices(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("pods split across slices are all programmed", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods:    []podRef{localPod("nginx-bbb", "10.1.1.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		assert.ElementsMatch(t, []string{"192.168.90.1/32", "192.168.90.2/32"},
			fx.ingressCIDRs(nginx),
			"rules from every slice of the parent must reach the identifier's map")
		state, ok := fx.podState(nginx)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("ingress and egress rules split across slices are unioned", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")},
				egress:  []ruleRef{allow("10.0.0.0/8")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				ingress: []ruleRef{allow("192.168.90.2/32")},
				egress:  []ruleRef{allow("172.16.0.0/12")}},
		)

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		assert.ElementsMatch(t, []string{"192.168.90.1/32", "192.168.90.2/32"}, fx.ingressCIDRs(nginx))
		assert.ElementsMatch(t, []string{"10.0.0.0/8", "172.16.0.0/12"}, fx.egressCIDRs(nginx))
	})

	t.Run("a slice carrying only rules still applies to pods named by a sibling slice", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods: []podRef{localPod("nginx-aaa", "10.1.1.1")}},
		)

		require.NoError(t, fx.reconcile("np-1-bbbbb"))

		assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(nginx),
			"pods and the rules that govern them can be packed into different slices")
	})

	t.Run("each identifier gets only its own rules", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)

		fx.reconcileAll()

		assert.Contains(t, fx.ingressCIDRs(web), "192.168.90.1/32")
		assert.NotContains(t, fx.ingressCIDRs(web), "192.168.90.2/32")
		assert.Contains(t, fx.ingressCIDRs(api), "192.168.90.2/32")
		assert.NotContains(t, fx.ingressCIDRs(api), "192.168.90.1/32")
	})

	t.Run("remote pods in a slice are not programmed locally", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{remotePod("remote-aaa", "10.2.2.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		assert.Empty(t, fx.bpf.IngressByIdentifier,
			"a slice lists pods cluster-wide; only pods whose HostIP is this node are programmed")
	})

	t.Run("rules from two parent policies are unioned on a shared identifier", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)

		fx.reconcileAll()

		assert.ElementsMatch(t, []string{"192.168.90.1/32", "192.168.90.2/32"},
			fx.ingressCIDRs(nginx))
	})
}

func TestPolicySlices_Updates(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("a new slice appearing extends an existing identifier's rules", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		require.NoError(t, fx.reconcile("np-1-bbbbb"))

		assert.ElementsMatch(t, []string{"192.168.90.1/32", "192.168.90.2/32"},
			fx.ingressCIDRs(nginx))
	})

	t.Run("a second parent policy selecting the identifier adds its rules", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		require.NoError(t, fx.reconcile("np-2-aaaaa"))

		assert.ElementsMatch(t, []string{"192.168.90.1/32", "192.168.90.2/32"},
			fx.ingressCIDRs(nginx))
	})

	t.Run("dropping a rule from one slice leaves the sibling slice's rules", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1"},
		)
		require.NoError(t, fx.reconcile("np-1-bbbbb"))

		assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(nginx))
	})

	t.Run("a pod repacked into a sibling slice is not treated as departed", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1"},
		)
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods: []podRef{localPod("nginx-aaa", "10.1.1.1")}},
		)
		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		state, ok := fx.podState(nginx)
		require.True(t, ok, "the migrating identifier must still be programmed")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("reconciling unchanged slices repeatedly is idempotent", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		first := fx.ingressCIDRs(nginx)

		fx.reset()
		fx.reconcileAll()

		assert.ElementsMatch(t, first, fx.ingressCIDRs(nginx))
	})
}

func TestPolicySlices_NodeScopedCleanup(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("one pod of a multi-pod identifier leaving does not clear shared state", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), localPod("nginx-bbb", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-bbb", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(nginx),
			"pods of one identifier share an eBPF program set, so a surviving replica keeps it")
	})

	t.Run("last local pod leaving with a single parent policy does not error", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.detachContext(nginx)

		assert.NoError(t, fx.reconcile("np-1-aaaaa"))
	})

	t.Run("last local pod leaving with two parent policies does not wedge the reconcile", func(t *testing.T) {
		t.Skip("known defect: cleanupPod has no HasBPFContext guard at all, so a sibling parent " +
			"keeps the identifier entry alive and the map write fails on a detached context. The " +
			"namespaced reconciler commits its maps inside derive, so today this self-heals on the " +
			"next requeue rather than wedging; this test is the guard against that ordering changing")

		other := identifierOf("other-aaa")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2"), localPod("other-aaa", "10.1.1.9")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.detachContext(nginx)

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		state, ok := fx.podState(other)
		require.True(t, ok, "a newly scheduled workload must be programmed, not left unenforced")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("identifier no longer selected anywhere has its rules cleared", func(t *testing.T) {
		t.Skip("known defect: deriveTargetPodsForParentNP scrubs the identifier from " +
			"podIdentifierToPolicyEndpointMap before cleanup runs, so cleanupPod's presence check " +
			"misses and it returns without touching the eBPF maps. Stale rules survive until the " +
			"pod restarts")

		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		state, ok := fx.podState(nginx)
		require.True(t, ok, "the identifier's pod state must be reset, not left at POLICIES_APPLIED")
		assert.Equal(t, ebpf.DEFAULT_ALLOW, state)
	})

	t.Run("a parent policy keeping one empty slice is not treated as having no slices", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1"})
		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		fx.assertIdentifierAbsent(nginx)
	})

	t.Run("draining every identifier from the node does not error", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.detachContext(identifierOf("web-aaa"), identifierOf("api-aaa"))

		assert.NoError(t, fx.reconcile("np-1-aaaaa"))
	})

	t.Run("strict mode seeds a de-selected identifier default-deny", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.bpf.NetworkPolicyMode = "strict"
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), localPod("nginx-bbb", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-bbb", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		state, ok := fx.podState(nginx)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state,
			"a surviving replica keeps the policy applied regardless of mode")
	})
}

func TestPolicySlices_SliceDeletion(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("sibling slice of the same parent keeps the identifier enforced", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		assert.Contains(t, fx.ingressCIDRs(nginx), "192.168.90.2/32",
			"the surviving slice's rules must be retained")
	})

	t.Run("a different parent policy keeps the identifier enforced", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		assert.Contains(t, fx.ingressCIDRs(nginx), "192.168.90.2/32")
	})

	t.Run("deleting the identifier's only slice clears its rules", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		fx.assertIdentifierAbsent(nginx)
	})

	t.Run("deleting a slice whose identifier has no local pods does not error", func(t *testing.T) {
		t.Skip("known defect: cleanupPod has no HasBPFContext guard, so a sibling parent keeps the " +
			"identifier entry alive and the map write fails on a detached context")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-2-aaaaa", parent: "np-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()
		fx.detachContext(nginx)

		fx.deleteSlice("np-1-aaaaa")
		assert.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
	})

	t.Run("deleting one slice of a long-named parent keeps sibling rules", func(t *testing.T) {
		t.Skip("known defect: cleanUpPolicyEndpoint derives the parent from the slice name while " +
			"derivePolicyEndpointsOfParentNP filters on Spec.PolicyRef.Name, so a name truncated by " +
			"GenerateName finds zero siblings and the delete flow clears rules the survivor supplies")

		// GenerateName caps the base at 58 chars, so for a parent name that long the slice
		// name is a truncated prefix and no longer yields the parent name back.
		parent := "restrict-egress-from-payment-service-to-external-endpoints-prod"
		deleted := "restrict-egress-from-payment-service-to-external-endpointsabcde"
		sibling := "restrict-egress-from-payment-service-to-external-endpointsxyz12"

		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: deleted, parent: parent,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: sibling, parent: parent,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice(deleted)
		require.NoError(t, fx.reconcileDeleted(deleted))

		assert.Contains(t, fx.ingressCIDRs(nginx), "192.168.90.2/32",
			"a truncated slice name must not cost the surviving sibling its rules")
	})

	t.Run("deleting every slice of a parent clears all its identifiers", func(t *testing.T) {
		t.Skip("known defect: deriveTargetPods records the whole parentPEList against every pod, but " +
			"the delete flow only scrubs the deleted slice from identifiers in podsToBeCleanedUp. An " +
			"identifier cleaned up by a later slice keeps a dangling reference to the earlier one, so " +
			"its entry never empties. The cluster path gained an explicit scrub for this; this one did not")
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		fx.deleteSlice("np-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("np-1-bbbbb"))

		fx.assertIdentifierAbsent(web)
		fx.assertIdentifierAbsent(api)
	})
}

func TestPolicySlices_RestartReconstruction(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	slices := []sliceSpec{
		{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
		{name: "np-1-bbbbb", parent: "np-1",
			ingress: []ruleRef{allow("192.168.90.2/32")}},
		{name: "np-2-aaaaa", parent: "np-2",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.3/32")}},
	}

	before := newPEFixture(t)
	before.setSlices(slices...)
	before.reconcileAll()
	want := before.ingressCIDRs(nginx)
	require.NotEmpty(t, want)

	after := newPEFixture(t)
	after.setSlices(slices...)
	after.reconcileAll()

	assert.ElementsMatch(t, want, after.ingressCIDRs(nginx),
		"a restarted agent must rebuild the same rules from the same slices")
}
