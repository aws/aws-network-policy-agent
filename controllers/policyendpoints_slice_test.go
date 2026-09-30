package controllers

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The namespaced path mirrors the cluster path: one NetworkPolicy is bin-packed across
// several PolicyEndpoints, so every slice contributes pods and rules to the identifiers
// it names.
//
// NetworkPolicy rules are allow-only. Isolation per direction comes from Spec.PodIsolation,
// which these fixtures leave unset, so both directions are un-isolated and the reconciler
// appends an allow-all entry to keep the datapath from dropping traffic it has no rule for.

func TestPolicySlices_ProgrammingAcrossSlices(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("distinct identifiers in sibling slices are each programmed", func(t *testing.T) {
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

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		for _, id := range []string{web, api} {
			assert.ElementsMatch(t, []string{"192.168.90.1/32", "192.168.90.2/32"}, fx.ingressCIDRs(id),
				"rules from every slice of the parent must reach each identifier the parent selects")
			state, ok := fx.podState(id)
			require.True(t, ok, "identifier %s must be programmed", id)
			assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		}
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

	t.Run("an un-isolated direction gets an allow-all entry", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		// Without PodIsolation the egress direction has no rules of its own, and the pod
		// state is POLICIES_APPLIED, so omitting the allow-all would drop all egress.
		assert.Contains(t, fx.egressCIDRs(nginx), "0.0.0.0/0",
			"an un-isolated direction with no rules must receive an allow-all entry")
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

		assert.ElementsMatch(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(web))
		assert.ElementsMatch(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(api))
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

		assertNoContextError(t, fx.reconcile("np-1-aaaaa"))
		assert.NotContains(t, fx.bpf.IngressByIdentifier, nginx,
			"an identifier with detached probes must not be written to")
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

		assertNoContextError(t, fx.reconcile("np-1-aaaaa"))
		assert.Empty(t, fx.bpf.IngressByIdentifier,
			"identifiers with detached probes must not be written to")
	})

	t.Run("losing one direction's rules during cleanup re-adds that direction's allow-all", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			survivor  sliceSpec
			emptied   func(*peFixture, string) []string
			remaining func(*peFixture, string) []string
		}{
			{
				name:      "egress emptied",
				survivor:  sliceSpec{name: "np-2-aaaaa", parent: "np-2", ingress: []ruleRef{allow("192.168.90.9/32")}},
				emptied:   (*peFixture).egressCIDRs,
				remaining: (*peFixture).ingressCIDRs,
			},
			{
				name:      "ingress emptied",
				survivor:  sliceSpec{name: "np-2-aaaaa", parent: "np-2", egress: []ruleRef{allow("192.168.91.9/32")}},
				emptied:   (*peFixture).ingressCIDRs,
				remaining: (*peFixture).egressCIDRs,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				nginx := identifierOf("nginx-aaa")
				pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}

				survivor := tc.survivor
				survivor.pods = pods
				fx := newPEFixture(t)
				fx.setSlices(
					sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: pods,
						ingress: []ruleRef{allow("192.168.90.1/32")},
						egress:  []ruleRef{allow("10.0.0.0/8")}},
					survivor,
				)
				fx.reconcileAll()
				fx.reset()

				// np-1 stops selecting the pod, so cleanup runs for the identifier. np-2 still
				// names it, so cleanup re-derives from np-2 rather than clearing everything --
				// and np-2 supplies only one direction.
				fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
					ingress: []ruleRef{allow("192.168.90.1/32")}}, survivor)
				require.NoError(t, fx.reconcile("np-1-aaaaa"))

				state, ok := fx.podState(nginx)
				require.True(t, ok)
				require.Equal(t, ebpf.POLICIES_APPLIED, state,
					"the identifier is still selected, so the datapath consults its maps")
				assert.NotEmpty(t, tc.remaining(fx, nginx), "the surviving direction keeps its rules")
				assert.Contains(t, tc.emptied(fx, nginx), "0.0.0.0/0",
					"a direction left with no rules while POLICIES_APPLIED must get an allow-all, "+
						"or the datapath drops all of that direction's traffic")
			})
		}
	})

	t.Run("a policy cannot claim a same-named policy's slice from another namespace", func(t *testing.T) {
		here, there := identifierOf("nginx-aaa"), identifierIn("nginx-aaa", "other-ns")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1", namespace: "other-ns",
				pods:    []podRef{localPod("nginx-aaa", "10.2.2.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)

		require.NoError(t, fx.reconcile("np-1-aaaaa"))

		assert.ElementsMatch(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(here),
			"a slice in another namespace must not contribute rules")
		assert.NotContains(t, fx.bpf.IngressByIdentifier, there,
			"reconciling one namespace must not program another's identifier")
		assert.ElementsMatch(t, []string{"np-1-aaaaa"}, fx.identifierSlices(here),
			"a same-named policy in another namespace is not a sibling and must not be recorded as one")
		_, crossNamespace := fx.r.policyEndpointSelectorMap.Load(
			utils.GetPolicyEndpointIdentifier("np-1-bbbbb", fixtureNamespace))
		assert.False(t, crossNamespace,
			"the foreign slice must not gain a selector entry keyed to this namespace")
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

		assert.ElementsMatch(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(nginx),
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

		assert.ElementsMatch(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(nginx))
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

		fx.assertRulesCleared(nginx)
		fx.assertIdentifierAbsent(nginx)
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
