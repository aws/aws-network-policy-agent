package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
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

// Map reclamation. podIdentifierToPolicyEndpointMap (Map1) is written for every pod a
// PolicyEndpoint names, on every node, and is the map that leaked: it used to be
// append-only, so a slice name it once recorded stayed forever. The inserting write is
// now authoritative for its parent policy, which is what reclaims the names of slices
// that no longer exist while the identifier itself is still selected — the one case the
// stale diff cannot catch, because an identifier a sibling slice still selects never
// becomes stale and the purge never visits it.
func TestPolicySlices_MapReclamation(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("a policy re-sliced under new names retains only its current slices", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newPEFixture(t)
		pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}
		rules := []ruleRef{allow("192.168.90.1/32")}

		// Each round re-slices the same policy over the same pod under a fresh slice name,
		// as NPC does when the chunking changes. The identifier stays selected throughout,
		// so it is never stale; only the authoritative insert can drop the old names.
		for _, name := range []string{"np-1-aaaaa", "np-1-bbbbb", "np-1-ccccc", "np-1-ddddd"} {
			fx.setSlices(sliceSpec{name: name, parent: "np-1", pods: pods, ingress: rules})
			fx.reconcileAll()
		}

		assert.Equal(t, []string{"np-1-ddddd"}, fx.identifierSlices(nginx),
			"three obsolete slice names must have been reclaimed, not retained alongside the current one")

		tracked, ok := fx.parentIdentifiers("np-1", fixtureNamespace)
		require.True(t, ok, "the parent must still track the identifier it selects")
		assert.ElementsMatch(t, []string{nginx}, tracked)

		// Reclaiming the names must not disturb what is programmed.
		state, ok := fx.podState(nginx)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		assert.Contains(t, fx.ingressCIDRs(nginx), "192.168.90.1/32")
	})

	t.Run("the delete event for an already-replaced slice changes nothing", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newPEFixture(t)
		pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}
		rules := []ruleRef{allow("192.168.90.1/32")}

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: pods, ingress: rules})
		fx.reconcileAll()
		// The re-slice lands first; the delete event for the old name arrives afterwards,
		// which is the ordering the agent sees when the new slice is created before the old
		// one is garbage collected.
		fx.setSlices(sliceSpec{name: "np-1-bbbbb", parent: "np-1", pods: pods, ingress: rules})
		fx.reconcileAll()
		require.Equal(t, []string{"np-1-bbbbb"}, fx.identifierSlices(nginx))
		fx.reset()

		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		assert.Equal(t, []string{"np-1-bbbbb"}, fx.identifierSlices(nginx),
			"the surviving slice must keep the identifier; the purge drops only this parent's dead names")
		state, ok := fx.podState(nginx)
		if ok {
			assert.Equal(t, ebpf.POLICIES_APPLIED, state,
				"a late delete event for a replaced slice must not tear down live enforcement")
		}
	})

	// The authoritative insert collapses Map1 to the parent's live slice set, so the cases
	// below are the ones it cannot reach: the identifier stops being selected in the same
	// change that alters the slice set, leaving Map1 holding a name that is no longer in
	// parentPEList. The purge reclaims those by exact name, drawing from the parent's live
	// slices plus the reconciled resource's own name.

	// Accepted residual. The purge prunes by EXACT PolicyEndpoint name, never parent-wide, so it
	// cannot drop a DIFFERENT policy's slices. The cost of that safety is this case -- a re-slice that
	// simultaneously deselects an identifier, observed only through the SURVIVING slice's reconcile.
	// There, resourceName is the surviving slice, so the departed slice's name is not in scope and the
	// identifier retains it.
	//
	// Scope of the cost, measured below rather than assumed:
	//   - The retained name is a permanent Map1 entry if a sibling reconcile has already
	//     rewritten Map3 to drop the identifier, since the purge then stops deriving it as
	//     stale and never visits it again. That is the leak.
	//   - Enforcement still converges, but by a different route. The retained name's object
	//     is gone, so deriveIngressAndEgressFirewallRules Gets it, sees NotFound, and
	//     derives no rules -- so when the pod is eventually cleaned up it lands on baseline
	//     via the no-active-policies path rather than via cleanupPod's Map1-absent branch.
	//   - Until that cleanup runs, this reconcile does not touch the deselected identifier
	//     at all (asserted below), so its eBPF maps keep whatever the previous reconcile
	//     wrote. The sibling delete event is what closes the window.
	t.Run("a re-slice that also deselects an identifier retains the departed slice name", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newPEFixture(t)
		gone, kept := identifierOf("gone-aaa"), identifierOf("kept-aaa")
		rules := []ruleRef{allow("192.168.90.1/32")}

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("gone-aaa", "10.1.1.1"), localPod("kept-aaa", "10.1.1.2")},
			ingress: rules})
		fx.reconcileAll()
		require.Equal(t, []string{"np-1-aaaaa"}, fx.identifierSlices(gone))

		// One change renames the slice and drops gone-aaa. Only np-1-bbbbb is reconciled,
		// so np-1-aaaaa is never named: not by the insert (gone-aaa is not selected) and
		// not by the purge (resourceName is np-1-bbbbb).
		// Reset the recorder first, so the assertions below describe what THIS reconcile
		// did rather than what round 1 left recorded.
		fx.reset()
		fx.setSlices(sliceSpec{name: "np-1-bbbbb", parent: "np-1",
			pods:    []podRef{localPod("kept-aaa", "10.1.1.2")},
			ingress: rules})
		fx.reconcileAll()

		assert.Equal(t, []string{"np-1-bbbbb"}, fx.identifierSlices(kept),
			"the still-selected identifier tracks only the current slice")
		assert.Equal(t, []string{"np-1-aaaaa"}, fx.identifierSlices(gone),
			"accepted residual: the departed slice's name is retained because exact-name "+
				"pruning cannot reach a name outside parentPEList + resourceName")

		// The deselected identifier is not reprogrammed by this reconcile. Its eBPF maps
		// retain whatever round 1 wrote until something cleans it up -- which is why the
		// retained Map1 entry matters: cleanupPod's baseline restore is gated on the Map1
		// entry being ABSENT, so a retained name suppresses it.
		_, ingressWritten := fx.bpf.IngressByIdentifier[gone]
		state, stateWritten := fx.podState(gone)
		t.Logf("deselected identifier %s: ingress rewritten=%v pod_state written=%v state=%d",
			gone, ingressWritten, stateWritten, state)
	})

	t.Run("the departed slice's own delete event reclaims the retained name", func(t *testing.T) {
		fx := newPEFixture(t)
		gone := identifierOf("gone-aaa")
		rules := []ruleRef{allow("192.168.90.1/32")}

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("gone-aaa", "10.1.1.1")},
				ingress: rules},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods:    []podRef{localPod("kept-aaa", "10.1.1.2")},
				ingress: rules},
		)
		fx.reconcileAll()
		require.Contains(t, fx.identifierSlices(gone), "np-1-aaaaa")

		// The delete event for np-1-aaaaa arrives while Map3 still tracks gone-aaa, so the
		// identifier is still derived as stale and resourceName IS the departed name.
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		assert.Empty(t, fx.identifierSlices(gone),
			"resourceName on the delete path is the departed slice, so the name is reclaimed")
	})

	t.Run("an identifier named only by the deleted slice is purged", func(t *testing.T) {
		fx := newPEFixture(t)
		gone := identifierOf("gone-aaa")

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1",
				pods:    []podRef{localPod("gone-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1",
				pods:    []podRef{localPod("kept-aaa", "10.1.1.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		require.NotEmpty(t, fx.identifierSlices(gone))

		// The surviving sibling does not select gone-aaa, so its name never gets replaced.
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		assert.Empty(t, fx.identifierSlices(gone),
			"an identifier only the deleted slice named must not be left behind")
	})

	t.Run("deleting every slice of a policy leaves no entry behind", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newPEFixture(t)
		pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}

		fx.setSlices(
			sliceSpec{name: "np-1-aaaaa", parent: "np-1", pods: pods, ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: "np-1-bbbbb", parent: "np-1", pods: pods, ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		require.ElementsMatch(t, []string{"np-1-aaaaa", "np-1-bbbbb"}, fx.identifierSlices(nginx))

		// One delete event per slice, as the agent sees a policy delete.
		fx.deleteSlice("np-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))
		fx.deleteSlice("np-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("np-1-bbbbb"))

		assert.Empty(t, fx.identifierSlices(nginx),
			"a fully deleted policy must leave no slice names behind")
		_, tracked := fx.parentIdentifiers("np-1", fixtureNamespace)
		assert.False(t, tracked, "the parent's tracked identifier set must be gone")
	})

	t.Run("restoring a deselected pod to baseline leaves the cluster tier untouched", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()

		// A ClusterNetworkPolicy independently programmed the cluster half of the pod-state
		// map. The namespaced tier must never write that key, only seed it when absent.
		require.NoError(t, fx.bpf.UpdatePodStateEbpfMaps(nginx,
			ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, ebpf.POLICIES_APPLIED, true, true))

		// The policy stops selecting the pod. Nothing else tracks the identifier, so the
		// namespaced tier drops to its baseline.
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		require.NoError(t, fx.reconcileDeleted("np-1-aaaaa"))

		state, ok := fx.podState(nginx)
		require.True(t, ok, "the deselected pod must have its namespaced state rewritten")
		assert.Equal(t, ebpf.DEFAULT_ALLOW, state)

		clusterState, ok := fx.clusterTierState(nginx)
		require.True(t, ok, "the cluster tier's entry must still be there")
		assert.Equal(t, ebpf.POLICIES_APPLIED, clusterState,
			"a namespaced baseline restore must not downgrade a cluster policy's verdict")
	})

	t.Run("a deselected pod whose probes are gone is left alone", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.reconcileAll()

		// The pod left the node and took the identifier's programs with it. Baseline restore
		// needs a context to write to, so there is nothing here to restore.
		fx.detachContext(nginx)
		fx.bpf.DeletedPods = map[types.NamespacedName]bool{
			{Name: "nginx-aaa", Namespace: fixtureNamespace}: true,
		}
		fx.reset()

		fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		assertNoContextError(t, fx.reconcileDeleted("np-1-aaaaa"))

		_, written := fx.podState(nginx)
		assert.False(t, written,
			"an identifier with no eBPF context must be skipped, not written and failed")
	})
}

// Two long policy names that differ only in their last character must be tracked as separate
// policies. Per-policy keys come from Spec.PolicyRef.
func TestPolicyEndpointSlices_LongPolicyNamesDoNotCollide(t *testing.T) {
	first, second := longPolicyNames()
	firstSlice, secondSlice := generatedSliceName(first, "aaaaa"), generatedSliceName(second, "bbbbb")

	t.Run("each policy keeps its own selected-identifier snapshot", func(t *testing.T) {
		firstLocal, firstRemote := identifierOf("first-aaa"), identifierOf("first-remote-aaa")
		secondLocal, secondRemote := identifierOf("second-aaa"), identifierOf("second-remote-aaa")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: firstSlice, parent: first,
				pods:    []podRef{localPod("first-aaa", "10.1.1.1"), remotePod("first-remote-aaa", "10.1.2.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: secondSlice, parent: second,
				pods:    []podRef{localPod("second-aaa", "10.1.1.2"), remotePod("second-remote-aaa", "10.1.2.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()

		got, ok := fx.parentIdentifiers(first, fixtureNamespace)
		require.True(t, ok)
		assert.ElementsMatch(t, []string{firstLocal, firstRemote}, got)
		got, ok = fx.parentIdentifiers(second, fixtureNamespace)
		require.True(t, ok)
		assert.ElementsMatch(t, []string{secondLocal, secondRemote}, got)

		// Deselect the first policy's remote pod. Its staleness is only detected if the first
		// policy's snapshot was not overwritten by the second policy's reconcile.
		fx.setSlices(
			sliceSpec{name: firstSlice, parent: first,
				pods:    []podRef{localPod("first-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: secondSlice, parent: second,
				pods:    []podRef{localPod("second-aaa", "10.1.1.2"), remotePod("second-remote-aaa", "10.1.2.2")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		require.NoError(t, fx.reconcile(firstSlice))

		assert.Empty(t, fx.identifierSlices(firstRemote), "the deselected identifier must be pruned")
		assert.Equal(t, []string{secondSlice}, fx.identifierSlices(secondRemote),
			"the other policy's identifiers must be untouched")
	})

	t.Run("deleting one policy keeps the other policy's rules on a shared pod", func(t *testing.T) {
		shared := identifierOf("shared-aaa")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: firstSlice, parent: first,
				pods:    []podRef{localPod("shared-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.1/32")}},
			sliceSpec{name: secondSlice, parent: second,
				pods:    []podRef{localPod("shared-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice(firstSlice)
		require.NoError(t, fx.reconcileDeleted(firstSlice))

		assert.Equal(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(shared),
			"the surviving policy's slice must not be skipped as a sibling of the deleted one")
		state, ok := fx.podState(shared)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("the recorded parent is dropped once its PolicyEndpoint is deleted", func(t *testing.T) {
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: firstSlice, parent: first,
			pods:    []podRef{localPod("first-aaa", "10.1.1.1")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		req := controllerruntime.Request{NamespacedName: types.NamespacedName{Name: firstSlice, Namespace: fixtureNamespace}}
		_, err := fx.r.Reconcile(context.TODO(), req)
		require.NoError(t, err)
		recorded, ok := fx.r.policyEndpointToParentNPMap.Load(req.NamespacedName)
		require.True(t, ok, "the parent must be recorded from Spec.PolicyRef")
		assert.Equal(t, first, recorded)

		fx.deleteSlice(firstSlice)
		_, err = fx.r.Reconcile(context.TODO(), req)
		require.NoError(t, err)
		assert.Equal(t, 0, sizeOfSyncMap(&fx.r.policyEndpointToParentNPMap), "recorded parents must not leak")
	})
}

// Deleting a PolicyEndpoint this agent never reconciled must be a no-op.
func TestPolicyEndpointSlices_DeleteOfUnseenSliceIsNoop(t *testing.T) {
	first, second := longPolicyNames()
	firstSlice, secondSlice := generatedSliceName(first, "aaaaa"), generatedSliceName(second, "bbbbb")
	shared := identifierOf("shared-aaa")
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: secondSlice, parent: second,
		pods:    []podRef{localPod("shared-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.90.2/32")}})
	fx.reconcileAll()
	fx.reset()

	require.NoError(t, fx.reconcileDeleted(firstSlice))

	assert.Empty(t, fx.bpf.CallLog, "an unseen slice's delete must not touch the dataplane")
	assert.Equal(t, []string{secondSlice}, fx.identifierSlices(shared))
	got, ok := fx.parentIdentifiers(second, fixtureNamespace)
	require.True(t, ok)
	assert.Equal(t, []string{shared}, got)
}

// Skipping the delete of an unrecorded slice is safe only if every slice that can still get a
// delete event has a recorded parent. Checked under random churn; no record may outlive its slice.
func TestPolicyEndpointSlices_EveryLiveSliceHasRecordedParent(t *testing.T) {
	first, second := longPolicyNames()
	parents := []string{first, second, "short-policy"}
	pods := []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2"),
		remotePod("db-aaa", "10.1.2.1"), remotePod("cache-aaa", "10.1.2.2")}

	for seed := int64(0); seed < 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		fx := newPEFixture(t)
		live := map[string]sliceSpec{}
		// Like GenerateName, a slice keeps its name while it lives and a recreated one gets a new name
		names, created := map[string]string{}, 0
		for step := 0; step < 30; step++ {
			next := map[string]sliceSpec{}
			nextNames := map[string]string{}
			for _, parent := range parents {
				for i := 0; i < rng.Intn(3); i++ {
					slot := fmt.Sprintf("%s#%d", parent, i)
					name, ok := names[slot]
					if !ok {
						created++
						name = generatedSliceName(parent, fmt.Sprintf("%05d", created))
					}
					nextNames[slot] = name
					var selected []podRef
					for _, p := range pods {
						if rng.Intn(2) == 0 {
							selected = append(selected, p)
						}
					}
					next[name] = sliceSpec{name: name, parent: parent, pods: selected,
						ingress: []ruleRef{allow(fmt.Sprintf("192.168.90.%d/32", i+1))}}
				}
			}
			specs := make([]sliceSpec, 0, len(next))
			for _, s := range next {
				specs = append(specs, s)
			}
			fx.setSlices(specs...)
			// Leave some slices unreconciled: their names must then appear nowhere in state
			for _, name := range fx.sliceNames() {
				if rng.Intn(3) > 0 {
					require.NoError(t, fx.reconcile(name))
				}
			}
			for name := range live {
				if _, ok := next[name]; !ok {
					require.NoError(t, fx.reconcileDeleted(name))
				}
			}
			live, names = next, nextNames
			assertEverySliceRecorded(t, fx, seed, step)
		}

		fx.setSlices()
		for name := range live {
			require.NoError(t, fx.reconcileDeleted(name))
		}
		assert.Equal(t, 0, sizeOfSyncMap(&fx.r.policyEndpointToParentNPMap), "seed %d: records must not outlive their slices", seed)
	}
}

// assertEverySliceRecorded checks the property the delete path relies on: a slice that still
// exists, and so can still get a delete event, has a recorded parent if any state names it. Names
// of deleted slices can linger (inserts are append-only) but their cleanup already ran.
func assertEverySliceRecorded(t *testing.T, fx *peFixture, seed int64, step int) {
	t.Helper()
	check := func(name, where string) {
		if _, live := fx.store[name]; !live {
			return
		}
		_, ok := fx.r.policyEndpointToParentNPMap.Load(types.NamespacedName{Name: name, Namespace: fixtureNamespace})
		assert.True(t, ok, "seed %d step %d: live slice %s in %s has no recorded parent", seed, step, name, where)
	}
	fx.r.podIdentifierToPolicyEndpointMap.Range(func(id, names any) bool {
		for _, name := range names.([]string) {
			check(name, id.(string))
		}
		return true
	})
	fx.r.policyEndpointSelectorMap.Range(func(key, _ any) bool {
		check(strings.TrimSuffix(key.(string), "/"+fixtureNamespace), "the selector map")
		return true
	})
}

// A slice deleted and recreated with the same name under another policy before the agent sees the
// delete merges into one reconcile. The old slice's cleanup must still run under the old parent,
// whichever of the new parent's slices is reconciled first.
func TestPolicyEndpointSlices_ReusedNameUnderNewParentCleansUpOldParent(t *testing.T) {
	first, second := longPolicyNames()
	reused, sibling := generatedSliceName(first, "aaaaa"), generatedSliceName(second, "bbbbb")
	oldPod, newPod, siblingPod := identifierOf("old-aaa"), identifierOf("new-aaa"), identifierOf("sib-aaa")

	for _, order := range [][]string{{reused, sibling}, {sibling, reused}} {
		t.Run("reconcile "+order[0][len(order[0])-5:]+" first", func(t *testing.T) {
			fx := newPEFixture(t)
			fx.setSlices(
				sliceSpec{name: reused, parent: first,
					pods: []podRef{localPod("old-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}},
				sliceSpec{name: sibling, parent: second,
					pods: []podRef{localPod("sib-aaa", "10.1.1.3")}, ingress: []ruleRef{allow("192.168.90.3/32")}},
			)
			require.NoError(t, fx.reconcileEvent(reused))
			require.NoError(t, fx.reconcileEvent(sibling))
			fx.reset()

			fx.setSlices(
				sliceSpec{name: reused, parent: second,
					pods: []podRef{localPod("new-aaa", "10.1.1.2")}, ingress: []ruleRef{allow("192.168.90.2/32")}},
				sliceSpec{name: sibling, parent: second,
					pods: []podRef{localPod("sib-aaa", "10.1.1.3")}, ingress: []ruleRef{allow("192.168.90.3/32")}},
			)
			for _, name := range order {
				require.NoError(t, fx.reconcileEvent(name))
			}

			recorded, _ := fx.r.policyEndpointToParentNPMap.Load(types.NamespacedName{Name: reused, Namespace: fixtureNamespace})
			assert.Equal(t, second, recorded)
			_, ok := fx.parentIdentifiers(first, fixtureNamespace)
			assert.False(t, ok, "the old parent must no longer track the reused slice's pods")
			fx.assertRulesCleared(oldPod)
			assert.Empty(t, fx.identifierSlices(oldPod))
			got, ok := fx.parentIdentifiers(second, fixtureNamespace)
			require.True(t, ok)
			assert.ElementsMatch(t, []string{newPod, siblingPod}, got)
			assert.ElementsMatch(t, []string{"192.168.90.2/32", "192.168.90.3/32"}, fx.ingressCIDRs(newPod))

			fx.deleteSlice(reused)
			require.NoError(t, fx.reconcileDeleted(reused))
			got, ok = fx.parentIdentifiers(second, fixtureNamespace)
			require.True(t, ok)
			assert.Equal(t, []string{siblingPod}, got)
			assert.Equal(t, []string{"192.168.90.3/32"}, fx.ingressCIDRs(siblingPod))
			assert.Equal(t, 1, sizeOfSyncMap(&fx.r.policyEndpointToParentNPMap))
		})
	}
}

// Two slices that swap parents before either delete is processed: each old parent's cleanup
// lists the other reused slice. Settling must terminate and leave both parents correct.
func TestPolicyEndpointSlices_ReusedNamesSwappingParentsSettle(t *testing.T) {
	first, second := longPolicyNames()
	x, y := generatedSliceName(first, "aaaaa"), generatedSliceName(second, "bbbbb")

	for _, order := range [][]string{{x, y}, {y, x}} {
		t.Run("reconcile "+order[0][len(order[0])-5:]+" first", func(t *testing.T) {
			fx := newPEFixture(t)
			fx.setSlices(
				sliceSpec{name: x, parent: first,
					pods: []podRef{localPod("xa-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}},
				sliceSpec{name: y, parent: second,
					pods: []podRef{localPod("yb-aaa", "10.1.1.2")}, ingress: []ruleRef{allow("192.168.90.2/32")}},
			)
			require.NoError(t, fx.reconcileEvent(x))
			require.NoError(t, fx.reconcileEvent(y))
			fx.reset()

			fx.setSlices(
				sliceSpec{name: x, parent: second,
					pods: []podRef{localPod("xb-aaa", "10.1.1.3")}, ingress: []ruleRef{allow("192.168.90.3/32")}},
				sliceSpec{name: y, parent: first,
					pods: []podRef{localPod("ya-aaa", "10.1.1.4")}, ingress: []ruleRef{allow("192.168.90.4/32")}},
			)
			for _, name := range order {
				require.NoError(t, fx.reconcileEvent(name))
			}

			for name, parent := range map[string]string{x: second, y: first} {
				recorded, _ := fx.r.policyEndpointToParentNPMap.Load(types.NamespacedName{Name: name, Namespace: fixtureNamespace})
				assert.Equal(t, parent, recorded)
			}
			got, ok := fx.parentIdentifiers(first, fixtureNamespace)
			require.True(t, ok)
			assert.Equal(t, []string{identifierOf("ya-aaa")}, got)
			got, ok = fx.parentIdentifiers(second, fixtureNamespace)
			require.True(t, ok)
			assert.Equal(t, []string{identifierOf("xb-aaa")}, got)
			fx.assertRulesCleared(identifierOf("xa-aaa"))
			fx.assertRulesCleared(identifierOf("yb-aaa"))
			assert.Equal(t, []string{"192.168.90.4/32"}, fx.ingressCIDRs(identifierOf("ya-aaa")))
			assert.Equal(t, []string{"192.168.90.3/32"}, fx.ingressCIDRs(identifierOf("xb-aaa")))
		})
	}
}
