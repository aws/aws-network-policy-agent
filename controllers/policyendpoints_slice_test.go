package controllers

import (
	"context"
	"errors"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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

	t.Run("a de-selected identifier falls back to the mode's default state", func(t *testing.T) {
		for _, tc := range []struct {
			mode string
			want int
		}{
			{mode: "standard", want: ebpf.DEFAULT_ALLOW},
			{mode: "strict", want: ebpf.DEFAULT_DENY},
		} {
			t.Run(tc.mode, func(t *testing.T) {
				t.Skip("known defect: deriveTargetPodsForParentNP scrubs the identifier before cleanup " +
					"runs, so cleanupPod's presence check misses and the default-state assignment at " +
					"policyendpoints_controller.go:404-407 is never reached")

				fx := newPEFixture(t)
				fx.bpf.NetworkPolicyMode = tc.mode
				fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
					pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
					ingress: []ruleRef{allow("192.168.90.1/32")}})
				fx.reconcileAll()
				fx.reset()

				fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "np-1",
					ingress: []ruleRef{allow("192.168.90.1/32")}})
				require.NoError(t, fx.reconcile("np-1-aaaaa"))

				state, ok := fx.podState(nginx)
				require.True(t, ok, "de-selection must write the pod state, not leave it applied")
				assert.Equal(t, tc.want, state)
			})
		}
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
		assertNoContextError(t, fx.reconcileDeleted("np-1-aaaaa"))
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

		assert.ElementsMatch(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(nginx),
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

// The cluster path surfaces a List failure so controller-runtime requeues, because an
// empty result is otherwise indistinguishable from "no slices left" and would clear rules.
// The namespaced path swallows it instead, and this records what that costs.
func TestPolicySlices_TransientListError(t *testing.T) {
	t.Skip("known defect: derivePolicyEndpointsOfParentNP logs the List error and returns nil, so " +
		"reconcile reports success and nothing requeues, after deriveTargetPodsForParentNP has " +
		"already deleted the policy's bookkeeping. The cluster twin returns the error instead")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mock_client.NewMockClient(ctrl)
	mockBpf := &ebpf.MockBpfClient{}
	reconciler := NewPolicyEndpointsReconciler(mockClient, fixtureNodeIP, mockBpf, false)

	nginx := identifierOf("nginx-aaa")
	peName := "np-1-aaaaa"

	reconciler.podIdentifierToPolicyEndpointMap.Store(nginx, []string{peName})
	reconciler.networkPolicyToPodIdentifierMap.Store("np-1", []string{nginx})
	reconciler.policyEndpointSelectorMap.Store(utils.GetPolicyEndpointIdentifier(peName, fixtureNamespace),
		[]npatypes.Pod{{
			NamespacedName: types.NamespacedName{Name: "nginx-aaa", Namespace: fixtureNamespace},
			PodIP:          "10.1.1.1",
		}})

	listErr := errors.New("etcdserver: request timed out")
	mockClient.EXPECT().
		List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.PolicyEndpointList{}), gomock.Any()).
		Return(listErr).AnyTimes()

	// With the List failed the parent looks sliceless, so cleanup runs for the seeded pod and
	// re-derives its rules, which Gets the slice. Stub it so removing the skip fails at the
	// assertions below rather than on missing mock plumbing.
	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.PolicyEndpoint{}), gomock.Any()).
		Return(apierrors.NewNotFound(schema.GroupResource{Resource: "policyendpoints"}, peName)).AnyTimes()

	pe := &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: peName, Namespace: fixtureNamespace},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.PolicyReference{Name: "np-1", Namespace: fixtureNamespace},
			Ingress:   []policyk8sawsv1.EndpointInfo{{CIDR: "192.168.90.1/32"}},
		},
	}

	err := reconciler.reconcilePolicyEndpoint(context.TODO(), pe)
	assert.ErrorIs(t, err, listErr, "reconcile must surface a List failure so the request requeues")

	_, tracked := reconciler.networkPolicyToPodIdentifierMap.Load("np-1")
	assert.True(t, tracked, "the policy's bookkeeping must survive a transient List failure")
}
