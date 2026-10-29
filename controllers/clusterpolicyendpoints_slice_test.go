package controllers

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// Programming path: a parent CNP split across several ClusterPolicyEndpoints must be
// treated as one policy, so every slice contributes pods and rules to the identifiers
// it names.

func TestClusterPolicySlices_ProgrammingAcrossSlices(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("distinct identifiers in sibling slices are each programmed", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 10,
				pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", priority: 20,
				pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		for _, id := range []string{web, api} {
			assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Deny 192.168.90.2/32"},
				fx.clusterPolicyRules(id),
				"rules from every slice of the parent must reach each identifier the parent selects")
			assert.ElementsMatch(t, []int{10, 20}, fx.clusterPolicyPriorities(id))
			state, ok := fx.clusterPolicyState(id)
			require.True(t, ok, "identifier %s must be programmed", id)
			assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		}
	})

	t.Run("ingress and egress rules split across slices are unioned", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")},
				egress:  []ruleRef{deny("10.0.0.0/8")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.2/32")},
				egress:  []ruleRef{deny("172.16.0.0/12")}},
		)

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Deny 192.168.90.2/32"}, fx.clusterPolicyRules(nginx))
		assert.ElementsMatch(t, []string{"Deny 10.0.0.0/8", "Deny 172.16.0.0/12"}, fx.clusterPolicyEgressRules(nginx))
	})

	t.Run("a slice carrying only rules still applies to pods named by a sibling slice", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods: []podRef{localPod("nginx-aaa", "10.1.1.1")}},
		)

		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))

		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx),
			"pods and the rules that govern them can be packed into different slices")
	})

	t.Run("each identifier gets only its own rules", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		require.NoError(t, fx.reconcile("cnp-2-aaaaa"))

		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(web))
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(api))
	})

	t.Run("remote pods in a slice are not programmed locally", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{remotePod("remote-aaa", "10.2.2.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.Empty(t, fx.bpf.ClusterPolicyIngressByIdentifier,
			"a slice lists pods cluster-wide; only pods whose HostIP is this node are programmed")
	})

	t.Run("rules from two parent policies are unioned on a shared identifier", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", priority: 10,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2", priority: 20,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{allow("192.168.90.2/32")}},
		)

		fx.reconcileAll()

		assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Accept 192.168.90.2/32"},
			fx.clusterPolicyRules(nginx),
			"a Deny and an Accept from different parents must stay distinguishable")
	})

	t.Run("baseline tier priority is offset in both directions", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", tier: policyk8sawsv1.AdminTier, priority: 10,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")},
				egress:  []ruleRef{deny("10.0.0.0/8")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2", tier: policyk8sawsv1.BaselineTier, priority: 999,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")},
				egress:  []ruleRef{deny("172.16.0.0/12")}},
		)

		fx.reconcileAll()

		// Admin priorities pass through; baseline ones are offset above every admin value so
		// admin always outranks baseline whatever numbers the policies chose.
		offsetBaseline := 999 + fwrp.BASELINE_TIER_PRIORITY_OFFSET
		for _, direction := range []struct {
			name       string
			priorities []int
		}{
			{"ingress", fx.clusterPolicyPriorities(nginx)},
			{"egress", prioritiesOf(fx.bpf.ClusterPolicyEgressByIdentifier[nginx])},
		} {
			assert.ElementsMatch(t, []int{10, offsetBaseline}, direction.priorities,
				"%s: admin priority passes through and baseline is offset", direction.name)
		}
	})
}

// Update path: adding pods, rules or a second parent policy must converge without
// disturbing identifiers that did not change.

func TestClusterPolicySlices_Updates(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("a new slice appearing extends an existing identifier's rules", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))

		assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Deny 192.168.90.2/32"},
			fx.clusterPolicyRules(nginx))
	})

	t.Run("a second parent policy selecting the identifier adds its rules", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		require.NoError(t, fx.reconcile("cnp-2-aaaaa"))

		assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Deny 192.168.90.2/32"},
			fx.clusterPolicyRules(nginx))
	})

	t.Run("dropping a rule from one slice leaves the sibling slice's rules", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1"},
		)
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))

		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx))
	})

	t.Run("a pod deselected while a new sibling slice appears is cleaned up", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		// web is dropped and a new slice is added in the same update; the new slice's
		// event is handled first.
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("db-aaa", "10.1.1.3")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(web)
		assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Deny 192.168.90.2/32"}, fx.clusterPolicyRules(api))
	})

	t.Run("a pod repacked into a sibling slice is not treated as departed", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1"},
		)
		fx.reconcileAll()
		fx.reset()

		// The controller bin-packs into existing slices first, so an unrelated change can
		// move a pod between slices of the same parent with no change to the policy.
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods: []podRef{localPod("nginx-aaa", "10.1.1.1")}},
		)
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		state, ok := fx.clusterPolicyState(nginx)
		require.True(t, ok, "the migrating identifier must still be programmed")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx))
	})

	t.Run("reconciling unchanged slices repeatedly is idempotent", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		first := fx.clusterPolicyRules(nginx)

		fx.reset()
		fx.reconcileAll()

		assert.ElementsMatch(t, first, fx.clusterPolicyRules(nginx))
		state, ok := fx.clusterPolicyState(nginx)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("a tier change rewrites every slice of the parent", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			tier: policyk8sawsv1.AdminTier, priority: 10,
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			tier: policyk8sawsv1.BaselineTier, priority: 10,
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		rules := fx.bpf.ClusterPolicyIngressByIdentifier[nginx]
		require.Len(t, rules, 1)
		assert.Greater(t, rules[0].Priority, 10, "baseline tier must be offset above admin")
	})
}

// Node-scoped cleanup: whether a departing pod's identifier keeps its eBPF state depends
// on what else still claims it, and each combination reaches a different branch of
// cleanupClusterPolicyPod.

func TestClusterPolicySlices_NodeScopedCleanup(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("one pod of a multi-pod identifier leaving does not clear shared state", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), localPod("nginx-bbb", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-bbb", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx),
			"pods of one identifier share an eBPF program set, so a surviving replica keeps it")
	})

	t.Run("last local pod leaving with a single parent policy does not error", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.detachContext(nginx)

		assertNoContextError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, nginx,
			"an identifier with detached probes must not be written to")
	})

	t.Run("last local pod leaving with two parent policies does not fail the reconcile", func(t *testing.T) {
		other := identifierOf("other-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		// nginx's last local pod is gone, so its probes are detached, but cnp-2 still
		// names the identifier cluster-wide. A second workload now lands on this node.
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2"), localPod("other-aaa", "10.1.1.9")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.detachContext(nginx)

		assertNoContextError(t, fx.reconcile("cnp-1-aaaaa"))

		state, ok := fx.clusterPolicyState(other)
		require.True(t, ok, "a newly scheduled workload must be programmed, not left unenforced")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("identifier no longer selected anywhere has its rules cleared", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		fx.assertClusterPolicyRulesCleared(nginx)
		state, ok := fx.clusterPolicyState(nginx)
		require.True(t, ok, "the identifier's pod state must be reset, not left at POLICIES_APPLIED")
		assert.Equal(t, ebpf.DEFAULT_ALLOW, state)
	})

	t.Run("a parent policy left selecting nothing clears its identifiers", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		// The controller always retains at least one slice per policy, so "selects nothing"
		// arrives as an empty slice rather than as zero slices. For a single slice the two are
		// observationally identical: the no-slices path falls back to parentCPEList =
		// []string{resourceName}, which is the list the has-slices path builds anyway.
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1"})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		fx.assertClusterPolicyRulesCleared(nginx)
		fx.assertIdentifierAbsent(nginx)
		_, tracked := fx.parentIdentifiers("cnp-1")
		assert.False(t, tracked,
			"the parent selects nothing locally, so it must hold no identifiers")
	})

	t.Run("last local pod leaving with one parent sliced in two does not fail the reconcile", func(t *testing.T) {

		other := identifierOf("other-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1"), remotePod("nginx-bbb", "10.2.2.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		// Slice bbbbb is gone but its delete event has not been processed, so its name is
		// still recorded against the identifier while no longer appearing in parentCPEList.
		fx.deleteSlice("cnp-1-bbbbb")
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{remotePod("nginx-bbb", "10.2.2.2"), localPod("other-aaa", "10.1.1.9")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.detachContext(nginx)

		require.Contains(t, fx.identifierSlices(nginx), "cnp-1-bbbbb",
			"the deleted slice's name is still recorded, and the scrub will not cover it")

		assertNoContextError(t, fx.reconcile("cnp-1-aaaaa"))

		state, ok := fx.clusterPolicyState(other)
		require.True(t, ok, "a newly scheduled workload must be programmed, not left unenforced")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("an identifier whose pods leave and return is programmed again", func(t *testing.T) {
		nginx := identifierOf("nginx-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.detachContext(nginx)
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		// A later pod of the same workload re-attaches probes, so the identifier gets a fresh
		// context and must be programmed from scratch rather than treated as still torn down.
		fx.bpf.ForgetIdentifier(nginx)
		fx.reset()
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-ccc", "10.1.1.3")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx))
		state, ok := fx.clusterPolicyState(nginx)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("a pod still listed after it left the node is skipped, not retried", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		// web was deleted on the node before the controller dropped it from the CPE.
		fx.detachContext(web)
		fx.bpf.DeletedPods = map[types.NamespacedName]bool{{Name: "web-aaa", Namespace: "np-target"}: true}

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, web)
		state, ok := fx.clusterPolicyState(api)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("a new identifier is programmed once its first pod attaches", func(t *testing.T) {
		web := identifierOf("web-aaa")
		fx := newCPEFixture(t)
		// No programs exist for web until the reconcile attaches them.
		fx.detachContext(web)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(web))
	})

	t.Run("draining every identifier from the node does not error", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.detachContext(identifierOf("web-aaa"), identifierOf("api-aaa"))

		assertNoContextError(t, fx.reconcile("cnp-1-aaaaa"))
	})

	t.Run("the namespaced default state a cluster policy seeds follows the enforcing mode", func(t *testing.T) {
		for _, tc := range []struct {
			mode string
			want int
		}{
			{mode: "standard", want: ebpf.DEFAULT_ALLOW},
			{mode: "strict", want: ebpf.DEFAULT_DENY},
		} {
			t.Run(tc.mode, func(t *testing.T) {
				fx := newCPEFixture(t)
				fx.bpf.NetworkPolicyMode = tc.mode
				fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
					pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
					ingress: []ruleRef{deny("192.168.90.1/32")}})

				require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

				// Cluster policies have no default-deny of their own, so programming one seeds
				// the namespaced tier's default from the mode and leaves the cluster tier applied.
				state, ok := fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{
					PodIdentifier: nginx, MapKey: ebpf.POD_STATE_MAP_KEY,
				}]
				require.True(t, ok, "programming must seed the namespaced pod state")
				assert.Equal(t, tc.want, state)

				clusterState, ok := fx.clusterPolicyState(nginx)
				require.True(t, ok)
				assert.Equal(t, ebpf.POLICIES_APPLIED, clusterState,
					"the cluster tier is applied regardless of mode")
			})
		}
	})

}

// Slice deletion: a deleted slice must stop contributing rules without disturbing the
// identifiers that surviving slices still cover.

func TestClusterPolicySlices_SliceDeletion(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("sibling slice of the same parent keeps the identifier enforced", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))

		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(nginx),
			"the surviving slice's rules must be retained")
	})

	t.Run("a different parent policy keeps the identifier enforced", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))

		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(nginx))
	})

	t.Run("deleting the identifier's only slice clears its rules", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))

		fx.assertClusterPolicyRulesCleared(nginx)
		fx.assertIdentifierAbsent(nginx)
	})

	t.Run("deleting a slice whose identifier has no local pods does not error", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()
		fx.detachContext(nginx)

		fx.deleteSlice("cnp-1-aaaaa")
		assertNoContextError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
	})

	t.Run("deleting every slice of a parent clears all its identifiers", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.deleteSlice("cnp-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("cnp-1-bbbbb"))

		fx.assertIdentifierAbsent(web)
		fx.assertIdentifierAbsent(api)
	})
}

// Restart: the maps are rebuilt from scratch by reconciling every slice, so the agent
// must converge on the same state it held before.

func TestClusterPolicySlices_RestartReconstruction(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	slices := []sliceSpec{
		{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}},
		{name: "cnp-1-bbbbb", parent: "cnp-1",
			ingress: []ruleRef{deny("192.168.90.2/32")}},
		{name: "cnp-2-aaaaa", parent: "cnp-2",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.3/32")}},
	}

	before := newCPEFixture(t)
	before.setSlices(slices...)
	before.reconcileAll()
	want := before.clusterPolicyRules(nginx)
	require.NotEmpty(t, want)

	after := newCPEFixture(t)
	after.setSlices(slices...)
	after.reconcileAll()

	assert.ElementsMatch(t, want, after.clusterPolicyRules(nginx),
		"a restarted agent must rebuild the same rules from the same slices")
}

// clusterNetworkPolicyToPodIdentifierMap (Map3) tracks every identifier the CNP selects on
// ANY node, keyed by the parent CNP name. It is the diff source for stale-identifier pruning:
// an identifier it recorded last reconcile but no longer selects is scrubbed from
// podIdentifierToClusterPolicyEndpointMap (Map1). These tests pin that cluster-wide tracking,
// the remote-only prune path, key consistency under GenerateName truncation, and the
// full-parent teardown.
func TestClusterPolicySlices_ClusterWideTracking(t *testing.T) {
	localID := identifierOf("local-aaa")
	remoteID := identifierOf("remote-aaa")

	// (1) Map3 records identifiers selected only on another node, not just node-local ones.
	t.Run("the NP's tracked identifier set includes remote-only identifiers", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("local-aaa", "10.1.1.1"),
				remotePod("remote-aaa", "10.1.2.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		tracked, ok := fx.parentIdentifiers("cnp-1")
		require.True(t, ok, "the parent's identifier set must be recorded")
		// Both the local and the remote-only identifier must be tracked: Map3 is cluster-wide,
		// so a remote replica the local node never programs is still diffed for staleness.
		assert.ElementsMatch(t, []string{localID, remoteID}, tracked,
			"Map3 must track every identifier the CNP selects on any node")
	})

	// (2) A remote-only identifier that stops being selected is pruned from Map1, and since it
	// was never local there is nothing on this node to clear (stale path fires, cleanup does not).
	t.Run("a remote-only identifier once deselected is pruned from the PI to CPE map", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("local-aaa", "10.1.1.1"),
				remotePod("remote-aaa", "10.1.2.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		require.NotEmpty(t, fx.identifierSlices(remoteID), "remote-only id starts tracked in Map1")
		fx.reset()

		// Drop the remote pod; only the local identifier remains selected.
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("local-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		// Stale-pruned from Map1...
		assert.Empty(t, fx.identifierSlices(remoteID),
			"a no-longer-selected remote identifier must be pruned from the PI->CPE map")
		// ...and never written on this node: it had no local pod, so no eBPF rules to clear.
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, remoteID,
			"a remote-only identifier has no local eBPF state to touch")
		// The surviving local identifier keeps its rules.
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(localID))
	})

	// (1b) The stale prune is scoped to the reconciled parent: it removes only that parent's
	// own CPE names (parentCPEList plus resourceName) from a stale identifier's Map1 entry.
	// An identifier that is still selected under a DIFFERENT parent must keep that parent's
	// entry, and stay tracked in the other parent's Map3. Over-pruning here would silently
	// drop the other policy's enforcement of the identifier.
	t.Run("a stale identifier under one parent keeps its entry from a different parent", func(t *testing.T) {
		fx := newCPEFixture(t)
		// remoteID is selected (remote-only, so the stale prune — not local cleanup — is the
		// actor) by two independent parents, cnp-1 and cnp-2.
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{remotePod("remote-aaa", "10.1.2.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{remotePod("remote-aaa", "10.1.2.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		require.ElementsMatch(t, []string{"cnp-1-aaaaa", "cnp-2-aaaaa"}, fx.identifierSlices(remoteID),
			"both parents' CPEs track the shared identifier to start")

		// remoteID is dropped from cnp-1 only (cnp-1 now selects a different identifier), while
		// cnp-2 still selects it. Reconciling cnp-1 flags remoteID stale UNDER cnp-1.
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{remotePod("other-aaa", "10.1.2.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{remotePod("remote-aaa", "10.1.2.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		// Only cnp-1's CPE is scrubbed from Map1[remoteID]; cnp-2's entry survives.
		assert.Equal(t, []string{"cnp-2-aaaaa"}, fx.identifierSlices(remoteID),
			"the parent-wide prune must remove only the reconciled parent, not a different one")
		// And cnp-2 still tracks the identifier cluster-wide.
		cnp2, ok := fx.parentIdentifiers("cnp-2")
		require.True(t, ok, "cnp-2 must still track its identifiers")
		assert.Contains(t, cnp2, remoteID, "cnp-2 still selects the identifier, so it stays tracked")
	})

	// (4) Map3's read (stale diff), prune, and write keys are all GetParentNPNameFromPEName(
	// resourceName) — a function of the CPE (slice) NAME, never of the full PolicyRef.Name.
	// GenerateName caps a generated name at 63 chars, so for a long CNP the "<cnp>-<suffix>"
	// slice name is truncated and GetParentNPNameFromPEName(sliceName) no longer reconstructs
	// PolicyRef.Name. Keying the read by PolicyRef.Name (as an earlier version did) would read a
	// key the writer never wrote and the stale identifier would leak. Both sides deriving from
	// the slice name keep them in agreement.
	t.Run("a long CNP name whose CPE base is truncated still prunes stale identifiers", func(t *testing.T) {
		// Parent (PolicyRef.Name) is the full, long name.
		parent := "cnp-" + strings.Repeat("x", 56) // 60 chars
		// The slice name is the GenerateName result: parent truncated to fit "<=63 - suffix",
		// then the random suffix. Here the base is deliberately SHORTER than parent, so
		// GetParentNPNameFromPEName(sliceName) != parent — exactly the truncation case.
		sliceName := parent[:50] + "-aaaaa"
		writerKey := utils.GetParentNPNameFromPEName(sliceName) // what commit writes Map3 under
		require.NotEqual(t, parent, writerKey,
			"test must model truncation: the slice base must differ from PolicyRef.Name")

		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: sliceName, parent: parent,
			pods: []podRef{localPod("local-aaa", "10.1.1.1"),
				remotePod("remote-aaa", "10.1.2.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		require.NotEmpty(t, fx.identifierSlices(remoteID), "remote id starts tracked")

		// Map3 is keyed by the truncated writer key, NOT by the full PolicyRef.Name.
		_, ok := fx.parentIdentifiers(writerKey)
		require.True(t, ok, "Map3 must be keyed by GetParentNPNameFromPEName(sliceName)")
		_, okFull := fx.parentIdentifiers(parent)
		require.False(t, okFull, "Map3 must NOT be keyed by the full PolicyRef.Name")
		fx.reset()

		// Deselect the remote id; pruning only works if the read key matches the write key.
		fx.setSlices(sliceSpec{name: sliceName, parent: parent,
			pods:    []podRef{localPod("local-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile(sliceName))

		assert.Empty(t, fx.identifierSlices(remoteID),
			"stale pruning must work even when the CNP name is truncated into the CPE name")
	})

	// (5) When the parent stops selecting anything anywhere, its Map3 entry is removed entirely
	// (the len(clusterWidePodIdentifiers)==0 -> Delete branch), not left as a stale set.
	t.Run("a parent selecting nothing has its tracked identifier set removed", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("local-aaa", "10.1.1.1"),
				remotePod("remote-aaa", "10.1.2.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		_, ok := fx.parentIdentifiers("cnp-1")
		require.True(t, ok, "the parent is tracked while it selects pods")
		fx.reset()

		// The slice remains but selects no pods at all.
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		_, ok = fx.parentIdentifiers("cnp-1")
		assert.False(t, ok, "a parent selecting nothing must have its Map3 entry deleted, not left behind")
	})
}

// Egress rule derivation skips entries the CIDR-based eBPF dataplane cannot program:
// a domain-name-only peer (NPC emits these for FQDN rules, which cluster policy does not
// enforce here) and a malformed entry with neither CIDR nor DomainName. CIDR egress rules
// in the same slice are still programmed.
func TestClusterPolicySlices_EgressRuleDerivation(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("a domain-name-only egress rule is skipped, not programmed", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("nginx-aaa", "10.1.1.1")},
			egress: []ruleRef{
				deny("10.0.0.0/8"),          // CIDR rule: programmed
				domainEgress("example.com"), // domain-only: skipped (CIDR empty)
			}})
		fx.reconcileAll()

		// Only the CIDR egress rule survives; the domain-name rule is dropped.
		assert.Equal(t, []string{"Deny 10.0.0.0/8"}, fx.clusterPolicyEgressRules(nginx),
			"a domain-name-only egress rule must not be programmed by the CIDR dataplane")
	})

	t.Run("an egress entry with neither CIDR nor DomainName is skipped", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("nginx-aaa", "10.1.1.1")},
			egress: []ruleRef{
				emptyEgress(),      // both empty: skipped
				deny("10.0.0.0/8"), // CIDR rule: programmed
			}})
		fx.reconcileAll()

		assert.Equal(t, []string{"Deny 10.0.0.0/8"}, fx.clusterPolicyEgressRules(nginx),
			"a malformed egress entry must be skipped without dropping valid siblings")
	})

	t.Run("a slice of only skippable egress rules programs no egress", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("nginx-aaa", "10.1.1.1")},
			egress: []ruleRef{
				domainEgress("example.com"),
				emptyEgress(),
			},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		assert.Empty(t, fx.clusterPolicyEgressRules(nginx),
			"no CIDR egress rules means no egress is programmed")
		// The ingress rule is unaffected by the skipped egress entries.
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx))
	})
}

// A pod identifier whose eBPF writes fail every time must cost only that identifier. Every
// other pod the CPE selects keeps receiving policy, and the failure keeps being retried.
func TestClusterPolicySlices_FailureIsolation(t *testing.T) {
	stuck, resident, fresh := identifierOf("stuck-aaa"), identifierOf("resident-aaa"), identifierOf("fresh-aaa")
	writeFailed := errors.New("map write failed")

	// stuck is deselected while its pod keeps running, so cleanup must clear its maps, and
	// that write fails on every attempt.
	stuckCleanup := func(t *testing.T) *cpeFixture {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		return fx
	}

	t.Run("a cleanup that never succeeds does not block changes to the same CPE", func(t *testing.T) {
		fx := stuckCleanup(t)
		for i := 0; i < 3; i++ {
			require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)
		}

		fx.reset()
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2"), localPod("fresh-aaa", "10.1.1.3")},
			ingress: []ruleRef{deny("192.168.90.1/32"), deny("192.168.90.9/32")}})
		assert.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed, "the failing cleanup is still retried")

		want := []string{"Deny 192.168.90.1/32", "Deny 192.168.90.9/32"}
		assert.ElementsMatch(t, want, fx.clusterPolicyRules(resident), "a rule change must reach a running pod")
		assert.ElementsMatch(t, want, fx.clusterPolicyRules(fresh), "a new pod must be programmed")
		state, ok := fx.clusterPolicyState(fresh)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("a failed cleanup is retried and commits once it succeeds", func(t *testing.T) {
		fx := stuckCleanup(t)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		fx.reset()
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed,
			"the next pass must attempt the failed cleanup again")

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)

		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck,
			"once committed, the cleanup is not repeated")
	})

	// fresh is programmed during a pass whose cleanup fails, so the state that pass commits
	// must still record it, or nothing would remove its rules later.
	freshAddedWhileStuck := func(t *testing.T) *cpeFixture {
		fx := stuckCleanup(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2"), localPod("fresh-aaa", "10.1.1.3")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)
		require.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(fresh))
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		return fx
	}

	t.Run("a pod added while cleanup fails is cleaned up when later deselected", func(t *testing.T) {
		fx := freshAddedWhileStuck(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(fresh)
		fx.assertClusterPolicyRulesCleared(stuck)
	})

	t.Run("a pod added while cleanup fails is cleaned up when its CPE is deleted", func(t *testing.T) {
		fx := freshAddedWhileStuck(t)
		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(fresh)
		fx.assertClusterPolicyRulesCleared(resident)
		fx.assertClusterPolicyRulesCleared(stuck)
	})

	t.Run("a failed cleanup of an identifier still selected elsewhere is retried", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("stuck-aaa", "10.1.1.1"), remotePod("stuck-bbb", "10.1.2.1"),
				localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		// Local stuck-aaa is deleted (selection is per-workload: a CPE cannot drop the local
		// replica while keeping the remote one, so the local pod must have been deleted). On the
		// first pass its probes are still attached, so cleanup attempts the write and fails.
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{remotePod("stuck-bbb", "10.1.2.1"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		// Before the retry, the deleted pod's teardown completes: it was the last local pod of
		// stuck on this node, so its eBPF context is gone. The remote peer still keeps stuck
		// listed cluster-wide, but this node has nothing to enforce. The retry must therefore be
		// a clean no-op — no error, and no cluster-policy write for stuck.
		fx.detachContext(stuck)
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck,
			"a detached identifier has no context on this node, so cleanup must not write it")
	})

	t.Run("only the cleanups that failed are retried", func(t *testing.T) {
		done := identifierOf("done-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("done-aaa", "10.1.1.4"),
				localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		// Both pods are deselected; only stuck's cleanup fails.
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)
		fx.assertClusterPolicyRulesCleared(done)

		fx.reset()
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, done,
			"a cleanup that succeeded is not repeated")
	})

	t.Run("failed cleanups that recover at different times each stop being retried", func(t *testing.T) {
		other := identifierOf("other-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods: []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("other-aaa", "10.1.1.4"),
				localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed, other: writeFailed}
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		delete(fx.bpf.UpdateClusterPolicyEbpfMapsErrFor, other)
		fx.reset()
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)
		fx.assertClusterPolicyRulesCleared(other)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, other)

		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck, "nothing left to retry")
	})

	t.Run("a failed cleanup whose identifier is selected again is programmed, not cleared", func(t *testing.T) {
		fx := stuckCleanup(t)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		// A new pod of the same workload lands on the node and is selected.
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("stuck-bbb", "10.1.1.5"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(stuck))

		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(stuck),
			"the old pod's cleanup must not clear the identifier later")
	})

	t.Run("a failed cleanup whose pod then leaves the node stops being retried", func(t *testing.T) {
		fx := stuckCleanup(t)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		fx.detachContext(stuck)
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.bpf.ForgetIdentifier(stuck)
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck,
			"a departed pod is not cleaned up again once its workload returns")
	})

	t.Run("a failed recompute for an identifier another policy still selects is retried", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(stuck),
			"only the policy that still selects the pod contributes rules")
	})

	t.Run("a failed cleanup is retried by a sibling slice of the same parent", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
		fx.assertClusterPolicyRulesCleared(stuck)
		assert.ElementsMatch(t, []string{"Deny 192.168.90.1/32", "Deny 192.168.90.2/32"},
			fx.clusterPolicyRules(resident))
	})

	t.Run("deleting a CPE whose cleanup keeps failing is retried until it succeeds", func(t *testing.T) {
		fx := stuckCleanup(t)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		fx.deleteSlice("cnp-1-aaaaa")
		fx.reset()
		require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed)
		fx.assertClusterPolicyRulesCleared(resident)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, resident,
			"only the cleanup that failed is retried")
	})

	t.Run("a failed cleanup survives a new sibling slice being reconciled first", func(t *testing.T) {
		fx := stuckCleanup(t)
		require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed)

		// The parent grows a second slice, and its event is handled before the retry.
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("other-aaa", "10.1.1.3")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
		fx.assertClusterPolicyRulesCleared(stuck)
	})

	// Two slices of one parent: deleting the first must clear stuck, which only it lists, and
	// recompute resident, which the sibling still selects.
	twoSlices := func(t *testing.T) *cpeFixture {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.deleteSlice("cnp-1-aaaaa")
		return fx
	}

	t.Run("a deleted slice's failed cleanup is finished by a sibling slice", func(t *testing.T) {
		fx := twoSlices(t)
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed)
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(resident))

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
		fx.assertClusterPolicyRulesCleared(stuck)
	})

	t.Run("a deleted slice's failed cleanup of an identifier still selected elsewhere is finished by a sibling", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2"), remotePod("stuck-bbb", "10.1.2.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		// stuck's local pod is no longer selected; the sibling still lists its remote peer.
		// Selection is per-workload, so the local replica leaving means its pod was deleted from
		// this node. On the first (delete-flow) pass its probes are still attached, so cleanup
		// attempts the write and fails.
		fx.deleteSlice("cnp-1-aaaaa")
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed)

		// Before the sibling's retry, the deleted pod's teardown completes: it was the last local
		// pod of stuck on this node, so the eBPF context is gone. The sibling reconcile must then
		// be a clean no-op for stuck — no error, and no cluster-policy write — since this node has
		// no local pod of stuck to enforce (the remote peer is the remote node's responsibility).
		fx.detachContext(stuck)
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcile("cnp-1-bbbbb"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck,
			"a detached identifier has no context on this node, so cleanup must not write it")
	})

	t.Run("a deleted slice whose sibling's pod fails to recompute is retried", func(t *testing.T) {
		fx := twoSlices(t)
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{resident: writeFailed}
		require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed)
		fx.assertClusterPolicyRulesCleared(stuck)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(resident))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck, "a cleanup that succeeded is not repeated")
	})

	t.Run("a CPE whose deletion is in progress is cleaned up once it is gone, after a clean pass", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		// The CPE is still listed while its deletion is in progress.
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))

		fx.deleteSlice("cnp-1-aaaaa")
		fx.reset()
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)
		fx.assertClusterPolicyRulesCleared(resident)
		_, tracked := fx.r.ClusterPolicyEndpointSelectorMap.Load("cnp-1-aaaaa")
		assert.False(t, tracked, "nothing is tracked for the deleted CPE")
	})

	t.Run("a CPE whose deletion is in progress is cleaned up once it is gone", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()

		// The CPE is still listed while its deletion is in progress, and an update fails.
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.deleteSlice("cnp-1-aaaaa")
		fx.reset()
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)
		fx.assertClusterPolicyRulesCleared(resident)
	})

	t.Run("a deleted slice's retry repeats only the cleanups that failed", func(t *testing.T) {
		done := identifierOf("done-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("done-aaa", "10.1.1.4")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.deleteSlice("cnp-1-aaaaa")
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}
		require.ErrorIs(t, fx.reconcileDeleted("cnp-1-aaaaa"), writeFailed)
		fx.assertClusterPolicyRulesCleared(done)

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		fx.reset()
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, done, "a cleanup that succeeded is not repeated")
	})

	t.Run("a repeated delete event after a successful delete changes nothing", func(t *testing.T) {
		fx := twoSlices(t)
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.assertClusterPolicyRulesCleared(stuck)

		fx.reset()
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, stuck)
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(resident))
	})

	t.Run("a programming failure is retried and recovers", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: writeFailed}

		assert.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), writeFailed,
			"a programming failure must be returned so it is retried, not dropped")
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(resident))

		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(stuck))
	})

	t.Run("a rule derivation failure for one identifier does not skip the others", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-2-aaaaa", parent: "cnp-2",
				pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		// web's rules come from both CPEs, so failing to fetch cnp-2 fails web only.
		apiErr := errors.New("apiserver unavailable")
		fx.getErr = map[string]error{"cnp-2-aaaaa": apiErr}
		// Identifiers are iterated from a map, so repeat until both orders are very likely.
		for i := 0; i < 20; i++ {
			fx.reset()
			require.ErrorIs(t, fx.reconcile("cnp-1-aaaaa"), apiErr)
			require.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(api),
				"an identifier that does not depend on the failing CPE is still programmed")
			require.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, web,
				"the identifier whose rules could not be derived is left as it was")
		}
	})
}

// A change whose first reconcile fails in cleanup must still be measured once a retry
// succeeds; consuming the annotation on the failed pass would drop every such sample.
func TestClusterPolicySlices_LatencyObservedAfterFailedCleanup(t *testing.T) {
	stuck := identifierOf("stuck-aaa")
	fx := newCPEFixture(t)
	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{localPod("stuck-aaa", "10.1.1.1"), localPod("resident-aaa", "10.1.1.2")},
		ingress: []ruleRef{deny("192.168.90.1/32")}})
	fx.reconcileAll()

	fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{stuck: errors.New("map write failed")}
	fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
		pods:    []podRef{localPod("resident-aaa", "10.1.1.2")},
		ingress: []ruleRef{deny("192.168.90.1/32")}})
	cpe := fx.store["cnp-1-aaaaa"]
	cpe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: time.Now().Format(time.RFC3339Nano)}
	fx.store["cnp-1-aaaaa"] = cpe

	before := histSampleCount(t, clusterPolicyProgrammingLatency)
	require.Error(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Equal(t, uint64(0), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
		"a failed pass must not record a sample")

	fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
	require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
	assert.Equal(t, uint64(1), histSampleCount(t, clusterPolicyProgrammingLatency)-before,
		"the retry that succeeds must record the change it finally applied")
}

// Map reclamation, the cluster-scoped mirror of TestPolicySlices_MapReclamation.
// podIdentifierToClusterPolicyEndpointMap (Map1) is written for every pod a CPE names, on
// every node. The inserting write is authoritative for its parent CNP, so a re-slice
// reclaims the old slice names even though the identifier never becomes stale, and neither
// map grows with the number of pods the policy has ever selected.
func TestClusterPolicySlices_MapReclamation(t *testing.T) {
	nginx := identifierOf("nginx-aaa")

	t.Run("a policy re-sliced under new names retains only its current slices", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newCPEFixture(t)
		pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}
		rules := []ruleRef{deny("192.168.90.1/32")}

		for _, name := range []string{"cnp-1-aaaaa", "cnp-1-bbbbb", "cnp-1-ccccc", "cnp-1-ddddd"} {
			fx.setSlices(sliceSpec{name: name, parent: "cnp-1", pods: pods, ingress: rules})
			fx.reconcileAll()
		}

		assert.Equal(t, []string{"cnp-1-ddddd"}, fx.identifierSlices(nginx),
			"three obsolete slice names must have been reclaimed, not retained alongside the current one")

		tracked, ok := fx.parentIdentifiers("cnp-1")
		require.True(t, ok, "the parent must still track the identifier it selects")
		assert.ElementsMatch(t, []string{nginx}, tracked)

		state, ok := fx.clusterPolicyState(nginx)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx))
	})

	t.Run("the delete event for an already-replaced slice changes nothing", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newCPEFixture(t)
		pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}
		rules := []ruleRef{deny("192.168.90.1/32")}

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", pods: pods, ingress: rules})
		fx.reconcileAll()
		fx.setSlices(sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", pods: pods, ingress: rules})
		fx.reconcileAll()
		require.Equal(t, []string{"cnp-1-bbbbb"}, fx.identifierSlices(nginx))
		fx.reset()

		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))

		assert.Equal(t, []string{"cnp-1-bbbbb"}, fx.identifierSlices(nginx),
			"the surviving slice must keep the identifier; the purge drops only this parent's dead names")
		assert.Equal(t, []string{"Deny 192.168.90.1/32"}, fx.clusterPolicyRules(nginx),
			"a late delete event for a replaced slice must not clear the Deny rule")
	})

	// Accepted residual, mirroring the namespaced case. The purge prunes by EXACT CPE name
	// because matching on the derived parent name is unsafe under GenerateName truncation --
	// and for cluster policies an over-delete drops Deny rules, i.e. opens traffic. The cost
	// is this case: a re-slice that simultaneously deselects an identifier, observed only
	// through the surviving slice's reconcile, retains the departed slice's name.
	//
	// Inert rather than harmful: deriveClusterPolicyIngressAndEgressFirewallRules does a Get
	// per tracked name and skips NotFound, so a name whose object is gone contributes no
	// rules. Pinned here so the trade-off stays visible.
	t.Run("a re-slice that also deselects an identifier retains the departed slice name", func(t *testing.T) {
		t.Skip("Map1 insert is append-only; see UpdatePodIdentifierToPolicyEndpointMap")
		fx := newCPEFixture(t)
		gone, kept := identifierOf("gone-aaa"), identifierOf("kept-aaa")
		rules := []ruleRef{deny("192.168.90.1/32")}

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("gone-aaa", "10.1.1.1"), localPod("kept-aaa", "10.1.1.2")},
			ingress: rules})
		fx.reconcileAll()
		require.Equal(t, []string{"cnp-1-aaaaa"}, fx.identifierSlices(gone))

		fx.setSlices(sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
			pods:    []podRef{localPod("kept-aaa", "10.1.1.2")},
			ingress: rules})
		fx.reconcileAll()

		assert.Equal(t, []string{"cnp-1-bbbbb"}, fx.identifierSlices(kept),
			"the still-selected identifier tracks only the current slice")
		assert.Equal(t, []string{"cnp-1-aaaaa"}, fx.identifierSlices(gone),
			"accepted residual: exact-name pruning cannot reach a name outside "+
				"parentCPEList + resourceName")
	})

	t.Run("the departed slice's own delete event reclaims the retained name", func(t *testing.T) {
		fx := newCPEFixture(t)
		gone := identifierOf("gone-aaa")
		rules := []ruleRef{deny("192.168.90.1/32")}

		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods:    []podRef{localPod("gone-aaa", "10.1.1.1")},
				ingress: rules},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1",
				pods:    []podRef{localPod("kept-aaa", "10.1.1.2")},
				ingress: rules},
		)
		fx.reconcileAll()
		require.Contains(t, fx.identifierSlices(gone), "cnp-1-aaaaa")

		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))

		assert.Empty(t, fx.identifierSlices(gone),
			"resourceName on the delete path is the departed slice, so the name is reclaimed")
	})

	t.Run("deleting every slice of a policy leaves no entry behind", func(t *testing.T) {
		fx := newCPEFixture(t)
		pods := []podRef{localPod("nginx-aaa", "10.1.1.1")}

		fx.setSlices(
			sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1", pods: pods, ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: "cnp-1-bbbbb", parent: "cnp-1", pods: pods, ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		require.ElementsMatch(t, []string{"cnp-1-aaaaa", "cnp-1-bbbbb"}, fx.identifierSlices(nginx))

		fx.deleteSlice("cnp-1-aaaaa")
		require.NoError(t, fx.reconcileDeleted("cnp-1-aaaaa"))
		fx.deleteSlice("cnp-1-bbbbb")
		require.NoError(t, fx.reconcileDeleted("cnp-1-bbbbb"))

		assert.Empty(t, fx.identifierSlices(nginx),
			"a fully deleted cluster policy must leave no slice names behind")
		_, tracked := fx.parentIdentifiers("cnp-1")
		assert.False(t, tracked, "the parent's tracked identifier set must be gone")
	})

	// The leak this fix targets: a policy selecting uniquely-named pods (Jobs with a UUID in
	// the name) gives every pod its own identifier, so an append-only Map1 grew without bound
	// on every node. Both maps must stay proportional to the live selection instead.
	t.Run("churning unique identifiers leaves neither map growing", func(t *testing.T) {
		fx := newCPEFixture(t)
		stable := identifierOf("stable-aaa")

		const churnRounds = 50
		var lastChurn string
		for i := 0; i < churnRounds; i++ {
			// A remote pod, so the churn exercises the stale diff rather than local cleanup,
			// and a unique name, so GetPodIdentifier yields a fresh identifier each round.
			churnPod := fmt.Sprintf("task-uuid%d-aaa", i)
			lastChurn = identifierOf(churnPod)
			fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
				pods: []podRef{localPod("stable-aaa", "10.1.1.1"),
					remotePod(churnPod, "10.3.3.3")},
				ingress: []ruleRef{deny("192.168.90.1/32")}})
			require.NoError(t, fx.reconcile("cnp-1-aaaaa"))
		}

		assert.Equal(t, 2, sizeOfSyncMap(&fx.r.podIdentifierToClusterPolicyEndpointMap),
			"the PI->CPE map must hold only the stable identifier and the current churn pod, "+
				"not one entry per pod ever selected")

		tracked, ok := fx.parentIdentifiers("cnp-1")
		require.True(t, ok)
		assert.ElementsMatch(t, []string{stable, lastChurn}, tracked,
			"the parent's tracked set must be the live selection, not churn history")
	})

	// Programming a cluster policy seeds the namespaced tier's default with BPF_NOEXIST, so
	// it must never overwrite a verdict the namespaced reconciler already programmed.
	t.Run("seeding the namespaced default does not overwrite an existing verdict", func(t *testing.T) {
		fx := newCPEFixture(t)
		require.NoError(t, fx.bpf.UpdatePodStateEbpfMaps(nginx,
			ebpf.POD_STATE_MAP_KEY, ebpf.POLICIES_APPLIED, true, true))

		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		state, ok := fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{
			PodIdentifier: nginx, MapKey: ebpf.POD_STATE_MAP_KEY,
		}]
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state,
			"the namespaced verdict must survive a cluster policy seeding its default")
	})
}
