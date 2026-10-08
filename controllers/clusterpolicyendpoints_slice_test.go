package controllers

import (
	"errors"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("last local pod leaving with two parent policies does not wedge the reconcile", func(t *testing.T) {
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

	t.Run("last local pod leaving with one parent sliced in two does not wedge the reconcile", func(t *testing.T) {

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

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, web)
		state, ok := fx.clusterPolicyState(api)
		require.True(t, ok)
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
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
