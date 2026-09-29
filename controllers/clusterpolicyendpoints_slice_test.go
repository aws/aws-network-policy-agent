package controllers

import (
	"testing"

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
		t.Skip("known defect: cleanupClusterPolicyPod guards only its no-siblings branch, so any name " +
			"the scrub does not cover keeps the identifier entry alive and the map write fails on a " +
			"detached context. The error returns above commitClusterPolicyEndpointState and the " +
			"programming loop, so the stale set is re-derived and the reconcile cannot make progress")
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

	t.Run("a parent policy keeping one empty slice is not treated as having no slices", func(t *testing.T) {
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.reconcileAll()
		fx.reset()

		// The controller always retains at least one slice per policy, so "selects nothing"
		// arrives as an empty slice rather than as zero slices.
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1"})
		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		fx.assertClusterPolicyRulesCleared(nginx)
		fx.assertIdentifierAbsent(nginx)
		_, tracked := fx.parentIdentifiers("cnp-1")
		assert.False(t, tracked,
			"the parent selects nothing locally, so it must hold no identifiers")
		assert.Equal(t, []string{"cnp-1-aaaaa"}, fx.sliceNames(),
			"the empty slice still exists, so this is not the no-slices-left path")
	})

	t.Run("last local pod leaving with one parent sliced in two does not wedge the reconcile", func(t *testing.T) {
		t.Skip("known defect: the scrub removes only the slices this parent currently has, so a " +
			"slice already gone from the API server leaves its name behind and the identifier takes " +
			"the unguarded branch. One parent policy is enough; a second is not required")

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

		assertNoContextError(t, fx.reconcile("cnp-1-aaaaa"))

		state, ok := fx.clusterPolicyState(other)
		require.True(t, ok, "a newly scheduled workload must be programmed, not left unenforced")
		assert.Equal(t, ebpf.POLICIES_APPLIED, state)
	})

	t.Run("one identifier failing does not stop another from being programmed", func(t *testing.T) {
		web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-1-aaaaa", parent: "cnp-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.detachContext(web)

		require.NoError(t, fx.reconcile("cnp-1-aaaaa"))

		assert.NotContains(t, fx.bpf.ClusterPolicyIngressByIdentifier, web)
		state, ok := fx.clusterPolicyState(api)
		require.True(t, ok, "a programming failure on one identifier must not skip the rest")
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
		t.Skip("known defect: same unguarded branch as the reconcile path, reached with isDeleteFlow=true")
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

	t.Run("deleting one slice of a long-named parent keeps sibling rules", func(t *testing.T) {
		// GenerateName caps the base at 58 chars, so for a parent name that long the
		// slice name is a truncated prefix and no longer yields the parent name back.
		parent := "restrict-egress-from-payment-service-to-external-endpoints-prod"
		deleted := "restrict-egress-from-payment-service-to-external-endpointsabcde"
		sibling := "restrict-egress-from-payment-service-to-external-endpointsxyz12"

		t.Skip("known defect: cleanUpClusterPolicyEndpoint derives the parent from the slice name " +
			"while getClusterPolicyEndpointsOfParentCNP filters on Spec.PolicyRef.Name, so a truncated " +
			"name finds zero siblings and the delete flow clears rules the survivor still supplies")

		fx := newCPEFixture(t)
		fx.setSlices(
			sliceSpec{name: deleted, parent: parent,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.1/32")}},
			sliceSpec{name: sibling, parent: parent,
				pods:    []podRef{localPod("nginx-aaa", "10.1.1.1")},
				ingress: []ruleRef{deny("192.168.90.2/32")}},
		)
		fx.reconcileAll()
		fx.reset()

		fx.deleteSlice(deleted)
		require.NoError(t, fx.reconcileDeleted(deleted))

		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(nginx),
			"a truncated slice name must not cost the surviving sibling its rules")
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
