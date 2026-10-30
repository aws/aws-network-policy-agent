package controllers

import (
	"context"
	"errors"
	"maps"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// A slice name moves from alpha to beta when NPC deletes alpha's slice and creates one for beta
// with the same truncated GenerateName, and the agent sees both as one update. The handler then
// queues (name, alpha) and (name, beta); these tests drive those requests in every order.

func drain(q workqueue.TypedRateLimitingInterface[EndpointRequest]) []EndpointRequest {
	var out []EndpointRequest
	for q.Len() > 0 {
		req, _ := q.Get()
		out = append(out, req)
		q.Done(req)
	}
	return out
}

func TestEndpointEventHandler(t *testing.T) {
	pe := func(parent, rv string) *policyk8sawsv1.PolicyEndpoint {
		return &policyk8sawsv1.PolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: "np-aaaaa", Namespace: "ns", ResourceVersion: rv},
			Spec:       policyk8sawsv1.PolicyEndpointSpec{PolicyRef: policyk8sawsv1.PolicyReference{Name: parent, Namespace: "ns"}},
		}
	}
	key := types.NamespacedName{Name: "np-aaaaa", Namespace: "ns"}
	alpha, beta := EndpointRequest{Endpoint: key, Parent: "alpha"}, EndpointRequest{Endpoint: key, Parent: "beta"}
	h := endpointEventHandler(policyEndpointParent)
	newQueue := func() workqueue.TypedRateLimitingInterface[EndpointRequest] {
		return workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[EndpointRequest]())
	}

	t.Run("create, delete and generic events queue the object's parent", func(t *testing.T) {
		q := newQueue()
		defer q.ShutDown()
		h.Create(context.TODO(), event.TypedCreateEvent[*policyk8sawsv1.PolicyEndpoint]{Object: pe("alpha", "1")}, q)
		assert.Equal(t, []EndpointRequest{alpha}, drain(q))
		h.Delete(context.TODO(), event.TypedDeleteEvent[*policyk8sawsv1.PolicyEndpoint]{Object: pe("beta", "2")}, q)
		assert.Equal(t, []EndpointRequest{beta}, drain(q))
		h.Generic(context.TODO(), event.TypedGenericEvent[*policyk8sawsv1.PolicyEndpoint]{Object: pe("alpha", "3")}, q)
		assert.Equal(t, []EndpointRequest{alpha}, drain(q))
	})

	t.Run("an update under the same parent queues it once", func(t *testing.T) {
		q := newQueue()
		defer q.ShutDown()
		h.Update(context.TODO(), event.TypedUpdateEvent[*policyk8sawsv1.PolicyEndpoint]{ObjectOld: pe("alpha", "1"), ObjectNew: pe("alpha", "2")}, q)
		assert.Equal(t, []EndpointRequest{alpha}, drain(q))
	})

	t.Run("an update that changes the parent queues both", func(t *testing.T) {
		q := newQueue()
		defer q.ShutDown()
		h.Update(context.TODO(), event.TypedUpdateEvent[*policyk8sawsv1.PolicyEndpoint]{ObjectOld: pe("alpha", "1"), ObjectNew: pe("beta", "2")}, q)
		assert.ElementsMatch(t, []EndpointRequest{alpha, beta}, drain(q))
	})

	t.Run("cluster policy endpoints are keyed by name alone", func(t *testing.T) {
		q := newQueue()
		defer q.ShutDown()
		cpe := func(parent string) *policyk8sawsv1.ClusterPolicyEndpoint {
			return &policyk8sawsv1.ClusterPolicyEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "cnp-aaaaa"},
				Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: parent}}}
		}
		endpointEventHandler(clusterPolicyEndpointParent).Update(context.TODO(),
			event.TypedUpdateEvent[*policyk8sawsv1.ClusterPolicyEndpoint]{ObjectOld: cpe("alpha"), ObjectNew: cpe("beta")}, q)
		assert.ElementsMatch(t, []EndpointRequest{cpeRequest("cnp-aaaaa", "alpha"), cpeRequest("cnp-aaaaa", "beta")}, drain(q))
	})
}

// peReuse sets up alpha with the slice that gets reused (old-aaa) and a sibling that stays
// (z-aaa), and beta with a sibling (sib-aaa), then moves the reused name to beta (new-aaa).
type peReuse struct {
	fx                           *peFixture
	x, alphaSibling, betaSibling string
}

func (s peReuse) before() []sliceSpec {
	return []sliceSpec{
		{name: s.x, parent: reuseAlpha, pods: []podRef{localPod("old-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}},
		{name: s.alphaSibling, parent: reuseAlpha, pods: []podRef{localPod("z-aaa", "10.1.1.4")}, ingress: []ruleRef{allow("192.168.90.4/32")}},
		{name: s.betaSibling, parent: reuseBeta, pods: []podRef{localPod("sib-aaa", "10.1.1.3")}, ingress: []ruleRef{allow("192.168.90.3/32")}},
	}
}

func (s peReuse) after() []sliceSpec {
	specs := s.before()
	specs[0] = sliceSpec{name: s.x, parent: reuseBeta, pods: []podRef{localPod("new-aaa", "10.1.1.2")}, ingress: []ruleRef{allow("192.168.90.2/32")}}
	return specs
}

func newPEReuse(t *testing.T) peReuse {
	s := peReuse{fx: newPEFixture(t), x: generatedSliceName(reuseAlpha, "aaaaa"),
		alphaSibling: generatedSliceName(reuseAlpha, "zzzzz"), betaSibling: generatedSliceName(reuseBeta, "bbbbb")}
	require.Equal(t, s.x, generatedSliceName(reuseBeta, "aaaaa"), "both policies must generate the reused name")
	s.fx.setSlices(s.before()...)
	s.fx.reconcileAll()
	s.fx.setSlices(s.after()...)
	return s
}

// assertMoved checks the end state: alpha keeps only its sibling's rules, beta's pods get both of
// beta's slices, and nothing about the reused name is left under alpha.
func (s peReuse) assertMoved(t *testing.T) {
	t.Helper()
	fx := s.fx
	fx.assertRulesCleared(identifierOf("old-aaa"))
	state, _ := fx.podState(identifierOf("old-aaa"))
	assert.Equal(t, ebpf.DEFAULT_ALLOW, state, "the old pod returns to its baseline")
	assert.Equal(t, []string{"192.168.90.4/32"}, fx.ingressCIDRs(identifierOf("z-aaa")), "alpha's remaining slice is reprogrammed alone")
	for _, pod := range []string{"new-aaa", "sib-aaa"} {
		assert.ElementsMatch(t, []string{"192.168.90.2/32", "192.168.90.3/32"}, fx.ingressCIDRs(identifierOf(pod)), pod)
		state, _ := fx.podState(identifierOf(pod))
		assert.Equal(t, ebpf.POLICIES_APPLIED, state, pod)
		assert.Equal(t, refsOf(reuseBeta, s.x, s.betaSibling), fx.identifierRefs(identifierOf(pod)), pod)
	}
	assert.Equal(t, refsOf(reuseAlpha, s.alphaSibling), fx.identifierRefs(identifierOf("z-aaa")))
	fx.assertIdentifierAbsent(identifierOf("old-aaa"))
	_, tracked := fx.r.policyEndpointSelectorMap.Load(fx.request(s.x, reuseAlpha))
	assert.False(t, tracked, "nothing may stay recorded for the name under alpha")
	got, _ := fx.parentIdentifiers(reuseAlpha, fixtureNamespace)
	assert.Equal(t, []string{identifierOf("z-aaa")}, got)
}

func TestPolicyEndpointNameReuse_AnyOrder(t *testing.T) {
	for _, tt := range []struct {
		name  string
		order func(s peReuse) []EndpointRequest
	}{
		{"old parent first", func(s peReuse) []EndpointRequest {
			return []EndpointRequest{s.fx.request(s.x, reuseAlpha), s.fx.request(s.x, reuseBeta)}
		}},
		{"new parent first", func(s peReuse) []EndpointRequest {
			return []EndpointRequest{s.fx.request(s.x, reuseBeta), s.fx.request(s.x, reuseAlpha)}
		}},
		{"new parent's sibling first", func(s peReuse) []EndpointRequest {
			return []EndpointRequest{s.fx.request(s.betaSibling, reuseBeta), s.fx.request(s.x, reuseAlpha), s.fx.request(s.x, reuseBeta)}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newPEReuse(t)
			for _, req := range tt.order(s) {
				require.NoError(t, s.fx.r.reconcile(context.TODO(), req), "%v", req)
			}
			s.assertMoved(t)
		})
	}

	t.Run("the old parent's cleanup does not program the new parent", func(t *testing.T) {
		s := newPEReuse(t)
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseAlpha))
		assert.NotContains(t, s.fx.bpf.IngressByIdentifier, identifierOf("new-aaa"))
	})

	t.Run("before the old parent's cleanup, its pods derive rules without the reused name", func(t *testing.T) {
		s := newPEReuse(t)
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
		// z-aaa still records (x, alpha), but x now belongs to beta, so the CNI path must skip it
		ingress, _, err := s.fx.r.DeriveFireWallRulesPerPodIdentifier(identifierOf("z-aaa"), fixtureNamespace)
		require.NoError(t, err)
		assert.Equal(t, []string{"192.168.90.4/32"}, cidrsOf(ingress))
		assert.True(t, s.fx.r.ArePoliciesAvailableInLocalCache(identifierOf("old-aaa")), "the old pod stays tracked until its cleanup")
		ingress, _, err = s.fx.r.DeriveFireWallRulesPerPodIdentifier(identifierOf("old-aaa"), fixtureNamespace)
		require.NoError(t, err)
		assert.Equal(t, []string{"192.168.90.4/32"}, cidrsOf(ingress), "only alpha's live slice applies")
	})

	t.Run("repeating either request after the move changes nothing", func(t *testing.T) {
		s := newPEReuse(t)
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseAlpha))
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
		ingress := maps.Clone(s.fx.bpf.IngressByIdentifier)
		for range 2 {
			require.NoError(t, s.fx.reconcileUnder(s.x, reuseAlpha))
			require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
		}
		assert.Equal(t, ingress, s.fx.bpf.IngressByIdentifier)
		s.assertMoved(t)
	})
}

func TestPolicyEndpointNameReuse_CleanupRetry(t *testing.T) {
	writeFailed := errors.New("injected map write failure")
	oldPod := identifierOf("old-aaa")

	t.Run("a failed cleanup retried after the new parent reconciles keeps the new parent's state", func(t *testing.T) {
		s := newPEReuse(t)
		s.fx.bpf.UpdateEbpfMapsErrFor = map[string]error{oldPod: writeFailed}
		require.ErrorIs(t, s.fx.reconcileUnder(s.x, reuseAlpha), writeFailed)
		pods, tracked := s.fx.r.policyEndpointSelectorMap.Load(s.fx.request(s.x, reuseAlpha))
		require.True(t, tracked, "the failed pod must stay tracked for the retry")
		assert.Len(t, pods, 1)

		s.fx.bpf.UpdateEbpfMapsErrFor = nil
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseAlpha))
		s.assertMoved(t)
		_, tracked = s.fx.r.policyEndpointSelectorMap.Load(s.fx.request(s.x, reuseBeta))
		assert.True(t, tracked, "the retry must not drop the new parent's tracking")
	})

	t.Run("a cleanup that keeps failing does not block the new parent", func(t *testing.T) {
		s := newPEReuse(t)
		s.fx.bpf.UpdateEbpfMapsErrFor = map[string]error{oldPod: writeFailed}
		for range 3 {
			require.ErrorIs(t, s.fx.reconcileUnder(s.x, reuseAlpha), writeFailed)
		}
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
		assert.ElementsMatch(t, []string{"192.168.90.2/32", "192.168.90.3/32"}, s.fx.ingressCIDRs(identifierOf("new-aaa")))

		s.fx.bpf.UpdateEbpfMapsErrFor = nil
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseAlpha))
		s.assertMoved(t)
	})
}

func TestPolicyEndpointNameReuse_SharedPod(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	shared := identifierOf("shared-aaa")
	for _, betaFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "old parent first", true: "new parent first"}[betaFirst], func(t *testing.T) {
			fx := newPEFixture(t)
			fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("shared-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
			fx.reconcileAll()
			fx.setSlices(sliceSpec{name: x, parent: reuseBeta, pods: []podRef{localPod("shared-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.2/32")}})
			order := []string{reuseAlpha, reuseBeta}
			if betaFirst {
				order = []string{reuseBeta, reuseAlpha}
			}
			for _, parent := range order {
				require.NoError(t, fx.reconcileUnder(x, parent))
			}

			assert.Equal(t, []string{"192.168.90.2/32"}, fx.ingressCIDRs(shared), "only the new parent's rules apply")
			state, _ := fx.podState(shared)
			assert.Equal(t, ebpf.POLICIES_APPLIED, state)
			assert.Equal(t, refsOf(reuseBeta, x), fx.identifierRefs(shared))
		})
	}
}

func TestPolicyEndpointNameReuse_MovesBack(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	for _, alphaFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "beta request first", true: "alpha request first"}[alphaFirst], func(t *testing.T) {
			fx := newPEFixture(t)
			fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("old-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
			fx.reconcileAll()
			// alpha -> beta -> alpha before the agent catches up: both parents are queued once
			fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("new-aaa", "10.1.1.2")}, ingress: []ruleRef{allow("192.168.90.3/32")}})
			order := []string{reuseBeta, reuseAlpha}
			if alphaFirst {
				order = []string{reuseAlpha, reuseBeta}
			}
			for _, parent := range order {
				require.NoError(t, fx.reconcileUnder(x, parent))
			}

			fx.assertRulesCleared(identifierOf("old-aaa"))
			assert.Equal(t, []string{"192.168.90.3/32"}, fx.ingressCIDRs(identifierOf("new-aaa")))
			assert.Equal(t, refsOf(reuseAlpha, x), fx.identifierRefs(identifierOf("new-aaa")))
			_, tracked := fx.r.policyEndpointSelectorMap.Load(fx.request(x, reuseBeta))
			assert.False(t, tracked)
		})
	}
}

func TestPolicyEndpointReconcile_RoutesByRequestParent(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("old-aaa", "10.1.1.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}})
	fx.reconcileAll()

	t.Run("a request for a parent that never owned the slice is a no-op", func(t *testing.T) {
		fx.reset()
		require.NoError(t, fx.reconcileUnder(x, "unrelated"))
		assert.Empty(t, fx.bpf.CallLog)
		assert.Equal(t, refsOf(reuseAlpha, x), fx.identifierRefs(identifierOf("old-aaa")))
	})

}

// cpeReuse is the cluster policy counterpart of peReuse, with Deny rules.
type cpeReuse struct {
	fx                           *cpeFixture
	x, alphaSibling, betaSibling string
}

func newCPEReuse(t *testing.T) cpeReuse {
	s := cpeReuse{fx: newCPEFixture(t), x: generatedSliceName(reuseAlpha, "aaaaa"),
		alphaSibling: generatedSliceName(reuseAlpha, "zzzzz"), betaSibling: generatedSliceName(reuseBeta, "bbbbb")}
	alphaSib := sliceSpec{name: s.alphaSibling, parent: reuseAlpha, pods: []podRef{localPod("z-aaa", "10.1.1.4")}, ingress: []ruleRef{deny("192.168.90.4/32")}}
	betaSib := sliceSpec{name: s.betaSibling, parent: reuseBeta, pods: []podRef{localPod("sib-aaa", "10.1.1.3")}, ingress: []ruleRef{deny("192.168.90.3/32")}}
	s.fx.setSlices(sliceSpec{name: s.x, parent: reuseAlpha, pods: []podRef{localPod("old-aaa", "10.1.1.1")}, ingress: []ruleRef{deny("192.168.90.1/32")}}, alphaSib, betaSib)
	s.fx.reconcileAll()
	s.fx.setSlices(sliceSpec{name: s.x, parent: reuseBeta, pods: []podRef{localPod("new-aaa", "10.1.1.2")}, ingress: []ruleRef{deny("192.168.90.2/32")}}, alphaSib, betaSib)
	return s
}

func (s cpeReuse) assertMoved(t *testing.T) {
	t.Helper()
	fx := s.fx
	fx.assertClusterPolicyRulesCleared(identifierOf("old-aaa"))
	state, _ := fx.clusterPolicyState(identifierOf("old-aaa"))
	assert.Equal(t, ebpf.DEFAULT_ALLOW, state)
	assert.Equal(t, []string{"Deny 192.168.90.4/32"}, fx.clusterPolicyRules(identifierOf("z-aaa")), "alpha's remaining slice is reprogrammed alone")
	for _, pod := range []string{"new-aaa", "sib-aaa"} {
		assert.ElementsMatch(t, []string{"Deny 192.168.90.2/32", "Deny 192.168.90.3/32"}, fx.clusterPolicyRules(identifierOf(pod)), pod)
		assert.Equal(t, refsOf(reuseBeta, s.x, s.betaSibling), fx.identifierRefs(identifierOf(pod)), pod)
	}
	fx.assertIdentifierAbsent(identifierOf("old-aaa"))
	_, tracked := fx.r.ClusterPolicyEndpointSelectorMap.Load(cpeRequest(s.x, reuseAlpha))
	assert.False(t, tracked, "nothing may stay recorded for the name under alpha")
	got, _ := fx.parentIdentifiers(reuseAlpha)
	assert.Equal(t, []string{identifierOf("z-aaa")}, got)
}

func TestClusterPolicyEndpointNameReuse_AnyOrder(t *testing.T) {
	for _, tt := range []struct {
		name  string
		order func(s cpeReuse) []EndpointRequest
	}{
		{"old parent first", func(s cpeReuse) []EndpointRequest {
			return []EndpointRequest{cpeRequest(s.x, reuseAlpha), cpeRequest(s.x, reuseBeta)}
		}},
		{"new parent first", func(s cpeReuse) []EndpointRequest {
			return []EndpointRequest{cpeRequest(s.x, reuseBeta), cpeRequest(s.x, reuseAlpha)}
		}},
		{"new parent's sibling first", func(s cpeReuse) []EndpointRequest {
			return []EndpointRequest{cpeRequest(s.betaSibling, reuseBeta), cpeRequest(s.x, reuseAlpha), cpeRequest(s.x, reuseBeta)}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newCPEReuse(t)
			for _, req := range tt.order(s) {
				require.NoError(t, s.fx.r.reconcile(context.TODO(), req), "%v", req)
			}
			s.assertMoved(t)
		})
	}

	t.Run("before the old parent's cleanup, its pods derive rules without the reused name", func(t *testing.T) {
		s := newCPEReuse(t)
		require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
		ingress, _, err := s.fx.r.DeriveClusterPolicyFireWallRulesPerPodIdentifier(context.TODO(), identifierOf("z-aaa"))
		require.NoError(t, err)
		assert.Equal(t, []string{"Deny 192.168.90.4/32"}, actionCIDRsOf(ingress))
	})
}

func TestClusterPolicyEndpointNameReuse_CleanupRetry(t *testing.T) {
	writeFailed := errors.New("injected map write failure")
	s := newCPEReuse(t)
	s.fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{identifierOf("old-aaa"): writeFailed}
	require.ErrorIs(t, s.fx.reconcileUnder(s.x, reuseAlpha), writeFailed)
	_, tracked := s.fx.r.ClusterPolicyEndpointSelectorMap.Load(cpeRequest(s.x, reuseAlpha))
	require.True(t, tracked, "the failed pod must stay tracked for the retry")

	s.fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = nil
	require.NoError(t, s.fx.reconcileUnder(s.x, reuseBeta))
	require.NoError(t, s.fx.reconcileUnder(s.x, reuseAlpha))
	s.assertMoved(t)
	_, tracked = s.fx.r.ClusterPolicyEndpointSelectorMap.Load(cpeRequest(s.x, reuseBeta))
	assert.True(t, tracked, "the retry must not drop the new parent's tracking")
}

func TestClusterPolicyEndpointNameReuse_SharedPodKeepsOnlyNewDeny(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	shared := identifierOf("shared-aaa")
	for _, betaFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "old parent first", true: "new parent first"}[betaFirst], func(t *testing.T) {
			fx := newCPEFixture(t)
			fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("shared-aaa", "10.1.1.1")}, ingress: []ruleRef{deny("192.168.90.1/32")}})
			fx.reconcileAll()
			fx.setSlices(sliceSpec{name: x, parent: reuseBeta, pods: []podRef{localPod("shared-aaa", "10.1.1.1")}, ingress: []ruleRef{deny("192.168.90.2/32")}})
			order := []string{reuseAlpha, reuseBeta}
			if betaFirst {
				order = []string{reuseBeta, reuseAlpha}
			}
			for _, parent := range order {
				require.NoError(t, fx.reconcileUnder(x, parent))
			}
			assert.Equal(t, []string{"Deny 192.168.90.2/32"}, fx.clusterPolicyRules(shared))
			assert.Equal(t, refsOf(reuseBeta, x), fx.identifierRefs(shared))
		})
	}
}

// A name that moves away from alpha and back must not revive alpha's entries on a pod alpha
// stopped selecting while the name was away (found by TestClusterPolicySlices_Randomized seed 3109).
// The pod is remote while alpha drops it, so only stale pruning can clear it.
func TestClusterPolicyEndpointNameReuse_MovingBackDoesNotReviveStaleEntries(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	z, g := generatedSliceName(reuseAlpha, "zzzzz"), "gamma-ggggg"
	wd := identifierOf("wd-aaa")
	gamma := func(pod podRef) sliceSpec {
		return sliceSpec{name: g, parent: "gamma", pods: []podRef{pod}, ingress: []ruleRef{allow("192.168.90.9/32")}}
	}
	alphaZ := sliceSpec{name: z, parent: reuseAlpha, pods: []podRef{localPod("l2-aaa", "10.1.1.2")}, ingress: []ruleRef{deny("192.168.90.4/32")}}

	fx := newCPEFixture(t)
	fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{remotePod("wd-aaa", "10.1.2.1")}, ingress: []ruleRef{deny("192.168.90.1/32")}},
		alphaZ, gamma(remotePod("wd-aaa", "10.1.2.1")))
	fx.reconcileAll()

	// x moves to beta; alpha's sibling reconciles first and finds wd stale
	fx.setSlices(sliceSpec{name: x, parent: reuseBeta, pods: []podRef{localPod("l3-aaa", "10.1.1.3")}, ingress: []ruleRef{deny("192.168.90.2/32")}},
		alphaZ, gamma(remotePod("wd-aaa", "10.1.2.1")))
	require.NoError(t, fx.reconcileUnder(z, reuseAlpha))
	require.NoError(t, fx.reconcileUnder(x, reuseAlpha))
	require.NoError(t, fx.reconcileUnder(x, reuseBeta))
	assert.Equal(t, refsOf("gamma", g), fx.identifierRefs(wd), "alpha no longer selects wd")

	// x moves back to alpha, still not selecting wd, then wd's pod lands on this node
	fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("l4-aaa", "10.1.1.4")}, ingress: []ruleRef{deny("192.168.90.3/32")}},
		alphaZ, gamma(localPod("wd-aaa", "10.1.2.1")))
	require.NoError(t, fx.reconcileUnder(x, reuseBeta))
	require.NoError(t, fx.reconcileUnder(x, reuseAlpha))
	require.NoError(t, fx.reconcileUnder(g, "gamma"))

	assert.Equal(t, []string{"Accept 192.168.90.9/32"}, fx.clusterPolicyRules(wd), "only gamma selects wd")
	assert.Equal(t, refsOf("gamma", g), fx.identifierRefs(wd))
}

func TestPolicyEndpointNameReuse_MovingBackDoesNotReviveStaleEntries(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	z, g := generatedSliceName(reuseAlpha, "zzzzz"), "gamma-ggggg"
	wd := identifierOf("wd-aaa")
	gamma := func(pod podRef) sliceSpec {
		return sliceSpec{name: g, parent: "gamma", pods: []podRef{pod}, ingress: []ruleRef{allow("192.168.90.9/32")}}
	}
	alphaZ := sliceSpec{name: z, parent: reuseAlpha, pods: []podRef{localPod("l2-aaa", "10.1.1.2")}, ingress: []ruleRef{allow("192.168.90.4/32")}}

	fx := newPEFixture(t)
	fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{remotePod("wd-aaa", "10.1.2.1")}, ingress: []ruleRef{allow("192.168.90.1/32")}},
		alphaZ, gamma(remotePod("wd-aaa", "10.1.2.1")))
	fx.reconcileAll()

	fx.setSlices(sliceSpec{name: x, parent: reuseBeta, pods: []podRef{localPod("l3-aaa", "10.1.1.3")}, ingress: []ruleRef{allow("192.168.90.2/32")}},
		alphaZ, gamma(remotePod("wd-aaa", "10.1.2.1")))
	require.NoError(t, fx.reconcileUnder(z, reuseAlpha))
	require.NoError(t, fx.reconcileUnder(x, reuseAlpha))
	require.NoError(t, fx.reconcileUnder(x, reuseBeta))
	assert.Equal(t, refsOf("gamma", g), fx.identifierRefs(wd), "alpha no longer selects wd")

	fx.setSlices(sliceSpec{name: x, parent: reuseAlpha, pods: []podRef{localPod("l4-aaa", "10.1.1.4")}, ingress: []ruleRef{allow("192.168.90.3/32")}},
		alphaZ, gamma(localPod("wd-aaa", "10.1.2.1")))
	require.NoError(t, fx.reconcileUnder(x, reuseBeta))
	require.NoError(t, fx.reconcileUnder(x, reuseAlpha))
	require.NoError(t, fx.reconcileUnder(g, "gamma"))

	assert.Equal(t, []string{"192.168.90.9/32"}, fx.ingressCIDRs(wd), "only gamma selects wd")
	assert.Equal(t, refsOf("gamma", g), fx.identifierRefs(wd))
}
