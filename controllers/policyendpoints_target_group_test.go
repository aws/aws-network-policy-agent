package controllers

import (
	"context"
	"fmt"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func tgPorts(n int32) []policyk8sawsv1.Port {
	proto := corev1.ProtocolTCP
	v := n
	return []policyk8sawsv1.Port{{Protocol: &proto, Port: &v}}
}

// tgPod is a local pod. Its identifier is the name minus the last "-" segment, so "pa-1" and
// "pb-1" land in different identifiers and therefore different eBPF maps.
func tgPod(name, ip string) policyk8sawsv1.PodEndpoint {
	return policyk8sawsv1.PodEndpoint{HostIP: benchNodeIP, PodIP: policyk8sawsv1.NetworkAddress(ip), Name: name, Namespace: "ns"}
}

func tgPE(name, group string, pods []policyk8sawsv1.PodEndpoint, port int32) *policyk8sawsv1.PolicyEndpoint {
	pe := &policyk8sawsv1.PolicyEndpoint{}
	pe.Name, pe.Namespace = name, "ns"
	pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: "np", Namespace: "ns"}
	pe.Spec.TargetGroup = group
	pe.Spec.PodSelectorEndpoints = pods
	pe.Spec.Ingress = []policyk8sawsv1.EndpointInfo{{CIDR: "10.1.0.0/16", Ports: tgPorts(port)}}
	return pe
}

func tgPortsOf(t *testing.T, rules []fwrp.EbpfFirewallRules) []int32 {
	t.Helper()
	var out []int32
	for _, r := range rules {
		for _, p := range r.L4Info {
			require.NotNil(t, p.Port)
			out = append(out, *p.Port)
		}
	}
	return out
}

// deriveRules records policy np the way its reconcile does, then derives the rules for one
// podIdentifier the way a programming pass does.
func deriveRules(t *testing.T, pes map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint,
	podIdentifier string) []fwrp.EbpfFirewallRules {
	t.Helper()
	return deriveRulesAcrossNPs(t, pes, []string{"np"}, podIdentifier)
}

func TestDeriveFirewallRules_TargetGroups(t *testing.T) {
	podA := tgPod("pa-1", "172.16.0.1")
	podB := tgPod("pb-1", "172.16.0.2")

	t.Run("a pod only gets the rules of the group that lists it", func(t *testing.T) {
		pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
			{Namespace: "ns", Name: "np-aaaa"}: tgPE("np-aaaa", "g1", []policyk8sawsv1.PodEndpoint{podA}, 8080),
			{Namespace: "ns", Name: "np-bbbb"}: tgPE("np-bbbb", "g2", []policyk8sawsv1.PodEndpoint{podB}, 9090),
		}
		assert.Equal(t, []int32{8080}, tgPortsOf(t, deriveRules(t, pes, "pa@ns")))
		assert.Equal(t, []int32{9090}, tgPortsOf(t, deriveRules(t, pes, "pb@ns")))
	})

	t.Run("an ungrouped PolicyEndpoint applies to every pod", func(t *testing.T) {
		pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
			{Namespace: "ns", Name: "np-aaaa"}: tgPE("np-aaaa", "g1", []policyk8sawsv1.PodEndpoint{podA}, 8080),
			{Namespace: "ns", Name: "np-bbbb"}: tgPE("np-bbbb", "g2", []policyk8sawsv1.PodEndpoint{podB}, 9090),
			{Namespace: "ns", Name: "np-cccc"}: tgPE("np-cccc", "", []policyk8sawsv1.PodEndpoint{podA, podB}, 443),
		}
		assert.ElementsMatch(t, []int32{8080, 443}, tgPortsOf(t, deriveRules(t, pes, "pa@ns")))
		assert.ElementsMatch(t, []int32{9090, 443}, tgPortsOf(t, deriveRules(t, pes, "pb@ns")))
	})

	// An older controller sets no group, so every PolicyEndpoint of the policy applies to every
	// pod. This is the pre-grouping behaviour and must be untouched.
	t.Run("no groups anywhere keeps the union", func(t *testing.T) {
		pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
			{Namespace: "ns", Name: "np-aaaa"}: tgPE("np-aaaa", "", []policyk8sawsv1.PodEndpoint{podA, podB}, 8080),
			{Namespace: "ns", Name: "np-bbbb"}: tgPE("np-bbbb", "", []policyk8sawsv1.PodEndpoint{podA, podB}, 9090),
		}
		assert.ElementsMatch(t, []int32{8080, 9090}, tgPortsOf(t, deriveRules(t, pes, "pa@ns")))
	})

	// A group whose pods the controller has moved elsewhere must not reach this pod, even while
	// the podIdentifier map still references it.
	t.Run("a group that no longer lists the pod contributes nothing", func(t *testing.T) {
		pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
			{Namespace: "ns", Name: "np-aaaa"}: tgPE("np-aaaa", "g1", []policyk8sawsv1.PodEndpoint{podA}, 8080),
			{Namespace: "ns", Name: "np-bbbb"}: tgPE("np-bbbb", "g2", []policyk8sawsv1.PodEndpoint{podA, podB}, 9090),
		}
		// podA is in both groups here, so it legitimately gets both.
		assert.ElementsMatch(t, []int32{8080, 9090}, tgPortsOf(t, deriveRules(t, pes, "pa@ns")))

		// Drop podA from g2: its rules must stop applying to podA.
		pes[types.NamespacedName{Namespace: "ns", Name: "np-bbbb"}] = tgPE("np-bbbb", "g2", []policyk8sawsv1.PodEndpoint{podB}, 9090)
		assert.Equal(t, []int32{8080}, tgPortsOf(t, deriveRules(t, pes, "pa@ns")))
	})
}

// tgPEWith is tgPE with the parent policy and peer spelled out, for the cases that need more than
// one policy.
func tgPEWith(name, parent, group, cidr string, pods []policyk8sawsv1.PodEndpoint, port int32) *policyk8sawsv1.PolicyEndpoint {
	pe := tgPE(name, group, pods, port)
	pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: parent, Namespace: "ns"}
	pe.Spec.Ingress = []policyk8sawsv1.EndpointInfo{{CIDR: policyk8sawsv1.NetworkAddress(cidr), Ports: tgPorts(port)}}
	return pe
}

// tgPeerPortsOf reports the peer each port was allowed from, which is what separates a group
// admitted under the wrong policy from one the pod is entitled to: a colliding group key is a hash
// of the ports, so the ports match by construction and only the peer differs.
func tgPeerPortsOf(t *testing.T, rules []fwrp.EbpfFirewallRules) []string {
	t.Helper()
	var out []string
	for _, r := range rules {
		for _, p := range r.L4Info {
			require.NotNil(t, p.Port)
			out = append(out, fmt.Sprintf("%s:%d", r.IPCidr, *p.Port))
		}
	}
	return out
}

// deriveRulesAcrossNPs records every parent against one reconciler, the way a separate reconcile
// of each policy would, then derives one podIdentifier's rules the way a programming pass does.
func deriveRulesAcrossNPs(t *testing.T, pes map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint,
	parents []string, podIdentifier string) []fwrp.EbpfFirewallRules {
	t.Helper()
	r := recordPolicies(t, pes, parents)
	ingress, _, _, _, err := r.identifierFirewallRules(context.Background(), podIdentifier)
	require.NoError(t, err)
	return ingress
}

func recordPolicies(t *testing.T, pes map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint,
	parents []string) *PolicyEndpointsReconciler {
	t.Helper()
	r := newTestPolicyEndpointsReconciler(t, &cacheReader{pes: pes}, benchNodeIP, &ebpf.MockBpfClient{}, false)
	for _, parent := range parents {
		_, err := r.reconcileNetworkPolicy(context.Background(), "ns", parent)
		require.NoError(t, err)
	}
	return r
}

// A group key is a content hash of the resolved ports, so two policies selecting the same pods can
// mint the same key for different pods. Matching a group without its policy then lets one policy's
// group admit the other's, and the pod is reachable from a peer no policy allowed it.
func TestDeriveFirewallRules_TargetGroupsAreScopedPerPolicy(t *testing.T) {
	podA := tgPod("pa-1", "172.16.0.1")
	podB := tgPod("pb-1", "172.16.0.2")

	// npx allows 10.1.0.0/16 on a named port: podA resolves 8080, podB resolves 9999.
	// npy allows 10.2.0.0/16 on another: podA resolves 9999, podB resolves 7777.
	// So npy's group for podA and npx's group for podB are both the hash of {9999}.
	const shared = "k9999"
	pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
		{Namespace: "ns", Name: "npx-a"}: tgPEWith("npx-a", "npx", "k8080", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
		{Namespace: "ns", Name: "npx-b"}: tgPEWith("npx-b", "npx", shared, "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9999),
		{Namespace: "ns", Name: "npy-a"}: tgPEWith("npy-a", "npy", shared, "10.2.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 9999),
		{Namespace: "ns", Name: "npy-b"}: tgPEWith("npy-b", "npy", "k7777", "10.2.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 7777),
	}
	parents := []string{"npx", "npy"}

	assert.ElementsMatch(t, []string{"10.1.0.0/16:8080", "10.2.0.0/16:9999"},
		tgPeerPortsOf(t, deriveRulesAcrossNPs(t, pes, parents, "pa@ns")),
		"podA must get npx's group for podA and npy's group for podA, not npx's group for podB")

	assert.ElementsMatch(t, []string{"10.1.0.0/16:9999", "10.2.0.0/16:7777"},
		tgPeerPortsOf(t, deriveRulesAcrossNPs(t, pes, parents, "pb@ns")),
		"podB must get npx's group for podB and npy's group for podB, not npy's group for podA")
}

// The shape a split policy is emitted in: the rules that do not vary by pod ride in an ungrouped
// PolicyEndpoint that lists no pods of its own, since the groups already list them all. It reaches
// a pod through its parent's PE list, so it must still apply to every group.
func TestDeriveFirewallRules_UngroupedPolicyEndpointWithoutPods(t *testing.T) {
	podA := tgPod("pa-1", "172.16.0.1")
	podB := tgPod("pb-1", "172.16.0.2")

	pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
		{Namespace: "ns", Name: "np-aaaa"}: tgPEWith("np-aaaa", "np", "g1", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
		{Namespace: "ns", Name: "np-bbbb"}: tgPEWith("np-bbbb", "np", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9090),
		{Namespace: "ns", Name: "np-cccc"}: tgPEWith("np-cccc", "np", "", "10.3.0.0/16", nil, 443),
	}
	parents := []string{"np"}

	assert.ElementsMatch(t, []string{"10.1.0.0/16:8080", "10.3.0.0/16:443"},
		tgPeerPortsOf(t, deriveRulesAcrossNPs(t, pes, parents, "pa@ns")),
		"the shared rule must reach podA even though the ungrouped PolicyEndpoint lists no pods")
	assert.ElementsMatch(t, []string{"10.1.0.0/16:9090", "10.3.0.0/16:443"},
		tgPeerPortsOf(t, deriveRulesAcrossNPs(t, pes, parents, "pb@ns")),
		"the shared rule must reach podB too")
}

// The CNI ADD path derives a new pod's rules from the same PolicyEndpoints, so it applies the same
// groups.
func TestDeriveFireWallRulesPerPodIdentifier_TargetGroups(t *testing.T) {
	podA := tgPod("pa-1", "172.16.0.1")
	podB := tgPod("pb-1", "172.16.0.2")
	pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{
		{Namespace: "ns", Name: "np-aaaa"}: tgPE("np-aaaa", "g1", []policyk8sawsv1.PodEndpoint{podA}, 8080),
		{Namespace: "ns", Name: "np-bbbb"}: tgPE("np-bbbb", "g2", []policyk8sawsv1.PodEndpoint{podB}, 9090),
	}
	r := recordPolicies(t, pes, []string{"np"})

	ingress, _, _, err := r.DeriveFireWallRulesPerPodIdentifier("pa@ns", "ns")
	require.NoError(t, err)
	assert.Equal(t, []int32{8080}, tgPortsOf(t, ingress))
}
