package controllers

import (
	"context"
	"fmt"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cpeTGPod is a local pod. Its identifier is the name minus the last "-" segment, so "pa-1" and
// "pb-1" land in different identifiers and therefore different eBPF maps.
func cpeTGPod(name, ip string) policyk8sawsv1.PodEndpoint {
	return policyk8sawsv1.PodEndpoint{HostIP: benchNodeIP, PodIP: policyk8sawsv1.NetworkAddress(ip), Name: name, Namespace: "ns"}
}

// cpeTG builds a ClusterPolicyEndpoint of parent with one Accept ingress rule on cidr:port.
func cpeTG(name, parent, group, cidr string, pods []policyk8sawsv1.PodEndpoint, port int32) *policyk8sawsv1.ClusterPolicyEndpoint {
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{}
	cpe.Name = name
	cpe.Spec.PolicyRef = policyk8sawsv1.ClusterPolicyReference{Name: parent}
	cpe.Spec.Tier = policyk8sawsv1.AdminTier
	cpe.Spec.Priority = 10
	cpe.Spec.TargetGroup = group
	cpe.Spec.PodSelectorEndpoints = pods
	cpe.Spec.Ingress = []policyk8sawsv1.ClusterEndpointInfo{{
		CIDR:   policyk8sawsv1.NetworkAddress(cidr),
		Action: policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept,
		Ports:  tgPorts(port),
	}}
	return cpe
}

func cpeTGPortsOf(t *testing.T, rules []fwrp.EbpfFirewallRules) []int32 {
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

// cpeTGPeerPortsOf reports the peer each port was allowed from, which is what separates a group
// admitted under the wrong policy from one the pod is entitled to: a colliding group key is a hash
// of the ports, so the ports match by construction and only the peer differs.
func cpeTGPeerPortsOf(t *testing.T, rules []fwrp.EbpfFirewallRules) []string {
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

// deriveCPERules registers every parent against one reconciler, the way a separate reconcile of
// each policy would, then derives one podIdentifier from the accumulated map.
func deriveCPERules(t *testing.T, cpes map[string]*policyk8sawsv1.ClusterPolicyEndpoint,
	parents []string, podIdentifier string) []fwrp.EbpfFirewallRules {
	t.Helper()
	r := NewClusterPolicyEndpointsReconciler(&cacheReader{cpes: cpes}, benchNodeIP, nil)
	ctx := context.Background()
	for _, parent := range parents {
		_, _, _, _, _, err := r.deriveTargetPodsForParentCNP(ctx, parent, "")
		require.NoError(t, err)
	}
	ingress, _, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, "", false)
	require.NoError(t, err)
	return ingress
}

func TestDeriveClusterPolicyFirewallRules_TargetGroups(t *testing.T) {
	podA := cpeTGPod("pa-1", "172.16.0.1")
	podB := cpeTGPod("pb-1", "172.16.0.2")

	t.Run("a pod only gets the rules of the group that lists it", func(t *testing.T) {
		cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
			"cnp-aaaa": cpeTG("cnp-aaaa", "cnp", "g1", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
			"cnp-bbbb": cpeTG("cnp-bbbb", "cnp", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9090),
		}
		assert.Equal(t, []int32{8080}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pa@ns")))
		assert.Equal(t, []int32{9090}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pb@ns")))
	})

	t.Run("an ungrouped ClusterPolicyEndpoint applies to every pod", func(t *testing.T) {
		cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
			"cnp-aaaa": cpeTG("cnp-aaaa", "cnp", "g1", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
			"cnp-bbbb": cpeTG("cnp-bbbb", "cnp", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9090),
			"cnp-cccc": cpeTG("cnp-cccc", "cnp", "", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA, podB}, 443),
		}
		assert.ElementsMatch(t, []int32{8080, 443}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pa@ns")))
		assert.ElementsMatch(t, []int32{9090, 443}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pb@ns")))
	})

	// An older controller sets no group, so every ClusterPolicyEndpoint of the policy applies to
	// every pod. This is the pre-grouping behaviour and must be untouched.
	t.Run("no groups anywhere keeps the union", func(t *testing.T) {
		cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
			"cnp-aaaa": cpeTG("cnp-aaaa", "cnp", "", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA, podB}, 8080),
			"cnp-bbbb": cpeTG("cnp-bbbb", "cnp", "", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA, podB}, 9090),
		}
		assert.ElementsMatch(t, []int32{8080, 9090}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pa@ns")))
	})

	// A group whose pods the controller has moved elsewhere must not reach this pod, even while
	// the podIdentifier map still references it.
	t.Run("a group that no longer lists the pod contributes nothing", func(t *testing.T) {
		cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
			"cnp-aaaa": cpeTG("cnp-aaaa", "cnp", "g1", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
			"cnp-bbbb": cpeTG("cnp-bbbb", "cnp", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA, podB}, 9090),
		}
		// podA is in both groups here, so it legitimately gets both.
		assert.ElementsMatch(t, []int32{8080, 9090}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pa@ns")))

		// Drop podA from g2: its rules must stop applying to podA.
		cpes["cnp-bbbb"] = cpeTG("cnp-bbbb", "cnp", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9090)
		assert.Equal(t, []int32{8080}, cpeTGPortsOf(t, deriveCPERules(t, cpes, []string{"cnp"}, "pa@ns")))
	})
}

// A group key is a content hash of the resolved ports, so two policies selecting the same pods can
// mint the same key for different pods. Matching a group without its policy then lets one policy's
// group admit the other's, and the pod is reachable from a peer no policy allowed it.
func TestDeriveClusterPolicyFirewallRules_TargetGroupsAreScopedPerPolicy(t *testing.T) {
	podA := cpeTGPod("pa-1", "172.16.0.1")
	podB := cpeTGPod("pb-1", "172.16.0.2")

	// cnpx allows 10.1.0.0/16 on a named port: podA resolves 8080, podB resolves 9999.
	// cnpy allows 10.2.0.0/16 on another: podA resolves 9999, podB resolves 7777.
	// So cnpy's group for podA and cnpx's group for podB are both the hash of {9999}.
	const shared = "k9999"
	cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
		"cnpx-a": cpeTG("cnpx-a", "cnpx", "k8080", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
		"cnpx-b": cpeTG("cnpx-b", "cnpx", shared, "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9999),
		"cnpy-a": cpeTG("cnpy-a", "cnpy", shared, "10.2.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 9999),
		"cnpy-b": cpeTG("cnpy-b", "cnpy", "k7777", "10.2.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 7777),
	}
	parents := []string{"cnpx", "cnpy"}

	assert.ElementsMatch(t, []string{"10.1.0.0/16:8080", "10.2.0.0/16:9999"},
		cpeTGPeerPortsOf(t, deriveCPERules(t, cpes, parents, "pa@ns")),
		"podA must get cnpx's group for podA and cnpy's group for podA, not cnpx's group for podB")

	assert.ElementsMatch(t, []string{"10.1.0.0/16:9999", "10.2.0.0/16:7777"},
		cpeTGPeerPortsOf(t, deriveCPERules(t, cpes, parents, "pb@ns")),
		"podB must get cnpx's group for podB and cnpy's group for podB, not cnpy's group for podA")
}

// The shape a split policy is emitted in: the rules that do not vary by pod, and the egress, ride
// in an ungrouped ClusterPolicyEndpoint that lists no pods of its own, since the groups already
// list them all. It reaches a pod through its parent's CPE list, so it must still apply to every
// group.
func TestDeriveClusterPolicyFirewallRules_UngroupedWithoutPods(t *testing.T) {
	podA := cpeTGPod("pa-1", "172.16.0.1")
	podB := cpeTGPod("pb-1", "172.16.0.2")

	cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
		"cnp-aaaa": cpeTG("cnp-aaaa", "cnp", "g1", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
		"cnp-bbbb": cpeTG("cnp-bbbb", "cnp", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9090),
		"cnp-cccc": cpeTG("cnp-cccc", "cnp", "", "10.3.0.0/16", nil, 443),
	}
	parents := []string{"cnp"}

	assert.ElementsMatch(t, []string{"10.1.0.0/16:8080", "10.3.0.0/16:443"},
		cpeTGPeerPortsOf(t, deriveCPERules(t, cpes, parents, "pa@ns")),
		"the shared rule must reach podA even though the ungrouped CPE lists no pods")
	assert.ElementsMatch(t, []string{"10.1.0.0/16:9090", "10.3.0.0/16:443"},
		cpeTGPeerPortsOf(t, deriveCPERules(t, cpes, parents, "pb@ns")),
		"the shared rule must reach podB too")
}

// Splitting a policy's rules across ClusterPolicyEndpoints must not change precedence: tier and
// priority are properties of the policy and every object of it carries the same values, and each
// derived rule carries its own priority rather than taking it from the object's position.
func TestDeriveClusterPolicyFirewallRules_TargetGroupsKeepPriority(t *testing.T) {
	podA := cpeTGPod("pa-1", "172.16.0.1")
	podB := cpeTGPod("pb-1", "172.16.0.2")

	cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{
		"cnp-aaaa": cpeTG("cnp-aaaa", "cnp", "g1", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podA}, 8080),
		"cnp-bbbb": cpeTG("cnp-bbbb", "cnp", "g2", "10.1.0.0/16", []policyk8sawsv1.PodEndpoint{podB}, 9090),
	}
	// Baseline sorts after Admin, which the offset encodes in the rule rather than in the object.
	cpes["cnp-bbbb"].Spec.Tier = policyk8sawsv1.BaselineTier

	rules := deriveCPERules(t, cpes, []string{"cnp"}, "pa@ns")
	require.Len(t, rules, 1)
	assert.Equal(t, 10, rules[0].Priority)
	assert.Equal(t, policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept, rules[0].Action)

	rules = deriveCPERules(t, cpes, []string{"cnp"}, "pb@ns")
	require.Len(t, rules, 1)
	assert.Equal(t, 10+fwrp.BASELINE_TIER_PRIORITY_OFFSET, rules[0].Priority)
}
