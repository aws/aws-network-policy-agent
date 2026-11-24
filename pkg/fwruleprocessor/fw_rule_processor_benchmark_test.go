package fwruleprocessor

import (
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	corev1 "k8s.io/api/core/v1"
)

// peerPodRules builds the shape the controller hands to compilation for a
// policy whose peer is a podSelector/namespaceSelector: the control plane
// resolves the selector to one /32 rule per peer pod.
func peerPodRules(n int, port int32) []EbpfFirewallRules {
	rules := make([]EbpfFirewallRules, 0, n)
	for i := range n {
		rules = append(rules, EbpfFirewallRules{
			IPCidr: v1alpha1.NetworkAddress(fmt.Sprintf("10.1.%d.%d/32", i/250, i%250+1)),
			L4Info: []v1alpha1.Port{{Protocol: new(corev1.ProtocolTCP), Port: new(port)}},
			Action: v1alpha1.ClusterNetworkPolicyRuleActionAccept,
		})
	}
	return rules
}

// exceptList builds n /32 excepts, the shape a large ipBlock except list
// (for example one generated from a managed prefix list) takes in a
// PolicyEndpoint.
func exceptList(n int) []v1alpha1.NetworkAddress {
	excepts := make([]v1alpha1.NetworkAddress, 0, n)
	for i := range n {
		excepts = append(excepts, v1alpha1.NetworkAddress(fmt.Sprintf("100.64.%d.%d/32", i/250, i%250+1)))
	}
	return excepts
}

// BenchmarkFirewallRuleCompilation measures ComputeMapEntriesFromEndpointRules
// and ComputeClusterPolicyMapEntriesFromEndpointRules on rule sets shaped like
// real policies:
//
//   - peer-pods-300: ingress from a selector matching 300 pods. Every
//     NetworkPolicy with a pod/namespaceSelector peer compiles this shape; the
//     rule count tracks the number of peer pods, not the policy text.
//   - large-except-6600: one ipBlock whose except list holds 6,600 /32s.
//     Recompiled for every pod event in the namespace.
//   - large-except-6600-with-peers: the previous two combined. Every peer /32
//     falls inside 0.0.0.0/0, so port inheritance scans the except list once
//     per peer pod.
func BenchmarkFirewallRuleCompilation(b *testing.B) {
	logger.New("error", "/dev/null", 200, 1)

	scenarios := []struct {
		name  string
		rules []EbpfFirewallRules
	}{
		{"peer-pods-300", peerPodRules(300, 80)},
		{"large-except-6600", []EbpfFirewallRules{{
			IPCidr: "0.0.0.0/0",
			Except: exceptList(6600),
			L4Info: []v1alpha1.Port{{Protocol: new(corev1.ProtocolTCP), Port: new(int32(443))}},
			Action: v1alpha1.ClusterNetworkPolicyRuleActionAccept,
		}}},
		{"large-except-6600-with-peers", append(peerPodRules(300, 80), EbpfFirewallRules{
			IPCidr: "0.0.0.0/0",
			Except: exceptList(6600),
			L4Info: []v1alpha1.Port{{Protocol: new(corev1.ProtocolTCP), Port: new(int32(443))}},
			Action: v1alpha1.ClusterNetworkPolicyRuleActionAccept,
		})},
	}

	processor := NewFirewallRuleProcessor("192.168.1.1", "/32", false)
	for _, scenario := range scenarios {
		for name, compile := range map[string]func([]EbpfFirewallRules) (map[string][]byte, error){
			"NetworkPolicy":        processor.ComputeMapEntriesFromEndpointRules,
			"ClusterNetworkPolicy": processor.ComputeClusterPolicyMapEntriesFromEndpointRules,
		} {
			b.Run(scenario.name+"/"+name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := compile(slices.Clone(scenario.rules)); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
