package fwruleprocessor

import (
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	corev1 "k8s.io/api/core/v1"
)

func BenchmarkFirewallRuleCompilation(b *testing.B) {
	logger.New("error", "/dev/null", 200, 1)
	rules := []EbpfFirewallRules{{
		IPCidr: "10.0.0.0/8",
		Except: []v1alpha1.NetworkAddress{"10.2.0.0/16"},
		L4Info: []v1alpha1.Port{{Protocol: new(corev1.ProtocolTCP), Port: new(int32(443))}},
		Action: v1alpha1.ClusterNetworkPolicyRuleActionAccept,
	}}
	for i := range 100 {
		rules = append(rules, EbpfFirewallRules{
			IPCidr: v1alpha1.NetworkAddress(fmt.Sprintf("10.1.0.%d/32", i+1)),
			L4Info: []v1alpha1.Port{{Protocol: new(corev1.ProtocolTCP), Port: new(int32(80))}},
			Action: v1alpha1.ClusterNetworkPolicyRuleActionAccept,
		})
	}
	processor := NewFirewallRuleProcessor("192.168.1.1", "/32", false)
	for name, compile := range map[string]func([]EbpfFirewallRules) (map[string][]byte, error){
		"NetworkPolicy":        processor.ComputeMapEntriesFromEndpointRules,
		"ClusterNetworkPolicy": processor.ComputeClusterPolicyMapEntriesFromEndpointRules,
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := compile(slices.Clone(rules)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
