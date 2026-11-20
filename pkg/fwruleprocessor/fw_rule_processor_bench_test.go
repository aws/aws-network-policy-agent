package fwruleprocessor

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	corev1 "k8s.io/api/core/v1"
)

func benchmarkRules() []EbpfFirewallRules {
	tcp := corev1.ProtocolTCP
	port := int32(9090)
	var rules []EbpfFirewallRules
	for i := 0; i < 290; i++ {
		rules = append(rules, EbpfFirewallRules{
			IPCidr: v1alpha1.NetworkAddress(fmt.Sprintf("10.%d.%d.%d", 1+i/65536, (i/256)%256, i%256)),
		})
	}
	for i := 0; i < 50; i++ {
		rules = append(rules, EbpfFirewallRules{
			IPCidr: v1alpha1.NetworkAddress(fmt.Sprintf("10.200.0.%d", i)),
			L4Info: []v1alpha1.Port{{Protocol: &tcp, Port: &port}},
		})
	}
	return rules
}

func BenchmarkComputeMapEntriesFromEndpointRules(b *testing.B) {
	logger.New("debug", filepath.Join(b.TempDir(), "agent.log"), 200, 1)
	f := NewFirewallRuleProcessor("192.168.0.1", "/32", false)
	rules := benchmarkRules()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := make([]EbpfFirewallRules, len(rules))
		copy(in, rules)
		if _, err := f.ComputeMapEntriesFromEndpointRules(in); err != nil {
			b.Fatal(err)
		}
	}
}
