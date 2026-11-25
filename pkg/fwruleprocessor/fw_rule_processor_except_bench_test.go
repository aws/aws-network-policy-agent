package fwruleprocessor

import (
	"fmt"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
)

// hostExcepts returns n disjoint /32 excepts, 10.0.0.0/32 upwards.
func hostExcepts(n int) []v1alpha1.NetworkAddress {
	out := make([]v1alpha1.NetworkAddress, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, v1alpha1.NetworkAddress(fmt.Sprintf("10.%d.%d.%d/32", i>>16&255, i>>8&255, i&255)))
	}
	return out
}

// BenchmarkComputeMapEntries_AllowAllWithHostExcepts is one 0.0.0.0/0 rule
// with N disjoint /32 excepts, the case reported on PR #767. Every except
// entry looks up the rule's excepts once, so the time per op should grow
// about linearly with N.
func BenchmarkComputeMapEntries_AllowAllWithHostExcepts(b *testing.B) {
	for _, n := range []int{1024, 4096, 16384} {
		b.Run(fmt.Sprintf("excepts=%d", n), func(b *testing.B) {
			rules := []EbpfFirewallRules{{IPCidr: "0.0.0.0/0", Except: hostExcepts(n)}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := NewFirewallRuleProcessor("192.168.0.1", "/32", false).
					ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules(nil), rules...)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
