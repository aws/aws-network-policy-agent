package fwruleprocessor

import (
	"fmt"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

// disjointExcepts returns n disjoint /24 excepts inside 10.0.0.0/8, starting
// at 10.1.0.0/24, so 10.0.0.0/24 stays outside every except.
func disjointExcepts(n int) []v1alpha1.NetworkAddress {
	out := make([]v1alpha1.NetworkAddress, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, v1alpha1.NetworkAddress(fmt.Sprintf("10.%d.%d.0/24", 1+(i+256)/256, i%256)))
	}
	return out
}

func exceptContributionFixture(n int) (*cidrTrie, map[string][]cidrContribution, []v1alpha1.NetworkAddress) {
	excepts := disjointExcepts(n)
	rule := rule(80, stringsOf(excepts)...)
	trie := newCIDRTrie()
	trie.insert("10.0.0.0/8")
	return trie, map[string][]cidrContribution{"10.0.0.0/8": {newCIDRContribution(rule)}}, excepts
}

func stringsOf(in []v1alpha1.NetworkAddress) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}

// The lookup must not parse CIDRs. Parsing a CIDR allocates, so with 4096
// excepts a lookup that reparsed them would allocate thousands of times.
func TestCheckAndDeriveL4Info_DoesNotParseExceptsPerLookup(t *testing.T) {
	trie, contributions, excepts := exceptContributionFixture(4096)

	for _, except := range excepts {
		_, ipNet, _ := net.ParseCIDR(string(except))
		assert.True(t, contributions["10.0.0.0/8"][0].inExcept(ipNet.IP), "except %s missing from the contribution's trie", except)
	}
	assert.Empty(t, checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(string(excepts[len(excepts)-1]), trie, contributions),
		"a target inside the rule's except must not inherit its ports")
	assert.NotEmpty(t, checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie("10.0.0.0/24", trie, contributions),
		"a target outside every except must inherit the rule's ports")

	allocs := testing.AllocsPerRun(5, func() {
		checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(string(excepts[len(excepts)-1]), trie, contributions)
	})
	assert.Less(t, allocs, 50.0, "lookup allocated like it was parsing the excepts (got %v allocs)", allocs)
}

// BenchmarkComputeMapEntries_ManyDisjointExcepts covers the except pass, which
// runs one lookup per unique except.
func BenchmarkComputeMapEntries_ManyDisjointExcepts(b *testing.B) {
	for _, n := range []int{256, 1024, 4096} {
		b.Run(fmt.Sprintf("excepts=%d", n), func(b *testing.B) {
			rules := []EbpfFirewallRules{{
				IPCidr: "10.0.0.0/8",
				Except: disjointExcepts(n),
				L4Info: rule(80).L4Info,
			}}
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
