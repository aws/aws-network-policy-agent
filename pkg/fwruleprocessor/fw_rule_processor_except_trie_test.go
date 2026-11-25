package fwruleprocessor

import (
	"fmt"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// TestComputeMapEntries_ExceptLookupIsATrieWalk counts the work the except
// pass does through exceptLookupHook. Each except entry must be checked with
// one lookup that visits at most 33 trie nodes (one per IPv4 bit plus the
// root), so the total stays linear in the number of excepts. A scan of the
// rule's except list would not report through the hook and fails the count.
func TestComputeMapEntries_ExceptLookupIsATrieWalk(t *testing.T) {
	for _, n := range []int{1024, 16384} {
		t.Run(fmt.Sprintf("excepts=%d", n), func(t *testing.T) {
			var lookups, visited, maxVisited int
			exceptLookupHook = func(v int) {
				lookups++
				visited += v
				maxVisited = max(maxVisited, v)
			}
			defer func() { exceptLookupHook = nil }()

			got, err := NewFirewallRuleProcessor("192.168.0.1", "/32", false).
				ComputeMapEntriesFromEndpointRules([]EbpfFirewallRules{{IPCidr: "0.0.0.0/0", Except: hostExcepts(n)}})
			assert.NoError(t, err)
			// node IP, 0.0.0.0/0 and one deny entry per except
			assert.Len(t, got, n+2)
			assert.Equal(t, n, lookups, "want one except lookup per except entry")
			assert.LessOrEqual(t, maxVisited, 33, "an except lookup walked more nodes than an IPv4 address has bits")
			assert.LessOrEqual(t, visited, 33*n, "except lookups did more than linear work")
		})
	}
}

// TestComputeMapEntries_AllowAllAlongsideExcept covers one policy that allows
// all egress next to a second policy that allows 0.0.0.0/0 (or ::/0) except a
// few hosts. An except only narrows the rule that declared it, so the excepted
// hosts stay reachable through the allow-all policy. The controller turns
// `egress: [{}]` into two PolicyEndpoint entries, 0.0.0.0/0 and ::/0, both with
// no ports and no excepts, and the agent copies each into an EbpfFirewallRules
// as is; allowAllEgress models that. The control cases drop the allow-all
// policy, and there the hosts must stay denied.
func TestComputeMapEntries_AllowAllAlongsideExcept(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	port443 := int32(443)
	tcp443 := []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}
	allowAllEgress := []EbpfFirewallRules{{IPCidr: "0.0.0.0/0"}, {IPCidr: "::/0"}}
	v4Except := EbpfFirewallRules{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.1.2.3/32", "10.1.2.4/32", "192.0.2.9/32"}}
	v4ExceptTCP443 := EbpfFirewallRules{IPCidr: "0.0.0.0/0", Except: v4Except.Except, L4Info: tcp443}
	v6Except := EbpfFirewallRules{IPCidr: "::/0", Except: []v1alpha1.NetworkAddress{"2001:db8::5/128"}}
	with := func(a []EbpfFirewallRules, b ...EbpfFirewallRules) []EbpfFirewallRules {
		return append(append([]EbpfFirewallRules(nil), a...), b...)
	}

	const v4Node, v6Node = "10.255.0.1", "2001:db8::1"
	tests := []struct {
		name       string
		enableIPv6 bool
		rules      []EbpfFirewallRules
		want       map[string]string
	}{
		{
			name:  "ipv4 allow-all keeps excepted hosts reachable",
			rules: with(allowAllEgress, v4Except),
			want: map[string]string{v4Node + "/32": "any", "0.0.0.0/0": "any",
				"10.1.2.3/32": "any", "10.1.2.4/32": "any", "192.0.2.9/32": "any"},
		},
		{
			name:  "ipv4 allow-all after the except policy",
			rules: with([]EbpfFirewallRules{v4Except}, allowAllEgress...),
			want: map[string]string{v4Node + "/32": "any", "0.0.0.0/0": "any",
				"10.1.2.3/32": "any", "10.1.2.4/32": "any", "192.0.2.9/32": "any"},
		},
		{
			name:       "ipv6 allow-all keeps the excepted host reachable",
			enableIPv6: true,
			rules:      with(allowAllEgress, v6Except),
			want:       map[string]string{v6Node + "/128": "any", "::/0": "any", "2001:db8::5/128": "any"},
		},
		{
			name:  "ipv4 allow-all with a port-scoped except policy",
			rules: with(allowAllEgress, v4ExceptTCP443),
			want: map[string]string{v4Node + "/32": "any", "0.0.0.0/0": "any,tcp/443",
				"10.1.2.3/32": "any", "10.1.2.4/32": "any", "192.0.2.9/32": "any"},
		},
		{
			name:  "control: ipv4 except policy alone denies the hosts",
			rules: []EbpfFirewallRules{v4Except},
			want: map[string]string{v4Node + "/32": "any", "0.0.0.0/0": "any",
				"10.1.2.3/32": "deny", "10.1.2.4/32": "deny", "192.0.2.9/32": "deny"},
		},
		{
			name:       "control: ipv6 except policy alone denies the host",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{v6Except},
			want:       map[string]string{v6Node + "/128": "any", "::/0": "any", "2001:db8::5/128": "deny"},
		},
		{
			name:  "control: port-scoped except policy alone denies the hosts",
			rules: []EbpfFirewallRules{v4ExceptTCP443},
			want: map[string]string{v4Node + "/32": "any", "0.0.0.0/0": "tcp/443",
				"10.1.2.3/32": "deny", "10.1.2.4/32": "deny", "192.0.2.9/32": "deny"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodeIP, hostMask := v4Node, "/32"
			if tt.enableIPv6 {
				nodeIP, hostMask = v6Node, "/128"
			}
			// Map iteration order is random; repeat so an order-dependent result shows up.
			for i := 0; i < 20; i++ {
				got, err := NewFirewallRuleProcessor(nodeIP, hostMask, tt.enableIPv6).
					ComputeMapEntriesFromEndpointRules(with(tt.rules))
				if err != nil {
					t.Fatalf("iteration %d: unexpected error: %v", i, err)
				}
				if !assert.Equal(t, tt.want, decodeFirewallMap(t, got), "iteration %d", i) {
					return
				}
			}
		})
	}
}
