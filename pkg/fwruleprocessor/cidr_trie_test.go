package fwruleprocessor

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	assert.NoError(t, err)
	return ipNet
}

func insertAll(t *testing.T, trie *cidrTrie, cidrs ...string) {
	t.Helper()
	for _, c := range cidrs {
		trie.insert(c, mustCIDR(t, c))
	}
}

func TestCIDRTrie_Insert_NilIPNet(t *testing.T) {
	trie := newCIDRTrie()
	trie.insert("10.0.0.0/8", nil)
	assert.Empty(t, trie.findContainingKeys(net.ParseIP("10.1.2.3")))
}

func TestCIDRTrie_FindContainingKeys_NilIP(t *testing.T) {
	trie := newCIDRTrie()
	insertAll(t, trie, "10.0.0.0/8")
	assert.Empty(t, trie.findContainingKeys(nil))
}

func TestCIDRTrie_IPv4_Containment(t *testing.T) {
	tests := []struct {
		name    string
		inserts []string
		lookup  string
		want    []string
	}{
		{"single containing CIDR", []string{"10.0.0.0/8"}, "10.1.2.3", []string{"10.0.0.0/8"}},
		{"nested ancestors broadest-first", []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"}, "10.1.2.3", []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"}},
		{"sibling prefix not matched", []string{"10.1.0.0/16", "10.2.0.0/16"}, "10.1.2.3", []string{"10.1.0.0/16"}},
		{"exact /32 match", []string{"10.1.2.3/32"}, "10.1.2.3", []string{"10.1.2.3/32"}},
		{"no match", []string{"192.168.0.0/16"}, "10.1.2.3", nil},
		{"catch-all /0", []string{"0.0.0.0/0"}, "10.1.2.3", []string{"0.0.0.0/0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := newCIDRTrie()
			insertAll(t, trie, tt.inserts...)
			assert.Equal(t, tt.want, trie.findContainingKeys(net.ParseIP(tt.lookup)))
		})
	}
}

func TestCIDRTrie_IPv6_Containment(t *testing.T) {
	tests := []struct {
		name    string
		inserts []string
		lookup  string
		want    []string
	}{
		{"single containing CIDR", []string{"2001:db8::/32"}, "2001:db8:abcd:12::10", []string{"2001:db8::/32"}},
		{"nested ancestors broadest-first", []string{"2001:db8::/32", "2001:db8:abcd::/48", "2001:db8:abcd:12::/64"}, "2001:db8:abcd:12::10", []string{"2001:db8::/32", "2001:db8:abcd::/48", "2001:db8:abcd:12::/64"}},
		{"sibling /64 not matched", []string{"2001:db8:abcd:12::/64", "2001:db8:abcd:13::/64"}, "2001:db8:abcd:12::10", []string{"2001:db8:abcd:12::/64"}},
		{"exact /128 match", []string{"2001:db8::1/128"}, "2001:db8::1", []string{"2001:db8::1/128"}},
		{"no match", []string{"fd00::/8"}, "2001:db8::1", nil},
		{"catch-all ::/0", []string{"::/0"}, "2001:db8::1", []string{"::/0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := newCIDRTrie()
			insertAll(t, trie, tt.inserts...)
			assert.Equal(t, tt.want, trie.findContainingKeys(net.ParseIP(tt.lookup)))
		})
	}
}

func TestCIDRTrie_FamilyIsolation(t *testing.T) {
	v6 := newCIDRTrie()
	insertAll(t, v6, "2001:db8::/32")
	assert.Empty(t, v6.findContainingKeys(net.ParseIP("32.1.13.184")), "v4 lookup must not match a v6 key")

	v4 := newCIDRTrie()
	insertAll(t, v4, "10.0.0.0/8")
	assert.Empty(t, v4.findContainingKeys(net.ParseIP("2001:db8::1")), "v6 lookup must not match a v4 key")
}

func TestCIDRTrie_MixedFamiliesSameTrie(t *testing.T) {
	trie := newCIDRTrie()
	insertAll(t, trie, "10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32", "2001:db8:abcd::/48")

	assert.Equal(t, []string{"10.0.0.0/8", "10.1.0.0/16"}, trie.findContainingKeys(net.ParseIP("10.1.2.3")))
	assert.Equal(t, []string{"2001:db8::/32", "2001:db8:abcd::/48"}, trie.findContainingKeys(net.ParseIP("2001:db8:abcd:12::10")))
}

func portKeyString(p v1alpha1.Port) string {
	proto := ""
	if p.Protocol != nil {
		proto = string(*p.Protocol)
	}
	port, endPort := 0, 0
	if p.Port != nil {
		port = int(*p.Port)
	}
	if p.EndPort != nil {
		endPort = int(*p.EndPort)
	}
	return fmt.Sprintf("%s-%d-%d", proto, port, endPort)
}

func portSet(ports []v1alpha1.Port) []string {
	keys := make([]string, 0, len(ports))
	for _, p := range ports {
		keys = append(keys, portKeyString(p))
	}
	sort.Strings(keys)
	return keys
}

func buildTrie(ruleMap map[string]EbpfFirewallRules) *cidrTrie {
	trie := newCIDRTrie()
	for cidr := range ruleMap {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet != nil {
			trie.insert(cidr, ipNet)
		}
	}
	return trie
}

func assertEquivalent(t *testing.T, ruleMap map[string]EbpfFirewallRules, target string) {
	t.Helper()
	linear := checkAndDeriveL4InfoFromAnyMatchingCIDRs(target, ruleMap)
	trie := checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(target, buildTrie(ruleMap), ruleMap)
	assert.Equal(t, portSet(linear), portSet(trie),
		"trie result must equal linear result for target %s", target)
}

func rule(port int32, except ...string) EbpfFirewallRules {
	tcp := corev1.ProtocolTCP
	p := port
	exc := make([]v1alpha1.NetworkAddress, 0, len(except))
	for _, e := range except {
		exc = append(exc, v1alpha1.NetworkAddress(e))
	}
	return EbpfFirewallRules{
		L4Info: []v1alpha1.Port{{Protocol: &tcp, Port: &p}},
		Except: exc,
	}
}

func TestTrieVsLinear_IPv4_Curated(t *testing.T) {
	ruleMap := map[string]EbpfFirewallRules{
		"10.0.0.0/8":     rule(80, "10.1.2.0/24"),
		"10.1.0.0/16":    rule(443),
		"192.168.0.0/16": rule(8080),
		"0.0.0.0/0":      rule(53),
	}
	for _, target := range []string{"10.1.2.3/32", "10.5.6.7/32", "192.168.1.1/32", "8.8.8.8/32"} {
		assertEquivalent(t, ruleMap, target)
	}
}

func TestTrieVsLinear_IPv6_Curated(t *testing.T) {
	ruleMap := map[string]EbpfFirewallRules{
		"2001:db8::/32":         rule(80, "2001:db8:abcd::/48"),
		"2001:db8:abcd:12::/64": rule(443),
		"fd00::/8":              rule(8080),
		"::/0":                  rule(53),
	}
	for _, target := range []string{"2001:db8:abcd:12::10/128", "2001:db8:1::1/128", "fd00::1/128", "2600::1/128"} {
		assertEquivalent(t, ruleMap, target)
	}
}

func TestTrieVsLinear_MixedFamilies(t *testing.T) {
	ruleMap := map[string]EbpfFirewallRules{
		"10.0.0.0/8":    rule(80),
		"2001:db8::/32": rule(443),
	}
	assertEquivalent(t, ruleMap, "10.1.2.3/32")
	assertEquivalent(t, ruleMap, "2001:db8::1/128")
	// 32.1.13.184 shares leading bits with 2001:db8::/32 -- must only match the v4 rule.
	assertEquivalent(t, ruleMap, "32.1.13.184/32")
}

func randV4CIDR(r *rand.Rand) string {
	prefix := r.Intn(25) + 8 // /8../32
	return fmt.Sprintf("%d.%d.%d.%d/%d", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256), prefix)
}

func randV6CIDR(r *rand.Rand) string {
	prefix := (r.Intn(8) + 4) * 8 // /32../96, byte-aligned for readable coverage
	return fmt.Sprintf("%x:%x:%x:%x::/%d", r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000), prefix)
}

func randV4IP(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d/32", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
}

func randV6IP(r *rand.Rand) string {
	return fmt.Sprintf("%x:%x:%x:%x::1/128", r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000))
}

func TestTrieVsLinear_Randomized(t *testing.T) {
	r := rand.New(rand.NewSource(1)) // fixed seed for reproducibility
	for iter := 0; iter < 500; iter++ {
		ruleMap := make(map[string]EbpfFirewallRules)
		targets := make([]string, 0, 8)

		for i := 0; i < 12; i++ {
			var cidr string
			switch r.Intn(3) {
			case 0:
				cidr = randV4CIDR(r)
			case 1:
				cidr = randV6CIDR(r)
			default:
				if r.Intn(2) == 0 {
					cidr = randV4CIDR(r)
				} else {
					cidr = randV6CIDR(r)
				}
			}
			// normalize to the canonical network form so both paths key identically
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil || ipNet == nil {
				continue
			}
			ruleMap[ipNet.String()] = rule(int32(r.Intn(65535) + 1))
		}
		for i := 0; i < 6; i++ {
			if r.Intn(2) == 0 {
				targets = append(targets, randV4IP(r))
			} else {
				targets = append(targets, randV6IP(r))
			}
		}
		for _, target := range targets {
			assertEquivalent(t, ruleMap, target)
		}
	}
}

func TestTrieVsLinear_V4MappedV6(t *testing.T) {
	ruleMap := map[string]EbpfFirewallRules{
		"::ffff:10.0.0.0/104": rule(80),
		"::ffff:0:0/96":       rule(443),
		"10.1.0.0/16":         rule(8080),
	}
	for _, target := range []string{"10.1.2.3/32", "10.5.6.7/32", "8.8.8.8/32"} {
		assertEquivalent(t, ruleMap, target)
	}
}

func TestCIDRTrie_V4MappedV6_Insert(t *testing.T) {
	trie := newCIDRTrie()
	insertAll(t, trie, "::ffff:10.0.0.0/104")
	assert.Contains(t, trie.findContainingKeys(net.ParseIP("10.1.2.3")), "::ffff:10.0.0.0/104")
	assert.NotContains(t, trie.findContainingKeys(net.ParseIP("11.0.0.1")), "::ffff:10.0.0.0/104")

	catchAll := newCIDRTrie()
	insertAll(t, catchAll, "::ffff:0:0/96")
	assert.Contains(t, catchAll.findContainingKeys(net.ParseIP("1.2.3.4")), "::ffff:0:0/96")
}
