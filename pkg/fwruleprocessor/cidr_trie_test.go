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

func insertAll(t *testing.T, trie *cidrTrie, cidrs ...string) {
	t.Helper()
	for _, c := range cidrs {
		trie.insert(c)
	}
}

// --- Core correctness ---

func TestCIDRTrie_IPv4_Containment(t *testing.T) {
	tests := []struct {
		name    string
		inserts []string
		lookup  string
		want    []string
	}{
		{"single containing CIDR", []string{"10.0.0.0/8"}, "10.1.2.3", []string{"10.0.0.0/8"}},
		{"nested ancestors broadest-first", []string{"0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"}, "10.1.2.3", []string{"0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"}},
		{"sibling prefix not matched", []string{"10.1.0.0/16", "10.2.0.0/16"}, "10.1.2.3", []string{"10.1.0.0/16"}},
		{"exact /32 match", []string{"10.1.2.3/32"}, "10.1.2.3", []string{"10.1.2.3/32"}},
		{"no match returns nil", []string{"192.168.0.0/16"}, "10.1.2.3", nil},
		{"catch-all /0", []string{"0.0.0.0/0"}, "0.0.0.0", []string{"0.0.0.0/0"}},
		{"empty trie", nil, "10.1.2.3", nil},
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
		{"nested ancestors broadest-first", []string{"::/0", "2001:db8::/32", "2001:db8:abcd::/48"}, "2001:db8:abcd:12::10", []string{"::/0", "2001:db8::/32", "2001:db8:abcd::/48"}},
		{"sibling /64 not matched", []string{"2001:db8:abcd:12::/64", "2001:db8:abcd:13::/64"}, "2001:db8:abcd:12::10", []string{"2001:db8:abcd:12::/64"}},
		{"exact /128 match", []string{"2001:db8::1/128"}, "2001:db8::1", []string{"2001:db8::1/128"}},
		{"no match", []string{"fd00::/8"}, "2001:db8::1", nil},
		{"catch-all ::/0 on zero IP", []string{"::/0"}, "::", []string{"::/0"}},
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
	// v6 lookup on v4-only trie must not match
	v4Only := newCIDRTrie()
	insertAll(t, v4Only, "10.0.0.0/8")
	assert.Empty(t, v4Only.findContainingKeys(net.ParseIP("2001:db8::1")),
		"v6 lookup must not match a v4 key")

	// v4 lookup on v6-only trie must not match
	v6Only := newCIDRTrie()
	insertAll(t, v6Only, "2001:db8::/32")
	assert.Empty(t, v6Only.findContainingKeys(net.ParseIP("10.1.2.3")),
		"v4 lookup must not match a v6 key")

	// v4 IP (32.1.13.184) whose leading bits resemble 2001:db8:: must not cross-match
	assert.Empty(t, v6Only.findContainingKeys(net.ParseIP("32.1.13.184")),
		"v4 IP sharing leading bits with v6 CIDR must not cross-match")

	// Mixed trie: each family finds only its own
	mixed := newCIDRTrie()
	insertAll(t, mixed, "10.0.0.0/8", "2001:db8::/32")
	assert.Equal(t, []string{"10.0.0.0/8"}, mixed.findContainingKeys(net.ParseIP("10.1.2.3")))
	assert.Equal(t, []string{"2001:db8::/32"}, mixed.findContainingKeys(net.ParseIP("2001:db8::1")))
}

// --- Nil / invalid input safety ---

func TestCIDRTrie_NilAndInvalidInputs(t *testing.T) {
	trie := newCIDRTrie()
	// Invalid inserts: must not panic, must not pollute
	trie.insert("")
	trie.insert("not-a-cidr")
	trie.insert("also/invalid")
	insertAll(t, trie, "10.0.0.0/8")

	// Only valid CIDR should be findable
	assert.Equal(t, []string{"10.0.0.0/8"}, trie.findContainingKeys(net.ParseIP("10.1.2.3")))

	// Nil and garbage IP queries: must not panic, must return empty
	assert.Empty(t, trie.findContainingKeys(nil))
	assert.Empty(t, trie.findContainingKeys(net.ParseIP("not-an-ip")))
}

// --- Canonicalization ---

func TestCIDRTrie_Canonicalization(t *testing.T) {
	trie := newCIDRTrie()

	// Non-canonical v4 (host bits set) -> stored as canonical
	trie.insert("10.0.0.1/8") // masks to 10.0.0.0/8
	assert.Equal(t, []string{"10.0.0.0/8"}, trie.findContainingKeys(net.ParseIP("10.99.99.99")))

	// v4-mapped IPv6 -> stored as v4 canonical
	trie2 := newCIDRTrie()
	trie2.insert("::ffff:10.0.0.0/104") // -> 10.0.0.0/8
	trie2.insert("::ffff:0:0/96")       // -> 0.0.0.0/0
	assert.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8"}, trie2.findContainingKeys(net.ParseIP("10.1.2.3")))
	assert.NotContains(t, trie2.findContainingKeys(net.ParseIP("11.0.0.1")), "10.0.0.0/8")

	// Duplicate insert -> idempotent (single result, not doubled)
	trie3 := newCIDRTrie()
	insertAll(t, trie3, "10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8")
	assert.Equal(t, []string{"10.0.0.0/8"}, trie3.findContainingKeys(net.ParseIP("10.1.2.3")))
}

// --- Oracle test: trie vs linear scan equivalence ---

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
		trie.insert(cidr)
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

func randV4CIDR(r *rand.Rand) string {
	prefix := r.Intn(25) + 8
	return fmt.Sprintf("%d.%d.%d.%d/%d", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256), prefix)
}

func randV6CIDR(r *rand.Rand) string {
	prefix := (r.Intn(8) + 4) * 8
	return fmt.Sprintf("%x:%x:%x:%x::/%d", r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000), prefix)
}

func randV4IP(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d/32", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
}

func randV6IP(r *rand.Rand) string {
	return fmt.Sprintf("%x:%x:%x:%x::1/128", r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000), r.Intn(0x10000))
}

func randV4MappedV6CIDR(r *rand.Rand) string {
	prefix := r.Intn(17) + 96
	return fmt.Sprintf("::ffff:%d.%d.0.0/%d", r.Intn(256), r.Intn(256), prefix)
}

func randSubCIDR(r *rand.Rand, parent string) string {
	_, ipNet, err := net.ParseCIDR(parent)
	if err != nil || ipNet == nil {
		return ""
	}
	ones, bits := ipNet.Mask.Size()
	if ones >= bits-1 {
		return ""
	}
	newOnes := ones + r.Intn(bits-ones-1) + 1
	return fmt.Sprintf("%s/%d", ipNet.IP.String(), newOnes)
}

func TestTrieVsLinear_Randomized(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for iter := 0; iter < 500; iter++ {
		ruleMap := make(map[string]EbpfFirewallRules)
		targets := make([]string, 0, 8)

		for i := 0; i < 12; i++ {
			var cidr string
			switch r.Intn(4) {
			case 0:
				cidr = randV4CIDR(r)
			case 1:
				cidr = randV6CIDR(r)
			case 2:
				cidr = randV4MappedV6CIDR(r)
			default:
				if r.Intn(2) == 0 {
					cidr = randV4CIDR(r)
				} else {
					cidr = randV6CIDR(r)
				}
			}
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil || ipNet == nil {
				continue
			}
			port := int32(r.Intn(65535) + 1)
			if r.Intn(3) == 0 {
				exc := randSubCIDR(r, ipNet.String())
				if exc != "" {
					ruleMap[ipNet.String()] = rule(port, exc)
					continue
				}
			}
			ruleMap[ipNet.String()] = rule(port)
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

// --- Concurrency safety ---


