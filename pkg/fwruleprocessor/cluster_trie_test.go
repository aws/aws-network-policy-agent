package fwruleprocessor

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	corev1 "k8s.io/api/core/v1"
)

// The original deduplicator iterates a Go map, so encoded 16-byte rule slots
// must be compared as a multiset; key bytes and all rule fields remain exact.
func normalizedValues(m map[string][]byte) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		for i := 0; i < len(v); i += 16 {
			out[k] = append(out[k], string(v[i:i+16]))
		}
		sort.Strings(out[k])
	}
	return out
}

func TestClusterTrieDifferential(t *testing.T) {
	logger.New("error", "stdout", 1, 1)
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	p, q, end := int32(4317), int32(4318), int32(4320)
	for _, v6 := range []bool{false, true} {
		f := NewFirewallRuleProcessor("10.255.255.254", "/32", false)
		cidrs := []string{"0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.1.1/32", "10.1.1.1/32", "192.0.2.1", "::ffff:10.1.1.1/128"}
		if v6 {
			f = NewFirewallRuleProcessor("2001:db8:ffff::1", "/128", true)
			cidrs = []string{"::/0", "2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1/128", "2001:db8:1::1/128", "2001:db8:2::1"}
		}
		rules := []EbpfFirewallRules{}
		for i, c := range cidrs {
			r := EbpfFirewallRules{IPCidr: v1alpha1.NetworkAddress(c), Priority: i, Action: []v1alpha1.ClusterNetworkPolicyRuleAction{"Accept", "Deny", "Pass"}[i%3]}
			if i%3 != 0 {
				r.L4Info = []v1alpha1.Port{{Protocol: &tcp, Port: &p}, {Protocol: &udp, Port: &q, EndPort: &end}}
			}
			rules = append(rules, r)
		}
		rng := rand.New(rand.NewSource(9))
		for i := 0; i < 300; i++ {
			c := fmt.Sprintf("10.%d.%d.%d/32", rng.Intn(256), rng.Intn(256), rng.Intn(256))
			if v6 {
				c = fmt.Sprintf("2001:db8:%x::%x/128", rng.Intn(65536), i)
			}
			rules = append(rules, EbpfFirewallRules{IPCidr: v1alpha1.NetworkAddress(c), Action: "Accept", Priority: 16, L4Info: []v1alpha1.Port{{Protocol: &tcp, Port: &p}}})
		}
		got, e := f.ComputeClusterPolicyMapEntriesFromEndpointRules(append([]EbpfFirewallRules(nil), rules...))
		if e != nil {
			t.Fatal(e)
		}
		want, e := f.computeClusterPolicyOriginal(append([]EbpfFirewallRules(nil), rules...))
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(normalizedValues(got), normalizedValues(want)) {
			t.Fatalf("encoded rule maps differ ipv6=%v", v6)
		}
	}
}

func TestClusterTrieOverlapDifferential(t *testing.T) {
	f := &FirewallRuleProcessor{}
	trie := newCIDRTrie()
	prior := []string{}
	rules := []string{"0.0.0.0/0", "10.0.0.0/8", "10.1.2.3/16", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.3/32", "::ffff:10.1.2.3/120", "::ffff:10.1.2.3/128", "::/0", "2001:db8::/32", "2001:db8::1/128", "::ffff:0:0/80"}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 1000; i++ {
		_, n, _ := net.ParseCIDR(fmt.Sprintf("10.%d.%d.%d/%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), 8+rng.Intn(25)))
		rules = append(rules, n.String())
	}
	for i := range rules {
		rules[i] = f.normalizeCIDR(rules[i])
	}
	sort.SliceStable(rules, func(i, j int) bool { return f.getPrefixLength(rules[i]) < f.getPrefixLength(rules[j]) })
	for _, c := range rules {
		got, want := f.findMostSpecificOverlap(c, trie), f.findMostSpecificOverlapOriginal(c, prior)
		if got != want {
			t.Fatalf("%s: %q != %q", c, got, want)
		}
		prior = append(prior, c)
		trie.insert(c)
	}
}

func TestClusterTrie15000(t *testing.T) {
	logger.New("error", "stdout", 1, 1)
	f := NewFirewallRuleProcessor("10.255.255.254", "/32", false)
	tcp := corev1.ProtocolTCP
	p := int32(4317)
	rules := make([]EbpfFirewallRules, 15000)
	for i := range rules {
		rules[i] = EbpfFirewallRules{IPCidr: v1alpha1.NetworkAddress(fmt.Sprintf("198.18.%d.%d/32", i/256, i%256)), Action: "Accept", Priority: 16, L4Info: []v1alpha1.Port{{Protocol: &tcp, Port: &p}}}
	}
	got, e := f.ComputeClusterPolicyMapEntriesFromEndpointRules(append([]EbpfFirewallRules(nil), rules...))
	if e != nil {
		t.Fatal(e)
	}
	want, e := f.computeClusterPolicyOriginal(rules)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 15001 || len(want) != 15001 {
		t.Fatal("entry count", len(got), len(want))
	}
	for k, v := range want {
		if !bytes.Equal(v, got[k]) {
			t.Fatal("15k map mismatch")
		}
	}
}

func BenchmarkClusterTrie15000(b *testing.B) {
	logger.New("error", "stdout", 1, 1)
	rules := make([]EbpfFirewallRules, 15000)
	for i := range rules {
		rules[i] = EbpfFirewallRules{IPCidr: v1alpha1.NetworkAddress(fmt.Sprintf("198.18.%d.%d/32", i/256, i%256)), Action: "Accept", Priority: 16}
	}
	f := NewFirewallRuleProcessor("10.255.255.254", "/32", false)
	for _, old := range []bool{true, false} {
		b.Run(fmt.Sprintf("original=%v", old), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				r := append([]EbpfFirewallRules(nil), rules...)
				var entries map[string][]byte
				var err error
				if old {
					entries, err = f.computeClusterPolicyOriginal(r)
				} else {
					entries, err = f.ComputeClusterPolicyMapEntriesFromEndpointRules(r)
				}
				if err != nil || len(entries) != 15001 {
					b.Fatalf("compile: entries=%d err=%v", len(entries), err)
				}
			}
		})
	}
}
