package fwruleprocessor

import (
	"bytes"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

func TestParsedCIDRMatchesLegacyKey(t *testing.T) {
	for _, cidr := range []string{
		"10.161.0.7/8", "192.168.1.7/32", "0.0.0.0/0",
		"2001:db8:abcd::7/32", "2001:db8::7/128", "::/0",
		"::ffff:10.161.0.7/104", "::ffff:10.0.0.7/128", "::ffff:10.0.0.7/80",
		"10.1.2.3/024", "2001:db8::/064",
	} {
		t.Run(cidr, func(t *testing.T) {
			_, legacy, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			prefix, err := parsePrefix(cidr)
			if err != nil {
				t.Fatal(err)
			}
			prefix = canonicalPrefix(prefix)
			if prefix.String() != legacy.String() {
				t.Fatalf("canonical CIDR = %s, want %s", prefix, legacy)
			}
			// The compiler historically reparsed IPNet.String before encoding.
			_, legacy, _ = net.ParseCIDR(legacy.String())
			for _, ipv6 := range []bool{false, true} {
				if got, want := computeTrieKey(prefix, ipv6), utils.ComputeTrieKey(*legacy, ipv6); !bytes.Equal(got, want) {
					t.Fatalf("IPv6=%t: key = %x, want %x", ipv6, got, want)
				}
			}
		})
	}
	processor := NewFirewallRuleProcessor("192.168.1.1", "/32", false)
	rules, err := processor.parseRules([]EbpfFirewallRules{{IPCidr: "10.0.0.7"}, {IPCidr: "::ffff:10.0.0.7/104"}})
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].prefix.String() != "10.0.0.7/32" || rules[1].prefixBits != 104 {
		t.Fatalf("bare-IP default or original prefix length changed: %+v", rules)
	}
	if _, err := processor.ComputeMapEntriesFromEndpointRules([]EbpfFirewallRules{{IPCidr: "invalid"}}); err == nil {
		t.Fatal("invalid CIDR must return an error")
	}
}

func TestCompilationAcceptsLegacyPrefixLengths(t *testing.T) {
	processor := NewFirewallRuleProcessor("192.168.1.1", "/032", false)
	_, node, _ := net.ParseCIDR("192.168.1.1/32")
	for name, compile := range map[string]func([]EbpfFirewallRules) (map[string][]byte, error){
		"NetworkPolicy":        processor.ComputeMapEntriesFromEndpointRules,
		"ClusterNetworkPolicy": processor.ComputeClusterPolicyMapEntriesFromEndpointRules,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := compile([]EbpfFirewallRules{{
				IPCidr: "10.1.2.3/024", Except: []v1alpha1.NetworkAddress{"10.1.2.128/025"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := got[string(utils.ComputeTrieKey(*node, false))]; !ok {
				t.Fatal("node allow entry missing")
			}
		})
	}
}

func TestIPv6CompilationSkipsBareIPv4(t *testing.T) {
	processor := NewFirewallRuleProcessor("2001:db8::1", "/128", true)
	for name, compile := range map[string]func([]EbpfFirewallRules) (map[string][]byte, error){
		"NetworkPolicy":        processor.ComputeMapEntriesFromEndpointRules,
		"ClusterNetworkPolicy": processor.ComputeClusterPolicyMapEntriesFromEndpointRules,
	} {
		t.Run(name, func(t *testing.T) {
			rules := []EbpfFirewallRules{
				{IPCidr: "10.1.2.3", Except: []v1alpha1.NetworkAddress{"ignored-invalid-exception"}},
				{IPCidr: "2001:db8:1::/64"},
				{IPCidr: "2001:db8:1::7/128"},
			}
			got, err := compile(rules)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 3 || rules[0].IPCidr != "2001:db8:1::/64" || rules[1].IPCidr != "10.1.2.3" {
				t.Fatalf("wrong-family filtering or stable input order changed: %v, %v", got, rules)
			}
		})
	}
}
