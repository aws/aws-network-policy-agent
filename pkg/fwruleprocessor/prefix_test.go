package fwruleprocessor

import (
	"bytes"
	"maps"
	"net"
	"slices"
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
				if got, want := utils.ComputeTrieKeyFromPrefix(prefix, ipv6), utils.ComputeTrieKey(*legacy, ipv6); !bytes.Equal(got, want) {
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
			validRules := []EbpfFirewallRules{
				{IPCidr: "10.2.0.0/16"},
				{IPCidr: "2001:db8:1::/64"},
				{IPCidr: "2001:db8:1::7/128"},
			}
			want, err := compile(slices.Clone(validRules))
			if err != nil {
				t.Fatal(err)
			}
			for _, cidr := range []string{"10.1.2.3", "010.0.0.0/8", "10.0.0.0/33", "fd00::/129", "invalid"} {
				t.Run(cidr, func(t *testing.T) {
					rules := append([]EbpfFirewallRules{{
						IPCidr: v1alpha1.NetworkAddress(cidr),
						Except: []v1alpha1.NetworkAddress{"ignored-invalid-exception"},
					}}, validRules...)
					got, err := compile(rules)
					if err != nil {
						t.Fatal(err)
					}
					if !maps.EqualFunc(got, want, bytes.Equal) {
						t.Fatalf("skipped rule changed valid IPv6 entries: got %v, want %v", got, want)
					}
					if cidr == "10.1.2.3" && rules[2].IPCidr != "10.1.2.3" {
						t.Fatalf("stable bare-IPv4 input order changed: %v", rules)
					}
				})
			}
		})
	}
}

func TestIPv4CompilationRejectsUnparseableCIDRs(t *testing.T) {
	processor := NewFirewallRuleProcessor("192.168.1.1", "/32", false)
	for name, compile := range map[string]func([]EbpfFirewallRules) (map[string][]byte, error){
		"NetworkPolicy":        processor.ComputeMapEntriesFromEndpointRules,
		"ClusterNetworkPolicy": processor.ComputeClusterPolicyMapEntriesFromEndpointRules,
	} {
		t.Run(name, func(t *testing.T) {
			for _, cidr := range []string{"010.0.0.0/8", "10.0.0.0/33", "fd00::/129", "invalid"} {
				t.Run(cidr, func(t *testing.T) {
					got, err := compile([]EbpfFirewallRules{{IPCidr: v1alpha1.NetworkAddress(cidr)}})
					if err == nil || got != nil {
						t.Fatalf("invalid CIDR must fail compilation: entries=%v, error=%v", got, err)
					}
				})
			}
		})
	}
}

func TestCompilationRejectsInvalidNodeCIDRs(t *testing.T) {
	for _, tt := range []struct {
		node string
		mask string
		ipv6 bool
	}{
		{"invalid", "/32", false},
		{"192.168.1.1", "/33", false},
		{"2001:db8::1", "/129", true},
	} {
		t.Run(tt.node+tt.mask, func(t *testing.T) {
			processor := NewFirewallRuleProcessor(tt.node, tt.mask, tt.ipv6)
			for name, compile := range map[string]func([]EbpfFirewallRules) (map[string][]byte, error){
				"NetworkPolicy":        processor.ComputeMapEntriesFromEndpointRules,
				"ClusterNetworkPolicy": processor.ComputeClusterPolicyMapEntriesFromEndpointRules,
			} {
				t.Run(name, func(t *testing.T) {
					got, err := compile(nil)
					if err == nil || got != nil {
						t.Fatalf("invalid node CIDR must fail compilation: entries=%v, error=%v", got, err)
					}
				})
			}
		})
	}
}
