package fwruleprocessor

import (
	"reflect"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func fpTestRules() []EbpfFirewallRules {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	p80, p90, p443 := int32(80), int32(90), int32(443)
	return []EbpfFirewallRules{
		{IPCidr: "10.0.0.0/16", Except: []v1alpha1.NetworkAddress{"10.0.1.0/24"},
			L4Info: []v1alpha1.Port{{Protocol: &tcp, Port: &p80, EndPort: &p90}}},
		{IPCidr: "10.1.0.1/32", L4Info: []v1alpha1.Port{{Protocol: &udp, Port: &p443}}},
		{Priority: 5, Action: "Deny", DomainName: "example.com"},
	}
}

func TestRulesFingerprint_EqualForEqualRules(t *testing.T) {
	assert.Equal(t, RulesFingerprint(fpTestRules()), RulesFingerprint(fpTestRules()),
		"equal rule lists built from distinct pointers must fingerprint the same")
	assert.Equal(t, RulesFingerprint(nil), RulesFingerprint([]EbpfFirewallRules{}))
}

// Every field, and the order of the rules, must reach the digest: a change that did not
// would let a caller skip programming a map whose entries should have changed.
func TestRulesFingerprint_EveryChangeIsDetected(t *testing.T) {
	sctp := corev1.ProtocolSCTP
	p1, p0 := int32(1), int32(0)
	mutations := map[string]func(r []EbpfFirewallRules) []EbpfFirewallRules{
		"cidr": func(r []EbpfFirewallRules) []EbpfFirewallRules { r[1].IPCidr = "10.1.0.2/32"; return r },
		"except added": func(r []EbpfFirewallRules) []EbpfFirewallRules {
			r[1].Except = []v1alpha1.NetworkAddress{"10.1.0.1/32"}
			return r
		},
		"except changed":   func(r []EbpfFirewallRules) []EbpfFirewallRules { r[0].Except[0] = "10.0.2.0/24"; return r },
		"protocol":         func(r []EbpfFirewallRules) []EbpfFirewallRules { r[0].L4Info[0].Protocol = &sctp; return r },
		"protocol removed": func(r []EbpfFirewallRules) []EbpfFirewallRules { r[0].L4Info[0].Protocol = nil; return r },
		"port":             func(r []EbpfFirewallRules) []EbpfFirewallRules { r[0].L4Info[0].Port = &p1; return r },
		"port nil vs 0":    func(r []EbpfFirewallRules) []EbpfFirewallRules { r[1].L4Info[0].EndPort = &p0; return r },
		"end port removed": func(r []EbpfFirewallRules) []EbpfFirewallRules { r[0].L4Info[0].EndPort = nil; return r },
		"port added": func(r []EbpfFirewallRules) []EbpfFirewallRules {
			r[1].L4Info = append(r[1].L4Info, v1alpha1.Port{})
			return r
		},
		"ports cleared": func(r []EbpfFirewallRules) []EbpfFirewallRules { r[1].L4Info = nil; return r },
		"priority":      func(r []EbpfFirewallRules) []EbpfFirewallRules { r[2].Priority = 6; return r },
		"action":        func(r []EbpfFirewallRules) []EbpfFirewallRules { r[2].Action = "Allow"; return r },
		"domain":        func(r []EbpfFirewallRules) []EbpfFirewallRules { r[2].DomainName = "example.org"; return r },
		"rule removed":  func(r []EbpfFirewallRules) []EbpfFirewallRules { return r[:2] },
		"rule added": func(r []EbpfFirewallRules) []EbpfFirewallRules {
			return append(r, EbpfFirewallRules{IPCidr: "0.0.0.0/0"})
		},
		"order": func(r []EbpfFirewallRules) []EbpfFirewallRules { r[0], r[1] = r[1], r[0]; return r },
		// Length prefixes keep a byte from moving between adjacent strings unnoticed.
		"boundary": func(r []EbpfFirewallRules) []EbpfFirewallRules {
			r[2].Action, r[2].DomainName = "Denye", "xample.com"
			return r
		},
	}
	base := RulesFingerprint(fpTestRules())
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			assert.NotEqual(t, base, RulesFingerprint(mutate(fpTestRules())))
		})
	}
}

// Guards RulesFingerprint against a new rule or port field: update the fingerprint (and the
// mutation table above) to cover it, then update the expected field lists here.
func TestRulesFingerprint_CoversEveryField(t *testing.T) {
	fieldNames := func(v any) []string {
		var names []string
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			names = append(names, typ.Field(i).Name)
		}
		return names
	}
	assert.Equal(t, []string{"Priority", "Action", "DomainName", "IPCidr", "Except", "L4Info"}, fieldNames(EbpfFirewallRules{}))
	assert.Equal(t, []string{"Protocol", "Port", "EndPort"}, fieldNames(v1alpha1.Port{}))
}
