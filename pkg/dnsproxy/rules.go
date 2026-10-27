package dnsproxy

import (
	"strings"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/miekg/dns"
)

// entrySize is the size of a port and protocol entry of utils.ComputeTrieValueForCPE output.
const entrySize = 16

// domainRule is a domain name of a policy rule with the rule's ports, encoded for the IP cache.
type domainRule struct {
	name    string // lower case FQDN, "*." prefix for a wildcard
	encoded []byte
}

func newDomainRules(rules []fwrp.EbpfFirewallRules) []domainRule {
	var domainRules []domainRule
	for _, rule := range rules {
		if rule.Action != v1alpha1.ClusterNetworkPolicyRuleActionAccept {
			log().Warnf("Ignoring domain rule %s with action %q: domain rules can only accept", rule.DomainName, rule.Action)
			continue
		}
		ports := rule.L4Info
		if len(ports) == 0 {
			ports = []v1alpha1.Port{{}} // every protocol and port
		}
		l4Rules := make([]utils.L4Rule, 0, len(ports))
		for _, port := range ports {
			l4Rules = append(l4Rules, utils.L4Rule{L4PortProtocolInfo: port, Action: rule.Action, Priority: rule.Priority})
		}
		domainRules = append(domainRules, domainRule{
			name:    dns.Fqdn(strings.ToLower(rule.DomainName)),
			encoded: utils.ComputeTrieValueForCPE(l4Rules),
		})
	}
	return domainRules
}

// matches reports whether the lower case FQDN qname is this domain or, for a wildcard, a subdomain of it.
func (d domainRule) matches(qname string) bool {
	if suffix, ok := strings.CutPrefix(d.name, "*"); ok {
		return len(qname) > len(suffix) && strings.HasSuffix(qname, suffix)
	}
	return qname == d.name
}

// entries returns the port and protocol entries of the rule, without the unused ones.
func (d domainRule) entries() []string {
	var entries []string
	for i := 0; i+entrySize <= len(d.encoded); i += entrySize {
		if entry := string(d.encoded[i : i+entrySize]); entry != string(make([]byte, entrySize)) {
			entries = append(entries, entry)
		}
	}
	return entries
}
