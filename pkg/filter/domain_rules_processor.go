package filter

import (
	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// ComputeDNSProxyRulesFromEbpfFirewallRulesForPE converts []EbpfFirewallRules to map[string][]L4Rule
// with merging logic for rules with the same domain name but different L4Info.
// This fn will be called by PolicyEndpointReconciler where priority for all firewallRules are same
func ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(firewallRules []fwrp.EbpfFirewallRules) map[string][]npatypes.L4Rule {
	domainRulesMap := make(map[string][]npatypes.L4Rule)

	for _, rule := range firewallRules {
		// Skip rules that don't have domain names (IP-based rules)
		if rule.DomainName == "" {
			log().Warn("invalid firewall rule passed, this fn always expects the firewallRules which has DomainName")
			continue
		}

		// If no L4Info is specified, treat it as allow-all-ports by using a single
		// empty Port (nil Protocol/Port -> ANY_IP_PROTOCOL, all ports) so the
		// domain still gets registered for DNS filtering.
		l4InfoList := rule.L4Info
		if len(l4InfoList) == 0 {
			l4InfoList = []policyk8sawsv1.Port{{}}
		}

		// Process each L4Info entry for this domain
		for _, l4Info := range l4InfoList {
			l4Rule := npatypes.L4Rule{
				L4PortProtocolInfo: l4Info,
				Priority:           rule.Priority,
			}

			// Check if we already have rules for this domain
			if existingRules, exists := domainRulesMap[rule.DomainName]; exists {
				// Check if this exact L4Rule already exists to avoid duplicates
				isDuplicate := false
				for _, existingRule := range existingRules {
					if existingRule.Equal(l4Rule) {
						isDuplicate = true
						break
					}
				}

				if !isDuplicate {
					domainRulesMap[rule.DomainName] = append(existingRules, l4Rule)
				}
			} else {
				// First rule for this domain
				domainRulesMap[rule.DomainName] = []npatypes.L4Rule{l4Rule}
			}
		}
	}

	return domainRulesMap
}

// ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE converts []EbpfFirewallRules to map[string][]L4Rule
// This fn will be called by ClusterPolicyEndpointReconciler where priority
// TODO: Optimize this function to remove duplicate rules and keep only the highest priority rule (lowest value). Reduces the number of lookups in ebpf code
func ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE(firewallRules []fwrp.EbpfFirewallRules) map[string][]npatypes.L4Rule {
	return ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(firewallRules)
}
