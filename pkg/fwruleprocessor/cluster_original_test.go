package fwruleprocessor

import (
	"net"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

// Test-only oracle: the cluster-policy compiler before trie overlap lookup.
func (f *FirewallRuleProcessor) computeClusterPolicyOriginal(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {
	firewallMap := make(map[string][]byte)
	cidrL4Rules := make(map[string][]utils.L4Rule)
	processedCIDRs := make([]string, 0)

	// Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	// This ensures kubelet liveness/readiness probes are never blocked by cluster network policies.
	_, mapKey, _ := net.ParseCIDR(f.nodeIP + f.hostMask)
	key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
	nodeIPL4Rule := []utils.L4Rule{
		{
			Action:   "Accept",
			Priority: 0, // Highest priority — node-IP allow must not be overridden
		},
	}
	value := utils.ComputeTrieValueForCPE(nodeIPL4Rule)
	firewallMap[string(key)] = value

	// Step 1: Sort by CIDR length
	f.sortByCIDRLength(firewallRules)

	// Step 2-3: Process each CIDR and handle overlaps
	for _, rule := range firewallRules {

		cidr := f.normalizeCIDR(string(rule.IPCidr))
		if f.shouldSkipRule(cidr) {
			continue
		}

		// Find the most specific overlapping CIDR
		overlappingCIDR := f.findMostSpecificOverlapOriginal(cidr, processedCIDRs)

		// Copy L4 rules from overlapping CIDR if found
		if overlappingCIDR != "" {
			cidrL4Rules[cidr] = append(cidrL4Rules[cidr], cidrL4Rules[overlappingCIDR]...)
		}

		// If this current rule doesn't have any port/protocol, the rule is not specific to any port/protocol
		if len(rule.L4Info) == 0 {
			log().Info("cluster policy endpoint rule processsing: No rule for port so adding catch all ports")
			cidrL4Rules[cidr] = append(cidrL4Rules[cidr], utils.L4Rule{
				Action:   rule.Action,
				Priority: rule.Priority,
			})
		}

		// Add current rule's L4 info
		for _, port := range rule.L4Info {
			l4Rule := utils.L4Rule{
				L4PortProtocolInfo: port,
				Action:             rule.Action,
				Priority:           rule.Priority,
			}
			cidrL4Rules[cidr] = append(cidrL4Rules[cidr], l4Rule)
		}
		processedCIDRs = append(processedCIDRs, cidr)
	}

	// Step 4: Resolve conflicts and create final map entries
	for cidr, l4Rules := range cidrL4Rules {
		log().Infof("cluster policy firewall rule processing complete: CIDR: %+v, Rules Count: %d", cidr, len(l4Rules))
		resolvedL4Rules := f.removeDuplicateL4Rules(l4Rules)

		_, firewallMapKey, _ := net.ParseCIDR(cidr)
		firewallKey := utils.ComputeTrieKey(*firewallMapKey, f.enableIPv6)

		firewallValue := utils.ComputeTrieValueForCPE(resolvedL4Rules)
		firewallMap[string(firewallKey)] = firewallValue
	}

	return firewallMap, nil
}
func (f *FirewallRuleProcessor) findMostSpecificOverlapOriginal(currentCIDR string, processedCIDRs []string) string {
	_, currentNet, _ := net.ParseCIDR(currentCIDR)

	// Loop from end to start since CIDRs are sorted in ascending order
	for i := len(processedCIDRs) - 1; i >= 0; i-- {
		processedCIDR := processedCIDRs[i]
		_, processedNet, _ := net.ParseCIDR(processedCIDR)

		// Check if current CIDR is contained within processed CIDR
		if processedNet.Contains(currentNet.IP) {
			return processedCIDR
		}
	}

	return ""
}
