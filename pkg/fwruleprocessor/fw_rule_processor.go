package fwruleprocessor

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

func log() logger.Logger {
	return logger.Get()
}

var (
	CATCH_ALL_PROTOCOL corev1.Protocol = "ANY_IP_PROTOCOL"
	DENY_ALL_PROTOCOL  corev1.Protocol = "RESERVED_IP_PROTOCOL_NUMBER"
)

type EbpfFirewallRules struct {
	IPCidr v1alpha1.NetworkAddress
	Except []v1alpha1.NetworkAddress
	L4Info []v1alpha1.Port
}

type FirewallRuleProcessor struct {
	// Primary IP of the node
	nodeIP   string
	hostMask string
	// Flag to track the IPv6 mode
	enableIPv6 bool
}

func NewFirewallRuleProcessor(nodeIP string, hostMask string, enableIPv6 bool) *FirewallRuleProcessor {
	fwrp := &FirewallRuleProcessor{
		nodeIP:     nodeIP,
		hostMask:   hostMask,
		enableIPv6: enableIPv6,
	}
	return fwrp
}

// computeMapEntriesFromEndpointRules generates a map of IP prefix keys to encoded L4 rules that will
// be used to update ebpf maps
//
// How it works:
//   1. A default allow-all entry is added for the node IP to ensure local node traffic is always permitted.
//   2. The list of firewall rules is sorted by prefix length in ascending order. This is crucial for
//      handling overlapping CIDRs because longest-prefix matches win in LPM TRIE.
//   3. Each rule is normalized:
//        - Ensures all entries contain a /mask (using hostMask if omitted).
//        - Filters out IPv4 rules in IPv6 clusters and vice versa.
//        - For rules without any L4 port info, a catch-all rule is inserted to match all traffic.
//   4. For any rule whose CIDR is more specific (e.g., /24) and falls within a broader one (e.g., /16),
//      we check existing rules in the map to see if it matches a prior CIDR. If it does and is not part of
//      that CIDR's "except" list, we inherit the broader rule's ports into the current one.
//      This ensures that the specific CIDR behaves consistently with the broader scope's intent.
//   5. We then handle all `except` CIDRs at the end.
//        - If not already in the map, each `except` CIDR is added explicitly with a deny-all L4 entry.
//        - This ensures specific excluded IP ranges override broader allow rules correctly in the LPM match tree.
//   6. Finally, all CIDRs are encoded into trie keys and their corresponding merged/derived L4 info is encoded
//      into the values, forming the output map.

func (f *FirewallRuleProcessor) ComputeMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {

	firewallMap := make(map[string][]byte)
	cidrsMap := make(map[string]EbpfFirewallRules)
	exceptCidrs := make(map[string]struct{})
	nonHostCIDRs := make(map[string]EbpfFirewallRules)

	//Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	_, mapKey, _ := net.ParseCIDR(f.nodeIP + f.hostMask)
	key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
	value := utils.ComputeTrieValue([]v1alpha1.Port{}, true, false)
	firewallMap[string(key)] = value

	//Sort the rules
	sortFirewallRulesByPrefixLength(firewallRules, f.hostMask)

	for _, firewallRule := range firewallRules {
		// Keep track of except CIDRs to handle later
		for _, exceptCidr := range firewallRule.Except {
			exceptCidrs[string(exceptCidr)] = struct{}{}
		}

		var cidrL4Info []v1alpha1.Port

		if !strings.Contains(string(firewallRule.IPCidr), "/") {
			firewallRule.IPCidr += v1alpha1.NetworkAddress(f.hostMask)
		}

		if utils.IsNodeIP(f.nodeIP, string(firewallRule.IPCidr)) {
			continue
		}

		if f.enableIPv6 && !strings.Contains(string(firewallRule.IPCidr), "::") {
			log().Debugf("Skipping ipv4 rule in ipv6 cluster CIDR: %s", string(firewallRule.IPCidr))
			continue
		}

		if !f.enableIPv6 && strings.Contains(string(firewallRule.IPCidr), "::") {
			log().Debugf("Skipping ipv6 rule in ipv4 cluster CIDR: %s", string(firewallRule.IPCidr))
			continue
		}

		// If no L4 specified add catch all entry
		if len(firewallRule.L4Info) == 0 {
			log().Debugf("No L4 specified. Add Catch all entry CIDR: %s", string(firewallRule.IPCidr))
			addCatchAllL4Entry(&firewallRule)
		}

		if existingFirewallRuleInfo, ok := cidrsMap[string(firewallRule.IPCidr)]; ok {
			firewallRule.L4Info = append(firewallRule.L4Info, existingFirewallRuleInfo.L4Info...)
			firewallRule.Except = append(firewallRule.Except, existingFirewallRuleInfo.Except...)
		} else {
			// Check if the /m entry is part of any /n CIDRs that we've encountered so far
			// If found, we need to include the port and protocol combination against the current entry as well since
			// we use LPM TRIE map and the /m will always win out.
			cidrL4Info = checkAndDeriveL4InfoFromAnyMatchingCIDRs(string(firewallRule.IPCidr), nonHostCIDRs)
			if len(cidrL4Info) > 0 {
				firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
			}
		}
		cidrsMap[string(firewallRule.IPCidr)] = firewallRule
		if utils.IsNonHostCIDR(string(firewallRule.IPCidr)) {
			nonHostCIDRs[string(firewallRule.IPCidr)] = firewallRule
		}
	}

	// Go through except CIDRs and append DENY all rule to the L4 info
	for exceptCidr := range exceptCidrs {
		if _, ok := cidrsMap[exceptCidr]; !ok {
			exceptFirewall := EbpfFirewallRules{
				IPCidr: v1alpha1.NetworkAddress(exceptCidr),
				Except: []v1alpha1.NetworkAddress{},
				L4Info: []v1alpha1.Port{},
			}
			addDenyAllL4Entry(&exceptFirewall)
			cidrsMap[exceptCidr] = exceptFirewall
		}
		log().Debugf("Parsed Except CIDR: %s", exceptCidr)
	}

	for key, value := range cidrsMap {
		log().Infof("Updating Map with IP Key: %s", string(key))
		_, firewallMapKey, _ := net.ParseCIDR(string(key))
		// Key format: Prefix length (4 bytes) followed by 4/16byte IP address
		firewallKey := utils.ComputeTrieKey(*firewallMapKey, f.enableIPv6)

		if len(value.L4Info) != 0 {
			value.L4Info = mergeDuplicateL4Info(value.L4Info)
		}
		firewallMap[string(firewallKey)] = utils.ComputeTrieValue(value.L4Info, false, false)
	}

	return firewallMap, nil
}

// sorting Firewall Rules in Ascending Order of Prefix length
func sortFirewallRulesByPrefixLength(rules []EbpfFirewallRules, prefixLenStr string) {
	sort.Slice(rules, func(i, j int) bool {

		prefixSplit := strings.Split(prefixLenStr, "/")
		prefixLen, _ := strconv.Atoi(prefixSplit[1])
		prefixLenIp1 := prefixLen
		prefixLenIp2 := prefixLen

		if strings.Contains(string(rules[i].IPCidr), "/") {
			prefixIp1 := strings.Split(string(rules[i].IPCidr), "/")
			prefixLenIp1, _ = strconv.Atoi(prefixIp1[1])

		}

		if strings.Contains(string(rules[j].IPCidr), "/") {

			prefixIp2 := strings.Split(string(rules[j].IPCidr), "/")
			prefixLenIp2, _ = strconv.Atoi(prefixIp2[1])
		}

		return prefixLenIp1 < prefixLenIp2
	})
}

func addCatchAllL4Entry(firewallRule *EbpfFirewallRules) {
	catchAllL4Entry := v1alpha1.Port{
		Protocol: &CATCH_ALL_PROTOCOL,
	}
	firewallRule.L4Info = append(firewallRule.L4Info, catchAllL4Entry)
}

func addDenyAllL4Entry(firewallRule *EbpfFirewallRules) {
	denyAllL4Entry := v1alpha1.Port{
		Protocol: &DENY_ALL_PROTOCOL,
	}
	firewallRule.L4Info = append(firewallRule.L4Info, denyAllL4Entry)
}

func checkAndDeriveL4InfoFromAnyMatchingCIDRs(firewallRule string,
	cidrsMap map[string]EbpfFirewallRules) []v1alpha1.Port {
	var matchingCIDRL4Info []v1alpha1.Port

	_, ipToCheck, _ := net.ParseCIDR(firewallRule)
	for cidr, cidrFirewallInfo := range cidrsMap {
		_, cidrEntry, _ := net.ParseCIDR(cidr)
		if cidrEntry.Contains(ipToCheck.IP) {
			log().Debugf("Found CIDR match or IP: %s in CIDR: %s", firewallRule, cidr)
			// If CIDR contains IP, check if it is part of any except block under CIDR. If yes, do not include cidrL4Info
			foundInExcept := false
			for _, except := range cidrFirewallInfo.Except {
				_, exceptEntry, _ := net.ParseCIDR(string(except))
				if exceptEntry.Contains(ipToCheck.IP) {
					foundInExcept = true
					log().Debugf("Found IP: %s in except block %s of CIDR %s. Skipping CIDR match", firewallRule, string(except), cidr)
					break
				}
			}
			if !foundInExcept {
				matchingCIDRL4Info = append(matchingCIDRL4Info, cidrFirewallInfo.L4Info...)
			}
		}
	}
	return matchingCIDRL4Info
}

func mergeDuplicateL4Info(ports []v1alpha1.Port) []v1alpha1.Port {
	uniquePorts := make(map[string]v1alpha1.Port)
	var result []v1alpha1.Port
	var key string

	for _, p := range ports {

		portKey := 0
		endPortKey := 0

		if p.Port != nil {
			portKey = int(*p.Port)
		}

		if p.EndPort != nil {
			endPortKey = int(*p.EndPort)
		}
		if p.Protocol == nil {
			key = fmt.Sprintf("%s-%d-%d", "", portKey, endPortKey)
		} else {
			key = fmt.Sprintf("%s-%d-%d", *p.Protocol, portKey, endPortKey)
		}

		if _, ok := uniquePorts[key]; ok {
			continue
		} else {
			uniquePorts[key] = p
		}
	}

	for _, port := range uniquePorts {
		result = append(result, port)
	}

	return result
}
