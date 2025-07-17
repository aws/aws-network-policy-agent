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

var CATCH_ALL_PROTOCOL corev1.Protocol = "ANY_IP_PROTOCOL"

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

func (f *FirewallRuleProcessor) ComputeMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {

	firewallMap := make(map[string][]byte)
	ipCIDRs := make(map[string][]v1alpha1.Port)
	nonHostCIDRs := make(map[string][]v1alpha1.Port)
	isCatchAllIPEntryPresent, allowAll := false, false
	var catchAllIPPorts []v1alpha1.Port

	//Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	_, mapKey, _ := net.ParseCIDR(f.nodeIP + f.hostMask)
	key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
	value := utils.ComputeTrieValue([]v1alpha1.Port{}, true, false)
	firewallMap[string(key)] = value

	//Sort the rules
	sortFirewallRulesByPrefixLength(firewallRules, f.hostMask)

	//Check and aggregate L4 Port Info for Catch All Entries.
	catchAllIPPorts, isCatchAllIPEntryPresent, allowAll = f.checkAndDeriveCatchAllIPPorts(firewallRules)
	if isCatchAllIPEntryPresent {
		//Add the Catch All IP entry
		_, mapKey, _ := net.ParseCIDR("0.0.0.0/0")
		key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
		value := utils.ComputeTrieValue(catchAllIPPorts, allowAll, false)
		firewallMap[string(key)] = value
	}

	for _, firewallRule := range firewallRules {
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

		if !utils.IsCatchAllIPEntry(string(firewallRule.IPCidr)) {
			if len(firewallRule.L4Info) == 0 {
				addCatchAllL4Entry(&firewallRule)
			}
			if utils.IsNonHostCIDR(string(firewallRule.IPCidr)) {
				existingL4Info, ok := nonHostCIDRs[string(firewallRule.IPCidr)]
				if ok {
					firewallRule.L4Info = append(firewallRule.L4Info, existingL4Info...)
				} else {
					// Check if the /m entry is part of any /n CIDRs that we've encountered so far
					// If found, we need to include the port and protocol combination against the current entry as well since
					// we use LPM TRIE map and the /m will always win out.
					cidrL4Info = checkAndDeriveL4InfoFromAnyMatchingCIDRs(string(firewallRule.IPCidr), nonHostCIDRs)
					if len(cidrL4Info) > 0 {
						firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
					}
				}
				nonHostCIDRs[string(firewallRule.IPCidr)] = firewallRule.L4Info
			} else {
				if existingL4Info, ok := ipCIDRs[string(firewallRule.IPCidr)]; ok {
					firewallRule.L4Info = append(firewallRule.L4Info, existingL4Info...)
				}
				// Check if the /32 entry is part of any non host CIDRs that we've encountered so far
				// If found, we need to include the port and protocol combination against the current entry as well since
				// we use LPM TRIE map and the /32 will always win out.
				cidrL4Info = checkAndDeriveL4InfoFromAnyMatchingCIDRs(string(firewallRule.IPCidr), nonHostCIDRs)
				if len(cidrL4Info) > 0 {
					firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
				}
				ipCIDRs[string(firewallRule.IPCidr)] = firewallRule.L4Info
			}
			//Include port and protocol combination paired with catch all entries
			firewallRule.L4Info = append(firewallRule.L4Info, catchAllIPPorts...)

			log().Debugf("Updating Map with IP Key: %s", string(firewallRule.IPCidr))
			_, firewallMapKey, _ := net.ParseCIDR(string(firewallRule.IPCidr))
			// Key format: Prefix length (4 bytes) followed by 4/16byte IP address
			firewallKey := utils.ComputeTrieKey(*firewallMapKey, f.enableIPv6)

			if len(firewallRule.L4Info) != 0 {
				mergedL4Info := mergeDuplicateL4Info(firewallRule.L4Info)
				firewallRule.L4Info = mergedL4Info

			}
			firewallValue := utils.ComputeTrieValue(firewallRule.L4Info, allowAll, false)
			firewallMap[string(firewallKey)] = firewallValue
		}
		if firewallRule.Except != nil {
			for _, exceptCIDR := range firewallRule.Except {
				_, mapKey, _ := net.ParseCIDR(string(exceptCIDR))
				key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
				log().Debugf("Parsed Except CIDR IP Key: %s", mapKey.String())
				if len(firewallRule.L4Info) != 0 {
					mergedL4Info := mergeDuplicateL4Info(firewallRule.L4Info)
					firewallRule.L4Info = mergedL4Info
				}
				value := utils.ComputeTrieValue(firewallRule.L4Info, false, true)
				firewallMap[string(key)] = value
			}
		}
	}

	return firewallMap, nil
}

func (f *FirewallRuleProcessor) checkAndDeriveCatchAllIPPorts(firewallRules []EbpfFirewallRules) ([]v1alpha1.Port, bool, bool) {
	var catchAllL4Info []v1alpha1.Port
	isCatchAllIPEntryPresent := false
	allowAllPortAndProtocols := false
	for _, firewallRule := range firewallRules {
		if !strings.Contains(string(firewallRule.IPCidr), "/") {
			firewallRule.IPCidr += v1alpha1.NetworkAddress(f.hostMask)
		}
		if !f.enableIPv6 && strings.Contains(string(firewallRule.IPCidr), "::") {
			log().Debug("IPv6 catch all entry in IPv4 mode - skip ")
			continue
		}
		if utils.IsCatchAllIPEntry(string(firewallRule.IPCidr)) {
			catchAllL4Info = append(catchAllL4Info, firewallRule.L4Info...)
			isCatchAllIPEntryPresent = true
			if len(firewallRule.L4Info) == 0 {
				//All ports and protocols
				allowAllPortAndProtocols = true
			}
		}
	}
	log().Debugf("Total L4 entry count for catch all entry: count: %d", len(catchAllL4Info))
	return catchAllL4Info, isCatchAllIPEntryPresent, allowAllPortAndProtocols
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

func checkAndDeriveL4InfoFromAnyMatchingCIDRs(firewallRule string,
	nonHostCIDRs map[string][]v1alpha1.Port) []v1alpha1.Port {
	var matchingCIDRL4Info []v1alpha1.Port

	_, ipToCheck, _ := net.ParseCIDR(firewallRule)
	for nonHostCIDR, l4Info := range nonHostCIDRs {
		_, cidrEntry, _ := net.ParseCIDR(nonHostCIDR)
		if cidrEntry.Contains(ipToCheck.IP) {
			log().Debugf("Found a CIDR match for IP: %s in CIDR %s ", firewallRule, nonHostCIDR)
			matchingCIDRL4Info = append(matchingCIDRL4Info, l4Info...)
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
