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
	CATCH_ALL_PROTOCOL            corev1.Protocol = "ANY_IP_PROTOCOL"
	DENY_ALL_PROTOCOL             corev1.Protocol = "RESERVED_IP_PROTOCOL_NUMBER"
	BASELINE_TIER_PRIORITY_OFFSET int             = 2000 // Baseline cluster policy rules will have priority offset of 2000
)

type EbpfFirewallRules struct {
	Priority   int
	Action     v1alpha1.ClusterNetworkPolicyRuleAction
	DomainName string
	IPCidr     v1alpha1.NetworkAddress
	Except     []v1alpha1.NetworkAddress
	L4Info     []v1alpha1.Port
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
//        - If not already in the map, each `except` CIDR is added explicitly. It keeps the ports of other
//          rules that cover the whole except range, and gets a deny-all L4 entry only when none do.
//        - This ensures specific excluded IP ranges override broader allow rules correctly in the LPM match tree.
//   6. Finally, all CIDRs are encoded into trie keys and their corresponding merged/derived L4 info is encoded
//      into the values, forming the output map.

func (f *FirewallRuleProcessor) ComputeMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {

	firewallMap := make(map[string][]byte)
	cidrsMap := make(map[string]EbpfFirewallRules)
	exceptCidrs := make(map[string]struct{})
	// nonHostCIDRs maps a canonical non-host CIDR to the list of individual rules
	// that contributed to it. We keep the contributions separate (rather than a
	// single merged rule) so that each rule's Except list stays paired with the
	// exact ports that rule allowed. This matters when two rules canonicalize to
	// the same CIDR (e.g. 10.0.0.0/8 and 10.161.0.0/8): one rule's except must not
	// suppress another rule's ports when a narrower CIDR inherits coverage.
	nonHostCIDRs := make(map[string][]EbpfFirewallRules)
	containmentTrie := newCIDRTrie()

	//Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	_, mapKey, _ := net.ParseCIDR(f.nodeIP + f.hostMask)
	key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
	value := utils.ComputeTrieValue([]v1alpha1.Port{}, true, false)
	firewallMap[string(key)] = value

	//Sort the rules
	sortFirewallRulesByPrefixLength(firewallRules, f.hostMask)

	for _, firewallRule := range firewallRules {
		var cidrL4Info []v1alpha1.Port

		if !strings.Contains(string(firewallRule.IPCidr), "/") {
			firewallRule.IPCidr += v1alpha1.NetworkAddress(f.hostMask)
		}

		// Canonicalize the CIDR (mask off host bits) before it is used as the
		// cidrsMap key. A rule expressed with host bits set - e.g. 10.161.0.0/8,
		// which a /8 mask reduces to the network 10.0.0.0/8 - would otherwise be
		// keyed by its raw string and treated as distinct from 10.0.0.0/8. Their
		// L4 (port) sets would never be merged, and because both encode to the
		// identical LPM trie key, the final map write silently overwrites one
		// with the other in Go's randomized map-iteration order, producing
		// non-deterministic port enforcement across reconciliations. Masking here
		// makes such rules share a key so their ports are merged deterministically.
		if _, ipNet, err := net.ParseCIDR(string(firewallRule.IPCidr)); err == nil {
			firewallRule.IPCidr = v1alpha1.NetworkAddress(ipNet.String())
		}

		if f.shouldSkipRule(string(firewallRule.IPCidr)) {
			continue
		}

		// Track this rule's except CIDRs to handle later.
		for _, exceptCidr := range firewallRule.Except {
			exceptCidrs[string(exceptCidr)] = struct{}{}
		}

		// If no L4 specified add catch all entry
		if len(firewallRule.L4Info) == 0 {
			log().Debugf("No L4 specified. Add Catch all entry CIDR: %s", string(firewallRule.IPCidr))
			addCatchAllL4Entry(&firewallRule)
		}

		// Capture this rule's own ports/except before any merging so the
		// contribution we record for inheritance keeps its Except paired with
		// exactly the ports this rule allowed.
		contribution := firewallRule

		if existingFirewallRuleInfo, ok := cidrsMap[string(firewallRule.IPCidr)]; ok {
			// Two rules canonicalize to the same CIDR. The broad CIDR's own entry
			// allows the union of both port sets. We intentionally do NOT union
			// the Except lists here: an except expresses "this rule does not cover
			// that sub-range", and that statement belongs only to the rule it came
			// from. Unioning excepts would let one rule's except suppress another
			// rule's ports when a narrower CIDR inherits coverage (issue #743),
			// which fails OPEN in some cases and OVER-restricts in others. Each
			// rule's (ports, except) pair is kept separately in nonHostCIDRs.
			firewallRule.L4Info = append(firewallRule.L4Info, existingFirewallRuleInfo.L4Info...)
		} else {
			cidrL4Info = checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(string(firewallRule.IPCidr), containmentTrie, nonHostCIDRs)
			if len(cidrL4Info) > 0 {
				firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
			}
		}
		cidrsMap[string(firewallRule.IPCidr)] = firewallRule
		if utils.IsNonHostCIDR(string(firewallRule.IPCidr)) {
			_, alreadyInTrie := nonHostCIDRs[string(firewallRule.IPCidr)]
			// Append this rule as a distinct contribution rather than overwriting,
			// so every rule that shares this canonical CIDR keeps its own except
			// scope for inheritance decisions.
			nonHostCIDRs[string(firewallRule.IPCidr)] = append(nonHostCIDRs[string(firewallRule.IPCidr)], contribution)
			if !alreadyInTrie {
				containmentTrie.insert(string(firewallRule.IPCidr))
			}
		}
	}

	// Go through except CIDRs and append DENY all rule to the L4 info
	for exceptCidr := range exceptCidrs {
		canonicalExcept := exceptCidr
		if _, ipNet, err := net.ParseCIDR(exceptCidr); err == nil {
			canonicalExcept = ipNet.String()
		}
		if _, ok := cidrsMap[canonicalExcept]; !ok {
			exceptFirewall := EbpfFirewallRules{
				IPCidr: v1alpha1.NetworkAddress(canonicalExcept),
				Except: []v1alpha1.NetworkAddress{},
				L4Info: []v1alpha1.Port{},
			}
			// An except only removes the ports of the rule that declared it. Other
			// rules covering the whole except range still allow their ports there
			// (issue #743), so carry those over and deny-all only when none remain.
			if inherited := checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(canonicalExcept, containmentTrie, nonHostCIDRs); len(inherited) > 0 {
				exceptFirewall.L4Info = append(exceptFirewall.L4Info, inherited...)
			} else {
				addDenyAllL4Entry(&exceptFirewall)
			}
			cidrsMap[canonicalExcept] = exceptFirewall
		}
		log().Debugf("Parsed Except CIDR: %s (canonical: %s)", exceptCidr, canonicalExcept)
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
// SliceStable is used so that rules sharing the same prefix length retain a
// deterministic relative order; this keeps the L4-info inheritance in
// checkAndDeriveL4InfoFromAnyMatchingCIDRs stable across runs.
func sortFirewallRulesByPrefixLength(rules []EbpfFirewallRules, prefixLenStr string) {
	sort.SliceStable(rules, func(i, j int) bool {

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

// checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie returns the ports a narrower CIDR
// should inherit from every broader non-host CIDR that contains it.
//
// Each broader CIDR may have been built from several ipBlock rules that
// canonicalize to the same key. Those rules are kept as separate contributions
// in nonHostCIDRs, and each contribution's Except list is evaluated on its own:
// a contribution's ports are inherited only when the target is NOT inside that
// contribution's except. This keeps an except scoped to the rule it came from,
// so one rule excepting a sub-range cannot suppress a different rule's ports for
// the same canonical CIDR (issue #743).
func checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(firewallRule string,
	trie *cidrTrie, nonHostCIDRs map[string][]EbpfFirewallRules) []v1alpha1.Port {
	var matchingCIDRL4Info []v1alpha1.Port

	_, ipToCheck, err := net.ParseCIDR(firewallRule)
	if err != nil || ipToCheck == nil {
		return matchingCIDRL4Info
	}

	containingKeys := trie.findContainingKeys(ipToCheck.IP)
	targetOnes, _ := ipToCheck.Mask.Size()

	for _, cidrKey := range containingKeys {
		contributions, ok := nonHostCIDRs[cidrKey]
		if !ok {
			continue
		}
		// Only CIDRs at least as broad as the target cover all of it. During the
		// main pass rules are sorted by prefix length, so this always holds; the
		// except pass runs after every rule is in the trie and needs the guard so
		// a narrower rule (e.g. a /24 at the start of an excepted /16) does not
		// spread its ports across the whole except range.
		if _, keyNet, err := net.ParseCIDR(cidrKey); err == nil {
			if keyOnes, _ := keyNet.Mask.Size(); keyOnes > targetOnes {
				continue
			}
		}
		for _, cidrFirewallInfo := range contributions {
			foundInExcept := false
			for _, except := range cidrFirewallInfo.Except {
				_, exceptEntry, _ := net.ParseCIDR(string(except))
				if exceptEntry != nil && exceptEntry.Contains(ipToCheck.IP) {
					foundInExcept = true
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
	type portKey struct {
		protocol string
		port     int
		endPort  int
	}
	uniquePorts := make(map[portKey]v1alpha1.Port, len(ports))
	result := make([]v1alpha1.Port, 0, len(ports))

	for _, p := range ports {

		pk := portKey{}

		if p.Port != nil {
			pk.port = int(*p.Port)
		}

		if p.EndPort != nil {
			pk.endPort = int(*p.EndPort)
		}
		if p.Protocol != nil {
			pk.protocol = string(*p.Protocol)
		}

		if _, ok := uniquePorts[pk]; ok {
			continue
		} else {
			uniquePorts[pk] = p
		}
	}

	for _, port := range uniquePorts {
		result = append(result, port)
	}

	return result
}

func (f *FirewallRuleProcessor) ComputeClusterPolicyMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {
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
		overlappingCIDR := f.findMostSpecificOverlap(cidr, processedCIDRs)

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

func (f *FirewallRuleProcessor) normalizeCIDR(cidr string) string {
	if !strings.Contains(cidr, "/") {
		cidr = cidr + f.hostMask
	}
	if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
		return ipNet.String()
	}
	return cidr
}

func (f *FirewallRuleProcessor) shouldSkipRule(cidr string) bool {
	if utils.IsNodeIP(f.nodeIP, cidr) {
		return true
	}
	isIPv6CIDR := isIPv6(cidr)
	if f.enableIPv6 && !isIPv6CIDR {
		log().Debugf("Skipping ipv4 rule in ipv6 cluster CIDR: %s", cidr)
		return true
	}
	if !f.enableIPv6 && isIPv6CIDR {
		log().Debugf("Skipping ipv6 rule in ipv4 cluster CIDR: %s", cidr)
		return true
	}
	return false
}

func (f *FirewallRuleProcessor) sortByCIDRLength(rules []EbpfFirewallRules) {
	sort.SliceStable(rules, func(i, j int) bool {
		cidrI := f.normalizeCIDR(string(rules[i].IPCidr))
		cidrJ := f.normalizeCIDR(string(rules[j].IPCidr))

		prefixI := f.getPrefixLength(cidrI)
		prefixJ := f.getPrefixLength(cidrJ)

		return prefixI < prefixJ // Bigger to smaller (/16 before /32)
	})
}

func (f *FirewallRuleProcessor) getPrefixLength(cidr string) int {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return 32 // Default for IPv4
	}
	prefixLen, _ := strconv.Atoi(parts[1])
	return prefixLen
}

func (f *FirewallRuleProcessor) findMostSpecificOverlap(currentCIDR string, processedCIDRs []string) string {
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

func (f *FirewallRuleProcessor) removeDuplicateL4Rules(l4Rules []utils.L4Rule) []utils.L4Rule {

	uniquePorts := make(map[string]utils.L4Rule)
	var result []utils.L4Rule
	var key string

	for _, p := range l4Rules {

		portKey := 0
		endPortKey := 0

		if p.L4PortProtocolInfo.Port != nil {
			portKey = int(*p.L4PortProtocolInfo.Port)
		}

		if p.L4PortProtocolInfo.EndPort != nil {
			endPortKey = int(*p.L4PortProtocolInfo.EndPort)
		}

		if p.L4PortProtocolInfo.Protocol == nil {
			key = fmt.Sprintf("%s-%d-%d-%d-%s", "TCP", portKey, endPortKey, p.Priority, p.Action)
		} else {
			key = fmt.Sprintf("%v-%d-%d-%d-%s", p.L4PortProtocolInfo.Protocol, portKey, endPortKey, p.Priority, p.Action)
		}

		if _, ok := uniquePorts[key]; ok {
			continue
		} else {
			uniquePorts[key] = p
		}
	}

	for _, rule := range uniquePorts {
		result = append(result, rule)
	}

	return result
}

// isIPv6 returns true if the given CIDR or IP address is IPv6.
func isIPv6(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
	}
	return ip != nil && ip.To4() == nil
}
