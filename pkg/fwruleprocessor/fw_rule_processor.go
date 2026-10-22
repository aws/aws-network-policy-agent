package fwruleprocessor

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
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

type parsedFirewallRule struct {
	EbpfFirewallRules
	prefix     netip.Prefix
	prefixBits int // NP sorts original widths; CNP uses canonical widths.
	except     []netip.Prefix
}

type FirewallRuleProcessor struct {
	// Primary IP of the node
	nodeIP   netip.Addr
	hostMask string
	// Flag to track the IPv6 mode
	enableIPv6 bool
}

func NewFirewallRuleProcessor(nodeIP string, hostMask string, enableIPv6 bool) *FirewallRuleProcessor {
	address, _ := netip.ParseAddr(nodeIP)
	fwrp := &FirewallRuleProcessor{
		nodeIP:     address,
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
	cidrsMap := make(map[netip.Prefix]parsedFirewallRule)
	exceptCidrs := make(map[netip.Prefix]struct{})
	nonHostCIDRs := make(map[netip.Prefix]parsedFirewallRule)
	containmentTrie := newCIDRTrie()

	//Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	nodePrefix, err := parsePrefix(f.nodeIP.String() + f.hostMask)
	if err != nil {
		return nil, fmt.Errorf("parse node CIDR: %w", err)
	}
	key := computeTrieKey(nodePrefix.Masked(), f.enableIPv6)
	value := utils.ComputeTrieValue([]v1alpha1.Port{}, true, false)
	firewallMap[string(key)] = value

	rules, err := f.parseRules(firewallRules)
	if err != nil {
		return nil, err
	}
	sortFirewallRulesByPrefixLength(rules)
	for i, rule := range rules {
		firewallRules[i] = rule.EbpfFirewallRules
	}

	for _, firewallRule := range rules {
		var cidrL4Info []v1alpha1.Port

		if f.shouldSkipRule(firewallRule.prefix) {
			continue
		}

		// Track this rule's except CIDRs to handle later.
		for _, exceptCidr := range firewallRule.Except {
			prefix, err := parsePrefix(string(exceptCidr))
			if err != nil {
				return nil, fmt.Errorf("parse except CIDR %q: %w", exceptCidr, err)
			}
			prefix = canonicalPrefix(prefix)
			firewallRule.except = append(firewallRule.except, prefix)
			exceptCidrs[prefix] = struct{}{}
		}

		// If no L4 specified add catch all entry
		if len(firewallRule.L4Info) == 0 {
			log().Debugf("No L4 specified. Add Catch all entry CIDR: %s", firewallRule.prefix)
			addCatchAllL4Entry(&firewallRule.EbpfFirewallRules)
		}

		if existingFirewallRuleInfo, ok := cidrsMap[firewallRule.prefix]; ok {
			firewallRule.L4Info = append(firewallRule.L4Info, existingFirewallRuleInfo.L4Info...)
			firewallRule.except = append(firewallRule.except, existingFirewallRuleInfo.except...)
		} else {
			cidrL4Info = checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(firewallRule.prefix, containmentTrie, nonHostCIDRs)
			if len(cidrL4Info) > 0 {
				firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
			}
		}
		cidrsMap[firewallRule.prefix] = firewallRule
		// Preserve the existing exclusion of /32 and /128 from inheritance.
		if firewallRule.prefix.Bits() != 32 && firewallRule.prefix.Bits() != 128 {
			_, alreadyInTrie := nonHostCIDRs[firewallRule.prefix]
			nonHostCIDRs[firewallRule.prefix] = firewallRule
			if !alreadyInTrie {
				containmentTrie.insert(firewallRule.prefix)
			}
		}
	}

	// Go through except CIDRs and append DENY all rule to the L4 info
	for exceptCidr := range maps.Keys(exceptCidrs) {
		if _, ok := cidrsMap[exceptCidr]; !ok {
			exceptFirewall := EbpfFirewallRules{}
			addDenyAllL4Entry(&exceptFirewall)
			cidrsMap[exceptCidr] = parsedFirewallRule{EbpfFirewallRules: exceptFirewall, prefix: exceptCidr}
		}
		log().Debugf("Parsed Except CIDR: %s", exceptCidr)
	}

	for key, value := range cidrsMap {
		log().Infof("Updating Map with IP Key: %s", key)
		// Key format: Prefix length (4 bytes) followed by 4/16byte IP address
		firewallKey := computeTrieKey(key, f.enableIPv6)

		if len(value.L4Info) != 0 {
			value.L4Info = mergeDuplicateL4Info(value.L4Info)
		}
		firewallMap[string(firewallKey)] = utils.ComputeTrieValue(value.L4Info, false, false)
	}

	return firewallMap, nil
}

// Stable prefix order preserves L4 inheritance between equally specific rules.
func sortFirewallRulesByPrefixLength(rules []parsedFirewallRule) {
	slices.SortStableFunc(rules, func(a, b parsedFirewallRule) int {
		return cmp.Compare(a.prefixBits, b.prefixBits)
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

func checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(firewallRule netip.Prefix,
	trie *cidrTrie, nonHostCIDRs map[netip.Prefix]parsedFirewallRule) []v1alpha1.Port {
	var matchingCIDRL4Info []v1alpha1.Port

	containingKeys := trie.findContainingKeys(firewallRule.Addr())

	for _, cidrKey := range containingKeys {
		cidrFirewallInfo, ok := nonHostCIDRs[cidrKey]
		if !ok {
			continue
		}
		foundInExcept := false
		for _, except := range cidrFirewallInfo.except {
			if except.Contains(firewallRule.Addr()) {
				foundInExcept = true
				break
			}
		}
		if !foundInExcept {
			matchingCIDRL4Info = append(matchingCIDRL4Info, cidrFirewallInfo.L4Info...)
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
	cidrL4Rules := make(map[netip.Prefix][]utils.L4Rule)
	processedCIDRs := make([]netip.Prefix, 0)

	// Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	// This ensures kubelet liveness/readiness probes are never blocked by cluster network policies.
	nodePrefix, err := parsePrefix(f.nodeIP.String() + f.hostMask)
	if err != nil {
		return nil, fmt.Errorf("parse node CIDR: %w", err)
	}
	key := computeTrieKey(nodePrefix.Masked(), f.enableIPv6)
	nodeIPL4Rule := []utils.L4Rule{
		{
			Action:   "Accept",
			Priority: 0, // Highest priority — node-IP allow must not be overridden
		},
	}
	value := utils.ComputeTrieValueForCPE(nodeIPL4Rule)
	firewallMap[string(key)] = value

	// Step 1: Sort by CIDR length
	rules, err := f.parseRules(firewallRules)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].prefix.IsValid() {
			rules[i].prefixBits = rules[i].prefix.Bits()
		}
	}
	sortFirewallRulesByPrefixLength(rules)
	for i, rule := range rules {
		firewallRules[i] = rule.EbpfFirewallRules
	}

	// Step 2-3: Process each CIDR and handle overlaps
	for _, rule := range rules {

		cidr := rule.prefix
		if f.shouldSkipRule(cidr) {
			continue
		}

		// Find the most specific overlapping CIDR
		overlappingCIDR := findMostSpecificOverlap(cidr, processedCIDRs)

		// Copy L4 rules from overlapping CIDR if found
		if overlappingCIDR.IsValid() {
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

		firewallKey := computeTrieKey(cidr, f.enableIPv6)

		firewallValue := utils.ComputeTrieValueForCPE(resolvedL4Rules)
		firewallMap[string(firewallKey)] = firewallValue
	}

	return firewallMap, nil
}

func (f *FirewallRuleProcessor) parseRules(rules []EbpfFirewallRules) ([]parsedFirewallRule, error) {
	parsed := make([]parsedFirewallRule, 0, len(rules))
	for _, rule := range rules {
		cidr := string(rule.IPCidr)
		if !strings.Contains(cidr, "/") {
			cidr += f.hostMask
		}
		prefix, err := parsePrefix(cidr)
		if err != nil {
			// IPv6 mode previously skipped bare IPv4 addresses with its /128 host mask.
			if address, addrErr := netip.ParseAddr(string(rule.IPCidr)); f.enableIPv6 && addrErr == nil && address.Is4() {
				bits, maskErr := strconv.Atoi(strings.TrimPrefix(f.hostMask, "/"))
				if maskErr != nil {
					return nil, fmt.Errorf("parse host mask %q: %w", f.hostMask, maskErr)
				}
				parsed = append(parsed, parsedFirewallRule{EbpfFirewallRules: rule, prefixBits: bits})
				continue
			}
			return nil, fmt.Errorf("parse rule CIDR %q: %w", rule.IPCidr, err)
		}
		parsed = append(parsed, parsedFirewallRule{
			EbpfFirewallRules: rule,
			prefix:            canonicalPrefix(prefix),
			prefixBits:        prefix.Bits(),
		})
	}
	return parsed, nil
}

func parsePrefix(cidr string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err == nil {
		return prefix, nil
	}
	// Keep spellings accepted by net.ParseCIDR, such as zero-padded prefix lengths.
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return netip.Prefix{}, err
	}
	address, _ := netip.AddrFromSlice(network.IP)
	bits, _ := network.Mask.Size()
	return netip.PrefixFrom(address, bits), nil
}

func canonicalPrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	// Match net.IPNet.String's IPv4-mapped CIDR normalization.
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix
}

func computeTrieKey(prefix netip.Prefix, enableIPv6 bool) []byte {
	length := utils.TRIE_KEY_LENGTH
	if enableIPv6 {
		length = utils.TRIE_V6_KEY_LENGTH
	}
	key := make([]byte, length)
	binary.LittleEndian.PutUint32(key[:4], uint32(prefix.Bits()))
	if prefix.Addr().Is4() {
		address := prefix.Addr().As4()
		copy(key[4:], address[:])
	} else {
		address := prefix.Addr().As16()
		copy(key[4:], address[:])
	}
	return key
}

func (f *FirewallRuleProcessor) shouldSkipRule(cidr netip.Prefix) bool {
	if f.nodeIP.Unmap() == cidr.Addr() {
		return true
	}
	isIPv6CIDR := cidr.Addr().Is6()
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

func findMostSpecificOverlap(currentCIDR netip.Prefix, processedCIDRs []netip.Prefix) netip.Prefix {
	// Loop from end to start since CIDRs are sorted in ascending order
	for i := len(processedCIDRs) - 1; i >= 0; i-- {
		processedCIDR := processedCIDRs[i]
		// Check if current CIDR is contained within processed CIDR
		if processedCIDR.Contains(currentCIDR.Addr()) {
			return processedCIDR
		}
	}

	return netip.Prefix{}
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
