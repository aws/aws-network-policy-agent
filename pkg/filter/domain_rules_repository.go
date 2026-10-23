package filter

import (
	"strings"
	"sync"

	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// SetPolicyEndpointDomains sets domains from PolicyEndpointController
// PolicyEndpointController will pass domainNames, there is no real meaning of Priority or Action for these
func SetPolicyEndpointDomains(podIdentifier string, domainFWRules []fwrp.EbpfFirewallRules) error {
	dnsProxyRules := ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(domainFWRules)
	log().Debugf("DNS proxy rules for PodId %s : %+v", podIdentifier, dnsProxyRules)
	setDNSProxyRulesFromController(podIdentifier, "policyEndpoints", dnsProxyRules)
	return nil
}

// DeletePolicyEndpointDomains removes domains set by PolicyEndpointController
func DeletePolicyEndpointDomains(podIdentifier string) {
	deleteDomainsForController(podIdentifier, "policyEndpoints")
}

// SetClusterPolicyEndpointDomains sets domains from ClusterPolicyEndpointController
// ClusterPolicyEndpointController will pass domainNames where Priority and Action needs to be honored
func SetClusterPolicyEndpointDomains(podIdentifier string, domainFWRules []fwrp.EbpfFirewallRules) error {
	dnsProxyRules := ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE(domainFWRules)
	log().Debugf("DNS proxy rules for PodId %s : %+v", podIdentifier, dnsProxyRules)
	setDNSProxyRulesFromController(podIdentifier, "clusterPolicyEndpoints", dnsProxyRules)
	return nil
}

// DeletePolicyEndpointDomains removes domains set by PolicyEndpointController
func DeleteClusterPolicyEndpointDomains(podIdentifier string) {
	deleteDomainsForController(podIdentifier, "clusterPolicyEndpoints")
}

// setDNSProxyRulesFromController is the internal implementation for setting domains for a specific controller
func setDNSProxyRulesFromController(podIdentifier string, controllerId string, dnsProxyRules map[string][]npatypes.L4Rule) {
	// Lock for this specific podId
	lock := getPodIdentifierLock(podIdentifier)
	lock.Lock()
	defer lock.Unlock()

	// 1. Parse domains into exact and pattern maps
	exactMap := make(domainL4Map)
	patternMap := make(domainL4Map)

	for domain, l4Rule := range dnsProxyRules {
		if strings.HasPrefix(domain, "*.") {
			patternMap[domain] = l4Rule
		} else {
			exactMap[domain] = l4Rule
		}
	}

	// 2. Store this controller's domains
	ctlrDomains := controllerDNSProxyRules{
		exactDomains:   exactMap,
		patternDomains: patternMap,
	}

	// 3. Update the controller-specific storage
	var controllerMap map[string]controllerDNSProxyRules
	if existing, ok := podControllerFilters.Load(podIdentifier); ok {
		controllerMap = existing.(map[string]controllerDNSProxyRules)
	} else {
		controllerMap = make(map[string]controllerDNSProxyRules)
	}

	controllerMap[controllerId] = ctlrDomains
	podControllerFilters.Store(podIdentifier, controllerMap)

	// 4. Trigger merge and update cached filter
	mergeAndCacheFilter(podIdentifier)
}

// deleteDomainsForController is the internal implementation for deleting domains for a specific controller
func deleteDomainsForController(podIdentifier string, controllerId string) {
	// Lock for this specific podId
	lock := getPodIdentifierLock(podIdentifier)
	lock.Lock()
	defer lock.Unlock()

	controllerMapInterface, ok := podControllerFilters.Load(podIdentifier)
	if !ok {
		return
	}

	controllerMap := controllerMapInterface.(map[string]controllerDNSProxyRules)
	delete(controllerMap, controllerId)

	if len(controllerMap) == 0 {
		// No more controllers, clean up everything
		podControllerFilters.Delete(podIdentifier)
		podMergedFilters.Delete(podIdentifier)
		// Clean up the lock as well since pod is no longer needed
		podLocks.Delete(podIdentifier)
	} else {
		// Update and re-merge
		podControllerFilters.Store(podIdentifier, controllerMap)
		mergeAndCacheFilter(podIdentifier)
	}
}

func mergeAndCacheFilter(podId string) {
	controllerMapInterface, ok := podControllerFilters.Load(podId)
	if !ok {
		// No controllers for this pod, remove cached filter
		podMergedFilters.Delete(podId)
		return
	}

	controllerMap := controllerMapInterface.(map[string]controllerDNSProxyRules)

	// Merge all controllers' domains
	mergedExactMap := make(domainL4Map)
	mergedPatternMap := make(domainL4Map)

	for _, domains := range controllerMap {
		// Merge exact domains
		for domain, l4InfoStruct := range domains.exactDomains {
			if existing, exists := mergedExactMap[domain]; exists {
				// Handle conflicts - use union of ports and higher priority
				mergedExactMap[domain] = mergeL4Rules(existing, l4InfoStruct)
			} else {
				mergedExactMap[domain] = l4InfoStruct
			}
		}

		// Merge pattern domains
		for pattern, l4InfoStruct := range domains.patternDomains {
			if existing, exists := mergedPatternMap[pattern]; exists {
				mergedPatternMap[pattern] = mergeL4Rules(existing, l4InfoStruct)
			} else {
				mergedPatternMap[pattern] = l4InfoStruct
			}
		}
	}

	// Create merged filter
	mergedFilter := &Filter{}
	mergedFilter.matchName.Store(&mergedExactMap)
	mergedFilter.matchPattern.Store(&mergedPatternMap)

	// Cache the merged result
	podMergedFilters.Store(podId, mergedFilter)
}

// todo (optimization) - revisit cross controller L4Rule merge
// for same domainName, if there is same port Info coming from CPE and PE. Then PE port info can be skipped
func mergeL4Rules(existing, new []npatypes.L4Rule) []npatypes.L4Rule {
	return append(existing, new...)
}

var podControllerFilters sync.Map // podId -> map[controllerId]ControllerDomains
var podMergedFilters sync.Map     // podId -> *Filter (cached merged result)
var podLocks sync.Map             // podId -> *sync.Mutex (per-pod locks)

// getPodIdentifierLock returns or creates a mutex for the given podId
func getPodIdentifierLock(podId string) *sync.Mutex {
	lock, _ := podLocks.LoadOrStore(podId, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// controllerDNSProxyRules stores proxy rules for a specific controller
type controllerDNSProxyRules struct {
	exactDomains   domainL4Map
	patternDomains domainL4Map
}

func HasAnyDomainRules(podIdentifier string) bool {
	_, exists := podMergedFilters.Load(podIdentifier)
	return exists
}

// HasPolicyEndpointDomains checks if PolicyEndpointController has set any domain rules for the pod
func HasPolicyEndpointDomains(podIdentifier string) bool {
	return hasDomainsForController(podIdentifier, "policyEndpoints")
}

// HasClusterPolicyEndpointDomains checks if ClusterPolicyEndpointController has set any domain rules for the pod
func HasClusterPolicyEndpointDomains(podIdentifier string) bool {
	return hasDomainsForController(podIdentifier, "clusterPolicyEndpoints")
}

// hasDomainsForController checks if a specific controller has set any domain rules for the pod
func hasDomainsForController(podIdentifier string, controllerId string) bool {
	controllerMapInterface, ok := podControllerFilters.Load(podIdentifier)
	if !ok {
		return false
	}

	controllerMap := controllerMapInterface.(map[string]controllerDNSProxyRules)
	domains, exists := controllerMap[controllerId]
	if !exists {
		return false
	}

	// Check if there are any exact or pattern domains
	return len(domains.exactDomains) > 0 || len(domains.patternDomains) > 0
}
