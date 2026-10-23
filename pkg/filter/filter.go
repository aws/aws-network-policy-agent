package filter

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// This package is referenced by Proxy Plugins (ipfilter) to get the data needed for their business logic

func log() logger.Logger {
	return logger.Get()
}

var BpfClient ebpf.BpfClient

// Filter is per Pod Identifier property
type Filter struct {
	matchName    atomic.Pointer[domainL4Map]
	matchPattern atomic.Pointer[domainL4Map]
}

// IsAllowed implements domain filtering logic for FQDN inputs
// Always checks both exact matches (MatchName) and wildcard patterns (MatchPattern)
// Input domain is always a FQDN, never contains "*"
// Returns whether the domain is allowed and the associated L4Info
func (f *Filter) IsAllowed(domain string) (bool, []npatypes.L4Rule) {
	// Input validation
	if domain == "" {
		return false, []npatypes.L4Rule{}
	}

	// First, check for exact match in MatchName (O(1) performance)
	if matchNames := f.matchName.Load(); matchNames != nil {
		if l4Rules, ok := (*matchNames)[domain]; ok {
			return true, l4Rules
		}
	}

	// Then, check if FQDN matches any wildcard patterns in MatchPattern
	if matchPatterns := f.matchPattern.Load(); matchPatterns != nil {
		for pattern, l4Rules := range *matchPatterns {
			// Validate pattern format and log invalid patterns
			if !strings.HasPrefix(pattern, "*.") {
				log().Warnf("Invalid wildcard pattern: %s", pattern)
				continue
			}

			if matchWildcardPattern(pattern, domain) {
				return true, l4Rules
			}
		}
	}

	return false, []npatypes.L4Rule{}
}

func GetIPFilter(podIdentifier string) (*Filter, bool) {
	// Return the cached merged filter
	val, ok := podMergedFilters.Load(podIdentifier)
	if !ok {
		return nil, false
	}
	return val.(*Filter), true
}

// domainL4Map stores domain names as keys and their associated L4Info as values
type domainL4Map map[string][]npatypes.L4Rule

// matchWildcardPattern checks if a domain matches a wildcard pattern like "*.google.com"
// Returns true for subdomains, false for root domain
func matchWildcardPattern(pattern, domain string) bool {
	// Input validation
	if pattern == "" || domain == "" {
		return false
	}

	// Pattern must start with "*."
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	// Extract suffix from pattern (remove "*." prefix)
	suffix := pattern[2:]

	// Suffix cannot be empty
	if suffix == "" {
		return false
	}

	// Domain must end with the suffix
	if !strings.HasSuffix(domain, suffix) {
		return false
	}

	// Domain must not be exactly the suffix (root domain exclusion)
	if domain == suffix {
		return false
	}

	// Domain must have at least one character before the suffix plus a dot separator
	prefixLen := len(domain) - len(suffix)
	if prefixLen <= 1 { // Must have subdomain + "."
		return false
	}

	// Ensure there's a "." separator between subdomain and suffix
	return domain[prefixLen-1] == '.'
}

var podIPToPodIdMap sync.Map

func SetPodIPToPodId(podIP string, podId string) {
	log().Debugf("Adding PodIP: %s to PodID: %s", podIP, podId)
	podIPToPodIdMap.Store(podIP, podId)
}

func GetPodId(podIP string) (string, error) {
	val, ok := podIPToPodIdMap.Load(podIP)
	if ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("podIP %s not found in local mappings", podIP)
}

func DeletePodIPToPodIdEntry(podIP string) {
	log().Debugf("deleting PodIP mapping for PodIP %s", podIP)
	podIPToPodIdMap.Delete(podIP)
}
