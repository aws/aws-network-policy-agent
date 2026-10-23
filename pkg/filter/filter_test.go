package filter

import (
	"fmt"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

// Helper function to create int32 pointer
func int32Ptr(i int32) *int32 {
	return &i
}

// Helper function to create protocol pointer
func protocolPtr(p corev1.Protocol) *corev1.Protocol {
	return &p
}

func TestSetPolicyEndpointDomains(t *testing.T) {
	tests := []struct {
		name           string
		podIdentifier  string
		domainFWRules  []fwrp.EbpfFirewallRules
		expectedDomain string
		expectedPort   int32
		expectError    bool
	}{
		{
			name:          "Set single domain with port",
			podIdentifier: "test-pod-1",
			domainFWRules: []fwrp.EbpfFirewallRules{
				{
					Priority:   1,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "example.com",
					L4Info: []v1alpha1.Port{
						{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
					},
				},
			},
			expectedDomain: "example.com",
			expectedPort:   80,
			expectError:    false,
		},
		{
			name:          "Set wildcard domain",
			podIdentifier: "test-pod-2",
			domainFWRules: []fwrp.EbpfFirewallRules{
				{
					Priority:   1,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "*.google.com",
					L4Info: []v1alpha1.Port{
						{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(443),
						},
					},
				},
			},
			expectedDomain: "*.google.com",
			expectedPort:   443,
			expectError:    false,
		},
		{
			name:          "Set multiple domains",
			podIdentifier: "test-pod-3",
			domainFWRules: []fwrp.EbpfFirewallRules{
				{
					Priority:   1,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "api.example.com",
					L4Info: []v1alpha1.Port{
						{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(8080),
						},
					},
				},
				{
					Priority:   2,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "db.example.com",
					L4Info: []v1alpha1.Port{
						{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(5432),
						},
					},
				},
			},
			expectedDomain: "api.example.com",
			expectedPort:   8080,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before test
			DeletePolicyEndpointDomains(tt.podIdentifier)

			err := SetPolicyEndpointDomains(tt.podIdentifier, tt.domainFWRules)
			if (err != nil) != tt.expectError {
				t.Errorf("SetPolicyEndpointDomains() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				// Verify the filter was created and can be retrieved
				filter, ok := GetIPFilter(tt.podIdentifier)
				if !ok {
					t.Errorf("Expected filter to be created for pod %s", tt.podIdentifier)
					return
				}

				// Test IsAllowed with the expected domain
				allowed, l4Rules := filter.IsAllowed(tt.expectedDomain)
				if !allowed {
					t.Errorf("Expected domain %s to be allowed", tt.expectedDomain)
				}

				if len(l4Rules) == 0 {
					t.Errorf("Expected L4 rules to be returned for domain %s", tt.expectedDomain)
				} else {
					// Check if the expected port is in the rules
					foundPort := false
					for _, rule := range l4Rules {
						if rule.L4PortProtocolInfo.Port != nil && *rule.L4PortProtocolInfo.Port == tt.expectedPort {
							foundPort = true
							break
						}
					}
					if !foundPort {
						t.Errorf("Expected port %d not found in L4 rules", tt.expectedPort)
					}
				}
			}

			// Clean up after test
			DeletePolicyEndpointDomains(tt.podIdentifier)
		})
	}
}

func TestDeletePolicyEndpointDomains(t *testing.T) {
	podIdentifier := "test-pod-delete"
	domainFWRules := []fwrp.EbpfFirewallRules{
		{
			Priority:   1,
			Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
			DomainName: "delete-test.com",
			L4Info: []v1alpha1.Port{
				{
					Protocol: protocolPtr(corev1.ProtocolTCP),
					Port:     int32Ptr(80),
				},
			},
		},
	}

	// First set the domains
	err := SetPolicyEndpointDomains(podIdentifier, domainFWRules)
	if err != nil {
		t.Fatalf("Failed to set policy endpoint domains: %v", err)
	}

	// Verify filter exists
	filter, ok := GetIPFilter(podIdentifier)
	if !ok {
		t.Fatalf("Expected filter to exist before deletion")
	}

	allowed, _ := filter.IsAllowed("delete-test.com")
	if !allowed {
		t.Fatalf("Expected domain to be allowed before deletion")
	}

	// Delete the domains
	DeletePolicyEndpointDomains(podIdentifier)

	// Verify filter is removed
	_, ok = GetIPFilter(podIdentifier)
	if ok {
		t.Errorf("Expected filter to be removed after deletion")
	}
}

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name           string
		setupDomains   map[string][]npatypes.L4Rule
		setupPatterns  map[string][]npatypes.L4Rule
		testDomain     string
		expectedResult bool
		expectedRules  int
	}{
		{
			name: "Exact match allowed",
			setupDomains: map[string][]npatypes.L4Rule{
				"example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
						Priority: 1,
					},
				},
			},
			testDomain:     "example.com",
			expectedResult: true,
			expectedRules:  1,
		},
		{
			name: "Wildcard pattern match allowed",
			setupPatterns: map[string][]npatypes.L4Rule{
				"*.google.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(443),
						},
						Priority: 1,
					},
				},
			},
			testDomain:     "api.google.com",
			expectedResult: true,
			expectedRules:  1,
		},
		{
			name: "Root domain not allowed for wildcard",
			setupPatterns: map[string][]npatypes.L4Rule{
				"*.google.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(443),
						},
						Priority: 1,
					},
				},
			},
			testDomain:     "google.com",
			expectedResult: false,
			expectedRules:  0,
		},
		{
			name:           "Domain not found",
			testDomain:     "notfound.com",
			expectedResult: false,
			expectedRules:  0,
		},
		{
			name:           "Empty domain",
			testDomain:     "",
			expectedResult: false,
			expectedRules:  0,
		},
		{
			name: "Multiple subdomains match wildcard",
			setupPatterns: map[string][]npatypes.L4Rule{
				"*.example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
						Priority: 1,
					},
				},
			},
			testDomain:     "api.v1.example.com",
			expectedResult: true,
			expectedRules:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &Filter{}

			// Setup exact domains
			if tt.setupDomains != nil {
				exactMap := make(domainL4Map)
				for domain, rules := range tt.setupDomains {
					exactMap[domain] = rules
				}
				filter.matchName.Store(&exactMap)
			}

			// Setup pattern domains
			if tt.setupPatterns != nil {
				patternMap := make(domainL4Map)
				for pattern, rules := range tt.setupPatterns {
					patternMap[pattern] = rules
				}
				filter.matchPattern.Store(&patternMap)
			}

			allowed, rules := filter.IsAllowed(tt.testDomain)

			if allowed != tt.expectedResult {
				t.Errorf("IsAllowed(%s) = %v, expected %v", tt.testDomain, allowed, tt.expectedResult)
			}

			if len(rules) != tt.expectedRules {
				t.Errorf("IsAllowed(%s) returned %d rules, expected %d", tt.testDomain, len(rules), tt.expectedRules)
			}
		})
	}
}

func TestSetPodIPToPodId(t *testing.T) {
	tests := []struct {
		name          string
		podIP         string
		podId         string
		expectedError bool
	}{
		{
			name:          "Valid IP and ID",
			podIP:         "192.168.1.100",
			podId:         "pod-12345",
			expectedError: false,
		},
		{
			name:          "IPv6 address",
			podIP:         "2001:db8::1",
			podId:         "pod-ipv6-test",
			expectedError: false,
		},
		{
			name:          "Empty IP",
			podIP:         "",
			podId:         "pod-empty-ip",
			expectedError: false, // Function doesn't validate input
		},
		{
			name:          "Empty ID",
			podIP:         "192.168.1.101",
			podId:         "",
			expectedError: false, // Function doesn't validate input
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before test
			DeletePodIPToPodIdEntry(tt.podIP)

			// Set the mapping
			SetPodIPToPodId(tt.podIP, tt.podId)

			// Verify the mapping was set
			retrievedId, err := GetPodId(tt.podIP)
			if (err != nil) != tt.expectedError {
				t.Errorf("GetPodId() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if !tt.expectedError && retrievedId != tt.podId {
				t.Errorf("GetPodId() = %v, expected %v", retrievedId, tt.podId)
			}

			// Clean up after test
			DeletePodIPToPodIdEntry(tt.podIP)
		})
	}
}

func TestGetPodId(t *testing.T) {
	tests := []struct {
		name          string
		setupIP       string
		setupId       string
		queryIP       string
		expectedId    string
		expectedError bool
	}{
		{
			name:          "Existing mapping",
			setupIP:       "192.168.1.200",
			setupId:       "pod-existing",
			queryIP:       "192.168.1.200",
			expectedId:    "pod-existing",
			expectedError: false,
		},
		{
			name:          "Non-existing mapping",
			queryIP:       "192.168.1.404",
			expectedId:    "",
			expectedError: true,
		},
		{
			name:          "Empty IP query",
			queryIP:       "",
			expectedId:    "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup if needed
			if tt.setupIP != "" {
				SetPodIPToPodId(tt.setupIP, tt.setupId)
				defer DeletePodIPToPodIdEntry(tt.setupIP)
			}

			// Test GetPodId
			retrievedId, err := GetPodId(tt.queryIP)

			if (err != nil) != tt.expectedError {
				t.Errorf("GetPodId() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if retrievedId != tt.expectedId {
				t.Errorf("GetPodId() = %v, expected %v", retrievedId, tt.expectedId)
			}
		})
	}
}

func TestDeletePodIPToPodIdEntry(t *testing.T) {
	podIP := "192.168.1.300"
	podId := "pod-to-delete"

	// Set up the mapping
	SetPodIPToPodId(podIP, podId)

	// Verify it exists
	retrievedId, err := GetPodId(podIP)
	if err != nil {
		t.Fatalf("Expected mapping to exist before deletion, got error: %v", err)
	}
	if retrievedId != podId {
		t.Fatalf("Expected pod ID %s, got %s", podId, retrievedId)
	}

	// Delete the mapping
	DeletePodIPToPodIdEntry(podIP)

	// Verify it's gone
	_, err = GetPodId(podIP)
	if err == nil {
		t.Errorf("Expected error after deletion, but mapping still exists")
	}
}

func TestMatchWildcardPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		domain   string
		expected bool
	}{
		{
			name:     "Valid subdomain match",
			pattern:  "*.google.com",
			domain:   "api.google.com",
			expected: true,
		},
		{
			name:     "Root domain should not match",
			pattern:  "*.google.com",
			domain:   "google.com",
			expected: false,
		},
		{
			name:     "Multiple level subdomain match",
			pattern:  "*.google.com",
			domain:   "api.v1.google.com",
			expected: true,
		},
		{
			name:     "Different domain should not match",
			pattern:  "*.google.com",
			domain:   "api.amazon.com",
			expected: false,
		},
		{
			name:     "Empty pattern",
			pattern:  "",
			domain:   "api.google.com",
			expected: false,
		},
		{
			name:     "Empty domain",
			pattern:  "*.google.com",
			domain:   "",
			expected: false,
		},
		{
			name:     "Invalid pattern without asterisk",
			pattern:  "google.com",
			domain:   "api.google.com",
			expected: false,
		},
		{
			name:     "Invalid pattern with only asterisk",
			pattern:  "*.",
			domain:   "api.google.com",
			expected: false,
		},
		{
			name:     "Pattern without dot after asterisk",
			pattern:  "*google.com",
			domain:   "api.google.com",
			expected: false,
		},
		{
			name:     "Single character subdomain",
			pattern:  "*.google.com",
			domain:   "a.google.com",
			expected: true,
		},
		{
			name:     "Domain shorter than suffix",
			pattern:  "*.verylongdomainname.com",
			domain:   "short.com",
			expected: false,
		},
		// Additional test cases (removing duplicates)
		{name: "subdomain matches", pattern: "*.google.com", domain: "search.google.com", expected: true},
		{name: "nested subdomain matches", pattern: "*.google.com", domain: "a.b.google.com", expected: true},
		{name: "any subdomain matches", pattern: "*.google.com", domain: "any.subdomain.google.com", expected: true},

		// Input validation and error handling
		{name: "both empty", pattern: "", domain: "", expected: false},

		// Edge cases
		{name: "domain doesn't end with suffix", pattern: "*.google.com", domain: "api.yahoo.com", expected: false},
		{name: "domain too short", pattern: "*.google.com", domain: ".com", expected: false},
		{name: "malformed domain no dot", pattern: "*.google.com", domain: "apigoogle.com", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchWildcardPattern(tt.pattern, tt.domain)
			if result != tt.expected {
				t.Errorf("matchWildcardPattern(%s, %s) = %v, expected %v", tt.pattern, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestGetIPFilter(t *testing.T) {
	podIdentifier := "test-get-filter"

	// Test when filter doesn't exist
	_, ok := GetIPFilter(podIdentifier)
	if ok {
		t.Errorf("Expected filter to not exist for pod %s", podIdentifier)
	}

	// Create a filter by setting policy endpoint domains
	domainFWRules := []fwrp.EbpfFirewallRules{
		{
			Priority:   1,
			Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
			DomainName: "test.com",
			L4Info: []v1alpha1.Port{
				{
					Protocol: protocolPtr(corev1.ProtocolTCP),
					Port:     int32Ptr(80),
				},
			},
		},
	}

	err := SetPolicyEndpointDomains(podIdentifier, domainFWRules)
	if err != nil {
		t.Fatalf("Failed to set policy endpoint domains: %v", err)
	}

	// Test when filter exists
	filter, ok := GetIPFilter(podIdentifier)
	if !ok {
		t.Errorf("Expected filter to exist for pod %s", podIdentifier)
	}

	if filter == nil {
		t.Errorf("Expected non-nil filter for pod %s", podIdentifier)
	}

	// Clean up
	DeletePolicyEndpointDomains(podIdentifier)
}

// Additional edge case tests

func TestSetPolicyEndpointDomainsEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		podIdentifier string
		domainFWRules []fwrp.EbpfFirewallRules
		expectError   bool
	}{
		{
			name:          "Empty domain rules",
			podIdentifier: "test-pod-empty",
			domainFWRules: []fwrp.EbpfFirewallRules{},
			expectError:   false,
		},
		{
			name:          "Rules with empty domain names",
			podIdentifier: "test-pod-empty-domain",
			domainFWRules: []fwrp.EbpfFirewallRules{
				{
					Priority:   1,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "", // Empty domain name should be skipped
					L4Info: []v1alpha1.Port{
						{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name:          "Rules with no L4Info",
			podIdentifier: "test-pod-no-l4",
			domainFWRules: []fwrp.EbpfFirewallRules{
				{
					Priority:   1,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "example.com",
					L4Info:     []v1alpha1.Port{}, // Empty L4Info
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before test
			DeletePolicyEndpointDomains(tt.podIdentifier)

			err := SetPolicyEndpointDomains(tt.podIdentifier, tt.domainFWRules)
			if (err != nil) != tt.expectError {
				t.Errorf("SetPolicyEndpointDomains() error = %v, expectError %v", err, tt.expectError)
			}

			// Clean up after test
			DeletePolicyEndpointDomains(tt.podIdentifier)
		})
	}
}

func TestIsAllowedEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupDomains   map[string][]npatypes.L4Rule
		setupPatterns  map[string][]npatypes.L4Rule
		testDomain     string
		expectedResult bool
	}{
		{
			name: "Domain with multiple L4 rules",
			setupDomains: map[string][]npatypes.L4Rule{
				"multi.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
						Priority: 1,
					},
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(443),
						},
						Priority: 2,
					},
				},
			},
			testDomain:     "multi.com",
			expectedResult: true,
		},
		{
			name: "Invalid wildcard pattern in setup",
			setupPatterns: map[string][]npatypes.L4Rule{
				"invalid-pattern.com": { // Missing *. prefix
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
						Priority: 1,
					},
				},
			},
			testDomain:     "sub.invalid-pattern.com",
			expectedResult: false,
		},
		{
			name: "Very long domain name",
			setupDomains: map[string][]npatypes.L4Rule{
				"very.long.subdomain.with.many.levels.example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(80),
						},
						Priority: 1,
					},
				},
			},
			testDomain:     "very.long.subdomain.with.many.levels.example.com",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &Filter{}

			// Setup exact domains
			if tt.setupDomains != nil {
				exactMap := make(domainL4Map)
				for domain, rules := range tt.setupDomains {
					exactMap[domain] = rules
				}
				filter.matchName.Store(&exactMap)
			}

			// Setup pattern domains
			if tt.setupPatterns != nil {
				patternMap := make(domainL4Map)
				for pattern, rules := range tt.setupPatterns {
					patternMap[pattern] = rules
				}
				filter.matchPattern.Store(&patternMap)
			}

			allowed, _ := filter.IsAllowed(tt.testDomain)

			if allowed != tt.expectedResult {
				t.Errorf("IsAllowed(%s) = %v, expected %v", tt.testDomain, allowed, tt.expectedResult)
			}
		})
	}
}

func TestConcurrentPodOperations(t *testing.T) {
	// Test concurrent operations on different pods
	podIdentifiers := []string{"concurrent-pod-1", "concurrent-pod-2", "concurrent-pod-3"}

	// Clean up before test
	for _, podId := range podIdentifiers {
		DeletePolicyEndpointDomains(podId)
	}

	// Set up domains for each pod concurrently
	done := make(chan bool, len(podIdentifiers))

	for i, podId := range podIdentifiers {
		go func(id string, port int32) {
			domainFWRules := []fwrp.EbpfFirewallRules{
				{
					Priority:   1,
					Action:     v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "concurrent-" + id + ".com",
					L4Info: []v1alpha1.Port{
						{
							Protocol: protocolPtr(corev1.ProtocolTCP),
							Port:     int32Ptr(port),
						},
					},
				},
			}

			err := SetPolicyEndpointDomains(id, domainFWRules)
			if err != nil {
				t.Errorf("Failed to set domains for pod %s: %v", id, err)
			}
			done <- true
		}(podId, int32(8080+i))
	}

	// Wait for all goroutines to complete
	for i := 0; i < len(podIdentifiers); i++ {
		<-done
	}

	// Verify each pod has its own filter
	for i, podId := range podIdentifiers {
		filter, ok := GetIPFilter(podId)
		if !ok {
			t.Errorf("Expected filter to exist for pod %s", podId)
			continue
		}

		expectedDomain := "concurrent-" + podId + ".com"
		allowed, rules := filter.IsAllowed(expectedDomain)
		if !allowed {
			t.Errorf("Expected domain %s to be allowed for pod %s", expectedDomain, podId)
		}

		if len(rules) == 0 {
			t.Errorf("Expected L4 rules for pod %s", podId)
		} else {
			expectedPort := int32(8080 + i)
			foundPort := false
			for _, rule := range rules {
				if rule.L4PortProtocolInfo.Port != nil && *rule.L4PortProtocolInfo.Port == expectedPort {
					foundPort = true
					break
				}
			}
			if !foundPort {
				t.Errorf("Expected port %d not found for pod %s", expectedPort, podId)
			}
		}
	}

	// Clean up after test
	for _, podId := range podIdentifiers {
		DeletePolicyEndpointDomains(podId)
	}
}

func TestPodIPToPodIdConcurrency(t *testing.T) {
	// Test concurrent operations on pod IP to pod ID mapping
	numOperations := 10
	done := make(chan bool, numOperations)

	// Concurrent set operations
	for i := 0; i < numOperations; i++ {
		go func(index int) {
			podIP := fmt.Sprintf("192.168.1.%d", 100+index)
			podId := fmt.Sprintf("concurrent-pod-%d", index)

			SetPodIPToPodId(podIP, podId)

			// Verify the mapping
			retrievedId, err := GetPodId(podIP)
			if err != nil {
				t.Errorf("Failed to get pod ID for IP %s: %v", podIP, err)
			} else if retrievedId != podId {
				t.Errorf("Expected pod ID %s, got %s for IP %s", podId, retrievedId, podIP)
			}

			done <- true
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < numOperations; i++ {
		<-done
	}

	// Clean up and verify deletion
	for i := 0; i < numOperations; i++ {
		podIP := fmt.Sprintf("192.168.1.%d", 100+i)
		DeletePodIPToPodIdEntry(podIP)

		// Verify the mapping is deleted - should return error (not found)
		_, err := GetPodId(podIP)
		if err == nil {
			t.Errorf("Expected error (not found) after deletion for IP %s, but mapping still exists", podIP)
		}
	}
}

func TestFilterWithNilMaps(t *testing.T) {
	// Test filter behavior when internal maps are nil
	filter := &Filter{}

	// Both maps are nil initially
	allowed, rules := filter.IsAllowed("test.com")
	if allowed {
		t.Errorf("Expected domain to not be allowed when maps are nil")
	}
	if len(rules) != 0 {
		t.Errorf("Expected no rules when maps are nil")
	}
}
