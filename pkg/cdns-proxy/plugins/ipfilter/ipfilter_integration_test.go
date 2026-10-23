package ipfilter

import (
	"context"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
)

// testResponseWriter implements dns.ResponseWriter for testing
type testResponseWriter struct {
	*dnstest.Recorder
	remoteAddr net.Addr
}

func (w *testResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func newTestResponseWriter(clientIP string) *testResponseWriter {
	return &testResponseWriter{
		Recorder:   &dnstest.Recorder{},
		remoteAddr: &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 53},
	}
}

// Helper function to convert string domains to EbpfFirewallRules with dummy L4Info
func createFirewallRules(domains []string) []fwrp.EbpfFirewallRules {
	tcpProtocol := corev1.ProtocolTCP
	port80 := int32(80)

	rules := make([]fwrp.EbpfFirewallRules, len(domains))
	for i, domain := range domains {
		rules[i] = fwrp.EbpfFirewallRules{
			DomainName: domain,
			L4Info: []v1alpha1.Port{
				{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
			},
		}
	}
	return rules
}

// TestIPFilterIntegrationExactDomains tests backward compatibility with exact domain matching
func TestIPFilterIntegrationExactDomains(t *testing.T) {
	// Setup
	podId := "test-pod-1"
	clientIP := "10.0.0.1"

	// Set up pod IP to pod ID mapping
	filter.SetPodIPToPodId(clientIP, podId)

	// Configure filter with exact domains only (backward compatibility test)
	exactDomains := []string{"google.com", "amazon.com", "example.com"}
	filter.SetPolicyEndpointDomains(podId, createFirewallRules(exactDomains))

	// Create IPFilter plugin
	ipFilter := &IPFilter{
		Next: test.NextHandler(dns.RcodeSuccess, nil),
	}

	tests := []struct {
		name     string
		qname    string
		expected bool
	}{
		{
			name:     "exact match google.com should be allowed",
			qname:    "google.com.",
			expected: true,
		},
		{
			name:     "exact match amazon.com should be allowed",
			qname:    "amazon.com.",
			expected: true,
		},
		{
			name:     "non-matching domain should not be allowed",
			qname:    "blocked.com.",
			expected: false,
		},
		{
			name:     "subdomain of exact match should not be allowed",
			qname:    "api.google.com.",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create DNS request
			req := new(dns.Msg)
			req.SetQuestion(tt.qname, dns.TypeA)

			// Create response writer with client IP
			w := newTestResponseWriter(clientIP)

			// Call ServeDNS
			code, err := ipFilter.ServeDNS(context.Background(), w, req)

			if err != nil {
				t.Fatalf("ServeDNS returned error: %v", err)
			}

			// Check if the request was processed (allowed) or passed to next handler
			if tt.expected {
				// Should be processed and passed to next handler
				if code != dns.RcodeSuccess {
					t.Errorf("Expected success code for allowed domain %s, got %d", tt.qname, code)
				}
			} else {
				// Should be passed to next handler without processing
				if code != dns.RcodeSuccess {
					t.Errorf("Expected success code (passed to next) for blocked domain %s, got %d", tt.qname, code)
				}
			}
		})
	}
}

// TestIPFilterIntegrationWildcardPatterns tests new wildcard pattern functionality
func TestIPFilterIntegrationWildcardPatterns(t *testing.T) {
	// Setup
	podId := "test-pod-2"
	clientIP := "10.0.0.2"

	// Set up pod IP to pod ID mapping
	filter.SetPodIPToPodId(clientIP, podId)

	// Configure filter with wildcard patterns
	patterns := []string{"*.google.com", "*.amazon.com"}
	filter.SetPolicyEndpointDomains(podId, createFirewallRules(patterns))

	// Create IPFilter plugin
	ipFilter := &IPFilter{
		Next: test.NextHandler(dns.RcodeSuccess, nil),
	}

	tests := []struct {
		name     string
		qname    string
		expected bool
	}{
		{
			name:     "subdomain api.google.com should be allowed",
			qname:    "api.google.com.",
			expected: true,
		},
		{
			name:     "subdomain search.google.com should be allowed",
			qname:    "search.google.com.",
			expected: true,
		},
		{
			name:     "nested subdomain a.b.google.com should be allowed",
			qname:    "a.b.google.com.",
			expected: true,
		},
		{
			name:     "root domain google.com should not be allowed",
			qname:    "google.com.",
			expected: false,
		},
		{
			name:     "non-matching domain should not be allowed",
			qname:    "blocked.com.",
			expected: false,
		},
		{
			name:     "amazon subdomain should be allowed",
			qname:    "aws.amazon.com.",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create DNS request
			req := new(dns.Msg)
			req.SetQuestion(tt.qname, dns.TypeA)

			// Create response writer with client IP
			w := newTestResponseWriter(clientIP)

			// Call ServeDNS
			code, err := ipFilter.ServeDNS(context.Background(), w, req)

			if err != nil {
				t.Fatalf("ServeDNS returned error: %v", err)
			}

			// Check if the request was processed (allowed) or passed to next handler
			if tt.expected {
				// Should be processed and passed to next handler
				if code != dns.RcodeSuccess {
					t.Errorf("Expected success code for allowed domain %s, got %d", tt.qname, code)
				}
			} else {
				// Should be passed to next handler without processing
				if code != dns.RcodeSuccess {
					t.Errorf("Expected success code (passed to next) for blocked domain %s, got %d", tt.qname, code)
				}
			}
		})
	}
}

// TestIPFilterIntegrationMixedConfiguration tests both exact domains and wildcard patterns together
func TestIPFilterIntegrationMixedConfiguration(t *testing.T) {
	// Setup
	podId := "test-pod-3"
	clientIP := "10.0.0.3"

	// Set up pod IP to pod ID mapping
	filter.SetPodIPToPodId(clientIP, podId)

	// Configure filter with both exact domains and wildcard patterns
	mixedDomains := []string{"exact.com", "*.wildcard.com", "another-exact.com", "*.another-wildcard.com"}
	filter.SetPolicyEndpointDomains(podId, createFirewallRules(mixedDomains))

	// Create IPFilter plugin
	ipFilter := &IPFilter{
		Next: test.NextHandler(dns.RcodeSuccess, nil),
	}

	tests := []struct {
		name     string
		qname    string
		expected bool
	}{
		{
			name:     "exact domain should be allowed",
			qname:    "exact.com.",
			expected: true,
		},
		{
			name:     "wildcard subdomain should be allowed",
			qname:    "api.wildcard.com.",
			expected: true,
		},
		{
			name:     "another exact domain should be allowed",
			qname:    "another-exact.com.",
			expected: true,
		},
		{
			name:     "another wildcard subdomain should be allowed",
			qname:    "test.another-wildcard.com.",
			expected: true,
		},
		{
			name:     "wildcard root domain should not be allowed",
			qname:    "wildcard.com.",
			expected: false,
		},
		{
			name:     "non-matching domain should not be allowed",
			qname:    "blocked.com.",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create DNS request
			req := new(dns.Msg)
			req.SetQuestion(tt.qname, dns.TypeA)

			// Create response writer with client IP
			w := newTestResponseWriter(clientIP)

			// Call ServeDNS
			code, err := ipFilter.ServeDNS(context.Background(), w, req)

			if err != nil {
				t.Fatalf("ServeDNS returned error: %v", err)
			}

			// Check if the request was processed (allowed) or passed to next handler
			if tt.expected {
				// Should be processed and passed to next handler
				if code != dns.RcodeSuccess {
					t.Errorf("Expected success code for allowed domain %s, got %d", tt.qname, code)
				}
			} else {
				// Should be passed to next handler without processing
				if code != dns.RcodeSuccess {
					t.Errorf("Expected success code (passed to next) for blocked domain %s, got %d", tt.qname, code)
				}
			}
		})
	}
}
