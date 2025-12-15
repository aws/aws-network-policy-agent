package types

import (
	"testing"

	v1alpha1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
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

func TestL4RuleString(t *testing.T) {
	tests := []struct {
		name     string
		rule     L4Rule
		expected string
	}{
		{
			name: "TCP port 80",
			rule: L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: protocolPtr(corev1.ProtocolTCP),
					Port:     int32Ptr(80),
				},
				Priority: 1,
			},
			expected: "L4Rule{Protocol:TCP, Port:80, Priority:1}",
		},
		{
			name: "UDP port range 8000-8080",
			rule: L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: protocolPtr(corev1.ProtocolUDP),
					Port:     int32Ptr(8000),
					EndPort:  int32Ptr(8080),
				},
				Priority: 2,
			},
			expected: "L4Rule{Protocol:UDP, Port:8000-8080, Priority:2}",
		},
		{
			name: "Any protocol and port",
			rule: L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					// No protocol or port specified
				},
				Priority: 0,
			},
			expected: "L4Rule{Protocol:ANY, Port:ANY, Priority:0}",
		},
		{
			name: "SCTP port 443 with high priority",
			rule: L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: protocolPtr(corev1.ProtocolSCTP),
					Port:     int32Ptr(443),
				},
				Priority: 1000,
			},
			expected: "L4Rule{Protocol:SCTP, Port:443, Priority:1000}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.String()
			if result != tt.expected {
				t.Errorf("L4Rule.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
