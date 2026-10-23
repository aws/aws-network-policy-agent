package filter

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestMain(m *testing.M) {
	logger.New(logger.DEFAULT_LOG_LEVEL, "stdout", logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
	m.Run()
}

func TestComputeDomainRulesFromEbpfFirewallRules(t *testing.T) {
	tcpProtocol := corev1.ProtocolTCP
	port80 := int32(80)
	port443 := int32(443)

	tests := []struct {
		name           string
		firewallRules  []fwrp.EbpfFirewallRules
		expectedResult map[string][]npatypes.L4Rule
	}{
		{
			name: "merge same domain with different L4Info",
			firewallRules: []fwrp.EbpfFirewallRules{
				{
					DomainName: "shared.example.com",
					Priority:   utils.PE_PRIORITY*10 + 1,
					L4Info: []v1alpha1.Port{
						{
							Protocol: &tcpProtocol,
							Port:     &port80,
						},
					},
				},
				{
					DomainName: "shared.example.com",
					Priority:   utils.PE_PRIORITY*10 + 1,
					L4Info: []v1alpha1.Port{
						{
							Protocol: &tcpProtocol,
							Port:     &port443,
						},
					},
				},
			},
			expectedResult: map[string][]npatypes.L4Rule{
				"shared.example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: &tcpProtocol,
							Port:     &port80,
						},
						Priority: utils.PE_PRIORITY*10 + 1,
					},
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: &tcpProtocol,
							Port:     &port443,
						},
						Priority: utils.PE_PRIORITY*10 + 1,
					},
				},
			},
		},
		{
			name: "skip IP-based rules (no domain name)",
			firewallRules: []fwrp.EbpfFirewallRules{
				{
					IPCidr:   "10.0.0.0/16",
					Priority: utils.PE_PRIORITY*10 + 1,
					L4Info: []v1alpha1.Port{
						{
							Protocol: &tcpProtocol,
							Port:     &port80,
						},
					},
				},
				{
					DomainName: "example.com",
					Priority:   utils.PE_PRIORITY*10 + 1,
					L4Info: []v1alpha1.Port{
						{
							Protocol: &tcpProtocol,
							Port:     &port443,
						},
					},
				},
			},
			expectedResult: map[string][]npatypes.L4Rule{
				"example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: &tcpProtocol,
							Port:     &port443,
						},
						Priority: utils.PE_PRIORITY*10 + 1,
					},
				},
			},
		},
		{
			name: "avoid duplicate L4Rules",
			firewallRules: []fwrp.EbpfFirewallRules{
				{
					DomainName: "example.com",
					Priority:   utils.PE_PRIORITY*10 + 1,
					L4Info: []v1alpha1.Port{
						{
							Protocol: &tcpProtocol,
							Port:     &port80,
						},
					},
				},
				{
					DomainName: "example.com",
					Priority:   utils.PE_PRIORITY*10 + 1,
					L4Info: []v1alpha1.Port{
						{
							Protocol: &tcpProtocol,
							Port:     &port80,
						},
					},
				},
			},
			expectedResult: map[string][]npatypes.L4Rule{
				"example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{
							Protocol: &tcpProtocol,
							Port:     &port80,
						},
						Priority: utils.PE_PRIORITY*10 + 1,
					},
				},
			},
		},
		{
			name:           "empty input",
			firewallRules:  []fwrp.EbpfFirewallRules{},
			expectedResult: map[string][]npatypes.L4Rule{},
		},
		{
			name: "no L4Info means allow all ports",
			firewallRules: []fwrp.EbpfFirewallRules{
				{
					DomainName: "example.com",
					Priority:   utils.PE_PRIORITY*10 + 1,
					L4Info:     []v1alpha1.Port{},
				},
			},
			expectedResult: map[string][]npatypes.L4Rule{
				"example.com": {
					{
						L4PortProtocolInfo: v1alpha1.Port{},
						Priority:           utils.PE_PRIORITY*10 + 1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(tt.firewallRules)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestL4RuleEqual(t *testing.T) {
	tcpProtocol := corev1.ProtocolTCP
	udpProtocol := corev1.ProtocolUDP
	port80 := int32(80)
	port443 := int32(443)

	tests := []struct {
		name     string
		rule1    npatypes.L4Rule
		rule2    npatypes.L4Rule
		expected bool
	}{
		{
			name: "identical rules",
			rule1: npatypes.L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
				Priority: utils.PE_PRIORITY*10 + 1,
			},
			rule2: npatypes.L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
				Priority: utils.PE_PRIORITY*10 + 1,
			},
			expected: true,
		},
		{
			name: "different protocols",
			rule1: npatypes.L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
				Priority: utils.PE_PRIORITY*10 + 1,
			},
			rule2: npatypes.L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: &udpProtocol,
					Port:     &port80,
				},
				Priority: utils.PE_PRIORITY*10 + 1,
			},
			expected: false,
		},
		{
			name: "different ports",
			rule1: npatypes.L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
				Priority: utils.PE_PRIORITY*10 + 1,
			},
			rule2: npatypes.L4Rule{
				L4PortProtocolInfo: v1alpha1.Port{
					Protocol: &tcpProtocol,
					Port:     &port443,
				},
				Priority: utils.PE_PRIORITY*10 + 1,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule1.Equal(tt.rule2)
			assert.Equal(t, tt.expected, result)
		})
	}
}
