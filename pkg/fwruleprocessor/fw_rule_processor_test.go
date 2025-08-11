package fwruleprocessor

import (
	"net"
	"sort"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestFWRuleProcessor_ComputeMapEntriesFromEndpointRules(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	//protocolUDP := corev1.ProtocolUDP
	//protocolSCTP := corev1.ProtocolSCTP

	var testIP v1alpha1.NetworkAddress
	var gotKeys []string

	nodeIP := "10.1.1.1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/32")
	nodeIPKey := utils.ComputeTrieKey(*nodeIPCIDR, false)

	var testPort int32
	testPort = 80
	testIP = "10.1.1.2/32"
	_, testIPCIDR, _ := net.ParseCIDR(string(testIP))

	testIPKey := utils.ComputeTrieKey(*testIPCIDR, false)
	type args struct {
		firewallRules []EbpfFirewallRules
	}

	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name: "CIDR with Port and Protocol",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "10.1.1.2/32",
						L4Info: []v1alpha1.Port{
							{
								Protocol: &protocolTCP,
								Port:     &testPort,
							},
						},
					},
				},
			},
			want: []string{string(nodeIPKey), string(testIPKey)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor("10.1.1.1", "/32", false).ComputeMapEntriesFromEndpointRules(tt.args.firewallRules)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for key, _ := range got {
					gotKeys = append(gotKeys, key)
				}
				sort.Strings(tt.want)
				sort.Strings(gotKeys)
				assert.Equal(t, tt.want, gotKeys)
			}
		})
	}
}

func TestFWRuleProcessor_CheckAndDeriveL4InfoFromAnyMatchingCIDRs(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	type want struct {
		matchingCIDRL4Info []v1alpha1.Port
	}

	sampleCidrsMap := map[string]EbpfFirewallRules{
		"1.1.1.0/24": {
			IPCidr: "1.1.1.0/24",
			Except: []v1alpha1.NetworkAddress{},
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	tests := []struct {
		name         string
		firewallRule string
		cidrsMap     map[string]EbpfFirewallRules
		want         want
	}{
		{
			name:         "Match Present",
			firewallRule: "1.1.1.2/32",
			cidrsMap:     sampleCidrsMap,
			want: want{
				matchingCIDRL4Info: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &port80,
					},
				},
			},
		},

		{
			name:         "No Match",
			firewallRule: "2.1.1.2/32",
			cidrsMap:     sampleCidrsMap,
			want:         want{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatchingCIDRL4Info := checkAndDeriveL4InfoFromAnyMatchingCIDRs(tt.firewallRule, tt.cidrsMap)
			assert.Equal(t, tt.want.matchingCIDRL4Info, gotMatchingCIDRL4Info)
		})
	}
}

func TestFWRuleProcessor_AddCatchAllL4Entry(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	l4InfoWithNoCatchAllEntry := EbpfFirewallRules{
		IPCidr: "1.1.1.1/32",
		L4Info: []v1alpha1.Port{
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
		},
	}

	l4InfoWithCatchAllL4Info := EbpfFirewallRules{
		IPCidr: "1.1.1.1/32",
		L4Info: []v1alpha1.Port{
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
			{
				Protocol: &CATCH_ALL_PROTOCOL,
			},
		},
	}

	tests := []struct {
		name          string
		firewallRules EbpfFirewallRules
	}{
		{
			name:          "Append Catch All Entry",
			firewallRules: l4InfoWithNoCatchAllEntry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addCatchAllL4Entry(&tt.firewallRules)
			assert.Equal(t, tt.firewallRules, l4InfoWithCatchAllL4Info)
		})
	}
}

func TestFWRuleProcessor_MergeDuplicateL4Info(t *testing.T) {
	type mergeDuplicatePortsTestCase struct {
		Name     string
		Ports    []v1alpha1.Port
		Expected []v1alpha1.Port
	}
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP

	testCases := []mergeDuplicatePortsTestCase{
		{
			Name: "Merge Duplicate Ports with nil Protocol",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: &protocolTCP, Port: Int32Ptr(8081), EndPort: Int32Ptr(8081)},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: &protocolTCP, Port: Int32Ptr(8081), EndPort: Int32Ptr(8081)},
			},
		},
		{
			Name: "Merge Duplicate Ports with nil EndPort",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
			},
		},
		{
			Name: "Merge Duplicate Ports with nil Port",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mergedPorts := mergeDuplicateL4Info(tc.Ports)
			assert.Equal(t, len(tc.Expected), len(mergedPorts))
		})
	}
}

func Int32Ptr(i int32) *int32 {
	return &i
}

func TestFWRuleProcessor_SortFirewallRulesByPrefixLength(t *testing.T) {
	tests := []struct {
		name           string
		inputRules     []EbpfFirewallRules
		hostMask       string
		expectedOutput []EbpfFirewallRules
	}{
		{
			name: "Sort IPv4 CIDRs by prefix length",
			inputRules: []EbpfFirewallRules{
				{IPCidr: "192.168.1.1/32"},
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "172.16.0.0/16"},
				{IPCidr: "192.168.0.0/24"},
			},
			hostMask: "/32",
			expectedOutput: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "172.16.0.0/16"},
				{IPCidr: "192.168.0.0/24"},
				{IPCidr: "192.168.1.1/32"},
			},
		},
		{
			name: "Sort IPv4 CIDRs with some missing prefix",
			inputRules: []EbpfFirewallRules{
				{IPCidr: "192.168.1.1"}, // No prefix, should use hostMask
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "172.16.0.0/16"},
			},
			hostMask: "/32",
			expectedOutput: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "172.16.0.0/16"},
				{IPCidr: "192.168.1.1"}, // Still no prefix in the output
			},
		},
		{
			name: "Sort IPv6 CIDRs by prefix length",
			inputRules: []EbpfFirewallRules{
				{IPCidr: "2001:db8::/32"},
				{IPCidr: "2001:db8:1::/48"},
				{IPCidr: "2001:db8:1:2::/64"},
				{IPCidr: "2001:db8:1:2:3::/80"},
			},
			hostMask: "/128",
			expectedOutput: []EbpfFirewallRules{
				{IPCidr: "2001:db8::/32"},
				{IPCidr: "2001:db8:1::/48"},
				{IPCidr: "2001:db8:1:2::/64"},
				{IPCidr: "2001:db8:1:2:3::/80"},
			},
		},
		{
			name: "Sort mixed IPv4 and IPv6 CIDRs",
			inputRules: []EbpfFirewallRules{
				{IPCidr: "192.168.1.0/24"},
				{IPCidr: "2001:db8::/32"},
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "2001:db8:1::/48"},
			},
			hostMask: "/32",
			expectedOutput: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "192.168.1.0/24"},
				{IPCidr: "2001:db8::/32"},
				{IPCidr: "2001:db8:1::/48"},
			},
		},
		{
			name: "Sort with catch-all IP entry (0.0.0.0/0)",
			inputRules: []EbpfFirewallRules{
				{IPCidr: "192.168.1.0/24"},
				{IPCidr: "0.0.0.0/0"},
				{IPCidr: "10.0.0.0/8"},
			},
			hostMask: "/32",
			expectedOutput: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0"},
				{IPCidr: "10.0.0.0/8"},
				{IPCidr: "192.168.1.0/24"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the input rules to avoid modifying the test data
			inputCopy := make([]EbpfFirewallRules, len(tt.inputRules))
			copy(inputCopy, tt.inputRules)

			// Call the function being tested
			sortFirewallRulesByPrefixLength(inputCopy, tt.hostMask)

			// Check if the result matches the expected output
			assert.Equal(t, tt.expectedOutput, inputCopy, "Sorted rules do not match expected output")
		})
	}
}

func TestFWRuleProcessor_SortFirewallRulesByPrefixLengthWithL4Info(t *testing.T) {
	// Create protocol variables for test
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	// Create port variables for test
	port80 := int32(80)
	port443 := int32(443)
	port8080 := int32(8080)

	tests := []struct {
		name           string
		inputRules     []EbpfFirewallRules
		hostMask       string
		expectedOutput []EbpfFirewallRules
	}{
		{
			name: "Sort rules with L4 info preserved",
			inputRules: []EbpfFirewallRules{
				{
					IPCidr: "192.168.1.0/24",
					L4Info: []v1alpha1.Port{
						{Protocol: &tcp, Port: &port80},
						{Protocol: &tcp, Port: &port443},
					},
				},
				{
					IPCidr: "10.0.0.0/8",
					L4Info: []v1alpha1.Port{
						{Protocol: &udp, Port: &port8080},
					},
				},
			},
			hostMask: "/32",
			expectedOutput: []EbpfFirewallRules{
				{
					IPCidr: "10.0.0.0/8",
					L4Info: []v1alpha1.Port{
						{Protocol: &udp, Port: &port8080},
					},
				},
				{
					IPCidr: "192.168.1.0/24",
					L4Info: []v1alpha1.Port{
						{Protocol: &tcp, Port: &port80},
						{Protocol: &tcp, Port: &port443},
					},
				},
			},
		},
		{
			name: "Sort rules with Except fields preserved",
			inputRules: []EbpfFirewallRules{
				{
					IPCidr: "192.168.1.0/24",
					Except: []v1alpha1.NetworkAddress{"192.168.1.5/32", "192.168.1.10/32"},
				},
				{
					IPCidr: "10.0.0.0/8",
					Except: []v1alpha1.NetworkAddress{"10.1.0.0/16"},
				},
			},
			hostMask: "/32",
			expectedOutput: []EbpfFirewallRules{
				{
					IPCidr: "10.0.0.0/8",
					Except: []v1alpha1.NetworkAddress{"10.1.0.0/16"},
				},
				{
					IPCidr: "192.168.1.0/24",
					Except: []v1alpha1.NetworkAddress{"192.168.1.5/32", "192.168.1.10/32"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the input rules to avoid modifying the test data
			inputCopy := make([]EbpfFirewallRules, len(tt.inputRules))
			copy(inputCopy, tt.inputRules)

			// Call the function being tested
			sortFirewallRulesByPrefixLength(inputCopy, tt.hostMask)

			// Check if the result matches the expected output
			assert.Equal(t, tt.expectedOutput, inputCopy, "Sorted rules do not match expected output")
		})
	}
}
