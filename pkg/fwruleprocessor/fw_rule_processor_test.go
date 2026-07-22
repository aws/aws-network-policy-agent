package fwruleprocessor

import (
	"encoding/binary"
	"net"
	"sort"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestFWRuleProcessor_ComputeMapEntriesFromEndpointRules_IPv4(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP

	var testIP v1alpha1.NetworkAddress

	nodeIP := "10.1.1.1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/32")
	nodeIPKey := utils.ComputeTrieKey(*nodeIPCIDR, false)

	var testPort int32
	testPort = 80
	testIP = "10.1.1.2/32"
	_, testIPCIDR, _ := net.ParseCIDR(string(testIP))

	_, catchAllCIDR, _ := net.ParseCIDR(string("0.0.0.0/0"))

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
		{
			name: "CatchAll CIDR",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "0.0.0.0/0",
					},
				},
			},
			want: []string{string(nodeIPKey), string(utils.ComputeTrieKey(*catchAllCIDR, false))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(tt.args.firewallRules)
			var gotKeys []string
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

func TestFWRuleProcessor_ComputeMapEntriesFromEndpointRules_IPv6(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP

	nodeIP := "2001:db8:abcd:0012::1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/128")
	nodeIPKey := utils.ComputeTrieKey(*nodeIPCIDR, true)

	var testPort int32
	testPort = 80
	_, testIPCIDR, _ := net.ParseCIDR("2001:db8:abcd:0012::10/128")

	_, catchAllCIDR, _ := net.ParseCIDR("::/0")

	testIPKey := utils.ComputeTrieKey(*testIPCIDR, true)
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
						IPCidr: "2001:db8:abcd:0012::10/128",
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
		{
			name: "CatchAll IPv4 CIDR",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "::/0",
					},
				},
			},
			want: []string{string(nodeIPKey), string(utils.ComputeTrieKey(*catchAllCIDR, true))},
		},
		{
			name: "CatchAll CIDR IPv4 ignored in rule computation",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "0.0.0.0/0",
					},
				},
			},
			want: []string{string(nodeIPKey)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor(nodeIP, "/128", true).ComputeMapEntriesFromEndpointRules(tt.args.firewallRules)
			var gotKeys []string
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

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{"IPv6 compressed", "2001:db8::1/128", true},
		{"IPv6 fully qualified", "fd16:9254:7127:1337:ffff:ffff:ffff:ffff/128", true},
		{"IPv6 catch-all", "::/0", true},
		{"IPv6 no mask", "2001:db8::1", true},
		{"IPv4 standard", "10.0.0.1/32", false},
		{"IPv4 catch-all", "0.0.0.0/0", false},
		{"IPv4 no mask", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isIPv6(tt.cidr))
		})
	}
}

func TestFirewallRuleProcessor_ShouldSkipRule(t *testing.T) {
	tests := []struct {
		name       string
		nodeIP     string
		hostMask   string
		enableIPv6 bool
		cidr       string
		expected   bool
	}{
		// IPv4 mode
		{"IPv4 mode: skip IPv6 compressed", "10.0.0.1", "/32", false, "2001:db8::1/128", true},
		{"IPv4 mode: skip IPv6 fully qualified", "10.0.0.1", "/32", false, "fd16:9254:7127:1337:ffff:ffff:ffff:ffff/128", true},
		{"IPv4 mode: allow IPv4", "10.0.0.1", "/32", false, "192.168.1.0/24", false},
		{"IPv4 mode: skip node IP", "10.0.0.1", "/32", false, "10.0.0.1/32", true},

		// IPv6 mode
		{"IPv6 mode: skip IPv4", "2001:db8::1", "/128", true, "10.0.0.1/32", true},
		{"IPv6 mode: allow IPv6 compressed", "2001:db8::1", "/128", true, "2001:db8::10/128", false},
		{"IPv6 mode: allow IPv6 fully qualified", "2001:db8::1", "/128", true, "fd16:9254:7127:1337:ffff:ffff:ffff:ffff/128", false},
		{"IPv6 mode: skip node IP", "2001:db8::1", "/128", true, "2001:db8::1/128", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFirewallRuleProcessor(tt.nodeIP, tt.hostMask, tt.enableIPv6)
			assert.Equal(t, tt.expected, f.shouldSkipRule(tt.cidr))
		})
	}
}

// decodeTrieValuePorts decodes a TRIE value produced by utils.ComputeTrieValue
// into the list of start ports it encodes. Each entry is 12 bytes:
// protocol (4) + startPort (4) + endPort (4), little-endian. Unused trailing
// entries have protocol == 0 and are skipped.
func decodeTrieValuePorts(value []byte) []int {
	var ports []int
	for off := 0; off+12 <= len(value); off += 12 {
		protocol := binary.LittleEndian.Uint32(value[off : off+4])
		if protocol == 0 {
			continue
		}
		startPort := binary.LittleEndian.Uint32(value[off+4 : off+8])
		ports = append(ports, int(startPort))
	}
	return ports
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// TestClusterPolicy_NonCanonicalCIDRCollision verifies the CNP path
// (ComputeClusterPolicyMapEntriesFromEndpointRules) canonicalizes CIDRs before
// using them as map keys, preventing the same LPM-collision bug that affected
// the pod-scoped path.
func TestClusterPolicy_NonCanonicalCIDRCollision(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	var port3128 int32 = 3128

	nodeIP := "192.168.0.1"

	rules := []EbpfFirewallRules{
		{
			IPCidr:   "10.0.0.0/8",
			L4Info:   []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
			Action:   v1alpha1.ClusterNetworkPolicyRuleActionAccept,
			Priority: 100,
		},
		{
			IPCidr:   "10.161.0.0/8", // host bits set; masks to 10.0.0.0/8
			L4Info:   []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port3128}},
			Action:   v1alpha1.ClusterNetworkPolicyRuleActionAccept,
			Priority: 100,
		},
	}

	_, canonicalNet, _ := net.ParseCIDR("10.0.0.0/8")
	canonicalKey := string(utils.ComputeTrieKey(*canonicalNet, false))

	for i := 0; i < 500; i++ {
		got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeClusterPolicyMapEntriesFromEndpointRules(rules)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}

		value, ok := got[canonicalKey]
		if !ok {
			t.Fatalf("iteration %d: expected a map entry for canonical key 10.0.0.0/8", i)
		}

		ports := decodeCPETrieValuePorts(value)
		if !containsInt(ports, int(port443)) || !containsInt(ports, int(port3128)) {
			t.Fatalf("iteration %d: CNP 10.0.0.0/8 entry lost a port; got ports=%v (want both 443 and 3128). "+
				"Non-canonical CIDR 10.161.0.0/8 collided with 10.0.0.0/8.", i, ports)
		}
	}
}

// TestFWRuleProcessor_ExceptCIDRCanonicalization verifies that an except CIDR
// with host bits set is canonicalized so it doesn't silently overwrite the allow
// rule for the same network prefix.
func TestFWRuleProcessor_ExceptCIDRCanonicalization(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443

	nodeIP := "192.168.0.1"

	rules := []EbpfFirewallRules{
		{
			IPCidr: "10.0.0.0/8",
			L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
			Except: []v1alpha1.NetworkAddress{"10.161.0.0/8"}, // host bits set; masks to 10.0.0.0/8
		},
	}

	_, canonicalNet, _ := net.ParseCIDR("10.0.0.0/8")
	canonicalKey := string(utils.ComputeTrieKey(*canonicalNet, false))

	for i := 0; i < 500; i++ {
		got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(rules)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}

		value, ok := got[canonicalKey]
		if !ok {
			t.Fatalf("iteration %d: expected a map entry for canonical key 10.0.0.0/8", i)
		}

		ports := decodeTrieValuePorts(value)
		if !containsInt(ports, int(port443)) {
			t.Fatalf("iteration %d: 10.0.0.0/8 entry lost port 443; got ports=%v. "+
				"Except CIDR 10.161.0.0/8 (canonicalizes to 10.0.0.0/8) overwrote the allow with a DENY.", i, ports)
		}
	}
}

// decodeCPETrieValuePorts decodes a TRIE value produced by utils.ComputeTrieValueForCPE.
// Each entry is 16 bytes: protocol (4) + priority (4) + startPort (4) + endPort (4).
func decodeCPETrieValuePorts(value []byte) []int {
	var ports []int
	for off := 0; off+16 <= len(value); off += 16 {
		protocol := binary.LittleEndian.Uint32(value[off : off+4])
		if protocol == 0 {
			continue
		}
		startPort := binary.LittleEndian.Uint32(value[off+8 : off+12])
		ports = append(ports, int(startPort))
	}
	return ports
}

// TestFWRuleProcessor_NonCanonicalCIDRCollision reproduces the intermittent
// enforcement bug where two ipBlock rules whose CIDRs reduce to the same
// network after masking (e.g. 10.0.0.0/8 and 10.161.0.0/8, since /8 makes the
// .161 octet meaningless) are keyed separately in cidrsMap by their raw string.
// Their L4 (port) sets are never merged, and the final encode loop collapses
// both to the identical LPM trie key and overwrites one with the other in a
// non-deterministic (Go map iteration) order.
//
// A correct implementation must canonicalize the CIDR before keying, so the
// resulting 10.0.0.0/8 entry carries the union of both port sets deterministically.
func TestFWRuleProcessor_NonCanonicalCIDRCollision(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443   // STS / VPC endpoint traffic
	var port3128 int32 = 3128 // proxy traffic

	nodeIP := "192.168.0.1"

	rules := []EbpfFirewallRules{
		{
			IPCidr: "10.0.0.0/8",
			L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
		},
		{
			IPCidr: "10.161.0.0/8", // host bits set; masks to 10.0.0.0/8
			L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port3128}},
		},
	}

	_, canonicalNet, _ := net.ParseCIDR("10.0.0.0/8")
	canonicalKey := string(utils.ComputeTrieKey(*canonicalNet, false))

	// Go map iteration order is randomized, so the overwrite is probabilistic.
	// Run many iterations to deterministically catch the bug and to prove the
	// fix is stable across orderings.
	for i := 0; i < 500; i++ {
		got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(rules)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}

		value, ok := got[canonicalKey]
		if !ok {
			t.Fatalf("iteration %d: expected a map entry for canonical key 10.0.0.0/8", i)
		}

		ports := decodeTrieValuePorts(value)
		if !containsInt(ports, int(port443)) || !containsInt(ports, int(port3128)) {
			t.Fatalf("iteration %d: 10.0.0.0/8 entry lost a port; got ports=%v (want both 443 and 3128). "+
				"Non-canonical CIDR 10.161.0.0/8 collided with 10.0.0.0/8 and overwrote its L4 info.", i, ports)
		}
	}
}
