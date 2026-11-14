package fwruleprocessor

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
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

func TestFWRuleProcessor_ComputeClusterPolicyMapEntriesFromEndpointRules_NodeIPAlwaysPresent(t *testing.T) {
	nodeIP := "10.1.1.1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/32")
	nodeIPKey := string(utils.ComputeTrieKey(*nodeIPCIDR, false))

	tests := []struct {
		name          string
		firewallRules []EbpfFirewallRules
	}{
		{
			name:          "Empty rules - node IP still present",
			firewallRules: []EbpfFirewallRules{},
		},
		{
			name: "Egress-only CNP rule - node IP still present in ingress map",
			firewallRules: []EbpfFirewallRules{
				{
					IPCidr:   "0.0.0.0/0",
					Action:   "Accept",
					Priority: 50,
				},
			},
		},
		{
			name: "Ingress rule with specific CIDR - node IP also present",
			firewallRules: []EbpfFirewallRules{
				{
					IPCidr:   "10.0.0.0/16",
					Action:   "Accept",
					Priority: 50,
					L4Info: []v1alpha1.Port{
						{
							Protocol: func() *corev1.Protocol { p := corev1.ProtocolTCP; return &p }(),
							Port:     Int32Ptr(80),
						},
					},
				},
			},
		},
		{
			name: "Rule with node IP CIDR - should be skipped but node IP entry still present",
			firewallRules: []EbpfFirewallRules{
				{
					IPCidr:   "10.1.1.1/32",
					Action:   "Accept",
					Priority: 50,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeClusterPolicyMapEntriesFromEndpointRules(tt.firewallRules)
			assert.NoError(t, err)

			// The node IP key must always be present in the resulting map
			_, nodeIPExists := got[nodeIPKey]
			assert.True(t, nodeIPExists, "Node IP entry must always be present in cluster policy firewall map")
		})
	}
}

func TestFWRuleProcessor_ComputeClusterPolicyMapEntriesFromEndpointRules_IPv6_NodeIPAlwaysPresent(t *testing.T) {
	nodeIP := "2001:db8:abcd:0012::1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/128")
	nodeIPKey := string(utils.ComputeTrieKey(*nodeIPCIDR, true))

	tests := []struct {
		name          string
		firewallRules []EbpfFirewallRules
	}{
		{
			name:          "Empty rules - IPv6 node IP still present",
			firewallRules: []EbpfFirewallRules{},
		},
		{
			name: "Egress-only CNP rule - IPv6 node IP still present",
			firewallRules: []EbpfFirewallRules{
				{
					IPCidr:   "::/0",
					Action:   "Accept",
					Priority: 50,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor(nodeIP, "/128", true).ComputeClusterPolicyMapEntriesFromEndpointRules(tt.firewallRules)
			assert.NoError(t, err)

			_, nodeIPExists := got[nodeIPKey]
			assert.True(t, nodeIPExists, "IPv6 Node IP entry must always be present in cluster policy firewall map")
		})
	}
}

// maxPrefixLenForFamily returns the largest legal prefix length for the
// cluster's address family (32 for IPv4 keys, 128 for IPv6 keys).
func maxPrefixLenForFamily(enableIPv6 bool) uint32 {
	if enableIPv6 {
		return 128
	}
	return 32
}

func TestFWRuleProcessor_ComputeMapEntriesFromEndpointRules_WrongFamilyExceptFiltered(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443

	tests := []struct {
		name       string
		nodeIP     string
		hostMask   string
		enableIPv6 bool
		rules      []EbpfFirewallRules
	}{
		{
			name:       "IPv6 except on IPv4 cluster",
			nodeIP:     "10.1.1.1",
			hostMask:   "/32",
			enableIPv6: false,
			rules: []EbpfFirewallRules{
				{
					IPCidr: "10.2.0.0/16",
					L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
				{
					IPCidr: "::/0",
					Except: []v1alpha1.NetworkAddress{"100::/64", "fe80::/10"},
					L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
			},
		},
		{
			name:       "IPv4 except on IPv6 cluster",
			nodeIP:     "2001:db8:abcd:0012::1",
			hostMask:   "/128",
			enableIPv6: true,
			rules: []EbpfFirewallRules{
				{
					IPCidr: "2001:db8::/32",
					L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
				{
					IPCidr: "0.0.0.0/0",
					Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "192.168.0.0/16"},
					L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor(tt.nodeIP, tt.hostMask, tt.enableIPv6).
				ComputeMapEntriesFromEndpointRules(tt.rules)
			assert.NoError(t, err)

			maxLen := maxPrefixLenForFamily(tt.enableIPv6)
			for key := range got {
				assert.GreaterOrEqual(t, len(key), 4, "key too short: %x", []byte(key))
				prefixLen := binary.LittleEndian.Uint32([]byte(key)[0:4])
				assert.LessOrEqualf(t, prefixLen, maxLen,
					"produced a key with prefix length %d (> %d) - wrong-family except leaked: %x",
					prefixLen, maxLen, []byte(key))
			}
		})
	}
}

func TestComputeMapEntries_SameFamilyExceptRetained(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443

	nodeIP := "10.1.1.1"
	rules := []EbpfFirewallRules{
		{
			IPCidr: "10.0.0.0/8",
			Except: []v1alpha1.NetworkAddress{"10.10.0.0/16"},
			L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
		},
	}

	got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).
		ComputeMapEntriesFromEndpointRules(rules)
	assert.NoError(t, err)

	// Expect the except CIDR 10.10.0.0/16 to be present as its own key.
	_, exceptNet, _ := net.ParseCIDR("10.10.0.0/16")
	wantKey := string(utils.ComputeTrieKey(*exceptNet, false))
	_, ok := got[wantKey]
	assert.Truef(t, ok, "same-family except 10.10.0.0/16 was not added to the map")
}

// TestFWRuleProcessor_IPv4MappedCIDRSortedByCanonicalPrefix covers an IPv4-mapped
// IPv6 ipBlock in an IPv4 cluster. "::ffff:10.0.0.0/104" canonicalizes to
// 10.0.0.0/8, so it must be ordered as a /8 (before the /24) for port
// inheritance to run from the broader CIDR to the narrower one.
func TestFWRuleProcessor_IPv4MappedCIDRSortedByCanonicalPrefix(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80, port443 int32 = 80, 443

	rules := []EbpfFirewallRules{
		{IPCidr: "10.0.0.0/24", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port80}}},
		{IPCidr: "::ffff:10.0.0.0/104", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
	}

	_, net8, _ := net.ParseCIDR("10.0.0.0/8")
	_, net24, _ := net.ParseCIDR("10.0.0.0/24")
	key8 := string(utils.ComputeTrieKey(*net8, false))
	key24 := string(utils.ComputeTrieKey(*net24, false))

	for i := 0; i < 50; i++ {
		got, err := NewFirewallRuleProcessor("10.255.0.1", "/32", false).ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules(nil), rules...))
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		ports8 := decodeTrieValuePorts(got[key8])
		ports24 := decodeTrieValuePorts(got[key24])
		if len(ports8) != 1 || !containsInt(ports8, 443) {
			t.Fatalf("iteration %d: 10.0.0.0/8 ports = %v, want [443]", i, ports8)
		}
		if len(ports24) != 2 || !containsInt(ports24, 80) || !containsInt(ports24, 443) {
			t.Fatalf("iteration %d: 10.0.0.0/24 ports = %v, want 80 and 443", i, ports24)
		}
	}
}

// TestFWRuleProcessor_IPv4MappedCIDRSkippedInIPv6Mode is the IPv6-cluster
// counterpart of the test above. "::ffff:10.0.0.0/104" canonicalizes to the IPv4
// network 10.0.0.0/8, so in an IPv6 cluster it is skipped like any other IPv4
// rule and must not contribute its port to the IPv6 entries or create an entry
// of its own.
func TestFWRuleProcessor_IPv4MappedCIDRSkippedInIPv6Mode(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80, port443 int32 = 80, 443

	rules := []EbpfFirewallRules{
		{IPCidr: "2001:db8::/32", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port80}}},
		{IPCidr: "::ffff:10.0.0.0/104", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
	}

	_, net32, _ := net.ParseCIDR("2001:db8::/32")
	_, net8, _ := net.ParseCIDR("10.0.0.0/8")
	key32 := string(utils.ComputeTrieKey(*net32, true))
	key8 := string(utils.ComputeTrieKey(*net8, false))

	got, err := NewFirewallRuleProcessor("fd00::1", "/128", true).ComputeMapEntriesFromEndpointRules(rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got[key8]; ok {
		t.Fatalf("IPv4-mapped rule created a 10.0.0.0/8 entry in an IPv6 cluster")
	}
	ports32 := decodeTrieValuePorts(got[key32])
	if len(ports32) != 1 || !containsInt(ports32, 80) {
		t.Fatalf("2001:db8::/32 ports = %v, want [80]", ports32)
	}
}

// TestClusterPolicy_RepeatedCIDRNotExponential verifies that N rules sharing the
// same CIDR are processed in linear time and memory. Previously each repeat copied
// the CIDR's own accumulated L4 rules onto itself, doubling the list per rule (O(2^N)).
func TestClusterPolicy_RepeatedCIDRNotExponential(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	const n = 20

	rules := make([]EbpfFirewallRules, 0, n)
	for i := 0; i < n; i++ {
		port := int32(1000 + i)
		rules = append(rules, EbpfFirewallRules{
			IPCidr:   "10.0.0.0/8",
			L4Info:   []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port}},
			Action:   v1alpha1.ClusterNetworkPolicyRuleActionAccept,
			Priority: 100,
		})
	}

	_, cidrNet, _ := net.ParseCIDR("10.0.0.0/8")
	key := string(utils.ComputeTrieKey(*cidrNet, false))

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err := NewFirewallRuleProcessor("192.168.0.1", "/32", false).ComputeClusterPolicyMapEntriesFromEndpointRules(rules)
	runtime.ReadMemStats(&after)

	assert.NoError(t, err)
	assert.Len(t, decodeCPETrieValuePorts(got[key]), n)
	// Linear processing allocates a few KB; the exponential version allocates hundreds of MB at n=20.
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(10<<20), "allocations grew exponentially with repeated CIDR")
}

func TestFWRuleProcessor_RemoveDuplicateL4Rules_ProtocolValue(t *testing.T) {
	protocolTCP1 := corev1.ProtocolTCP
	protocolTCP2 := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP

	tests := []struct {
		name string
		l4   []utils.L4Rule
		want int
	}{
		{
			name: "same protocol through distinct pointers is deduplicated",
			l4: []utils.L4Rule{
				{L4PortProtocolInfo: v1alpha1.Port{Protocol: &protocolTCP1, Port: Int32Ptr(80)}, Action: "Accept", Priority: 100},
				{L4PortProtocolInfo: v1alpha1.Port{Protocol: &protocolTCP2, Port: Int32Ptr(80)}, Action: "Accept", Priority: 100},
			},
			want: 1,
		},
		{
			name: "different protocols are kept",
			l4: []utils.L4Rule{
				{L4PortProtocolInfo: v1alpha1.Port{Protocol: &protocolTCP1, Port: Int32Ptr(80)}, Action: "Accept", Priority: 100},
				{L4PortProtocolInfo: v1alpha1.Port{Protocol: &protocolUDP, Port: Int32Ptr(80)}, Action: "Accept", Priority: 100},
			},
			want: 2,
		},
	}

	f := NewFirewallRuleProcessor("10.0.0.1", "/32", false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.removeDuplicateL4Rules(tt.l4); len(got) != tt.want {
				t.Fatalf("removeDuplicateL4Rules() kept %d rules, want %d", len(got), tt.want)
			}
		})
	}
}

func TestFWRuleProcessor_RemoveDuplicateL4Rules_CatchAllKept(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP

	tests := []struct {
		name string
		l4   []utils.L4Rule
		want int
	}{
		{
			name: "explicit port-less TCP rule before empty catch-all keeps both",
			l4: []utils.L4Rule{
				{L4PortProtocolInfo: v1alpha1.Port{Protocol: &protocolTCP}, Action: "Deny", Priority: 100},
				{L4PortProtocolInfo: v1alpha1.Port{}, Action: "Deny", Priority: 100},
			},
			want: 2,
		},
		{
			name: "empty catch-all before explicit port-less TCP rule keeps both",
			l4: []utils.L4Rule{
				{L4PortProtocolInfo: v1alpha1.Port{}, Action: "Deny", Priority: 100},
				{L4PortProtocolInfo: v1alpha1.Port{Protocol: &protocolTCP}, Action: "Deny", Priority: 100},
			},
			want: 2,
		},
		{
			name: "two empty catch-alls with same priority/action deduplicate",
			l4: []utils.L4Rule{
				{L4PortProtocolInfo: v1alpha1.Port{}, Action: "Deny", Priority: 100},
				{L4PortProtocolInfo: v1alpha1.Port{}, Action: "Deny", Priority: 100},
			},
			want: 1,
		},
	}

	f := NewFirewallRuleProcessor("10.0.0.1", "/32", false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.removeDuplicateL4Rules(tt.l4); len(got) != tt.want {
				t.Fatalf("removeDuplicateL4Rules() kept %d rules, want %d", len(got), tt.want)
			}
		})
	}
}

// decodeFirewallMap renders a map from ComputeMapEntriesFromEndpointRules as
// "prefix" -> sorted entries ("tcp/80", "any", "deny"), so a test can compare
// the exact set of keys. IPv4-mapped 16-byte keys print as ::ffff:a.b.c.d/N.
func decodeFirewallMap(t *testing.T, got map[string][]byte) map[string]string {
	t.Helper()
	out := make(map[string]string, len(got))
	for k, v := range got {
		b := []byte(k)
		addr, ok := netip.AddrFromSlice(b[4:])
		if !ok {
			t.Fatalf("key has invalid address length %d: %x", len(b)-4, b)
		}
		prefix := netip.PrefixFrom(addr, int(binary.LittleEndian.Uint32(b[0:4])))
		var entries []string
		for off := 0; off+12 <= len(v); off += 12 {
			switch protocol := int(binary.LittleEndian.Uint32(v[off : off+4])); protocol {
			case 0:
			case utils.ANY_IP_PROTOCOL:
				entries = append(entries, "any")
			case utils.RESERVED_IP_PROTOCOL_NUMBER:
				entries = append(entries, "deny")
			case utils.TCP_PROTOCOL_NUMBER:
				entries = append(entries, fmt.Sprintf("tcp/%d", binary.LittleEndian.Uint32(v[off+4:off+8])))
			default:
				entries = append(entries, fmt.Sprintf("proto%d/%d", protocol, binary.LittleEndian.Uint32(v[off+4:off+8])))
			}
		}
		sort.Strings(entries)
		out[prefix.String()] = strings.Join(entries, ",")
	}
	return out
}

// TestComputeMapEntries_ExceptFamilyHandling covers except CIDRs whose text
// form or address family differs from the cluster's (issue #742): IPv4-mapped
// excepts in both families, cross-family excepts, bare addresses and
// unparseable input. Each case compares the exact set of map keys.
func TestComputeMapEntries_ExceptFamilyHandling(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	tcp := func(port int32) []v1alpha1.Port {
		return []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port}}
	}
	except := func(cidrs ...string) []v1alpha1.NetworkAddress {
		out := make([]v1alpha1.NetworkAddress, 0, len(cidrs))
		for _, c := range cidrs {
			out = append(out, v1alpha1.NetworkAddress(c))
		}
		return out
	}

	const v4Node, v6Node = "10.255.0.1", "2001:db8::1"
	tests := []struct {
		name       string
		enableIPv6 bool
		rules      []EbpfFirewallRules
		want       map[string]string
	}{
		{
			name:       "ipv6 mapped except ::ffff:0:0/96 does not collide with ::/0",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "::/0", Except: except("::ffff:0:0/96"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "::/0": "tcp/80", "::ffff:0.0.0.0/96": "deny"},
		},
		{
			name:       "ipv6 mapped except keeps its 16-byte form and mask",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "::/0", Except: except("::ffff:10.0.0.0/104"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "::/0": "tcp/80", "::ffff:10.0.0.0/104": "deny"},
		},
		{
			name:       "ipv6 native IPv4 except is skipped",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "::/0", Except: except("10.0.0.0/8"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "::/0": "tcp/80"},
		},
		{
			name:       "ipv6 native except is unchanged",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "2001:db8::/32", Except: except("2001:db8:1::/48"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "2001:db8::/32": "tcp/80", "2001:db8:1::/48": "deny"},
		},
		{
			name:       "ipv6 mapped-range prefix shorter than /96 is native IPv6",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "::/0", Except: except("::ffff:0:0/80"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "::/0": "tcp/80", "::/80": "deny"},
		},
		{
			name:       "ipv6 bare mapped except is a /128 host",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "::/0", Except: except("::ffff:10.1.2.3"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "::/0": "tcp/80", "::ffff:10.1.2.3/128": "deny"},
		},
		{
			name:       "ipv6 bare except is a /128 host",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "2001:db8::/32", Except: except("2001:db8::5"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any", "2001:db8::/32": "tcp/80", "2001:db8::5/128": "deny"},
		},
		{
			name:  "ipv4 mapped except denies its IPv4 range",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("::ffff:10.1.0.0/112"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80", "10.1.0.0/16": "deny"},
		},
		{
			name:  "ipv4 mapped parent with mapped except",
			rules: []EbpfFirewallRules{{IPCidr: "::ffff:10.0.0.0/104", Except: except("::ffff:10.1.0.0/112"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80", "10.1.0.0/16": "deny"},
		},
		{
			name:  "ipv4 mapped and native forms of one except share a key",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("10.1.0.0/16", "::ffff:10.1.0.0/112"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80", "10.1.0.0/16": "deny"},
		},
		{
			name: "ipv4 mapped except blocks port inheritance into its range",
			rules: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", Except: except("::ffff:10.1.0.0/112"), L4Info: tcp(80)},
				{IPCidr: "10.1.2.0/24", L4Info: tcp(443)},
			},
			want: map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80", "10.1.0.0/16": "deny", "10.1.2.0/24": "tcp/443"},
		},
		{
			name:  "ipv4 native IPv6 except is skipped",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("2001:db8::/64"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80"},
		},
		{
			name:  "ipv4 bare except is a /32 host",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("10.1.2.3"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80", "10.1.2.3/32": "deny"},
		},
		{
			name:  "ipv4 bare mapped except is a /32 host",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("::ffff:10.1.2.3"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/80", "10.1.2.3/32": "deny"},
		},
		{
			name:  "rule with an unparseable except is dropped",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("not-a-cidr"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any"},
		},
		{
			name:  "rule with a valid and an unparseable except is dropped",
			rules: []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", Except: except("10.1.0.0/16", "10.2.0.0/33"), L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any"},
		},
		{
			name:       "ipv6 rule with an unparseable except is dropped",
			enableIPv6: true,
			rules:      []EbpfFirewallRules{{IPCidr: "2001:db8::/32", Except: except("2001:db8::/129"), L4Info: tcp(80)}},
			want:       map[string]string{v6Node + "/128": "any"},
		},
		{
			name: "dropped rule leaves a sibling rule for the same CIDR intact",
			rules: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", Except: except("not-a-cidr"), L4Info: tcp(80)},
				{IPCidr: "10.0.0.0/8", L4Info: tcp(443)},
			},
			want: map[string]string{v4Node + "/32": "any", "10.0.0.0/8": "tcp/443"},
		},
		{
			name: "narrower rule does not inherit ports from a dropped rule",
			rules: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", Except: except("not-a-cidr"), L4Info: tcp(80)},
				{IPCidr: "10.1.0.0/16", L4Info: tcp(443)},
			},
			want: map[string]string{v4Node + "/32": "any", "10.1.0.0/16": "tcp/443"},
		},
		{
			name:  "unparseable rule is skipped",
			rules: []EbpfFirewallRules{{IPCidr: "not-a-cidr", L4Info: tcp(80)}},
			want:  map[string]string{v4Node + "/32": "any"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodeIP, hostMask := v4Node, "/32"
			if tt.enableIPv6 {
				nodeIP, hostMask = v6Node, "/128"
			}
			var origExcepts [][]v1alpha1.NetworkAddress
			for _, r := range tt.rules {
				origExcepts = append(origExcepts, append([]v1alpha1.NetworkAddress(nil), r.Except...))
			}
			// Map iteration order is random; repeat so a key collision cannot pass by luck.
			for i := 0; i < 100; i++ {
				got, err := NewFirewallRuleProcessor(nodeIP, hostMask, tt.enableIPv6).
					ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules(nil), tt.rules...))
				if err != nil {
					t.Fatalf("iteration %d: unexpected error: %v", i, err)
				}
				if decoded := decodeFirewallMap(t, got); !assert.Equal(t, tt.want, decoded, "iteration %d", i) {
					return
				}
			}
			for i, r := range tt.rules {
				assert.Equal(t, origExcepts[i], r.Except, "caller's except slice for rule %d was modified", i)
			}
		})
	}
}

// TestCanonicalizeExcepts_ReturnsNewSlice checks that the result never shares
// the input's backing array, for empty and non-empty input, so appends to it
// cannot write into a cached PolicyEndpoint's array.
func TestCanonicalizeExcepts_ReturnsNewSlice(t *testing.T) {
	f := NewFirewallRuleProcessor("10.255.0.1", "/32", false)
	for _, in := range [][]v1alpha1.NetworkAddress{
		make([]v1alpha1.NetworkAddress, 0, 4),
		append(make([]v1alpha1.NetworkAddress, 0, 4), "10.1.0.0/16"),
	} {
		backing := in[:cap(in)]
		before := append([]v1alpha1.NetworkAddress(nil), backing...)
		out, err := f.canonicalizeExcepts(in)
		assert.NoError(t, err)
		_ = append(out, "10.9.0.0/16", "10.8.0.0/16", "10.7.0.0/16", "10.6.0.0/16")
		assert.Equal(t, before, backing, "canonicalizeExcepts result shares the input's backing array (len %d)", len(in))
	}
}
