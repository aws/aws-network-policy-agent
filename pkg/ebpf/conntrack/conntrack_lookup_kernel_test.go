package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests run the netlink lookup and dump against a real kernel, using the
// namespace setup in conntrack_gc_kernel_test.go.

// testFamilies are the address families the tests run for, with the shared
// addresses of each.
var testFamilies = []struct {
	name               string
	v6                 bool
	family             netlink.InetFamily
	podA, podB, remote string
}{
	{"v4", false, unix.AF_INET, podA, podB, remote},
	{"v6", true, unix.AF_INET6, podA6, podB6, remote6},
}

// TestStreamProtocolFlowsKernel dumps the ICMP (or ICMPv6) and the GRE flows,
// which the GC matches by dump, from a table that has flows of each protocol,
// one ICMP flow of them in a non-default zone.
func TestStreamProtocolFlowsKernel(t *testing.T) {
	for _, fam := range testFamilies {
		t.Run(fam.name, func(t *testing.T) {
			enterTestNetns(t)
			a, b, r := fam.podA, fam.podB, fam.remote
			icmp := protoICMP
			if fam.v6 {
				icmp = protoICMPv6
			}
			createFlow(t, testFlow(fam.v6, protoTCP, a, 40000, r, 443, r, 443))
			createFlow(t, testFlow(fam.v6, protoUDP, a, 40001, r, 53, r, 53))
			createFlow(t, testFlow(fam.v6, protoGRE, a, 0, r, 0, r, 0))
			createFlow(t, testFlow(fam.v6, protoTCP, b, 40002, r, 443, r, 443))
			createFlow(t, testFlow(fam.v6, protoGRE, b, 0, r, 0, r, 0))
			createFlow(t, testFlow(fam.v6, icmp, a, 0, r, 0, r, 0))
			createFlow(t, inZone(testFlow(fam.v6, icmp, b, 0, r, 0, r, 0), 5))

			for _, protocol := range []uint8{protoGRE, icmp} {
				var got []string
				err := streamProtocolFlows(fam.family, protocol, func(flow *netlink.ConntrackFlow) {
					assert.Equal(t, protocol, flow.Forward.Protocol)
					assert.Equal(t, protocol, flow.Reverse.Protocol)
					assert.Zero(t, flow.Forward.SrcPort+flow.Forward.DstPort, "ports")
					got = append(got, flow.Forward.SrcIP.String()+" -> "+flow.Forward.DstIP.String())
				})
				require.NoError(t, err)
				assert.ElementsMatch(t, []string{a + " -> " + r, b + " -> " + r}, got, "protocol %d", protocol)
			}
		})
	}
}
