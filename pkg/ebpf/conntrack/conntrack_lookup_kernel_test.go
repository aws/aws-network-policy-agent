package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// These tests run the netlink lookup and dump against a real kernel, using the
// namespace setup in conntrack_gc_kernel_test.go.

// testFamilies are the address families the tests run for, with the shared
// addresses of each.
var testFamilies = []struct {
	name                    string
	v6                      bool
	family                  netlink.InetFamily
	podA, podB, vip, remote string
}{
	{"v4", false, unix.AF_INET, podA, podB, vip, remote},
	{"v6", true, unix.AF_INET6, podA6, podB6, vip6, remote6},
}

func tupleEqual(a, b *netlink.IPTuple) bool {
	return a.SrcIP.Equal(b.SrcIP) && a.DstIP.Equal(b.DstIP) &&
		a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.Protocol == b.Protocol
}

func TestNetlinkFlowLookupKernel(t *testing.T) {
	for _, fam := range testFamilies {
		t.Run(fam.name, func(t *testing.T) {
			enterTestNetns(t)
			plain := testFlow(fam.v6, protoTCP, fam.podA, 40000, fam.remote, 443, fam.remote, 443)
			dnat := testFlow(fam.v6, protoUDP, fam.podA, 40001, fam.vip, 53, fam.podB, 5353)
			zoned := testFlow(fam.v6, protoTCP, fam.podA, 40002, fam.remote, 443, fam.remote, 443)
			missing := testFlow(fam.v6, protoTCP, fam.podA, 40003, fam.remote, 443, fam.remote, 443)
			createFlow(t, plain)
			createFlow(t, dnat)
			createFlow(t, inZone(zoned, 5))

			lookup, err := openNetlinkFlowLookup(fam.family)
			require.NoError(t, err)
			defer lookup.close()

			// Every case below is a GET on the one socket. The socket stays in
			// the namespace it was opened in, so subtests can use it from any
			// thread.
			cases := []struct {
				name string
				dir  int
				tpl  netlink.IPTuple
				want *netlink.ConntrackFlow
			}{
				{"original tuple", nl.CTA_TUPLE_ORIG, plain.Forward, plain},
				{"reply tuple of a DNAT'd flow", nl.CTA_TUPLE_REPLY, dnat.Reverse, dnat},
				{"missing tuple", nl.CTA_TUPLE_ORIG, missing.Forward, nil},
				{"flow in a non-default zone is not found", nl.CTA_TUPLE_ORIG, zoned.Forward, nil},
				{"original tuple of a DNAT'd flow", nl.CTA_TUPLE_ORIG, dnat.Forward, dnat},
				{"reply tuple", nl.CTA_TUPLE_REPLY, plain.Reverse, plain},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var got netlink.ConntrackFlow
					found, err := lookup.lookup(tc.dir, &tc.tpl, &got)
					require.NoError(t, err)
					require.Equal(t, tc.want != nil, found, "found")
					if tc.want != nil {
						assert.Equal(t, tc.want.FamilyType, got.FamilyType)
						assert.True(t, tupleEqual(&tc.want.Forward, &got.Forward), "forward: %v", got.Forward)
						assert.True(t, tupleEqual(&tc.want.Reverse, &got.Reverse), "reverse: %v", got.Reverse)
					}
				})
			}
		})
	}
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
