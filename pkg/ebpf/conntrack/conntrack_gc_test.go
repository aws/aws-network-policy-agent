package conntrack

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests pin which local conntrack entries one GC pass keeps and which it
// deletes, for a given kernel conntrack table. Each case creates its flows in
// the kernel conntrack table of a new network namespace (see enterTestNetns
// and createFlow), and the pass reads them over ctnetlink as the agent does.
// Every expectation is spelled out per case.

const testGCStart = uint64(1_000_000)

// Protocol numbers used by the cases. GRE stands in for protocols the datapath
// stores without ports.
const (
	protoTCP    = uint8(unix.IPPROTO_TCP)
	protoUDP    = uint8(unix.IPPROTO_UDP)
	protoSCTP   = uint8(unix.IPPROTO_SCTP)
	protoICMP   = uint8(unix.IPPROTO_ICMP)
	protoICMPv6 = uint8(unix.IPPROTO_ICMPV6)
	protoGRE    = uint8(unix.IPPROTO_GRE)
)

// Shared addresses: two pods on the node, a service VIP, a remote peer, and the
// node IP that SNAT'd traffic leaves from.
const (
	podA   = "10.0.1.10"
	podB   = "10.0.1.20"
	vip    = "172.20.0.10"
	remote = "10.0.9.9"
	node   = "10.0.1.1"

	podA6   = "2001:db8::a"
	podB6   = "2001:db8::b"
	vip6    = "fd00:20::10"
	remote6 = "2001:db8:9::9"
	node6   = "2001:db8::1"
)

// bpfV4 returns ip the way the datapath stores it in a ConntrackKey: the
// network-order bytes read as a little-endian u32.
func bpfV4(ip string) uint32 {
	return binary.LittleEndian.Uint32(net.ParseIP(ip).To4())
}

func bpfV6(ip string) [16]byte {
	var b [16]byte
	copy(b[:], net.ParseIP(ip).To16())
	return b
}

func v4Key(sip string, sport uint16, dip string, dport uint16, proto uint8, owner string, ifindex uint32) utils.ConntrackKey {
	return utils.ConntrackKey{
		Source_ip: bpfV4(sip), Source_port: sport,
		Dest_ip: bpfV4(dip), Dest_port: dport,
		Protocol: proto, Owner_ip: bpfV4(owner), Ifindex: ifindex,
	}
}

func v6Key(sip string, sport uint16, dip string, dport uint16, proto uint8, owner string, ifindex uint32) utils.ConntrackKeyV6 {
	return utils.ConntrackKeyV6{
		Source_ip: bpfV6(sip), Source_port: sport,
		Dest_ip: bpfV6(dip), Dest_port: dport,
		Protocol: proto, Owner_ip: bpfV6(owner), Ifindex: ifindex,
	}
}

// ipForFamily returns ip in the length netlink reports it for the family: 4
// bytes for AF_INET, 16 for AF_INET6.
func ipForFamily(ip string, v6 bool) net.IP {
	if v6 {
		return net.ParseIP(ip).To16()
	}
	return net.ParseIP(ip).To4()
}

// testFlow builds a kernel flow as netlink reports it. The reply tuple is
// rsrc:rsport -> fsrc:fsport, so a DNAT'd flow has rsrc set to the backend
// instead of fdst. netlink reports ports as zero for protocols other than TCP
// and UDP, so pass zero ports for ICMP and GRE.
func testFlow(v6 bool, proto uint8, fsrc string, fsport uint16, fdst string, fdport uint16, rsrc string, rsport uint16) *netlink.ConntrackFlow {
	family := uint8(unix.AF_INET)
	if v6 {
		family = unix.AF_INET6
	}
	return &netlink.ConntrackFlow{
		FamilyType: family,
		Forward: netlink.IPTuple{
			SrcIP: ipForFamily(fsrc, v6), SrcPort: fsport,
			DstIP: ipForFamily(fdst, v6), DstPort: fdport,
			Protocol: proto,
		},
		Reverse: netlink.IPTuple{
			SrcIP: ipForFamily(rsrc, v6), SrcPort: rsport,
			DstIP: ipForFamily(fsrc, v6), DstPort: fsport,
			Protocol: proto,
		},
	}
}

// testNATFlow builds a kernel flow whose reply tuple is
// rsrc:rsport -> rdst:rdport, so the reply destination can differ from the
// original source, as it does when the source is SNAT'd.
func testNATFlow(v6 bool, proto uint8, fsrc string, fsport uint16, fdst string, fdport uint16,
	rsrc string, rsport uint16, rdst string, rdport uint16) *netlink.ConntrackFlow {
	f := testFlow(v6, proto, fsrc, fsport, fdst, fdport, rsrc, rsport)
	f.Reverse.DstIP = ipForFamily(rdst, v6)
	f.Reverse.DstPort = rdport
	return f
}

// inZone returns f moved to conntrack zone zone.
func inZone(f *netlink.ConntrackFlow, zone uint16) *netlink.ConntrackFlow {
	f.Zone = zone
	return f
}

// gcCase is one GC pass over a kernel table.
type gcCase[K comparable] struct {
	name string
	// flows is the kernel conntrack table. readErr, if set, fails the pass's
	// kernel reads (see gcCaseTable).
	flows   []*netlink.ConntrackFlow
	readErr error
	// local is the agent's conntrack map. active holds the entries the
	// datapath touched at or after gcStart.
	local  []K
	active []K
	// wantDeleted and wantKept partition local.
	wantDeleted []K
	wantKept    []K
}

func keySet[K comparable](keys []K) map[K]bool {
	s := make(map[K]bool, len(keys))
	for _, k := range keys {
		s[k] = true
	}
	return s
}

// checkGCResult checks one pass's result against tc.
func checkGCResult[K comparable](t *testing.T, tc gcCase[K], deleted map[K]bool, n int, err error) {
	t.Helper()
	assert.Equal(t, len(tc.local), len(tc.wantDeleted)+len(tc.wantKept), "wantDeleted and wantKept must cover local")
	kept := make(map[K]bool)
	for _, k := range tc.local {
		if !deleted[k] {
			kept[k] = true
		}
	}
	assert.Equal(t, keySet(tc.wantDeleted), deleted, "deleted")
	assert.Equal(t, keySet(tc.wantKept), kept, "kept")
	assert.Equal(t, len(deleted), n, "returned delete count")
	if tc.readErr != nil {
		assert.ErrorIs(t, err, tc.readErr)
	} else {
		assert.NoError(t, err)
	}
}

// lastSeenActive reports what isEntryActive would for k: active if the
// datapath stamped it at or after gcStart.
func lastSeenActive[K comparable](active map[K]bool, k K) bool {
	val := utils.ConntrackVal{Value: 1, LastSeen: testGCStart - 1}
	if active[k] {
		val.LastSeen = testGCStart
	}
	return entryActiveFromRead(val, nil, testGCStart)
}

// gcCaseTable creates flows in the kernel conntrack table of a new network
// namespace and returns the table for a pass to read. If readErr is set, every
// dump of the pass fails with it (see conntrackTableProbe.dumpErr).
func gcCaseTable(t *testing.T, flows []*netlink.ConntrackFlow, readErr error) conntrackTable {
	enterTestNetns(t)
	for _, f := range flows {
		createFlow(t, f)
	}
	table := newConntrackTableProbe(t)
	table.dumpErr = readErr
	return table
}

func runV4GCCase(t *testing.T, tc gcCase[utils.ConntrackKey]) {
	table := gcCaseTable(t, tc.flows, tc.readErr)
	active := keySet(tc.active)
	c := &conntrackClient{kernelTable: table, localConntrackV4Cache: keySet(tc.local)}
	deleted := make(map[utils.ConntrackKey]bool)
	n, err := c.removeStaleV4Entries(testGCStart,
		func(k utils.ConntrackKey, gcStart uint64) bool {
			assert.Equal(t, testGCStart, gcStart)
			return lastSeenActive(active, k)
		},
		func(k utils.ConntrackKey) {
			assert.False(t, deleted[k], "deleted twice: %v", k)
			deleted[k] = true
		})
	checkGCResult(t, tc, deleted, n, err)
	assert.Len(t, c.localConntrackV4Cache, len(tc.local), "local cache must not change")
}

func runV6GCCase(t *testing.T, tc gcCase[utils.ConntrackKeyV6]) {
	table := gcCaseTable(t, tc.flows, tc.readErr)
	active := keySet(tc.active)
	c := &conntrackClient{kernelTable: table, enableIPv6: true, localConntrackV6Cache: keySet(tc.local)}
	deleted := make(map[utils.ConntrackKeyV6]bool)
	n, err := c.removeStaleV6Entries(testGCStart,
		func(k utils.ConntrackKeyV6, gcStart uint64) bool {
			assert.Equal(t, testGCStart, gcStart)
			return lastSeenActive(active, k)
		},
		func(k utils.ConntrackKeyV6) {
			assert.False(t, deleted[k], "deleted twice: %v", k)
			deleted[k] = true
		})
	checkGCResult(t, tc, deleted, n, err)
	assert.Len(t, c.localConntrackV6Cache, len(tc.local), "local cache must not change")
}

func TestConntrackGCV4KeepDeleteKernel(t *testing.T) {
	cases := []gcCase[utils.ConntrackKey]{
		{
			name: "forward flow: entries owned by the source or by the destination are kept",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoTCP, podA, 40000, remote, 443, remote, 443),
				testFlow(false, protoUDP, podA, 40001, remote, 53, remote, 53),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 40000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 40000, remote, 443, protoTCP, remote, 7),
				v4Key(podA, 40001, remote, 53, protoUDP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 40000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 40000, remote, 443, protoTCP, remote, 7),
				v4Key(podA, 40001, remote, 53, protoUDP, podA, 7),
			},
		},
		{
			name: "reply-direction key of a live flow is deleted",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoUDP, podA, 41000, remote, 53, remote, 53),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 41000, remote, 53, protoUDP, podA, 7),
				v4Key(remote, 53, podA, 41000, protoUDP, podA, 7),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(remote, 53, podA, 41000, protoUDP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 41000, remote, 53, protoUDP, podA, 7),
			},
		},
		{
			name: "same-node VIP DNAT: keys by VIP or by backend are kept",
			flows: []*netlink.ConntrackFlow{
				// Pod A to the VIP, DNAT'd to pod B on the same node.
				testFlow(false, protoTCP, podA, 42000, vip, 80, podB, 8080),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 42000, vip, 80, protoTCP, podA, 7),
				v4Key(podA, 42000, vip, 80, protoTCP, vip, 7),
				v4Key(podA, 42000, podB, 8080, protoTCP, podA, 7),
				v4Key(podA, 42000, podB, 8080, protoTCP, podB, 9),
				// The VIP key is never owned by the backend.
				v4Key(podA, 42000, vip, 80, protoTCP, podB, 9),
				// The backend's reply direction is not a key.
				v4Key(podB, 8080, podA, 42000, protoTCP, podB, 9),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 42000, vip, 80, protoTCP, podB, 9),
				v4Key(podB, 8080, podA, 42000, protoTCP, podB, 9),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 42000, vip, 80, protoTCP, podA, 7),
				v4Key(podA, 42000, vip, 80, protoTCP, vip, 7),
				v4Key(podA, 42000, podB, 8080, protoTCP, podA, 7),
				v4Key(podA, 42000, podB, 8080, protoTCP, podB, 9),
			},
		},
		{
			name: "port-only DNAT: the backend port is not a key when the IP is unchanged",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoTCP, podA, 43000, podB, 80, podB, 8080),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 43000, podB, 80, protoTCP, podA, 7),
				v4Key(podA, 43000, podB, 8080, protoTCP, podB, 9),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 43000, podB, 8080, protoTCP, podB, 9),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 43000, podB, 80, protoTCP, podA, 7),
			},
		},
		{
			name: "SNAT only: the reply destination is not read",
			flows: []*netlink.ConntrackFlow{
				testNATFlow(false, protoTCP, podA, 44000, remote, 443, remote, 443, node, 61000),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 44000, remote, 443, protoTCP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 44000, remote, 443, protoTCP, podA, 7),
			},
		},
		{
			// Pod A reaches the VIP, which is DNAT'd to pod B, and the source is
			// SNAT'd to the node IP, as kube-proxy does for hairpin traffic.
			name: "DNAT plus SNAT (hairpin)",
			flows: []*netlink.ConntrackFlow{
				testNATFlow(false, protoTCP, podA, 45000, vip, 80, podB, 8080, node, 61001),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 45000, vip, 80, protoTCP, podA, 7),
				v4Key(podA, 45000, podB, 8080, protoTCP, podA, 7),
				v4Key(podA, 45000, podB, 8080, protoTCP, podB, 9),
				// What pod B sees after SNAT. No key has the node IP as source.
				v4Key(node, 61001, podB, 8080, protoTCP, podB, 9),
			},
			// BEHAVIOR CHANGE (reverse lookup): the backend keys are deleted.
			// The flow still produces pod A to the backend as a key, but the
			// GC now finds flows by tuple, and neither that tuple nor its
			// inverse is one of the flow's tuples, because the reply goes to
			// the node IP rather than to pod A. The full dump used to keep
			// these entries.
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 45000, podB, 8080, protoTCP, podA, 7),
				v4Key(podA, 45000, podB, 8080, protoTCP, podB, 9),
				v4Key(node, 61001, podB, 8080, protoTCP, podB, 9),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 45000, vip, 80, protoTCP, podA, 7),
			},
		},
		{
			name: "flow in a non-default conntrack zone",
			flows: []*netlink.ConntrackFlow{
				inZone(testFlow(false, protoTCP, podA, 46000, remote, 443, remote, 443), 5),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 46000, remote, 443, protoTCP, podA, 7),
			},
			// BEHAVIOR CHANGE (reverse lookup): the entry is deleted. A
			// ctnetlink GET without CTA_ZONE searches the default zone only,
			// while the full dump used to return every zone.
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 46000, remote, 443, protoTCP, podA, 7),
			},
		},
		{
			name: "ICMP: ports are not compared, so any ICMP flow between the IPs keeps the entry",
			flows: []*netlink.ConntrackFlow{
				// netlink reports zero ports for ICMP.
				testFlow(false, protoICMP, podA, 0, remote, 0, remote, 0),
				inZone(testFlow(false, protoICMP, podB, 0, remote, 0, remote, 0), 5),
				testFlow(false, protoTCP, podA, 47000, podB, 80, podB, 80),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, remote, 7),
				// The zone does not matter here.
				v4Key(podB, 0, remote, 0, protoICMP, podB, 9),
				v4Key(remote, 0, podA, 0, protoICMP, podA, 7),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 7),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 9),
				// Kept by a TCP flow while ICMP entries are present.
				v4Key(podA, 47000, podB, 80, protoTCP, podA, 7),
			},
			active: []utils.ConntrackKey{
				v4Key(podA, 0, podB, 0, protoICMP, podA, 9),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(remote, 0, podA, 0, protoICMP, podA, 7),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, remote, 7),
				v4Key(podB, 0, remote, 0, protoICMP, podB, 9),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 9),
				v4Key(podA, 47000, podB, 80, protoTCP, podA, 7),
			},
		},
		{
			name: "other protocol without ports (GRE) is matched like ICMP",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoGRE, podA, 0, remote, 0, remote, 0),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoGRE, podA, 7),
				v4Key(podB, 0, remote, 0, protoGRE, podB, 9),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podB, 0, remote, 0, protoGRE, podB, 9),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoGRE, podA, 7),
			},
		},
		{
			name: "SCTP: netlink reports no ports, so an entry with ports never matches",
			flows: []*netlink.ConntrackFlow{
				// The kernel flow has the entries' ports, but netlink reports
				// them as zero.
				testFlow(false, protoSCTP, podA, 48000, remote, 9999, remote, 9999),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 48000, remote, 9999, protoSCTP, podA, 7),
				v4Key(podA, 48001, remote, 9999, protoSCTP, podA, 7),
			},
			active: []utils.ConntrackKey{
				v4Key(podA, 48001, remote, 9999, protoSCTP, podA, 7),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 48000, remote, 9999, protoSCTP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 48001, remote, 9999, protoSCTP, podA, 7),
			},
		},
		{
			name: "owner that is neither side is deleted",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoTCP, podA, 49000, remote, 443, remote, 443),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 49000, remote, 443, protoTCP, podB, 7),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 49000, remote, 443, protoTCP, podB, 7),
			},
		},
		{
			name: "protocol must match",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoUDP, podA, 50000, remote, 53, remote, 53),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 50000, remote, 53, protoTCP, podA, 7),
				v4Key(podA, 50000, remote, 53, protoUDP, podA, 7),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 50000, remote, 53, protoTCP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 50000, remote, 53, protoUDP, podA, 7),
			},
		},
		{
			name: "ifindex is ignored: copies on two interfaces are kept or deleted together",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoTCP, podA, 51000, podB, 80, podB, 80),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 51000, podB, 80, protoTCP, podA, 7),
				v4Key(podA, 51000, podB, 80, protoTCP, podA, 9),
				v4Key(podA, 51001, podB, 80, protoTCP, podA, 7),
				v4Key(podA, 51001, podB, 80, protoTCP, podA, 9),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 51001, podB, 80, protoTCP, podA, 7),
				v4Key(podA, 51001, podB, 80, protoTCP, podA, 9),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 51000, podB, 80, protoTCP, podA, 7),
				v4Key(podA, 51000, podB, 80, protoTCP, podA, 9),
			},
		},
		{
			name: "no kernel flow: stale entry is deleted, entry active in the gc window is kept",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoTCP, podB, 1, remote, 2, remote, 2),
			},
			local: []utils.ConntrackKey{
				v4Key(podA, 52000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 52001, remote, 443, protoTCP, podA, 7),
			},
			active: []utils.ConntrackKey{
				v4Key(podA, 52001, remote, 443, protoTCP, podA, 7),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 52000, remote, 443, protoTCP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 52001, remote, 443, protoTCP, podA, 7),
			},
		},
		{
			name: "empty kernel table: every idle entry is deleted",
			local: []utils.ConntrackKey{
				v4Key(podA, 53000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
			},
			wantDeleted: []utils.ConntrackKey{
				v4Key(podA, 53000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
			},
		},
		{
			name: "interrupted dump deletes nothing",
			flows: []*netlink.ConntrackFlow{
				testFlow(false, protoICMP, podA, 0, remote, 0, remote, 0),
			},
			readErr: netlink.ErrDumpInterrupted,
			local: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 7),
				v4Key(podA, 55000, remote, 443, protoTCP, podA, 7),
			},
			wantKept: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 7),
				v4Key(podA, 55000, remote, 443, protoTCP, podA, 7),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runV4GCCase(t, tc) })
	}
}

func TestConntrackGCV6KeepDeleteKernel(t *testing.T) {
	cases := []gcCase[utils.ConntrackKeyV6]{
		{
			name: "forward flow: entries owned by the source or by the destination are kept",
			flows: []*netlink.ConntrackFlow{
				testFlow(true, protoTCP, podA6, 40000, remote6, 443, remote6, 443),
				testFlow(true, protoUDP, podA6, 40001, remote6, 53, remote6, 53),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 40000, remote6, 443, protoTCP, podA6, 7),
				v6Key(podA6, 40000, remote6, 443, protoTCP, remote6, 7),
				v6Key(podA6, 40001, remote6, 53, protoUDP, podA6, 7),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 40000, remote6, 443, protoTCP, podA6, 7),
				v6Key(podA6, 40000, remote6, 443, protoTCP, remote6, 7),
				v6Key(podA6, 40001, remote6, 53, protoUDP, podA6, 7),
			},
		},
		{
			name: "reply-direction key of a live flow is deleted",
			flows: []*netlink.ConntrackFlow{
				testFlow(true, protoUDP, podA6, 41000, remote6, 53, remote6, 53),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 41000, remote6, 53, protoUDP, podA6, 7),
				v6Key(remote6, 53, podA6, 41000, protoUDP, podA6, 7),
			},
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(remote6, 53, podA6, 41000, protoUDP, podA6, 7),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 41000, remote6, 53, protoUDP, podA6, 7),
			},
		},
		{
			name: "same-node VIP DNAT: keys by VIP or by backend are kept",
			flows: []*netlink.ConntrackFlow{
				testFlow(true, protoTCP, podA6, 42000, vip6, 80, podB6, 8080),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 42000, vip6, 80, protoTCP, podA6, 7),
				v6Key(podA6, 42000, podB6, 8080, protoTCP, podA6, 7),
				v6Key(podA6, 42000, podB6, 8080, protoTCP, podB6, 9),
				v6Key(podA6, 42000, vip6, 80, protoTCP, podB6, 9),
			},
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(podA6, 42000, vip6, 80, protoTCP, podB6, 9),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 42000, vip6, 80, protoTCP, podA6, 7),
				v6Key(podA6, 42000, podB6, 8080, protoTCP, podA6, 7),
				v6Key(podA6, 42000, podB6, 8080, protoTCP, podB6, 9),
			},
		},
		{
			name: "DNAT plus SNAT (hairpin)",
			flows: []*netlink.ConntrackFlow{
				testNATFlow(true, protoTCP, podA6, 43000, vip6, 80, podB6, 8080, node6, 61000),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 43000, vip6, 80, protoTCP, podA6, 7),
				v6Key(podA6, 43000, podB6, 8080, protoTCP, podA6, 7),
				v6Key(node6, 61000, podB6, 8080, protoTCP, podB6, 9),
			},
			// BEHAVIOR CHANGE (reverse lookup): the backend key is deleted, as
			// in the IPv4 case.
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(podA6, 43000, podB6, 8080, protoTCP, podA6, 7),
				v6Key(node6, 61000, podB6, 8080, protoTCP, podB6, 9),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 43000, vip6, 80, protoTCP, podA6, 7),
			},
		},
		{
			name: "flow in a non-default conntrack zone",
			flows: []*netlink.ConntrackFlow{
				inZone(testFlow(true, protoTCP, podA6, 44000, remote6, 443, remote6, 443), 5),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 44000, remote6, 443, protoTCP, podA6, 7),
			},
			// BEHAVIOR CHANGE (reverse lookup): the entry is deleted, as in the
			// IPv4 case.
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(podA6, 44000, remote6, 443, protoTCP, podA6, 7),
			},
		},
		{
			name: "ICMPv6: ports are not compared, so any ICMPv6 flow between the IPs keeps the entry",
			flows: []*netlink.ConntrackFlow{
				testFlow(true, protoICMPv6, podA6, 0, remote6, 0, remote6, 0),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 8),
				v6Key(remote6, 0, podA6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 0, podB6, 0, protoICMPv6, podA6, 7),
			},
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(remote6, 0, podA6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 0, podB6, 0, protoICMPv6, podA6, 7),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 8),
			},
		},
		{
			name: "SCTP: netlink reports no ports, so an entry with ports never matches",
			flows: []*netlink.ConntrackFlow{
				testFlow(true, protoSCTP, podA6, 45000, remote6, 9999, remote6, 9999),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 45000, remote6, 9999, protoSCTP, podA6, 7),
			},
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(podA6, 45000, remote6, 9999, protoSCTP, podA6, 7),
			},
		},
		{
			name: "owner that is neither side is deleted, ifindex copies are kept together",
			flows: []*netlink.ConntrackFlow{
				testFlow(true, protoTCP, podA6, 46000, remote6, 443, remote6, 443),
			},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 46000, remote6, 443, protoTCP, podB6, 7),
				v6Key(podA6, 46000, remote6, 443, protoTCP, podA6, 7),
				v6Key(podA6, 46000, remote6, 443, protoTCP, podA6, 9),
			},
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(podA6, 46000, remote6, 443, protoTCP, podB6, 7),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 46000, remote6, 443, protoTCP, podA6, 7),
				v6Key(podA6, 46000, remote6, 443, protoTCP, podA6, 9),
			},
		},
		{
			name: "no kernel flow: stale entry is deleted, entry active in the gc window is kept",
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 47000, remote6, 443, protoTCP, podA6, 7),
				v6Key(podA6, 47001, remote6, 443, protoTCP, podA6, 7),
			},
			active: []utils.ConntrackKeyV6{
				v6Key(podA6, 47001, remote6, 443, protoTCP, podA6, 7),
			},
			wantDeleted: []utils.ConntrackKeyV6{
				v6Key(podA6, 47000, remote6, 443, protoTCP, podA6, 7),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 47001, remote6, 443, protoTCP, podA6, 7),
			},
		},
		{
			name:    "interrupted dump deletes nothing",
			readErr: netlink.ErrDumpInterrupted,
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 49000, remote6, 443, protoTCP, podA6, 7),
			},
			wantKept: []utils.ConntrackKeyV6{
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 49000, remote6, 443, protoTCP, podA6, 7),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runV6GCCase(t, tc) })
	}
}
