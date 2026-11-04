package conntrack

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// These tests run against the kernel's conntrack table, in a new network
// namespace so the table starts empty and the host's is untouched. The flows
// are created over ctnetlink, so no traffic is needed. The tests skip unless
// run as root on a kernel with ctnetlink. CI runs them as root with
// CONNTRACK_KERNEL_TESTS=required, which turns a skip into a failure so the
// step cannot pass without running them.

// testFlowTimeout is the conntrack timeout of created flows, in seconds. It
// outlasts the test.
const testFlowTimeout = 300

// enterTestNetns locks the test goroutine to its thread and moves the thread
// into a new network namespace until the test ends. It skips the test if that
// is not possible or the namespace has no ctnetlink.
func enterTestNetns(t *testing.T) {
	t.Helper()
	skip := t.Skipf
	if os.Getenv("CONNTRACK_KERNEL_TESTS") == "required" {
		skip = t.Fatalf
	}
	if os.Geteuid() != 0 {
		skip("needs root to create a network namespace")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		skip("get network namespace: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		skip("create network namespace: %v", err)
	}
	t.Cleanup(func() {
		ns.Close()
		defer orig.Close()
		if err := netns.Set(orig); err != nil {
			// Leave the thread locked, so it exits with the goroutine instead
			// of running other goroutines in the test namespace.
			t.Errorf("restore network namespace: %v", err)
			return
		}
		runtime.UnlockOSThread()
	})
	if _, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET); err != nil {
		skip("ctnetlink not available: %v", err)
	}
}

// createFlow adds flow to the kernel conntrack table, in conntrack zone
// flow.Zone. netlink.ConntrackCreate creates flows of protocols whose tuples
// carry ports, such as TCP, UDP, SCTP and GRE, but sends no CTA_ZONE, and the
// kernel refuses ICMP and ICMPv6 flows from it with EINVAL because it sends
// ports where the kernel needs the ICMP id, type and code. Flows in another
// zone, and ICMP and ICMPv6 flows, are sent with newFlowCreateRequest instead.
func createFlow(t *testing.T, flow *netlink.ConntrackFlow) {
	t.Helper()
	f := *flow
	f.TimeOut = testFlowTimeout
	if f.Zone == 0 && !isICMP(f.Forward.Protocol) {
		require.NoError(t, netlink.ConntrackCreate(netlink.ConntrackTable, netlink.InetFamily(f.FamilyType), &f))
		return
	}
	_, err := newFlowCreateRequest(&f).Execute(unix.NETLINK_NETFILTER, 0)
	require.NoError(t, err)
}

func isICMP(protocol uint8) bool {
	return protocol == unix.IPPROTO_ICMP || protocol == unix.IPPROTO_ICMPV6
}

// enum ctattr_l4proto values from include/uapi/linux/netfilter/nfnetlink_conntrack.h
// that nl does not define.
const (
	ctaProtoICMPID     = 4 // CTA_PROTO_ICMP_ID
	ctaProtoICMPType   = 5 // CTA_PROTO_ICMP_TYPE
	ctaProtoICMPCode   = 6 // CTA_PROTO_ICMP_CODE
	ctaProtoICMPv6ID   = 7 // CTA_PROTO_ICMPV6_ID
	ctaProtoICMPv6Type = 8 // CTA_PROTO_ICMPV6_TYPE
	ctaProtoICMPv6Code = 9 // CTA_PROTO_ICMPV6_CODE
)

// Echo request and reply types, from include/uapi/linux/icmp.h and
// include/uapi/linux/icmpv6.h. They are the ICMP types a pod's ping creates
// flows for.
const (
	icmpEchoRequest   = 8
	icmpEchoReply     = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

// testICMPID is the ICMP echo id of the flows newFlowCreateRequest builds.
const testICMPID = 0x4e50

// newFlowCreateRequest builds the ctnetlink IPCTNL_MSG_CT_NEW request that
// creates flow, in conntrack zone flow.Zone with timeout flow.TimeOut. It is the
// request netlink.ConntrackCreate sends, with CTA_ZONE added for a zone other
// than the default one. For ICMP and ICMPv6, each tuple carries an echo id,
// type and code in place of ports, which the kernel requires for those
// protocols: an echo request in the original tuple and an echo reply in the
// reply tuple, as a ping creates. The kernel reports such flows with zero
// ports, as testFlow builds them.
func newFlowCreateRequest(flow *netlink.ConntrackFlow) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(ctnetlinkMsgType(nl.IPCTNL_MSG_CT_NEW), unix.NLM_F_ACK|unix.NLM_F_CREATE)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: flow.FamilyType, Version: nl.NFNETLINK_V0})
	for _, tuple := range []struct {
		dir      int
		tpl      *netlink.IPTuple
		icmpType uint8
	}{
		{nl.CTA_TUPLE_ORIG, &flow.Forward, icmpEchoRequest},
		{nl.CTA_TUPLE_REPLY, &flow.Reverse, icmpEchoReply},
	} {
		attrs := tupleToNlData(tuple.tpl, flow.FamilyType)
		if isICMP(tuple.tpl.Protocol) {
			// Replace the ports with the ICMP fields.
			idType, typeType, codeType := ctaProtoICMPID, ctaProtoICMPType, ctaProtoICMPCode
			icmpType := tuple.icmpType
			if tuple.tpl.Protocol == unix.IPPROTO_ICMPV6 {
				idType, typeType, codeType = ctaProtoICMPv6ID, ctaProtoICMPv6Type, ctaProtoICMPv6Code
				icmpType = icmpv6EchoRequest
				if tuple.dir == nl.CTA_TUPLE_REPLY {
					icmpType = icmpv6EchoReply
				}
			}
			proto := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
			proto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_NUM, []byte{tuple.tpl.Protocol}))
			proto.AddChild(nl.NewRtAttr(idType, nl.BEUint16Attr(testICMPID)))
			proto.AddChild(nl.NewRtAttr(typeType, []byte{icmpType}))
			proto.AddChild(nl.NewRtAttr(codeType, []byte{0}))
			attrs[1] = proto
		}
		attr := nl.NewRtAttr(unix.NLA_F_NESTED|tuple.dir, nil)
		for _, a := range attrs {
			attr.AddChild(a)
		}
		req.AddData(attr)
	}
	req.AddData(nl.NewRtAttr(nl.CTA_TIMEOUT, nl.BEUint32Attr(flow.TimeOut)))
	if flow.Zone != 0 {
		req.AddData(nl.NewRtAttr(nl.CTA_ZONE, nl.BEUint16Attr(flow.Zone)))
	}
	return req
}

// conntrackTableProbe is the kernel conntrack table that the agent reads,
// netlinkConntrackTable, with call counts and injected failures for tests.
// Every read it does not fail goes to the kernel, and the kernel's answer
// reaches the GC unchanged: the probe never makes up a flow or an answer.
type conntrackTableProbe struct {
	// openErr, if set, fails openLookup without opening a socket.
	openErr error
	// failLookupAt is the 1-based lookup that fails with failLookupErr
	// instead of being sent, or 0 for none.
	failLookupAt  int
	failLookupErr error
	// dumpErr, if set, fails each dump. netlink.ErrDumpInterrupted is returned
	// after the kernel's dump has delivered its flows, which is how netlink
	// reports a dump the kernel flagged as inconsistent. Any other error is
	// returned without dumping.
	dumpErr error

	opens, closes int
	lookups       int
	// dumps holds the protocol of each dump, in order.
	dumps []uint8
}

// newConntrackTableProbe returns a probe that checks, when the test ends, that
// every lookup it opened was closed.
func newConntrackTableProbe(t *testing.T) *conntrackTableProbe {
	p := &conntrackTableProbe{}
	t.Cleanup(func() { assert.Equal(t, p.opens, p.closes, "lookups opened and closed") })
	return p
}

func (p *conntrackTableProbe) openLookup(family netlink.InetFamily) (flowLookup, error) {
	if p.openErr != nil {
		return nil, p.openErr
	}
	l, err := netlinkConntrackTable{}.openLookup(family)
	if err != nil {
		return nil, err
	}
	p.opens++
	return &probeFlowLookup{probe: p, flowLookup: l}, nil
}

func (p *conntrackTableProbe) dumpFlows(family netlink.InetFamily, protocol uint8, onFlow func(flow *netlink.ConntrackFlow)) error {
	p.dumps = append(p.dumps, protocol)
	if p.dumpErr != nil && !errors.Is(p.dumpErr, netlink.ErrDumpInterrupted) {
		return p.dumpErr
	}
	if err := (netlinkConntrackTable{}).dumpFlows(family, protocol, onFlow); err != nil {
		return err
	}
	return p.dumpErr
}

// probeFlowLookup counts the lookups of a kernel flowLookup and fails the
// probe's failLookupAt one.
type probeFlowLookup struct {
	probe *conntrackTableProbe
	flowLookup
}

func (l *probeFlowLookup) lookup(dir int, tpl *netlink.IPTuple, flow *netlink.ConntrackFlow) (bool, error) {
	l.probe.lookups++
	if l.probe.lookups == l.probe.failLookupAt {
		return false, l.probe.failLookupErr
	}
	return l.flowLookup.lookup(dir, tpl, flow)
}

func (l *probeFlowLookup) close() {
	l.probe.closes++
	l.flowLookup.close()
}

// TestRemoveStaleEntriesKernel runs a GC pass against kernel flows, with the BPF
// map reads and deletes replaced.
func TestRemoveStaleEntriesKernel(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		enterTestNetns(t)
		createFlow(t, testFlow(false, protoTCP, podA, 40000, remote, 443, remote, 443))
		createFlow(t, testFlow(false, protoTCP, podA, 40001, vip, 80, podB, 8080))
		createFlow(t, testFlow(false, protoGRE, podA, 0, remote, 0, remote, 0))
		createFlow(t, testFlow(false, protoSCTP, podA, 40002, remote, 9000, remote, 9000))

		kept := []utils.ConntrackKey{
			v4Key(podA, 40000, remote, 443, protoTCP, podA, 7),
			v4Key(podA, 40000, remote, 443, protoTCP, remote, 7),
			v4Key(podA, 40001, vip, 80, protoTCP, podA, 7),
			// The DNAT'd flow's key towards the backend, found by the inverse GET.
			v4Key(podA, 40001, podB, 8080, protoTCP, podB, 9),
			v4Key(podA, 0, remote, 0, protoGRE, podA, 7),
		}
		// active matches no flow, but the datapath touched it during the pass.
		active := v4Key(podA, 40098, remote, 443, protoTCP, podA, 7)
		stale := []utils.ConntrackKey{
			v4Key(podA, 40099, remote, 443, protoTCP, podA, 7),
			v4Key(podA, 40000, remote, 53, protoUDP, podA, 7),
			v4Key(podA, 0, podB, 0, protoGRE, podA, 7),
			// A reverse-direction key: a GET finds the flow by its reply tuple,
			// but the flow does not produce this key.
			v4Key(remote, 443, podA, 40000, protoTCP, remote, 7),
			// netlink reports no SCTP ports, so an entry with ports matches no
			// flow even though the kernel has it.
			v4Key(podA, 40002, remote, 9000, protoSCTP, podA, 7),
		}
		c := &conntrackClient{kernelTable: netlinkConntrackTable{}, localConntrackV4Cache: keySet(append(append(kept, stale...), active))}
		deleted := make(map[utils.ConntrackKey]bool)
		n, err := c.removeStaleV4Entries(testGCStart,
			func(k utils.ConntrackKey, _ uint64) bool { return k == active },
			func(k utils.ConntrackKey) { deleted[k] = true })
		require.NoError(t, err)
		assert.Equal(t, keySet(stale), deleted)
		assert.Equal(t, len(stale), n)
	})
	t.Run("v6", func(t *testing.T) {
		enterTestNetns(t)
		createFlow(t, testFlow(true, protoTCP, podA6, 40000, remote6, 443, remote6, 443))
		createFlow(t, testFlow(true, protoTCP, podA6, 40001, vip6, 80, podB6, 8080))
		createFlow(t, testFlow(true, protoGRE, podA6, 0, remote6, 0, remote6, 0))
		createFlow(t, testFlow(true, protoSCTP, podA6, 40002, remote6, 9000, remote6, 9000))

		kept := []utils.ConntrackKeyV6{
			v6Key(podA6, 40000, remote6, 443, protoTCP, podA6, 7),
			v6Key(podA6, 40000, remote6, 443, protoTCP, remote6, 7),
			v6Key(podA6, 40001, vip6, 80, protoTCP, podA6, 7),
			v6Key(podA6, 40001, podB6, 8080, protoTCP, podB6, 9),
			v6Key(podA6, 0, remote6, 0, protoGRE, podA6, 7),
		}
		active := v6Key(podA6, 40098, remote6, 443, protoTCP, podA6, 7)
		stale := []utils.ConntrackKeyV6{
			v6Key(podA6, 40099, remote6, 443, protoTCP, podA6, 7),
			v6Key(podA6, 40000, remote6, 53, protoUDP, podA6, 7),
			v6Key(podA6, 0, podB6, 0, protoGRE, podA6, 7),
			v6Key(remote6, 443, podA6, 40000, protoTCP, remote6, 7),
			v6Key(podA6, 40002, remote6, 9000, protoSCTP, podA6, 7),
		}
		c := &conntrackClient{kernelTable: netlinkConntrackTable{}, enableIPv6: true, localConntrackV6Cache: keySet(append(append(kept, stale...), active))}
		deleted := make(map[utils.ConntrackKeyV6]bool)
		n, err := c.removeStaleV6Entries(testGCStart,
			func(k utils.ConntrackKeyV6, _ uint64) bool { return k == active },
			func(k utils.ConntrackKeyV6) { deleted[k] = true })
		require.NoError(t, err)
		assert.Equal(t, keySet(stale), deleted)
		assert.Equal(t, len(stale), n)
	})
}

// withoutNetAdmin drops CAP_NET_ADMIN from the test thread's effective
// capabilities until the test ends, so the kernel answers its ctnetlink
// requests with EPERM.
func withoutNetAdmin(t *testing.T) {
	t.Helper()
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	require.NoError(t, unix.Capget(&hdr, &caps[0]))
	orig := caps
	caps[0].Effective &^= 1 << unix.CAP_NET_ADMIN
	require.NoError(t, unix.Capset(&hdr, &caps[0]))
	t.Cleanup(func() { require.NoError(t, unix.Capset(&hdr, &orig[0])) })
}

// TestRemoveStaleEntriesReadErrorKernel checks that a GC pass deletes nothing
// when the kernel refuses its reads, for an entry that is looked up and for one
// that is matched by a protocol dump.
func TestRemoveStaleEntriesReadErrorKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		v4   utils.ConntrackKey
		v6   utils.ConntrackKeyV6
	}{
		{"TCP entry", v4Key(podA, 40099, remote, 443, protoTCP, podA, 7), v6Key(podA6, 40099, remote6, 443, protoTCP, podA6, 7)},
		{"GRE entry", v4Key(podA, 0, podB, 0, protoGRE, podA, 7), v6Key(podA6, 0, podB6, 0, protoGRE, podA6, 7)},
	} {
		t.Run(tc.name+"/v4", func(t *testing.T) {
			enterTestNetns(t)
			c := &conntrackClient{kernelTable: netlinkConntrackTable{}, localConntrackV4Cache: keySet([]utils.ConntrackKey{tc.v4})}
			withoutNetAdmin(t)
			n, err := c.removeStaleV4Entries(testGCStart,
				func(utils.ConntrackKey, uint64) bool { return false },
				func(k utils.ConntrackKey) { t.Errorf("deleted %v", k) })
			assert.ErrorIs(t, err, unix.EPERM)
			assert.Zero(t, n)
		})
		t.Run(tc.name+"/v6", func(t *testing.T) {
			enterTestNetns(t)
			c := &conntrackClient{kernelTable: netlinkConntrackTable{}, enableIPv6: true, localConntrackV6Cache: keySet([]utils.ConntrackKeyV6{tc.v6})}
			withoutNetAdmin(t)
			n, err := c.removeStaleV6Entries(testGCStart,
				func(utils.ConntrackKeyV6, uint64) bool { return false },
				func(k utils.ConntrackKeyV6) { t.Errorf("deleted %v", k) })
			assert.ErrorIs(t, err, unix.EPERM)
			assert.Zero(t, n)
		})
	}
}
