package conntrack

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// tupleToNlData is netlink v1.3.1's IPTuple.toNlData, copied because it is
// unexported. It builds the inner attributes of a CTA_TUPLE_ORIG or
// CTA_TUPLE_REPLY, in the order the kernel emits them.
func tupleToNlData(t *netlink.IPTuple, family uint8) []*nl.RtAttr {
	srcIPsFlag, dstIPsFlag := nl.CTA_IP_V4_SRC, nl.CTA_IP_V4_DST
	if family == nl.FAMILY_V6 {
		srcIPsFlag, dstIPsFlag = nl.CTA_IP_V6_SRC, nl.CTA_IP_V6_DST
	}
	ctTupleIP := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	ctTupleIP.AddChild(nl.NewRtAttr(srcIPsFlag, t.SrcIP))
	ctTupleIP.AddChild(nl.NewRtAttr(dstIPsFlag, t.DstIP))

	ctTupleProto := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	ctTupleProto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_NUM, []byte{t.Protocol}))
	ctTupleProto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(t.SrcPort)))
	ctTupleProto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(t.DstPort)))
	return []*nl.RtAttr{ctTupleIP, ctTupleProto}
}

// flowToNlData is netlink v1.3.1's ConntrackFlow.toNlData, copied because it is
// unexported, with CTA_STATUS, CTA_ID and CTA_COUNTERS_ORIG added so the
// fixture also carries attributes a kernel GET reply has and the parser must skip.
func flowToNlData(s *netlink.ConntrackFlow) []*nl.RtAttr {
	ctTupleOrig := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	for _, a := range tupleToNlData(&s.Forward, s.FamilyType) {
		ctTupleOrig.AddChild(a)
	}
	ctTupleReply := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_REPLY, nil)
	for _, a := range tupleToNlData(&s.Reverse, s.FamilyType) {
		ctTupleReply.AddChild(a)
	}
	ctCounters := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_COUNTERS_ORIG, nil)
	ctCounters.AddChild(nl.NewRtAttr(nl.CTA_COUNTERS_PACKETS, nl.BEUint64Attr(3)))
	ctCounters.AddChild(nl.NewRtAttr(nl.CTA_COUNTERS_BYTES, nl.BEUint64Attr(180)))

	payload := []*nl.RtAttr{
		ctTupleOrig, ctTupleReply, ctCounters,
		nl.NewRtAttr(nl.CTA_STATUS, nl.BEUint32Attr(0x18e)),
		nl.NewRtAttr(nl.CTA_MARK, nl.BEUint32Attr(s.Mark)),
		nl.NewRtAttr(nl.CTA_TIMEOUT, nl.BEUint32Attr(s.TimeOut)),
		nl.NewRtAttr(nl.CTA_ID, nl.BEUint32Attr(0xdeadbeef)),
	}
	if p, ok := s.ProtoInfo.(*netlink.ProtoInfoTCP); ok {
		ctProtoInfo := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO, []byte{})
		ctProtoInfoTCP := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO_TCP, []byte{})
		ctProtoInfoTCP.AddChild(nl.NewRtAttr(nl.CTA_PROTOINFO_TCP_STATE, nl.Uint8Attr(p.State)))
		ctProtoInfo.AddChild(ctProtoInfoTCP)
		payload = append(payload, ctProtoInfo)
	}
	return payload
}

// flowMessage serializes a conntrack message body as ExecuteIter hands it
// to the callback: the nfgenmsg header followed by the attributes.
func flowMessage(family uint8, attrs []*nl.RtAttr) []byte {
	msg := (&nl.Nfgenmsg{NfgenFamily: family, Version: nl.NFNETLINK_V0}).Serialize()
	msg = append([]byte{}, msg...)
	for _, a := range attrs {
		msg = append(msg, a.Serialize()...)
	}
	return msg
}

func TestParseConntrackFlow(t *testing.T) {
	tcp, udp, sctp := uint8(unix.IPPROTO_TCP), uint8(unix.IPPROTO_UDP), uint8(unix.IPPROTO_SCTP)
	cases := []struct {
		name string
		flow *netlink.ConntrackFlow
		// want is the flow the parser should return when it differs from flow.
		want *netlink.ConntrackFlow
	}{
		{
			name: "v4 tcp with protoinfo",
			flow: func() *netlink.ConntrackFlow {
				f := testFlow(false, tcp, podA, 40000, remote, 443, remote, 443)
				f.ProtoInfo = &netlink.ProtoInfoTCP{State: nl.TCP_CONNTRACK_ESTABLISHED}
				f.TimeOut = 120
				return f
			}(),
		},
		{
			name: "v4 udp via VIP",
			flow: testFlow(false, udp, podA, 41000, vip, 53, podB, 5353),
		},
		{
			name: "v6 tcp via VIP",
			flow: testFlow(true, tcp, podA6, 42000, vip6, 80, podB6, 8080),
		},
		{
			name: "v4 sctp ports are left at zero like netlink's parser",
			flow: testFlow(false, sctp, podA, 43000, remote, 9999, remote, 9999),
			want: testFlow(false, sctp, podA, 0, remote, 0, remote, 0),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := flowMessage(tc.flow.FamilyType, flowToNlData(tc.flow))
			var got netlink.ConntrackFlow
			require.NoError(t, parseConntrackFlow(msg, &got))
			want := tc.flow
			if tc.want != nil {
				want = tc.want
			}
			assert.Equal(t, want.FamilyType, got.FamilyType)
			assert.Equal(t, want.Forward, got.Forward)
			assert.Equal(t, want.Reverse, got.Reverse)
		})
	}
}

// TestParseConntrackFlowICMP builds the tuple the kernel emits for ICMP, which
// carries CTA_PROTO_ICMP_* attributes instead of ports.
func TestParseConntrackFlowICMP(t *testing.T) {
	orig := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	reply := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_REPLY, nil)
	for _, pair := range []struct {
		parent   *nl.RtAttr
		src, dst string
	}{{orig, podA, remote}, {reply, remote, podA}} {
		ip := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
		ip.AddChild(nl.NewRtAttr(nl.CTA_IP_V4_SRC, net.ParseIP(pair.src).To4()))
		ip.AddChild(nl.NewRtAttr(nl.CTA_IP_V4_DST, net.ParseIP(pair.dst).To4()))
		proto := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
		proto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_NUM, []byte{unix.IPPROTO_ICMP}))
		proto.AddChild(nl.NewRtAttr(ctaProtoICMPID, nl.BEUint16Attr(77)))
		proto.AddChild(nl.NewRtAttr(ctaProtoICMPType, []byte{8}))
		proto.AddChild(nl.NewRtAttr(ctaProtoICMPCode, []byte{0}))
		pair.parent.AddChild(ip)
		pair.parent.AddChild(proto)
	}
	msg := flowMessage(nl.FAMILY_V4, []*nl.RtAttr{orig, reply})

	var got netlink.ConntrackFlow
	require.NoError(t, parseConntrackFlow(msg, &got))
	want := testFlow(false, unix.IPPROTO_ICMP, podA, 0, remote, 0, remote, 0)
	assert.Equal(t, want.Forward, got.Forward)
	assert.Equal(t, want.Reverse, got.Reverse)
}

// TestParseConntrackFlowMasksFlags checks the attribute type masking against
// netlink's parser: inner attributes without NLA_F_NESTED still parse, and a
// port attribute with NLA_F_NET_BYTEORDER is not recognized, so its port stays
// zero.
func TestParseConntrackFlowMasksFlags(t *testing.T) {
	flow := testFlow(false, unix.IPPROTO_TCP, podA, 40000, remote, 443, remote, 443)
	build := func(portFlag int) []byte {
		var attrs []*nl.RtAttr
		for _, parentType := range []int{nl.CTA_TUPLE_ORIG, nl.CTA_TUPLE_REPLY} {
			tpl := &flow.Forward
			if parentType == nl.CTA_TUPLE_REPLY {
				tpl = &flow.Reverse
			}
			ip := nl.NewRtAttr(nl.CTA_TUPLE_IP, nil)
			ip.AddChild(nl.NewRtAttr(nl.CTA_IP_V4_SRC, tpl.SrcIP))
			ip.AddChild(nl.NewRtAttr(nl.CTA_IP_V4_DST, tpl.DstIP))
			proto := nl.NewRtAttr(nl.CTA_TUPLE_PROTO, nil)
			proto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_NUM, []byte{tpl.Protocol}))
			proto.AddChild(nl.NewRtAttr(portFlag|nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(tpl.SrcPort)))
			proto.AddChild(nl.NewRtAttr(portFlag|nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(tpl.DstPort)))
			parent := nl.NewRtAttr(unix.NLA_F_NESTED|parentType, nil)
			parent.AddChild(ip)
			parent.AddChild(proto)
			attrs = append(attrs, parent)
		}
		return flowMessage(nl.FAMILY_V4, attrs)
	}

	var got netlink.ConntrackFlow
	require.NoError(t, parseConntrackFlow(build(0), &got))
	assert.Equal(t, flow.Forward, got.Forward)
	assert.Equal(t, flow.Reverse, got.Reverse)

	require.NoError(t, parseConntrackFlow(build(unix.NLA_F_NET_BYTEORDER), &got))
	noPorts := testFlow(false, unix.IPPROTO_TCP, podA, 0, remote, 0, remote, 0)
	assert.Equal(t, noPorts.Forward, got.Forward)
	assert.Equal(t, noPorts.Reverse, got.Reverse)
}

// TestParseConntrackFlowResetsReusedFlow checks that fields from the previous
// message do not leak into the next one when the flow is reused.
func TestParseConntrackFlowResetsReusedFlow(t *testing.T) {
	var got netlink.ConntrackFlow
	first := testFlow(false, unix.IPPROTO_TCP, podA, 40000, remote, 443, remote, 443)
	require.NoError(t, parseConntrackFlow(flowMessage(nl.FAMILY_V4, flowToNlData(first)), &got))
	second := testFlow(false, unix.IPPROTO_SCTP, podB, 1, remote, 2, remote, 2)
	require.NoError(t, parseConntrackFlow(flowMessage(nl.FAMILY_V4, flowToNlData(second)), &got))
	assert.Equal(t, testFlow(false, unix.IPPROTO_SCTP, podB, 0, remote, 0, remote, 0).Forward, got.Forward)
}

func TestParseConntrackFlowErrors(t *testing.T) {
	flow := testFlow(false, unix.IPPROTO_TCP, podA, 40000, remote, 443, remote, 443)
	full := flowToNlData(flow)
	noIPs := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	noIPs.AddChild(tupleToNlData(&flow.Forward, nl.FAMILY_V4)[1])

	cases := []struct {
		name string
		msg  []byte
	}{
		{name: "shorter than nfgenmsg", msg: []byte{unix.AF_INET, 0}},
		{name: "no tuples", msg: flowMessage(nl.FAMILY_V4, full[2:])},
		{name: "missing reply tuple", msg: flowMessage(nl.FAMILY_V4, []*nl.RtAttr{full[0]})},
		{name: "tuple without IPs", msg: flowMessage(nl.FAMILY_V4, []*nl.RtAttr{noIPs, full[1]})},
		{name: "attribute length past end", msg: func() []byte {
			m := flowMessage(nl.FAMILY_V4, full)
			return m[:len(m)-3]
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got netlink.ConntrackFlow
			assert.Error(t, parseConntrackFlow(tc.msg, &got))
		})
	}
}

func TestNewFlowGetRequest(t *testing.T) {
	cases := []struct {
		name   string
		family netlink.InetFamily
		dir    int
		tpl    netlink.IPTuple
		// want is the request after the nlmsghdr: the nfgenmsg header and the
		// attributes, with attribute lengths and types in host byte order
		// (little-endian here).
		want []byte
	}{
		{
			name:   "v4 original tuple",
			family: unix.AF_INET,
			dir:    nl.CTA_TUPLE_ORIG,
			tpl: netlink.IPTuple{
				SrcIP: net.ParseIP(podA), SrcPort: 40000,
				DstIP: net.ParseIP(remote), DstPort: 443,
				Protocol: unix.IPPROTO_TCP,
			},
			want: []byte{
				unix.AF_INET, nl.NFNETLINK_V0, 0x00, 0x00, // nfgenmsg, res_id 0
				0x34, 0x00, 0x01, 0x80, // CTA_TUPLE_ORIG | NLA_F_NESTED, 52 bytes
				0x14, 0x00, 0x01, 0x80, // CTA_TUPLE_IP | NLA_F_NESTED, 20 bytes
				0x08, 0x00, 0x01, 0x00, 10, 0, 1, 10, // CTA_IP_V4_SRC 10.0.1.10
				0x08, 0x00, 0x02, 0x00, 10, 0, 9, 9, // CTA_IP_V4_DST 10.0.9.9
				0x1c, 0x00, 0x02, 0x80, // CTA_TUPLE_PROTO | NLA_F_NESTED, 28 bytes
				0x05, 0x00, 0x01, 0x00, unix.IPPROTO_TCP, 0x00, 0x00, 0x00, // CTA_PROTO_NUM, padded
				0x06, 0x00, 0x02, 0x00, 0x9c, 0x40, 0x00, 0x00, // CTA_PROTO_SRC_PORT 40000, big-endian
				0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, // CTA_PROTO_DST_PORT 443, big-endian
			},
		},
		{
			name:   "v6 reply tuple",
			family: unix.AF_INET6,
			dir:    nl.CTA_TUPLE_REPLY,
			tpl: netlink.IPTuple{
				SrcIP: net.ParseIP(podB6), SrcPort: 8080,
				DstIP: net.ParseIP(podA6), DstPort: 41000,
				Protocol: unix.IPPROTO_UDP,
			},
			want: []byte{
				unix.AF_INET6, nl.NFNETLINK_V0, 0x00, 0x00,
				0x4c, 0x00, 0x02, 0x80, // CTA_TUPLE_REPLY | NLA_F_NESTED, 76 bytes
				0x2c, 0x00, 0x01, 0x80, // CTA_TUPLE_IP | NLA_F_NESTED, 44 bytes
				0x14, 0x00, 0x03, 0x00, // CTA_IP_V6_SRC 2001:db8::b
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b,
				0x14, 0x00, 0x04, 0x00, // CTA_IP_V6_DST 2001:db8::a
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
				0x1c, 0x00, 0x02, 0x80,
				0x05, 0x00, 0x01, 0x00, unix.IPPROTO_UDP, 0x00, 0x00, 0x00,
				0x06, 0x00, 0x02, 0x00, 0x1f, 0x90, 0x00, 0x00, // 8080
				0x06, 0x00, 0x03, 0x00, 0xa0, 0x28, 0x00, 0x00, // 41000
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newFlowGetRequest(tc.family, tc.dir, &tc.tpl)
			b := req.Serialize()
			require.Greater(t, len(b), unix.SizeofNlMsghdr)
			assert.Equal(t, tc.want, b[unix.SizeofNlMsghdr:])
			assert.Equal(t, uint32(len(b)), req.Len)
			assert.Equal(t, uint16(unix.NFNL_SUBSYS_CTNETLINK<<8|nl.IPCTNL_MSG_CT_GET), req.Type)
			// A single-flow GET, not a dump, with an ACK to end the reply.
			assert.Equal(t, uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK), req.Flags)
		})
	}
}

// TestParseGetReply checks the reply a kernel sends for a GET of a DNAT'd and
// SNAT'd flow: both tuples come back, whichever one the request carried.
func TestParseGetReply(t *testing.T) {
	flow := testNATFlow(false, unix.IPPROTO_TCP, podA, 49000, vip, 80, podB, 8080, node, 61001)
	var got netlink.ConntrackFlow
	require.NoError(t, parseConntrackFlow(flowMessage(nl.FAMILY_V4, flowToNlData(flow)), &got))
	assert.Equal(t, flow.Forward, got.Forward)
	assert.Equal(t, flow.Reverse, got.Reverse)
	assert.True(t, flowHasKey(&got, v4GCEntry(v4Key(podA, 49000, vip, 80, unix.IPPROTO_TCP, podA, 7)).key))
	assert.True(t, flowHasKey(&got, v4GCEntry(v4Key(podA, 49000, podB, 8080, unix.IPPROTO_TCP, podB, 7)).key))
	assert.False(t, flowHasKey(&got, v4GCEntry(v4Key(node, 61001, podB, 8080, unix.IPPROTO_TCP, podB, 7)).key))
}

func TestNewProtocolDumpRequest(t *testing.T) {
	cases := []struct {
		name     string
		family   netlink.InetFamily
		protocol uint8
		// want is the request after the nlmsghdr: the nfgenmsg header and the
		// attributes, with attribute lengths, types and the filter flags in
		// host byte order (little-endian here).
		want []byte
	}{
		{
			name:     "v4 ICMP",
			family:   unix.AF_INET,
			protocol: unix.IPPROTO_ICMP,
			want: []byte{
				unix.AF_INET, nl.NFNETLINK_V0, 0x00, 0x00, // nfgenmsg, res_id 0
				0x10, 0x00, 0x01, 0x80, // CTA_TUPLE_ORIG | NLA_F_NESTED, 16 bytes
				0x0c, 0x00, 0x02, 0x80, // CTA_TUPLE_PROTO | NLA_F_NESTED, 12 bytes
				0x05, 0x00, 0x01, 0x00, unix.IPPROTO_ICMP, 0x00, 0x00, 0x00, // CTA_PROTO_NUM, padded
				0x0c, 0x00, 0x19, 0x80, // CTA_FILTER (25) | NLA_F_NESTED, 12 bytes
				0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, // CTA_FILTER_ORIG_FLAGS = CTA_FILTER_F_CTA_PROTO_NUM
			},
		},
		{
			name:     "v6 ICMPv6",
			family:   unix.AF_INET6,
			protocol: unix.IPPROTO_ICMPV6,
			want: []byte{
				unix.AF_INET6, nl.NFNETLINK_V0, 0x00, 0x00,
				0x10, 0x00, 0x01, 0x80,
				0x0c, 0x00, 0x02, 0x80,
				0x05, 0x00, 0x01, 0x00, unix.IPPROTO_ICMPV6, 0x00, 0x00, 0x00,
				0x0c, 0x00, 0x19, 0x80,
				0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newProtocolDumpRequest(tc.family, tc.protocol)
			b := req.Serialize()
			require.Greater(t, len(b), unix.SizeofNlMsghdr)
			assert.Equal(t, tc.want, b[unix.SizeofNlMsghdr:])
			assert.Equal(t, uint32(len(b)), req.Len)
			assert.Equal(t, uint16(unix.NFNL_SUBSYS_CTNETLINK<<8|nl.IPCTNL_MSG_CT_GET), req.Type)
			assert.Equal(t, uint16(unix.NLM_F_REQUEST|unix.NLM_F_DUMP), req.Flags)
		})
	}
}

// kernelReadCase checks which kernel reads one GC pass sends, with flows in
// the kernel conntrack table of a new network namespace.
type kernelReadCase[K comparable] struct {
	name  string
	flows []*netlink.ConntrackFlow
	local []K
	// failLookupAt and failLookupErr make that lookup fail, openErr makes
	// the open fail, and dumpErr makes the dumps fail, as described on
	// conntrackTableProbe.
	failLookupAt  int
	failLookupErr error
	openErr       error
	dumpErr       error

	wantLookups int
	wantDumps   []uint8
	wantDeleted int
	wantErr     error
}

// kernelReadTable creates tc's flows in the kernel conntrack table of a new
// network namespace and returns a probe of the table with tc's failures.
func kernelReadTable[K comparable](t *testing.T, tc kernelReadCase[K]) *conntrackTableProbe {
	enterTestNetns(t)
	for _, f := range tc.flows {
		createFlow(t, f)
	}
	table := newConntrackTableProbe(t)
	table.failLookupAt, table.failLookupErr = tc.failLookupAt, tc.failLookupErr
	table.openErr, table.dumpErr = tc.openErr, tc.dumpErr
	return table
}

func checkKernelReads[K comparable](t *testing.T, tc kernelReadCase[K], table *conntrackTableProbe, n int, err error) {
	t.Helper()
	assert.Equal(t, tc.wantLookups, table.lookups, "lookups")
	assert.ElementsMatch(t, tc.wantDumps, table.dumps, "dumps")
	assert.Equal(t, tc.wantDeleted, n, "deleted")
	if tc.wantErr != nil {
		assert.ErrorIs(t, err, tc.wantErr)
	} else {
		assert.NoError(t, err)
	}
}

func TestRemoveStaleV4EntriesReadsKernel(t *testing.T) {
	tcpFlow := testFlow(false, protoTCP, podA, 40000, remote, 443, remote, 443)
	icmpFlow := testFlow(false, protoICMP, podA, 0, remote, 0, remote, 0)
	cases := []kernelReadCase[utils.ConntrackKey]{
		{
			name:  "no ICMP entries: lookups only, no dump",
			flows: []*netlink.ConntrackFlow{tcpFlow, icmpFlow},
			local: []utils.ConntrackKey{
				v4Key(podA, 40000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 40001, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 40002, remote, 53, protoUDP, podA, 7),
			},
			wantLookups: 1 + 2 + 2,
			wantDeleted: 2,
		},
		{
			name:  "ICMP entries: one ICMP dump, no lookups for them",
			flows: []*netlink.ConntrackFlow{tcpFlow, icmpFlow},
			local: []utils.ConntrackKey{
				v4Key(podA, 40000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, podA, 9),
				v4Key(podA, 0, podB, 0, protoICMP, podA, 7),
			},
			wantLookups: 1,
			wantDumps:   []uint8{protoICMP},
			wantDeleted: 1,
		},
		{
			name:  "one dump per portless protocol",
			flows: []*netlink.ConntrackFlow{icmpFlow},
			local: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
				v4Key(podA, 0, remote, 0, protoGRE, podA, 7),
			},
			wantDumps:   []uint8{protoICMP, protoGRE},
			wantDeleted: 1,
		},
		{
			name:  "entries that match nothing need no read",
			flows: []*netlink.ConntrackFlow{tcpFlow, icmpFlow},
			local: []utils.ConntrackKey{
				// netlink reports no SCTP ports.
				v4Key(podA, 41000, remote, 9999, protoSCTP, podA, 7),
				// The datapath stores ICMP without ports.
				v4Key(podA, 1, remote, 0, protoICMP, podA, 7),
			},
			wantDeleted: 2,
		},
		{
			// No flow produces a key whose owner is neither side, so these are
			// read like any other entry and found stale.
			name:  "owner that is neither side: read, then deleted",
			flows: []*netlink.ConntrackFlow{tcpFlow, icmpFlow},
			local: []utils.ConntrackKey{
				v4Key(podA, 0, remote, 0, protoICMP, podB, 7),
				v4Key(podA, 40000, remote, 443, protoTCP, podB, 7),
			},
			wantLookups: 2,
			wantDumps:   []uint8{protoICMP},
			wantDeleted: 2,
		},
		{
			name: "first lookup fails: nothing deleted",
			local: []utils.ConntrackKey{
				v4Key(podA, 42000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
			},
			failLookupAt:  1,
			failLookupErr: unix.ENOBUFS,
			wantLookups:   1,
			wantErr:       unix.ENOBUFS,
		},
		{
			name: "inverse lookup fails after a stale entry: nothing deleted",
			local: []utils.ConntrackKey{
				v4Key(podA, 43000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 43001, remote, 443, protoTCP, podA, 7),
			},
			failLookupAt:  4,
			failLookupErr: unix.EAGAIN,
			wantLookups:   4,
			wantErr:       unix.EAGAIN,
		},
		{
			name: "socket open fails: nothing read or deleted",
			local: []utils.ConntrackKey{
				v4Key(podA, 44000, remote, 443, protoTCP, podA, 7),
			},
			openErr: unix.EMFILE,
			wantErr: unix.EMFILE,
		},
		{
			name: "dump fails after lookups: nothing deleted",
			local: []utils.ConntrackKey{
				v4Key(podA, 45000, remote, 443, protoTCP, podA, 7),
				v4Key(podA, 0, remote, 0, protoICMP, podA, 7),
			},
			dumpErr:     netlink.ErrDumpInterrupted,
			wantLookups: 2,
			wantDumps:   []uint8{protoICMP},
			wantErr:     netlink.ErrDumpInterrupted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table := kernelReadTable(t, tc)
			c := &conntrackClient{kernelTable: table, localConntrackV4Cache: keySet(tc.local)}
			deleted := 0
			n, err := c.removeStaleV4Entries(testGCStart,
				func(utils.ConntrackKey, uint64) bool { return false },
				func(utils.ConntrackKey) { deleted++ })
			assert.Equal(t, deleted, n)
			checkKernelReads(t, tc, table, n, err)
		})
	}
}

func TestRemoveStaleV6EntriesReadsKernel(t *testing.T) {
	icmp6Flow := testFlow(true, protoICMPv6, podA6, 0, remote6, 0, remote6, 0)
	errRecv := errors.New("netlink receive failed")
	cases := []kernelReadCase[utils.ConntrackKeyV6]{
		{
			name: "no ICMPv6 entries: lookups only, no dump",
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 40000, remote6, 443, protoTCP, podA6, 7),
			},
			wantLookups: 2,
			wantDeleted: 1,
		},
		{
			name:  "ICMPv6 entries: one ICMPv6 dump",
			flows: []*netlink.ConntrackFlow{icmp6Flow},
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 7),
				v6Key(podA6, 0, podB6, 0, protoICMPv6, podA6, 7),
			},
			wantDumps:   []uint8{protoICMPv6},
			wantDeleted: 1,
		},
		{
			name: "lookup fails: nothing deleted",
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 41000, remote6, 443, protoTCP, podA6, 7),
			},
			failLookupAt:  2,
			failLookupErr: errRecv,
			wantLookups:   2,
			wantErr:       errRecv,
		},
		{
			name: "dump fails: nothing deleted",
			local: []utils.ConntrackKeyV6{
				v6Key(podA6, 0, remote6, 0, protoICMPv6, podA6, 7),
			},
			dumpErr:   unix.ENOBUFS,
			wantDumps: []uint8{protoICMPv6},
			wantErr:   unix.ENOBUFS,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table := kernelReadTable(t, tc)
			c := &conntrackClient{kernelTable: table, enableIPv6: true, localConntrackV6Cache: keySet(tc.local)}
			deleted := 0
			n, err := c.removeStaleV6Entries(testGCStart,
				func(utils.ConntrackKeyV6, uint64) bool { return false },
				func(utils.ConntrackKeyV6) { deleted++ })
			assert.Equal(t, deleted, n)
			checkKernelReads(t, tc, table, n, err)
		})
	}
}
