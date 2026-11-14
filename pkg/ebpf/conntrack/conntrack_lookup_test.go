package conntrack

import (
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

// kernelReadCase checks which kernel reads one GC pass sends, with flows in
// the kernel conntrack table of a new network namespace.
type kernelReadCase struct {
	name  string
	flows []*netlink.ConntrackFlow
	local []utils.ConntrackKey
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

func TestRemoveStaleV4EntriesReadsKernel(t *testing.T) {
	tcpFlow := testFlow(false, protoTCP, podA, 40000, remote, 443, remote, 443)
	icmpFlow := testFlow(false, protoICMP, podA, 0, remote, 0, remote, 0)
	cases := []kernelReadCase{
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
			enterTestNetns(t)
			for _, f := range tc.flows {
				createFlow(t, f)
			}
			table := newConntrackTableProbe(t)
			table.failLookupAt, table.failLookupErr = tc.failLookupAt, tc.failLookupErr
			table.openErr, table.dumpErr = tc.openErr, tc.dumpErr
			c := &conntrackClient{kernelTable: table, localConntrackV4Cache: keySet(tc.local)}
			deleted := 0
			n, err := c.removeStaleV4Entries(testGCStart,
				func(utils.ConntrackKey, uint64) bool { return false },
				func(utils.ConntrackKey) { deleted++ })
			assert.Equal(t, deleted, n)
			assert.Equal(t, tc.wantLookups, table.lookups, "lookups")
			assert.ElementsMatch(t, tc.wantDumps, table.dumps, "dumps")
			assert.Equal(t, tc.wantDeleted, n, "deleted")
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
