package conntrack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// nlaTypeMask strips NLA_F_NESTED from an attribute type. It is the mask
// netlink's own conntrack parser applies, which keeps NLA_F_NET_BYTEORDER, so an
// attribute with that flag is not recognized here either. ctnetlink does not set
// it on the tuple attributes.
const nlaTypeMask = nl.NLA_F_NESTED - 1

// flowLookup looks up single flows in the kernel conntrack table.
type flowLookup interface {
	// lookup asks the kernel for the flow that has tpl as one of its tuples and
	// fills flow with it. dir is nl.CTA_TUPLE_ORIG or nl.CTA_TUPLE_REPLY. The
	// kernel ignores dir when it searches: its conntrack hash holds both tuples
	// of every flow and a tuple belongs to at most one flow per zone, so either
	// direction finds the flow that has tpl as its original or its reply tuple.
	// The search covers the default conntrack zone only. found is false if no
	// flow has tpl. Any other failure is returned as an error.
	lookup(dir int, tpl *netlink.IPTuple, flow *netlink.ConntrackFlow) (found bool, err error)
	close()
}

// conntrackTable is how the GC reads the kernel conntrack table: lookups of
// single flows, and dumps of one protocol's flows. netlinkConntrackTable reads
// it over ctnetlink; tests wrap it to count reads and inject failures.
type conntrackTable interface {
	// openLookup opens a flowLookup for family.
	openLookup(family netlink.InetFamily) (flowLookup, error)
	// dumpFlows calls onFlow with each flow of family whose L4 protocol is
	// protocol, as streamProtocolFlows does.
	dumpFlows(family netlink.InetFamily, protocol uint8, onFlow func(flow *netlink.ConntrackFlow)) error
}

// netlinkConntrackTable is the conntrackTable the agent uses.
type netlinkConntrackTable struct{}

func (netlinkConntrackTable) openLookup(family netlink.InetFamily) (flowLookup, error) {
	return openNetlinkFlowLookup(family)
}

func (netlinkConntrackTable) dumpFlows(family netlink.InetFamily, protocol uint8, onFlow func(flow *netlink.ConntrackFlow)) error {
	return streamProtocolFlows(family, protocol, onFlow)
}

// netlinkFlowLookup sends ctnetlink GET requests over one netlink socket, so a
// cleanup cycle opens a single socket however many entries it looks up.
type netlinkFlowLookup struct {
	family netlink.InetFamily // for each request's nfgenmsg header
	socket *nl.SocketHandle   // shared by all the cycle's GETs
}

// openNetlinkFlowLookup opens the ctnetlink socket that one GC cycle sends all
// its GETs over, so a cycle opens one socket rather than one per lookup. The
// caller closes the lookup when the cycle ends.
func openNetlinkFlowLookup(family netlink.InetFamily) (flowLookup, error) {
	// netns.None() for both namespaces: the socket is opened in the agent's
	// current network namespace.
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	// ExecuteIter sets send and receive timeouts only on the sockets it opens
	// itself, and uses a socket passed in through req.Sockets as it is. Set the
	// same timeouts here, so a reply that never arrives fails the lookup
	// instead of blocking the GC.
	if err := s.SetSendTimeout(&nl.SocketTimeoutTv); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.SetReceiveTimeout(&nl.SocketTimeoutTv); err != nil {
		s.Close()
		return nil, err
	}
	return &netlinkFlowLookup{family: family, socket: &nl.SocketHandle{Socket: s}}, nil
}

// lookup sends one ctnetlink GET for tpl over the cycle's socket and fills
// flow with the kernel's answer. See flowLookup for what it reports.
func (l *netlinkFlowLookup) lookup(dir int, tpl *netlink.IPTuple, flow *netlink.ConntrackFlow) (bool, error) {
	req := newFlowGetRequest(l.family, dir, tpl)
	// Send over the cycle's socket rather than one ExecuteIter would open. On a
	// shared socket, ExecuteIter skips replies whose sequence number is not
	// this request's, such as a late reply to an earlier GET that timed out.
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: l.socket}
	var parseErr error
	got := false
	// When a flow has tpl, the kernel sends the flow and then an ACK, which
	// ExecuteIter reads and does not pass on, so the callback sees only the
	// flow. Returning false makes ExecuteIter drain the rest of the reply
	// without calling it again.
	err := req.ExecuteIter(unix.NETLINK_NETFILTER, 0, func(msg []byte) bool {
		parseErr = parseConntrackFlow(msg, flow)
		got = true
		return false
	})
	// When no flow has tpl, the kernel's only reply is an ENOENT error.
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if parseErr != nil {
		return false, parseErr
	}
	// An ACK with no flow before it is not an answer the kernel gives to a GET.
	// Report it as an error, so the cycle deletes nothing, rather than as "no
	// such flow", which would make the entry stale.
	if !got {
		return false, errors.New("conntrack get returned no flow")
	}
	return true, nil
}

func (l *netlinkFlowLookup) close() {
	l.socket.Close()
}

// newCtnetlinkRequest starts a ctnetlink request for message msg about flows
// of family. nfnetlink puts the subsystem in the high byte of the message type
// and the subsystem's own message in the low byte (NFNL_SUBSYS_ID and
// NFNL_MSG_TYPE in include/uapi/linux/netfilter/nfnetlink.h), and the payload
// must start with an nfgenmsg header: the address family, the protocol
// version, and a resource ID that ctnetlink does not use.
func newCtnetlinkRequest(msg, flags int, family netlink.InetFamily) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(unix.NFNL_SUBSYS_CTNETLINK<<8|msg, flags)
	req.AddData(&nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	})
	return req
}

// newFlowGetRequest builds a ctnetlink IPCTNL_MSG_CT_GET request for the flow
// with tuple tpl. dir is nl.CTA_TUPLE_ORIG or nl.CTA_TUPLE_REPLY and names the
// attribute that carries the tuple. The tuple attributes are the ones netlink's
// unexported IPTuple.toNlData builds. The request has no CTA_ZONE, so the
// kernel looks in the default zone.
//
// The kernel sends the flow with NLM_F_MULTI set and no NLMSG_DONE after it,
// so ExecuteIter would wait for more messages until the socket times out. The
// request sets NLM_F_ACK so that an ACK follows the flow and ends the exchange.
// When no flow has the tuple, the only reply is an ENOENT error.
func newFlowGetRequest(family netlink.InetFamily, dir int, tpl *netlink.IPTuple) *nl.NetlinkRequest {
	req := newCtnetlinkRequest(nl.IPCTNL_MSG_CT_GET, unix.NLM_F_ACK, family)

	// The kernel takes 4-byte CTA_IP_V4_* and 16-byte CTA_IP_V6_* addresses.
	// A net.IP can hold an IPv4 address in 16 bytes, so convert it to the
	// family's length.
	srcIPType, dstIPType := nl.CTA_IP_V4_SRC, nl.CTA_IP_V4_DST
	srcIP, dstIP := tpl.SrcIP.To4(), tpl.DstIP.To4()
	if family == unix.AF_INET6 {
		srcIPType, dstIPType = nl.CTA_IP_V6_SRC, nl.CTA_IP_V6_DST
		srcIP, dstIP = tpl.SrcIP.To16(), tpl.DstIP.To16()
	}
	// The tuple and its parts are nested attributes, flagged NLA_F_NESTED as
	// in the requests netlink builds itself.
	tuple := nl.NewRtAttr(unix.NLA_F_NESTED|dir, nil)
	tupleIP := tuple.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	tupleIP.AddRtAttr(srcIPType, srcIP)
	tupleIP.AddRtAttr(dstIPType, dstIP)
	tupleProto := tuple.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	tupleProto.AddRtAttr(nl.CTA_PROTO_NUM, []byte{tpl.Protocol})
	// Ports go in network byte order, which is how conntrack stores them.
	tupleProto.AddRtAttr(nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(tpl.SrcPort))
	tupleProto.AddRtAttr(nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(tpl.DstPort))
	req.AddData(tuple)
	return req
}

// ctnetlink attributes from linux/netfilter/nfnetlink_conntrack.h that nl does
// not define, and the CTA_FILTER flag for the protocol number from
// net/netfilter/nf_internals.h.
const (
	ctaFilter             = 25     // CTA_FILTER
	ctaFilterOrigFlags    = 1      // CTA_FILTER_ORIG_FLAGS
	ctaFilterFlagProtoNum = 1 << 3 // CTA_FILTER_F_CTA_PROTO_NUM
)

// streamProtocolFlows dumps the kernel conntrack flows of family whose original
// tuple has L4 protocol protocol, and calls onFlow once per flow as the
// netlink messages arrive. The flow passed to onFlow is reused between calls
// and its IPs point into the receive buffer, so onFlow must not keep it.
//
// The request asks the kernel to filter the dump by protocol with CTA_FILTER,
// which ctnetlink supports since Linux 5.8. The kernel then sends only the
// matching flows, from every conntrack zone since the request has no CTA_ZONE.
// Older kernels ignore the attribute and send the whole family. That is still
// correct, only slower: keys built from other protocols' flows carry their own
// protocol, so they match no entry of this one. If the kernel flagged the dump
// as inconsistent, it returns netlink.ErrDumpInterrupted.
func streamProtocolFlows(family netlink.InetFamily, protocol uint8, onFlow func(flow *netlink.ConntrackFlow)) error {
	req := newProtocolDumpRequest(family, protocol)
	// One flow, reused for every message, so the dump never holds more than
	// one flow at a time.
	var flow netlink.ConntrackFlow
	// A message that does not parse is returned as the dump's error once
	// ExecuteIter finishes, so the GC fails the cycle instead of acting on a
	// partial view of the table.
	var parseErr error
	err := req.ExecuteIter(unix.NETLINK_NETFILTER, 0, func(msg []byte) bool {
		if parseErr = parseConntrackFlow(msg, &flow); parseErr != nil {
			// Stop calling onFlow. ExecuteIter drains the rest of the dump.
			return false
		}
		onFlow(&flow)
		return true
	})
	if err != nil {
		return err
	}
	return parseErr
}

// newProtocolDumpRequest builds a ctnetlink IPCTNL_MSG_CT_GET dump request for
// the flows of family whose original tuple has L4 protocol protocol. The
// nfgenmsg family limits the dump to the family, and CTA_FILTER with
// CTA_FILTER_ORIG_FLAGS set to CTA_FILTER_F_CTA_PROTO_NUM tells the kernel to
// compare only the protocol number of the CTA_TUPLE_ORIG that follows.
func newProtocolDumpRequest(family netlink.InetFamily, protocol uint8) *nl.NetlinkRequest {
	req := newCtnetlinkRequest(nl.IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP, family)
	tuple := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	tupleProto := tuple.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	tupleProto.AddRtAttr(nl.CTA_PROTO_NUM, []byte{protocol})
	req.AddData(tuple)
	filter := nl.NewRtAttr(unix.NLA_F_NESTED|ctaFilter, nil)
	filter.AddRtAttr(ctaFilterOrigFlags, nl.Uint32Attr(ctaFilterFlagProtoNum))
	req.AddData(filter)
	return req
}

// parseConntrackFlow fills flow with the fields the conntrack GC uses: family,
// and the source and destination IPs, ports and L4 protocol of the original and
// reply tuples. The IPs in flow point into msg.
//
// The GC needs its own parser because netlink's (parseRawData) is unexported:
// the library only parses flows inside ConntrackTableList, which buffers the
// whole table, so agent memory would grow with the node's conntrack table
// rather than with the entries the agent tracks. This one parses one message
// at a time into a flow the caller reuses, so a dump never holds more than
// one flow. It gives the same values as netlink's parser for these fields.
func parseConntrackFlow(msg []byte, flow *netlink.ConntrackFlow) error {
	// The caller reuses flow, so clear what the previous message left in it.
	*flow = netlink.ConntrackFlow{}
	// The payload starts with an nfgenmsg header, whose first byte is the
	// address family, followed by the flow's attributes.
	if len(msg) < nl.SizeofNfgenmsg {
		return fmt.Errorf("conntrack message too short: %d bytes", len(msg))
	}
	flow.FamilyType = msg[0]
	attrs, err := nl.ParseRouteAttr(msg[nl.SizeofNfgenmsg:])
	if err != nil {
		return fmt.Errorf("parse conntrack attributes: %v", err)
	}
	var haveOrig, haveReply bool
	for _, attr := range attrs {
		// The kernel always sends the tuples as nested attributes, and
		// netlink's parser reads them only from nested ones, so skip the rest
		// as it does.
		if attr.Attr.Type&unix.NLA_F_NESTED == 0 {
			continue
		}
		switch attr.Attr.Type & nlaTypeMask {
		case nl.CTA_TUPLE_ORIG:
			if err := parseConntrackTuple(attr.Value, &flow.Forward); err != nil {
				return fmt.Errorf("parse original tuple: %v", err)
			}
			haveOrig = true
		case nl.CTA_TUPLE_REPLY:
			if err := parseConntrackTuple(attr.Value, &flow.Reverse); err != nil {
				return fmt.Errorf("parse reply tuple: %v", err)
			}
			haveReply = true
		}
	}
	// A flow with an empty tuple would match no entry and make them all look
	// stale, so fail the message, and with it the cycle, instead.
	if !haveOrig || !haveReply {
		return errors.New("conntrack message is missing the original or reply tuple")
	}
	return nil
}

// parseConntrackTuple parses the CTA_TUPLE_IP and CTA_TUPLE_PROTO attributes of
// a CTA_TUPLE_ORIG or CTA_TUPLE_REPLY payload. The IPs in tpl point into b
// rather than being copied.
func parseConntrackTuple(b []byte, tpl *netlink.IPTuple) error {
	attrs, err := nl.ParseRouteAttr(b)
	if err != nil {
		return err
	}
	// The ports are kept aside until the protocol is known, because they are
	// stored only for TCP and UDP (see the end of the function). Attributes
	// are read by type, so this does not depend on their order.
	var srcPort, dstPort uint16
	for _, attr := range attrs {
		switch attr.Attr.Type & nlaTypeMask {
		case nl.CTA_TUPLE_IP:
			ipAttrs, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return err
			}
			for _, ipAttr := range ipAttrs {
				switch ipAttr.Attr.Type & nlaTypeMask {
				case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
					tpl.SrcIP = net.IP(ipAttr.Value)
				case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
					tpl.DstIP = net.IP(ipAttr.Value)
				}
			}
		case nl.CTA_TUPLE_PROTO:
			protoAttrs, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return err
			}
			for _, protoAttr := range protoAttrs {
				// Each value is checked for length before it is read, so a
				// short attribute fails the message instead of panicking.
				switch protoAttr.Attr.Type & nlaTypeMask {
				case nl.CTA_PROTO_NUM:
					if len(protoAttr.Value) < 1 {
						return errors.New("empty CTA_PROTO_NUM")
					}
					tpl.Protocol = protoAttr.Value[0]
				case nl.CTA_PROTO_SRC_PORT:
					if len(protoAttr.Value) < 2 {
						return errors.New("short CTA_PROTO_SRC_PORT")
					}
					srcPort = binary.BigEndian.Uint16(protoAttr.Value)
				case nl.CTA_PROTO_DST_PORT:
					if len(protoAttr.Value) < 2 {
						return errors.New("short CTA_PROTO_DST_PORT")
					}
					dstPort = binary.BigEndian.Uint16(protoAttr.Value)
				}
			}
		}
	}
	// A tuple without both IPs cannot be compared with any entry, so it fails
	// the message, and the cycle, rather than matching nothing.
	if len(tpl.SrcIP) == 0 || len(tpl.DstIP) == 0 {
		return errors.New("tuple is missing an IP address")
	}
	// netlink's parser reads ports for TCP and UDP only, and leaves them zero
	// for other protocols such as SCTP even when the kernel sends them. Do the
	// same: the datapath stores ICMP entries with zero ports, so a dumped
	// ICMP flow must produce keys with zero ports to match them.
	if isTCPOrUDP(tpl.Protocol) {
		tpl.SrcPort = srcPort
		tpl.DstPort = dstPort
	}
	return nil
}
