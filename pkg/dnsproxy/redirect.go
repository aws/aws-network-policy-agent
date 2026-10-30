package dnsproxy

import (
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	nftTableName = "aws-network-policy-dns"
	nftSetName   = "pods"
)

// redirect DNATs the DNS queries that pods in the set send to the cluster DNS IP to the proxy.
type redirect struct {
	conn       *nftables.Conn
	table      *nftables.Table
	set        *nftables.Set
	clusterDNS net.IP
}

func newRedirect(conn *nftables.Conn) *redirect {
	return &redirect{conn: conn, table: &nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTableName}}
}

// install replaces any table left by a previous run with an empty pod set.
func (r *redirect) install(clusterDNS, listener net.IP, listenerPort uint16) error {
	r.delete()
	r.clusterDNS = clusterDNS
	r.conn.AddTable(r.table)
	chain := r.conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    r.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 10), // ahead of kube-proxy's DNAT
	})
	// Host byte order, like nft itself uses for ifname, so `nft list set` shows the names.
	r.set = &nftables.Set{Table: r.table, Name: nftSetName, KeyType: nftables.TypeIFName, KeyByteOrder: binaryutil.NativeEndian}
	if err := r.conn.AddSet(r.set, nil); err != nil {
		return err
	}
	for _, protocol := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		r.conn.AddRule(&nftables.Rule{Table: r.table, Chain: chain, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Lookup{SourceRegister: 1, SetName: r.set.Name, SetID: r.set.ID},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, // daddr
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: clusterDNS.To4()},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // dport
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)},
			&expr.Immediate{Register: 1, Data: listener.To4()},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(listenerPort)},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
		}})
	}
	return r.conn.Flush()
}

func (r *redirect) add(veth string) error {
	if err := r.conn.SetAddElements(r.set, []nftables.SetElement{{Key: ifname(veth)}}); err != nil {
		return err
	}
	return r.conn.Flush()
}

func (r *redirect) remove(veth string) error {
	if err := r.conn.SetDeleteElements(r.set, []nftables.SetElement{{Key: ifname(veth)}}); err != nil {
		return err
	}
	return r.conn.Flush()
}

// forgetDirectFlows deletes the conntrack entries of the DNS flows from ips to the cluster DNS that
// were not DNATed to the proxy, so their next packets are.
func (r *redirect) forgetDirectFlows(ips []string) {
	src := map[string]bool{}
	for _, ip := range ips {
		src[ip] = true
	}
	deleteConntrack(directDNSFlows{src: src, clusterDNS: r.clusterDNS})
}

// delete removes the table, so pods query the cluster DNS directly, and the flows DNATed to the proxy.
func (r *redirect) delete() {
	r.conn.DelTable(r.table)
	if err := r.conn.Flush(); err != nil {
		return // no table, so no flow was DNATed to the proxy
	}
	toProxy := &netlink.ConntrackFilter{}
	_ = toProxy.AddIP(netlink.ConntrackReplySrcIP, listenerIP)
	deleteConntrack(toProxy)
}

// RemoveRedirect deletes the redirect an earlier run may have left, so pods query the cluster DNS
// directly until the proxy runs. The agent calls it first, whatever its configuration: a redirect
// without a running proxy leaves pods without DNS.
func RemoveRedirect() {
	conn, err := nftables.New()
	if err != nil {
		log().Errorf("failed to open nftables to remove an earlier DNS redirect: %v", err)
		return
	}
	newRedirect(conn).delete()
}

// directDNSFlows matches the DNS flows from src to the cluster DNS whose replies do not come from the proxy.
type directDNSFlows struct {
	src        map[string]bool
	clusterDNS net.IP
}

func (f directDNSFlows) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return f.src[flow.Forward.SrcIP.String()] && flow.Forward.DstIP.Equal(f.clusterDNS) && flow.Forward.DstPort == 53 &&
		!flow.Reverse.SrcIP.Equal(listenerIP)
}

// deleteConntrack deletes the IPv4 flows the filter matches; tests replace it.
var deleteConntrack = func(filter netlink.CustomConntrackFilter) {
	if _, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, filter); err != nil {
		log().Warnf("failed to delete the conntrack entries of redirected DNS flows: %v", err)
	}
}

func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}
