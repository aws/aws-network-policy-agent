package dnsproxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// recordingConn returns an nftables connection that records the netlink messages it would send.
func recordingConn(t *testing.T, msgs *[]netlink.Message) *nftables.Conn {
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		*msgs = append(*msgs, req...)
		return req, nil
	}))
	assert.NoError(t, err)
	return conn
}

// nftMessages returns the data of the messages of type msgType (NFT_MSG_*).
func nftMessages(msgs []netlink.Message, msgType int) [][]byte {
	var data [][]byte
	for _, m := range msgs {
		if int(m.Header.Type) == unix.NFNL_SUBSYS_NFTABLES<<8|msgType {
			data = append(data, m.Data)
		}
	}
	return data
}

func TestRedirect(t *testing.T) {
	var filters []vnetlink.CustomConntrackFilter
	origDelete := deleteConntrack
	t.Cleanup(func() { deleteConntrack = origDelete })
	deleteConntrack = func(f vnetlink.CustomConntrackFilter) { filters = append(filters, f) }

	var msgs []netlink.Message
	clusterDNS := net.IPv4(10, 100, 0, 10)
	r := newRedirect(recordingConn(t, &msgs))
	assert.NoError(t, r.install(clusterDNS, listenerIP, listenerPort))

	assert.Len(t, nftMessages(msgs, unix.NFT_MSG_DELTABLE), 1, "a table left by a previous run is removed")
	assert.Len(t, nftMessages(msgs, unix.NFT_MSG_NEWTABLE), 1)
	chains := nftMessages(msgs, unix.NFT_MSG_NEWCHAIN)
	assert.Len(t, chains, 1)
	dstnatMinus10 := int32(-110)
	priority := make([]byte, 4)
	binary.BigEndian.PutUint32(priority, uint32(dstnatMinus10))
	assert.True(t, bytes.Contains(chains[0], priority), "the chain runs at dstnat - 10, before kube-proxy")
	assert.Len(t, nftMessages(msgs, unix.NFT_MSG_NEWSET), 1)
	rules := nftMessages(msgs, unix.NFT_MSG_NEWRULE)
	assert.Len(t, rules, 2, "one rule for UDP and one for TCP")
	for _, rule := range rules {
		assert.True(t, bytes.Contains(rule, clusterDNS.To4()), "matches the cluster DNS IP")
		assert.True(t, bytes.Contains(rule, listenerIP.To4()), "DNATs to the listener")
	}
	assert.True(t, matchesFlow(filters, "0.0.0.0", "0.0.0.0", listenerIP), "flows DNATed by the previous run are removed")

	msgs, filters = nil, nil
	assert.NoError(t, r.add("eni0123456789a"))
	elements := nftMessages(msgs, unix.NFT_MSG_NEWSETELEM)
	assert.Len(t, elements, 1)
	assert.True(t, bytes.Contains(elements[0], ifname("eni0123456789a")), "the interface name padded to IFNAMSIZ")
	assert.NoError(t, r.remove("eni0123456789a"))
	assert.Len(t, nftMessages(msgs, unix.NFT_MSG_DELSETELEM), 1)
	assert.Empty(t, filters, "set changes leave the flows alone")

	r.forgetDirectFlows([]string{"192.0.2.10", "192.0.2.11"})
	assert.Len(t, filters, 1, "one conntrack dump for all the IPs")
	coreDNSPod := net.IPv4(192, 0, 2, 53)
	assert.True(t, matchesFlow(filters, "192.0.2.10", "10.100.0.10", coreDNSPod), "the pod's queries to kube-dns that were not redirected")
	assert.True(t, matchesFlow(filters, "192.0.2.11", "10.100.0.10", coreDNSPod))
	assert.False(t, matchesFlow(filters, "192.0.2.10", "10.100.0.10", listenerIP), "not its queries already redirected, still in flight")
	assert.False(t, matchesFlow(filters, "192.0.2.12", "10.100.0.10", coreDNSPod), "not other pods'")
	assert.False(t, matchesFlow(filters, "192.0.2.10", "192.0.2.80", coreDNSPod), "not its other flows")

	msgs, filters = nil, nil
	r.delete()
	assert.Len(t, nftMessages(msgs, unix.NFT_MSG_DELTABLE), 1)
	assert.True(t, matchesFlow(filters, "192.0.2.11", "10.100.0.10", listenerIP), "every flow DNATed to the proxy is removed")
}

func TestDeletingNoRedirectLeavesConntrackAlone(t *testing.T) {
	dumps := 0
	origDelete := deleteConntrack
	t.Cleanup(func() { deleteConntrack = origDelete })
	deleteConntrack = func(vnetlink.CustomConntrackFilter) { dumps++ }

	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nil, unix.ENOENT // the kernel's answer to deleting a table that does not exist
	}))
	assert.NoError(t, err)
	newRedirect(conn).delete()
	assert.Zero(t, dumps, "a node without a redirect does not read its conntrack table")
}

// matchesFlow reports whether any filter matches a UDP DNS flow from src to dst whose replies come from replySrc.
func matchesFlow(filters []vnetlink.CustomConntrackFilter, src, dst string, replySrc net.IP) bool {
	flow := &vnetlink.ConntrackFlow{FamilyType: unix.AF_INET, Forward: vnetlink.IPTuple{
		SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Protocol: unix.IPPROTO_UDP, SrcPort: 40000, DstPort: 53,
	}, Reverse: vnetlink.IPTuple{SrcIP: replySrc, DstIP: net.ParseIP(src)}}
	for _, f := range filters {
		if f.MatchConntrackFlow(flow) {
			return true
		}
	}
	return false
}
