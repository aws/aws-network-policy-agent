package conntrack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var (
	CONNTRACK_MAP_PIN_PATH = "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map"
)

// entryActiveFromRead reports whether an entry must be kept. An entry counts as
// active if the datapath stamped it at or after gcStart, or if the re-read
// failed, in which case we keep the entry rather than risk deleting a live one.
// Split out from isEntryActive so it can be tested without a live BPF map.
func entryActiveFromRead(cur utils.ConntrackVal, readErr error, gcStart uint64) bool {
	if readErr != nil {
		return true
	}
	return cur.LastSeen >= gcStart
}

// isEntryActive re-reads the live map entry to see whether the datapath has
// touched it since gcStart.
func (c *conntrackClient) isEntryActive(key unsafe.Pointer, gcStart uint64) bool {
	var cur utils.ConntrackVal
	// The datapath may be storing last_seen while we copy the value out. Aligned
	// u64 stores are atomic on x86-64/arm64, so the worst case is one stale GC
	// decision that self-heals on the next cycle.
	err := c.conntrackMap.GetMapEntry(uintptr(key), uintptr(unsafe.Pointer(&cur)))
	if err != nil {
		log().Debugf("Conntrack GC: re-read failed, keeping entry: %v", err)
	}
	return entryActiveFromRead(cur, err, gcStart)
}

func log() logger.Logger {
	return logger.Get()
}

type ConntrackClient interface {
	CleanupConntrackMap()
	Cleanupv6ConntrackMap()
}

var _ ConntrackClient = (*conntrackClient)(nil)

type conntrackClient struct {
	conntrackMap          goebpfmaps.BpfMap
	kernelTable           conntrackTable
	enableIPv6            bool
	hydratelocalConntrack bool
	localConntrackV4Cache map[utils.ConntrackKey]bool
	localConntrackV6Cache map[utils.ConntrackKeyV6]bool
}

func NewConntrackClient(conntrackMap goebpfmaps.BpfMap, enableIPv6 bool) *conntrackClient {
	return &conntrackClient{
		conntrackMap:          conntrackMap,
		kernelTable:           netlinkConntrackTable{},
		enableIPv6:            enableIPv6,
		hydratelocalConntrack: true,
	}
}

func (c *conntrackClient) InitializeLocalCache() {
	if c.enableIPv6 {
		c.localConntrackV6Cache = make(map[utils.ConntrackKeyV6]bool)
	} else {
		c.localConntrackV4Cache = make((map[utils.ConntrackKey]bool))
	}
}

func (c *conntrackClient) CleanupConntrackMap() {
	log().Info("Check for any stale entries in the conntrack map")
	bpfMapApi := &goebpfmaps.BpfMap{}
	mapInfo, err := bpfMapApi.GetMapFromPinPath(CONNTRACK_MAP_PIN_PATH)
	if err != nil {
		log().Errorf("Failed to get mapInfo for conntrack pinpath %v", err)
		return
	}
	mapID := int(mapInfo.Id)

	// Read from eBPF Table if local conntrack table is not cached
	if c.hydratelocalConntrack {
		//Lets cleanup all entries in cache
		c.InitializeLocalCache()

		iterKey := utils.ConntrackKey{}
		iterNextKey := utils.ConntrackKey{}
		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
		if err != nil {
			return
		} else {
			for {
				iterValue := utils.ConntrackVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					if errors.Is(err, unix.ENOENT) {
						err = nil
						break
					}
					return
				} else {

					newKey := utils.ConntrackKey{}
					newKey.Source_ip = iterKey.Source_ip
					newKey.Source_port = iterKey.Source_port
					newKey.Dest_ip = iterKey.Dest_ip
					newKey.Dest_port = iterKey.Dest_port
					newKey.Protocol = iterKey.Protocol
					newKey.Owner_ip = iterKey.Owner_ip
					newKey.Ifindex = iterKey.Ifindex
					c.localConntrackV4Cache[newKey] = true
				}
				err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)), mapID)
				if errors.Is(err, unix.ENOENT) {
					err = nil
					break
				}
				if err != nil {
					break
				}

				iterKey = iterNextKey
			}
		}
		log().Info("hydrated local conntrack cache")
		c.hydratelocalConntrack = false
	} else {
		// Conntrack table is already hydrated from previous run
		// So read from kernel conntrack table
		gcStart, err := utils.KtimeGetNs()
		if err != nil {
			// Without a reference time every entry would look stale, so skip the
			// cycle rather than risk deleting active entries.
			log().Errorf("clock_gettime(CLOCK_MONOTONIC) failed, GC skipping eviction this cycle: %v", err)
			c.hydratelocalConntrack = true
			return
		}
		trackedEntries := len(c.localConntrackV4Cache)
		deletedEntries, err := c.removeStaleV4Entries(gcStart, c.isV4EntryActive, c.deleteV4MapEntry)
		if err != nil {
			log().Errorf("Failed to read from conntrack table %v", err)
			return
		}
		//c.localConntrackV4Cache = make(map[utils.ConntrackKey]bool)
		log().Infof("Done cleanup of conntrack map: deleted %d stale entries out of %d tracked", deletedEntries, trackedEntries)
		c.hydratelocalConntrack = true
	}
	return
}

func (c *conntrackClient) Cleanupv6ConntrackMap() {
	log().Info("Check for any stale entries in the conntrack map")
	bpfMapApi := &goebpfmaps.BpfMap{}
	mapInfo, err := bpfMapApi.GetMapFromPinPath(CONNTRACK_MAP_PIN_PATH)
	if err != nil {
		log().Info("Failed to get mapInfo for conntrack pinpath")
		return
	}
	mapID := int(mapInfo.Id)

	// Read from eBPF Table if local conntrack table is not cached
	if c.hydratelocalConntrack {
		//Lets cleanup all entries in cache
		c.InitializeLocalCache()
		iterKey := utils.ConntrackKeyV6{}
		iterNextKey := utils.ConntrackKeyV6{}

		byteSlice := utils.ConvConntrackV6ToByte(iterKey)
		nextbyteSlice := utils.ConvConntrackV6ToByte(iterNextKey)

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
		if err != nil {
			return
		} else {
			for {
				iterValue := utils.ConntrackVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					if errors.Is(err, unix.ENOENT) {
						err = nil
						break
					}
					return
				} else {
					newKey := utils.ConntrackKeyV6{}
					connKey := utils.ConvByteToConntrackV6(byteSlice)

					utils.CopyV6Bytes(&newKey.Source_ip, connKey.Source_ip)
					utils.CopyV6Bytes(&newKey.Dest_ip, connKey.Dest_ip)

					newKey.Source_port = connKey.Source_port
					newKey.Dest_port = connKey.Dest_port
					newKey.Protocol = connKey.Protocol

					utils.CopyV6Bytes(&newKey.Owner_ip, connKey.Owner_ip)
					newKey.Ifindex = connKey.Ifindex
					c.localConntrackV6Cache[newKey] = true
				}
				err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&nextbyteSlice[0])), mapID)
				if errors.Is(err, unix.ENOENT) {
					err = nil
					break
				}
				if err != nil {
					break
				}
				copy(byteSlice, nextbyteSlice)
			}
		}
		log().Info("hydrated local conntrack cache")
		c.hydratelocalConntrack = false
	} else {
		// Conntrack table is already hydrated from previous run
		// So read from kernel conntrack table
		gcStart, err := utils.KtimeGetNs()
		if err != nil {
			// Without a reference time every entry would look stale, so skip the
			// cycle rather than risk deleting active entries.
			log().Errorf("clock_gettime(CLOCK_MONOTONIC) failed, GC skipping eviction this cycle: %v", err)
			c.hydratelocalConntrack = true
			return
		}
		trackedEntries := len(c.localConntrackV6Cache)
		deletedEntries, err := c.removeStaleV6Entries(gcStart, c.isV6EntryActive, c.deleteV6MapEntry)
		if err != nil {
			log().Errorf("Failed to read from conntrack table %v", err)
			return
		}
		//Lets cleanup all entries in cache
		c.localConntrackV6Cache = make(map[utils.ConntrackKeyV6]bool)
		log().Infof("Done cleanup of conntrack map: deleted %d stale entries out of %d tracked", deletedEntries, trackedEntries)
		c.hydratelocalConntrack = true
	}
	return
}

func (c *conntrackClient) printByteArray(byteArray []byte) {
	for _, b := range byteArray {
		log().Debugf("CONNTRACK VAL -> %v", b)
	}
	log().Debug("DONE")
}

// isV4EntryActive and deleteV4MapEntry pass key to the BPF conntrack map in
// its in-kernel layout, which for IPv4 is the struct itself.
func (c *conntrackClient) isV4EntryActive(key utils.ConntrackKey, gcStart uint64) bool {
	return c.isEntryActive(unsafe.Pointer(&key), gcStart)
}

func (c *conntrackClient) deleteV4MapEntry(key utils.ConntrackKey) {
	c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&key)))
}

// isV6EntryActive and deleteV6MapEntry pass key to the BPF conntrack map in
// its serialized in-kernel layout.
func (c *conntrackClient) isV6EntryActive(key utils.ConntrackKeyV6, gcStart uint64) bool {
	b := utils.ConvConntrackV6ToByte(key)
	return c.isEntryActive(unsafe.Pointer(&b[0]), gcStart)
}

func (c *conntrackClient) deleteV6MapEntry(key utils.ConntrackKeyV6) {
	b := utils.ConvConntrackV6ToByte(key)
	c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&b[0])))
}

// gcKey is a BPF conntrack map key in the form the stale pass compares with
// kernel flows, the same for both families. It leaves out the key's ifindex,
// because kernel conntrack has no per-veth ifindex.
type gcKey struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
	protocol         uint8
	owner            netip.Addr
}

// gcEntry is one BPF conntrack map entry as the stale pass sees it.
type gcEntry struct {
	key     gcKey
	ifindex uint32 // for the logs only
}

// String formats the entry the way the cleanup logs print a BPF map key.
func (e gcEntry) String() string {
	return fmt.Sprintf("Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d",
		e.key.src, e.key.srcPort, e.key.dst, e.key.dstPort, e.key.protocol, e.key.owner, e.ifindex)
}

// addrOf converts an IP to a netip.Addr, with an IPv4 address in its 4-byte
// form whichever form it came in. netlink and net.IP can hold an IPv4 address
// in 16 bytes, and unmapping makes both forms compare equal in a gcKey.
func addrOf(ip net.IP) netip.Addr {
	// AddrFromSlice fails only for a slice that is not 4 or 16 bytes long. The
	// zero Addr it returns then matches no key, so the entry is found stale
	// rather than matched by mistake.
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

// v4GCEntry converts an IPv4 BPF map key. The map holds each address as a
// uint32 that utils.ConvIntToIPv4 turns back into the address's bytes.
func v4GCEntry(key utils.ConntrackKey) gcEntry {
	return gcEntry{key: gcKey{
		src: addrOf(utils.ConvIntToIPv4(key.Source_ip)), srcPort: key.Source_port,
		dst: addrOf(utils.ConvIntToIPv4(key.Dest_ip)), dstPort: key.Dest_port,
		protocol: key.Protocol, owner: addrOf(utils.ConvIntToIPv4(key.Owner_ip)),
	}, ifindex: key.Ifindex}
}

// v6GCEntry converts an IPv6 BPF map key.
func v6GCEntry(key utils.ConntrackKeyV6) gcEntry {
	return gcEntry{key: gcKey{
		src: addrOf(key.Source_ip[:]), srcPort: key.Source_port,
		dst: addrOf(key.Dest_ip[:]), dstPort: key.Dest_port,
		protocol: key.Protocol, owner: addrOf(key.Owner_ip[:]),
	}, ifindex: key.Ifindex}
}

// removeStaleV4Entries runs removeStaleEntries on localConntrackV4Cache.
func (c *conntrackClient) removeStaleV4Entries(gcStart uint64, isActive func(key utils.ConntrackKey, gcStart uint64) bool,
	deleteEntry func(key utils.ConntrackKey)) (int, error) {
	// keys and entries share indexes, so the callbacks, which get an entry's
	// index, can pass on the BPF map key it came from.
	keys := make([]utils.ConntrackKey, 0, len(c.localConntrackV4Cache))
	entries := make([]gcEntry, 0, len(c.localConntrackV4Cache))
	for key := range c.localConntrackV4Cache {
		keys = append(keys, key)
		entries = append(entries, v4GCEntry(key))
	}
	return removeStaleEntries(c.kernelTable, unix.AF_INET, entries, gcStart,
		func(i int, gcStart uint64) bool { return isActive(keys[i], gcStart) },
		func(i int) { deleteEntry(keys[i]) })
}

// removeStaleV6Entries runs removeStaleEntries on localConntrackV6Cache.
func (c *conntrackClient) removeStaleV6Entries(gcStart uint64, isActive func(key utils.ConntrackKeyV6, gcStart uint64) bool,
	deleteEntry func(key utils.ConntrackKeyV6)) (int, error) {
	// keys and entries share indexes, as in removeStaleV4Entries.
	keys := make([]utils.ConntrackKeyV6, 0, len(c.localConntrackV6Cache))
	entries := make([]gcEntry, 0, len(c.localConntrackV6Cache))
	for key := range c.localConntrackV6Cache {
		keys = append(keys, key)
		entries = append(entries, v6GCEntry(key))
	}
	return removeStaleEntries(c.kernelTable, unix.AF_INET6, entries, gcStart,
		func(i int, gcStart uint64) bool { return isActive(keys[i], gcStart) },
		func(i int) { deleteEntry(keys[i]) })
}

// removeStaleEntries deletes the entries that no kernel flow produces (see
// forEachFlowKey) and that isActive does not report as touched since gcStart,
// and returns how many it deleted. It reads only the flows the entries need,
// so memory does not grow with the kernel table. If the table cannot be read,
// it deletes nothing and returns the error, rather than treating the unread
// entries as stale. isActive and deleteEntry take an entry's index in entries.
func removeStaleEntries(table conntrackTable, family netlink.InetFamily, entries []gcEntry, gcStart uint64,
	isActive func(i int, gcStart uint64) bool, deleteEntry func(i int)) (int, error) {
	ctLookup, err := table.openLookup(family)
	if err != nil {
		return 0, err
	}
	defer ctLookup.close()

	var stale []int
	// Port-less entries are checked against a dump of their protocol's flows.
	// portlessKeyLive holds their keys per protocol, set to true once a dumped
	// flow produces them.
	var portlessEntries []int
	portlessKeyLive := make(map[uint8]map[gcKey]bool)
	// Scratch space for the lookups, reused so a cycle does not allocate a
	// flow per GET.
	var conntrackFlow netlink.ConntrackFlow
	lookups := 0
	for i, entry := range entries {
		key := entry.key
		if needsProtocolDump(key.protocol, key.srcPort, key.dstPort) {
			if portlessKeyLive[key.protocol] == nil {
				portlessKeyLive[key.protocol] = make(map[gcKey]bool)
			}
			portlessKeyLive[key.protocol][key] = false
			portlessEntries = append(portlessEntries, i)
			continue
		}
		live, n, err := entryHasFlow(ctLookup, key, &conntrackFlow)
		lookups += n
		if err != nil {
			return 0, err
		}
		if !live {
			stale = append(stale, i)
		}
	}
	// One dump per port-less protocol among the entries, since the kernel
	// cannot look these entries up by tuple. A dumped flow keeps an entry when
	// it produces the entry's key (see forEachFlowKey). No dump is sent if
	// there are none.
	for protocol, keys := range portlessKeyLive {
		err := table.dumpFlows(family, protocol, func(flow *netlink.ConntrackFlow) {
			forEachFlowKey(flow, func(key gcKey) {
				if _, ok := keys[key]; ok {
					keys[key] = true
				}
			})
		})
		if err != nil {
			return 0, err
		}
	}
	for _, i := range portlessEntries {
		key := entries[i].key
		if !portlessKeyLive[key.protocol][key] {
			stale = append(stale, i)
		}
	}
	log().Debugf("Conntrack GC: %v kernel conntrack lookups and %v protocol dumps for %v tracked entries",
		lookups, len(portlessKeyLive), len(entries))

	deletedEntries := 0
	for _, i := range stale {
		// No kernel flow matched, so a delete candidate. The flow may have been
		// picked up again since it was checked, so re-read the live entry first.
		if isActive(i, gcStart) {
			log().Debugf("Conntrack cleanup Skip (in use) - %s", entries[i])
			continue
		}
		log().Debugf("Conntrack cleanup Delete - Conntrack Key : %s", entries[i])
		deleteEntry(i)
		deletedEntries++
	}
	return deletedEntries, nil
}

// forEachFlowKey calls onLiveKey with each key conntrackFlow produces. An entry
// is live if some kernel flow produces its key. For a flow with original tuple
// src:sport -> dst:dport and reply tuple rsrc:rsport -> rdst:rdport, the keys
// are:
//
//   - src:sport -> dst:dport, owned by src or by dst.
//   - If dst != rsrc (the destination was DNAT'd, for example a service VIP to a
//     backend pod): src:sport -> rsrc:rsport, owned by src or by rsrc.
func forEachFlowKey(conntrackFlow *netlink.ConntrackFlow, onLiveKey func(key gcKey)) {
	fwd, rev := conntrackFlow.Forward, conntrackFlow.Reverse
	src, dst, rsrc := addrOf(fwd.SrcIP), addrOf(fwd.DstIP), addrOf(rev.SrcIP)

	key := gcKey{src: src, srcPort: fwd.SrcPort, dst: dst, dstPort: fwd.DstPort, protocol: fwd.Protocol}
	key.owner = src
	onLiveKey(key)
	key.owner = dst
	onLiveKey(key)

	// Without DNAT, the reply comes from the original destination, and the
	// keys below would repeat the ones above.
	if dst == rsrc {
		return
	}

	key.dst, key.dstPort = rsrc, rev.SrcPort
	key.owner = src
	onLiveKey(key)
	key.owner = rsrc
	onLiveKey(key)
}

// flowHasKey reports whether conntrackFlow produces key (see forEachFlowKey).
func flowHasKey(conntrackFlow *netlink.ConntrackFlow, key gcKey) bool {
	found := false
	forEachFlowKey(conntrackFlow, func(flowKey gcKey) {
		if flowKey == key {
			found = true
		}
	})
	return found
}

// isTCPOrUDP reports whether protocol is TCP or UDP. netlink reports ports
// only for these, so the key rule compares ports only for them.
func isTCPOrUDP(protocol uint8) bool {
	return protocol == unix.IPPROTO_TCP || protocol == unix.IPPROTO_UDP
}

// needsProtocolDump reports whether an entry must be checked against a dump of
// its protocol's flows (see streamProtocolFlows) rather than looked up: its
// protocol is not TCP or UDP and both ports are zero, as the datapath stores
// ICMP entries. Such an entry cannot be looked up, because a GET needs the
// protocol's own tuple fields (the ICMP id, type and code) and the entry does
// not carry them.
func needsProtocolDump(protocol uint8, srcPort, dstPort uint16) bool {
	return !isTCPOrUDP(protocol) && srcPort == 0 && dstPort == 0
}

// entryHasFlow reports whether a kernel flow produces key (see forEachFlowKey),
// and how many lookups it sent. flow is scratch space for the lookups.
//
// Two kinds of flow that produce key are missed, so the entry is deleted
// unless the datapath touched it during the cycle:
//   - a DNAT'd flow whose source is also rewritten (for example kube-proxy
//     masquerading hairpin traffic): its reply tuple does not end at
//     src:sport, so neither GET finds it;
//   - a flow outside the default conntrack zone, which a GET does not search.
func entryHasFlow(ctLookup flowLookup, key gcKey, flow *netlink.ConntrackFlow) (found bool, lookups int, err error) {
	// Other protocols reach here only with a non-zero port (see
	// needsProtocolDump), and their flows have zero ports, so nothing matches.
	if !isTCPOrUDP(key.protocol) {
		return false, lookups, nil
	}
	srcIP, dstIP := net.IP(key.src.AsSlice()), net.IP(key.dst.AsSlice())
	fwd := netlink.IPTuple{SrcIP: srcIP, SrcPort: key.srcPort, DstIP: dstIP, DstPort: key.dstPort, Protocol: key.protocol}
	lookups++
	found, err = ctLookup.lookup(nl.CTA_TUPLE_ORIG, &fwd, flow)
	if err != nil {
		return false, lookups, err
	}
	if found && flowHasKey(flow, key) {
		return true, lookups, nil
	}
	// The inverse tuple finds a DNAT'd flow by its reply tuple
	// (rsrc:rsport -> src:sport), which produces the entry's second key.
	rev := netlink.IPTuple{SrcIP: dstIP, SrcPort: key.dstPort, DstIP: srcIP, DstPort: key.srcPort, Protocol: key.protocol}
	lookups++
	found, err = ctLookup.lookup(nl.CTA_TUPLE_REPLY, &rev, flow)
	if err != nil {
		return false, lookups, err
	}
	return found && flowHasKey(flow, key), lookups, nil
}
