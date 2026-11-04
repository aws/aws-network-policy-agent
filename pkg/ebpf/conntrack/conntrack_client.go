package conntrack

import (
	"errors"
	"net"
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
			log().Info("Failed to read from conntrack table")
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

// removeStaleV4Entries deletes the entries in localConntrackV4Cache that no
// kernel conntrack flow matches and that isActive does not report as touched
// since gcStart, and returns how many it deleted. An entry is live if a flow
// produces its key under the rule on v4FlowKeys. TCP and UDP entries are looked
// up one at a time (entryHasFlow), and port-less entries such as ICMP are
// matched against one dump per protocol (needsProtocolDump), so memory does
// not grow with the kernel table. If a lookup fails other than with "no such
// flow", or a dump fails or is interrupted, it deletes nothing and returns the
// error.
func (c *conntrackClient) removeStaleV4Entries(gcStart uint64, isActive func(key utils.ConntrackKey, gcStart uint64) bool,
	deleteEntry func(key utils.ConntrackKey)) (int, error) {
	ctLookup, err := c.kernelTable.openLookup(unix.AF_INET)
	if err != nil {
		return 0, err
	}
	defer ctLookup.close()

	var staleEntries []utils.ConntrackKey
	// Port-less entries are checked against a dump of their protocol's flows.
	// portlessKeyLive holds their keys per protocol, set to true once a dumped
	// flow produces them.
	var portlessEntries []utils.ConntrackKey
	portlessKeyLive := make(map[uint8]map[utils.ConntrackKey]bool)
	var conntrackFlow netlink.ConntrackFlow
	lookups := 0
	for localConntrackEntry := range c.localConntrackV4Cache {
		key := v4LookupKey(localConntrackEntry)
		if needsProtocolDump(key.Protocol, key.Source_port, key.Dest_port) {
			if portlessKeyLive[key.Protocol] == nil {
				portlessKeyLive[key.Protocol] = make(map[utils.ConntrackKey]bool)
			}
			portlessKeyLive[key.Protocol][key] = false
			portlessEntries = append(portlessEntries, localConntrackEntry)
			continue
		}
		live, n, err := v4EntryHasFlow(ctLookup, key, &conntrackFlow)
		lookups += n
		if err != nil {
			return 0, err
		}
		if !live {
			staleEntries = append(staleEntries, localConntrackEntry)
		}
	}
	// One dump per port-less protocol among the entries, matched with the same
	// rule the full table dump used. No dump is sent if there are none.
	for protocol, keys := range portlessKeyLive {
		err := c.kernelTable.dumpFlows(unix.AF_INET, protocol, func(flow *netlink.ConntrackFlow) {
			v4FlowKeys(flow, func(key utils.ConntrackKey) {
				if _, ok := keys[key]; ok {
					keys[key] = true
				}
			})
		})
		if err != nil {
			return 0, err
		}
	}
	for _, localConntrackEntry := range portlessEntries {
		key := v4LookupKey(localConntrackEntry)
		if !portlessKeyLive[key.Protocol][key] {
			staleEntries = append(staleEntries, localConntrackEntry)
		}
	}
	log().Debugf("Conntrack GC: %v kernel conntrack lookups and %v protocol dumps for %v tracked entries",
		lookups, len(portlessKeyLive), len(c.localConntrackV4Cache))

	deletedEntries := 0
	for _, expiredFlow := range staleEntries {
		// No kernel flow matched, so a delete candidate. The flow may have been
		// picked up again since it was checked, so re-read the live entry first.
		if isActive(expiredFlow, gcStart) {
			log().Debugf("Conntrack cleanup Skip (in use) - Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d",
				utils.ConvIntToIPv4(expiredFlow.Source_ip).String(), expiredFlow.Source_port,
				utils.ConvIntToIPv4(expiredFlow.Dest_ip).String(), expiredFlow.Dest_port,
				expiredFlow.Protocol, utils.ConvIntToIPv4(expiredFlow.Owner_ip).String(), expiredFlow.Ifindex)
			continue
		}
		log().Debugf("Conntrack cleanup Delete - Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d", utils.ConvIntToIPv4(expiredFlow.Source_ip).String(), expiredFlow.Source_port, utils.ConvIntToIPv4(expiredFlow.Dest_ip).String(), expiredFlow.Dest_port, expiredFlow.Protocol, utils.ConvIntToIPv4(expiredFlow.Owner_ip).String(), expiredFlow.Ifindex)
		deleteEntry(expiredFlow)
		deletedEntries++
	}
	return deletedEntries, nil
}

// v4LookupKey converts a BPF map key into the form v4FlowKeys produces: IPs in
// the byte order utils.ConvIPv4ToInt produces, and Ifindex stripped for 5-tuple
// comparison.
func v4LookupKey(entry utils.ConntrackKey) utils.ConntrackKey {
	return utils.ConntrackKey{
		Source_ip:   utils.ConvIPv4ToInt(utils.ConvIntToIPv4(entry.Source_ip)),
		Source_port: entry.Source_port,
		Dest_ip:     utils.ConvIPv4ToInt(utils.ConvIntToIPv4(entry.Dest_ip)),
		Dest_port:   entry.Dest_port,
		Protocol:    entry.Protocol,
		Owner_ip:    utils.ConvIPv4ToInt(utils.ConvIntToIPv4(entry.Owner_ip)),
		// Ifindex left zero: stripped for 5-tuple comparison
	}
}

// v4EntryHasFlow runs the GETs for key, a v4LookupKey of an entry that is not
// matched by a dump, and reports whether a kernel flow matches it and how many
// lookups it sent. An entry of a protocol other than TCP and UDP gets here only
// with a non-zero port. Flows of those protocols have zero ports (see
// v4FlowKeys), so it matches nothing and is stale without a lookup. flow is
// scratch space for the lookups.
func v4EntryHasFlow(ctLookup flowLookup, key utils.ConntrackKey, flow *netlink.ConntrackFlow) (live bool, lookups int, err error) {
	if !isTCPOrUDP(key.Protocol) {
		return false, lookups, nil
	}
	srcIP := utils.ConvIntToIPv4NetworkOrder(key.Source_ip)
	dstIP := utils.ConvIntToIPv4NetworkOrder(key.Dest_ip)
	return entryHasFlow(ctLookup, srcIP, key.Source_port, dstIP, key.Dest_port, key.Protocol, flow,
		func(flow *netlink.ConntrackFlow) bool { return v4FlowHasKey(flow, key) })
}

// v4FlowHasKey reports whether conntrackFlow produces key under the rule on
// v4FlowKeys.
func v4FlowHasKey(conntrackFlow *netlink.ConntrackFlow, key utils.ConntrackKey) bool {
	found := false
	v4FlowKeys(conntrackFlow, func(flowKey utils.ConntrackKey) {
		if flowKey == key {
			found = true
		}
	})
	return found
}

// v4FlowKeys calls onLiveKey with each key conntrackFlow produces. An entry is
// live if some kernel flow produces its key. For a flow with original tuple
// src:sport -> dst:dport and reply tuple rsrc:rsport -> rdst:rdport, the keys
// are:
//
//   - src:sport -> dst:dport, owned by src or by dst.
//   - If dst != rsrc (the destination was DNAT'd, for example a service VIP to a
//     backend pod): src:sport -> rsrc:rsport, owned by src or by rsrc.
//
// The dst != rsrc test compares IPs only. Ifindex is ignored because kernel
// conntrack has no per-veth ifindex. Ports are compared for TCP and UDP only,
// because netlink reports them as zero for other protocols.
func v4FlowKeys(conntrackFlow *netlink.ConntrackFlow, onLiveKey func(key utils.ConntrackKey)) {
	//Check fwd flow with SIP as owner
	fwdFlowWithSIP := utils.ConntrackKey{}
	fwdFlowWithSIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
	fwdFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
	fwdFlowWithSIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.DstIP)
	fwdFlowWithSIP.Dest_port = conntrackFlow.Forward.DstPort
	fwdFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
	fwdFlowWithSIP.Owner_ip = fwdFlowWithSIP.Source_ip
	fwdFlowWithSIP.Ifindex = 0 // not available from netlink
	onLiveKey(fwdFlowWithSIP)

	//Check fwd flow with DIP as owner
	fwdFlowWithDIP := fwdFlowWithSIP
	fwdFlowWithDIP.Owner_ip = fwdFlowWithDIP.Dest_ip
	onLiveKey(fwdFlowWithDIP)

	// Without DNAT, the reply comes from the original destination, and the
	// keys below would repeat the ones above.
	destIP := net.ParseIP(conntrackFlow.Forward.DstIP.String())
	revDestIP := net.ParseIP(conntrackFlow.Reverse.SrcIP.String())
	if destIP.Equal(revDestIP) {
		return
	}

	//Check rev flow with SIP as owner
	revFlowWithSIP := utils.ConntrackKey{}
	revFlowWithSIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
	revFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
	revFlowWithSIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Reverse.SrcIP)
	revFlowWithSIP.Dest_port = conntrackFlow.Reverse.SrcPort
	revFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
	revFlowWithSIP.Owner_ip = revFlowWithSIP.Source_ip
	revFlowWithSIP.Ifindex = 0 // not available from netlink
	onLiveKey(revFlowWithSIP)

	//Check rev flow with DIP as owner
	revFlowWithDIP := revFlowWithSIP
	revFlowWithDIP.Owner_ip = revFlowWithDIP.Dest_ip
	onLiveKey(revFlowWithDIP)
}

// removeStaleV6Entries is the IPv6 counterpart of removeStaleV4Entries for
// localConntrackV6Cache.
func (c *conntrackClient) removeStaleV6Entries(gcStart uint64, isActive func(key utils.ConntrackKeyV6, gcStart uint64) bool,
	deleteEntry func(key utils.ConntrackKeyV6)) (int, error) {
	ctLookup, err := c.kernelTable.openLookup(unix.AF_INET6)
	if err != nil {
		return 0, err
	}
	defer ctLookup.close()

	var staleEntries []utils.ConntrackKeyV6
	var portlessEntries []utils.ConntrackKeyV6
	portlessKeyLive := make(map[uint8]map[utils.ConntrackKeyV6]bool)
	var conntrackFlow netlink.ConntrackFlow
	lookups := 0
	for localConntrackEntry := range c.localConntrackV6Cache {
		key := v6LookupKey(localConntrackEntry)
		if needsProtocolDump(key.Protocol, key.Source_port, key.Dest_port) {
			if portlessKeyLive[key.Protocol] == nil {
				portlessKeyLive[key.Protocol] = make(map[utils.ConntrackKeyV6]bool)
			}
			portlessKeyLive[key.Protocol][key] = false
			portlessEntries = append(portlessEntries, localConntrackEntry)
			continue
		}
		live, n, err := v6EntryHasFlow(ctLookup, key, &conntrackFlow)
		lookups += n
		if err != nil {
			return 0, err
		}
		if !live {
			staleEntries = append(staleEntries, localConntrackEntry)
		}
	}
	for protocol, keys := range portlessKeyLive {
		err := c.kernelTable.dumpFlows(unix.AF_INET6, protocol, func(flow *netlink.ConntrackFlow) {
			v6FlowKeys(flow, func(key utils.ConntrackKeyV6) {
				if _, ok := keys[key]; ok {
					keys[key] = true
				}
			})
		})
		if err != nil {
			return 0, err
		}
	}
	for _, localConntrackEntry := range portlessEntries {
		key := v6LookupKey(localConntrackEntry)
		if !portlessKeyLive[key.Protocol][key] {
			staleEntries = append(staleEntries, localConntrackEntry)
		}
	}
	log().Debugf("Conntrack GC: %v kernel conntrack lookups and %v protocol dumps for %v tracked entries",
		lookups, len(portlessKeyLive), len(c.localConntrackV6Cache))

	deletedEntries := 0
	for _, expiredFlow := range staleEntries {
		if isActive(expiredFlow, gcStart) {
			log().Debugf("Conntrack cleanup Skip (in use) - Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d",
				utils.ConvByteToIPv6(expiredFlow.Source_ip).String(), expiredFlow.Source_port,
				utils.ConvByteToIPv6(expiredFlow.Dest_ip).String(), expiredFlow.Dest_port,
				expiredFlow.Protocol, utils.ConvByteToIPv6(expiredFlow.Owner_ip).String(), expiredFlow.Ifindex)
			continue
		}
		log().Debugf("Conntrack cleanup Delete - Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d", utils.ConvByteToIPv6(expiredFlow.Source_ip).String(), expiredFlow.Source_port, utils.ConvByteToIPv6(expiredFlow.Dest_ip).String(), expiredFlow.Dest_port, expiredFlow.Protocol, utils.ConvByteToIPv6(expiredFlow.Owner_ip).String(), expiredFlow.Ifindex)
		deleteEntry(expiredFlow)
		deletedEntries++
	}
	return deletedEntries, nil
}

// v6LookupKey is the IPv6 counterpart of v4LookupKey. IPv6 keys need no byte
// order conversion, only Ifindex stripped for 5-tuple comparison.
func v6LookupKey(entry utils.ConntrackKeyV6) utils.ConntrackKeyV6 {
	entry.Ifindex = 0
	return entry
}

// v6EntryHasFlow is the IPv6 counterpart of v4EntryHasFlow. key has Ifindex
// stripped.
func v6EntryHasFlow(ctLookup flowLookup, key utils.ConntrackKeyV6, flow *netlink.ConntrackFlow) (live bool, lookups int, err error) {
	if !isTCPOrUDP(key.Protocol) {
		return false, lookups, nil
	}
	srcIP := utils.ConvByteToIPv6(key.Source_ip)
	dstIP := utils.ConvByteToIPv6(key.Dest_ip)
	return entryHasFlow(ctLookup, srcIP, key.Source_port, dstIP, key.Dest_port, key.Protocol, flow,
		func(flow *netlink.ConntrackFlow) bool { return v6FlowHasKey(flow, key) })
}

// v6FlowHasKey is the IPv6 counterpart of v4FlowHasKey.
func v6FlowHasKey(conntrackFlow *netlink.ConntrackFlow, key utils.ConntrackKeyV6) bool {
	found := false
	v6FlowKeys(conntrackFlow, func(flowKey utils.ConntrackKeyV6) {
		if flowKey == key {
			found = true
		}
	})
	return found
}

// v6FlowKeys is the IPv6 counterpart of v4FlowKeys.
func v6FlowKeys(conntrackFlow *netlink.ConntrackFlow, onLiveKey func(key utils.ConntrackKeyV6)) {
	//Check fwd flow with SIP as owner
	fwdFlowWithSIP := utils.ConntrackKeyV6{}
	sip := utils.ConvIPv6ToByte(conntrackFlow.Forward.SrcIP)
	copy(fwdFlowWithSIP.Source_ip[:], sip)
	fwdFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
	dip := utils.ConvIPv6ToByte(conntrackFlow.Forward.DstIP)
	copy(fwdFlowWithSIP.Dest_ip[:], dip)
	fwdFlowWithSIP.Dest_port = conntrackFlow.Forward.DstPort
	fwdFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
	copy(fwdFlowWithSIP.Owner_ip[:], sip)
	fwdFlowWithSIP.Ifindex = 0 // not available from netlink
	onLiveKey(fwdFlowWithSIP)

	//Check fwd flow with DIP as owner
	fwdFlowWithDIP := fwdFlowWithSIP
	fwdFlowWithDIP.Owner_ip = [16]byte{}
	copy(fwdFlowWithDIP.Owner_ip[:], dip)
	onLiveKey(fwdFlowWithDIP)

	// Without DNAT, the reply comes from the original destination, and the
	// keys below would repeat the ones above.
	destIP := net.ParseIP(conntrackFlow.Forward.DstIP.String())
	revDestIP := net.ParseIP(conntrackFlow.Reverse.SrcIP.String())
	if destIP.Equal(revDestIP) {
		return
	}

	//Check rev flow with SIP as owner
	revFlowWithSIP := utils.ConntrackKeyV6{}
	copy(revFlowWithSIP.Source_ip[:], sip)
	revFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
	revDip := utils.ConvIPv6ToByte(conntrackFlow.Reverse.SrcIP)
	copy(revFlowWithSIP.Dest_ip[:], revDip)
	revFlowWithSIP.Dest_port = conntrackFlow.Reverse.SrcPort
	revFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
	copy(revFlowWithSIP.Owner_ip[:], sip)
	revFlowWithSIP.Ifindex = 0 // not available from netlink
	onLiveKey(revFlowWithSIP)

	//Check rev flow with DIP as owner
	revFlowWithDIP := revFlowWithSIP
	revFlowWithDIP.Owner_ip = [16]byte{}
	copy(revFlowWithDIP.Owner_ip[:], revDip)
	onLiveKey(revFlowWithDIP)
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
// not carry them. An entry of such a protocol with a non-zero port matches no
// flow and needs neither.
func needsProtocolDump(protocol uint8, srcPort, dstPort uint16) bool {
	return !isTCPOrUDP(protocol) && srcPort == 0 && dstPort == 0
}

// entryHasFlow looks up the kernel flows for the 5-tuple srcIP:srcPort ->
// dstIP:dstPort and reports whether matches accepts a flow they return, and how
// many lookups it sent. A GET finds the flow that has the requested tuple as its
// original or its reply tuple, and a tuple belongs to at most one flow per zone:
//
//  1. GET src:sport -> dst:dport. This finds the flow whose original tuple is
//     the entry's 5-tuple, which covers the first key on v4FlowKeys.
//  2. If 1 did not match, GET the inverse, dst:dport -> src:sport. This finds a
//     DNAT'd flow whose reply tuple is rsrc:rsport -> src:sport, which covers
//     the second key.
//
// The GETs find no matching flow, where a full dump would, in two cases. The
// entry is then deleted unless the datapath touched it during the cycle:
//
//   - The flow is DNAT'd and its source is also rewritten, so rdst:rdport is
//     not src:sport (for example kube-proxy masquerading hairpin traffic). The
//     second key is not the inverse of any kernel tuple, so GET 2 misses it.
//   - The flow is in a conntrack zone other than the default one. A GET without
//     CTA_ZONE searches the default zone only, while a dump returns every zone.
func entryHasFlow(ctLookup flowLookup, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol uint8,
	flow *netlink.ConntrackFlow, matches func(flow *netlink.ConntrackFlow) bool) (found bool, lookups int, err error) {
	fwd := netlink.IPTuple{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort, Protocol: protocol}
	lookups++
	found, err = ctLookup.lookup(nl.CTA_TUPLE_ORIG, &fwd, flow)
	if err != nil {
		return false, lookups, err
	}
	if found && matches(flow) {
		return true, lookups, nil
	}
	rev := netlink.IPTuple{SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort, Protocol: protocol}
	lookups++
	found, err = ctLookup.lookup(nl.CTA_TUPLE_REPLY, &rev, flow)
	if err != nil {
		return false, lookups, err
	}
	return found && matches(flow), lookups, nil
}
