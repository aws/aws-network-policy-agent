package conntrack

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	CONNTRACK_MAP_PIN_PATH = "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map"
)

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
	enableIPv6            bool
	hydratelocalConntrack bool
	localConntrackV4Cache map[utils.ConntrackKey]bool
	localConntrackV6Cache map[utils.ConntrackKeyV6]bool
	
	// Consecutive miss tracking for IPv4 - requires 2 consecutive cleanup cycles
	// before deletion to avoid race condition during 5-tuple reuse
	missingEntriesEvenCycleV4 map[utils.ConntrackKey]bool
	missingEntriesOddCycleV4  map[utils.ConntrackKey]bool
	
	// Consecutive miss tracking for IPv6
	missingEntriesEvenCycleV6 map[utils.ConntrackKeyV6]bool
	missingEntriesOddCycleV6  map[utils.ConntrackKeyV6]bool
	
	// Track current cycle parity (true = even, false = odd)
	isEvenCycle bool
}

func NewConntrackClient(conntrackMap goebpfmaps.BpfMap, enableIPv6 bool) *conntrackClient {
	return &conntrackClient{
		conntrackMap:              conntrackMap,
		enableIPv6:                enableIPv6,
		hydratelocalConntrack:     true,
		missingEntriesEvenCycleV4: make(map[utils.ConntrackKey]bool),
		missingEntriesOddCycleV4:  make(map[utils.ConntrackKey]bool),
		missingEntriesEvenCycleV6: make(map[utils.ConntrackKeyV6]bool),
		missingEntriesOddCycleV6:  make(map[utils.ConntrackKeyV6]bool),
		isEvenCycle:               true, // Start with even cycle
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
		conntrackFlows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
		if err != nil {
			log().Errorf("Failed to read from conntrack table %v", err)
			return
		}
		kernelConntrackV4Cache := make(map[utils.ConntrackKey]bool)
		// Build kernel conntrack cache
		for _, conntrackFlow := range conntrackFlows {
			//Check fwd flow with SIP as owner
			fwdFlowWithSIP := utils.ConntrackKey{}
			fwdFlowWithSIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
			fwdFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
			fwdFlowWithSIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.DstIP)
			fwdFlowWithSIP.Dest_port = conntrackFlow.Forward.DstPort
			fwdFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
			fwdFlowWithSIP.Owner_ip = fwdFlowWithSIP.Source_ip

			kernelConntrackV4Cache[fwdFlowWithSIP] = true

			//Check fwd flow with DIP as owner
			fwdFlowWithDIP := utils.ConntrackKey{}
			fwdFlowWithDIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
			fwdFlowWithDIP.Source_port = conntrackFlow.Forward.SrcPort
			fwdFlowWithDIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.DstIP)
			fwdFlowWithDIP.Dest_port = conntrackFlow.Forward.DstPort
			fwdFlowWithDIP.Protocol = conntrackFlow.Forward.Protocol
			fwdFlowWithDIP.Owner_ip = fwdFlowWithDIP.Dest_ip

			kernelConntrackV4Cache[fwdFlowWithDIP] = true

			//Dest can be VIP and pods can be on same node
			destIP := net.ParseIP(conntrackFlow.Forward.DstIP.String())
			revDestIP := net.ParseIP(conntrackFlow.Reverse.SrcIP.String())

			if !destIP.Equal(revDestIP) {
				//Check fwd flow with SIP as owner
				revFlowWithSIP := utils.ConntrackKey{}
				revFlowWithSIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
				revFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
				revFlowWithSIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Reverse.SrcIP)
				revFlowWithSIP.Dest_port = conntrackFlow.Reverse.SrcPort
				revFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
				revFlowWithSIP.Owner_ip = revFlowWithSIP.Source_ip

				kernelConntrackV4Cache[revFlowWithSIP] = true

				//Check fwd flow with DIP as owner
				revFlowWithDIP := utils.ConntrackKey{}
				revFlowWithDIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
				revFlowWithDIP.Source_port = conntrackFlow.Forward.SrcPort
				revFlowWithDIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Reverse.SrcIP)
				revFlowWithDIP.Dest_port = conntrackFlow.Reverse.SrcPort
				revFlowWithDIP.Protocol = conntrackFlow.Forward.Protocol
				revFlowWithDIP.Owner_ip = revFlowWithDIP.Dest_ip

				kernelConntrackV4Cache[revFlowWithDIP] = true
			}
		}
		// Check if the local cache and kernel cache is in sync
		// Consecutive miss approach: require entry to be missing for 2 consecutive cycles
		for localConntrackEntry, _ := range c.localConntrackV4Cache {
			newKey := utils.ConntrackKey{}
			newKey.Source_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(localConntrackEntry.Source_ip))
			newKey.Source_port = localConntrackEntry.Source_port
			newKey.Dest_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(localConntrackEntry.Dest_ip))
			newKey.Dest_port = localConntrackEntry.Dest_port
			newKey.Protocol = localConntrackEntry.Protocol
			newKey.Owner_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(localConntrackEntry.Owner_ip))
			_, ok := kernelConntrackV4Cache[newKey]
			if !ok {
				// Entry missing from kernel - apply consecutive miss logic
				expiredFlow := localConntrackEntry
				key := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s", utils.ConvIntToIPv4(expiredFlow.Source_ip).String(), expiredFlow.Source_port, utils.ConvIntToIPv4(expiredFlow.Dest_ip).String(), expiredFlow.Dest_port, expiredFlow.Protocol, utils.ConvIntToIPv4(expiredFlow.Owner_ip).String())
				
				if c.isEvenCycle {
					// Even cycle: check if also missing in previous odd cycle
					if _, existsInOdd := c.missingEntriesOddCycleV4[newKey]; existsInOdd {
						// Missing for 2 consecutive cycles - safe to delete
						log().Infof("Conntrack cleanup Delete (consecutive miss) - %s", key)
						c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&expiredFlow)))
					} else {
						// First miss - track in even cycle set
						c.missingEntriesEvenCycleV4[newKey] = true
					}
				} else {
					// Odd cycle: check if also missing in previous even cycle
					if _, existsInEven := c.missingEntriesEvenCycleV4[newKey]; existsInEven {
						// Missing for 2 consecutive cycles - safe to delete
						log().Infof("Conntrack cleanup Delete (consecutive miss) - %s", key)
						c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&expiredFlow)))
					} else {
						// First miss - track in odd cycle set
						c.missingEntriesOddCycleV4[newKey] = true
					}
				}
			}
		}
		
		// Cycle management: clear previous cycle's tracking and toggle
		if c.isEvenCycle {
			// Clear previous odd cycle entries
			c.missingEntriesOddCycleV4 = make(map[utils.ConntrackKey]bool)
		} else {
			// Clear previous even cycle entries
			c.missingEntriesEvenCycleV4 = make(map[utils.ConntrackKey]bool)
		}
		// Toggle cycle for next cleanup
		c.isEvenCycle = !c.isEvenCycle
		
		//c.localConntrackV4Cache = make(map[utils.ConntrackKey]bool)
		log().Info("Done cleanup of conntrack map")
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
		conntrackFlows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET6)
		if err != nil {
			log().Info("Failed to read from conntrack table")
			return
		}

		kernelConntrackV6Cache := make(map[utils.ConntrackKeyV6]bool)
		// Build local conntrack cache
		for _, conntrackFlow := range conntrackFlows {
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

			kernelConntrackV6Cache[fwdFlowWithSIP] = true

			//Check fwd flow with DIP as owner
			fwdFlowWithDIP := utils.ConntrackKeyV6{}
			sip = utils.ConvIPv6ToByte(conntrackFlow.Forward.SrcIP)
			copy(fwdFlowWithDIP.Source_ip[:], sip)
			fwdFlowWithDIP.Source_port = conntrackFlow.Forward.SrcPort
			dip = utils.ConvIPv6ToByte(conntrackFlow.Forward.DstIP)
			copy(fwdFlowWithDIP.Dest_ip[:], dip)
			fwdFlowWithDIP.Dest_port = conntrackFlow.Forward.DstPort
			fwdFlowWithDIP.Protocol = conntrackFlow.Forward.Protocol
			copy(fwdFlowWithDIP.Owner_ip[:], dip)

			kernelConntrackV6Cache[fwdFlowWithDIP] = true

			//Dest can be VIP and pods can be on same node
			destIP := net.ParseIP(conntrackFlow.Forward.DstIP.String())
			revDestIP := net.ParseIP(conntrackFlow.Reverse.SrcIP.String())

			if !destIP.Equal(revDestIP) {
				//Check fwd flow with SIP as owner
				revFlowWithSIP := utils.ConntrackKeyV6{}
				sip = utils.ConvIPv6ToByte(conntrackFlow.Forward.SrcIP)
				copy(revFlowWithSIP.Source_ip[:], sip)
				revFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
				dip = utils.ConvIPv6ToByte(conntrackFlow.Reverse.SrcIP)
				copy(revFlowWithSIP.Dest_ip[:], dip)
				revFlowWithSIP.Dest_port = conntrackFlow.Reverse.SrcPort
				revFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
				copy(revFlowWithSIP.Owner_ip[:], sip)

				kernelConntrackV6Cache[revFlowWithSIP] = true

				//Check fwd flow with DIP as owner
				revFlowWithDIP := utils.ConntrackKeyV6{}
				sip = utils.ConvIPv6ToByte(conntrackFlow.Forward.SrcIP)
				copy(revFlowWithDIP.Source_ip[:], sip)
				revFlowWithDIP.Source_port = conntrackFlow.Forward.SrcPort
				dip = utils.ConvIPv6ToByte(conntrackFlow.Reverse.SrcIP)
				copy(revFlowWithDIP.Dest_ip[:], dip)
				revFlowWithDIP.Dest_port = conntrackFlow.Reverse.SrcPort
				revFlowWithDIP.Protocol = conntrackFlow.Forward.Protocol
				copy(revFlowWithDIP.Owner_ip[:], dip)

				kernelConntrackV6Cache[revFlowWithDIP] = true
			}

		}
		// Check if the local cache and kernel cache is in sync
		// Consecutive miss approach: require entry to be missing for 2 consecutive cycles
		for localConntrackEntry, _ := range c.localConntrackV6Cache {
			_, ok := kernelConntrackV6Cache[localConntrackEntry]
			if !ok {
				// Entry missing from kernel - apply consecutive miss logic
				expiredFlow := localConntrackEntry
				key := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s", utils.ConvByteToIPv6(expiredFlow.Source_ip).String(), expiredFlow.Source_port, utils.ConvByteToIPv6(expiredFlow.Dest_ip).String(), expiredFlow.Dest_port, expiredFlow.Protocol, utils.ConvByteToIPv6(expiredFlow.Owner_ip).String())
				
				if c.isEvenCycle {
					// Even cycle: check if also missing in previous odd cycle
					if _, existsInOdd := c.missingEntriesOddCycleV6[localConntrackEntry]; existsInOdd {
						// Missing for 2 consecutive cycles - safe to delete
						log().Infof("Conntrack cleanup Delete (consecutive miss) - %s", key)
						ceByteSlice := utils.ConvConntrackV6ToByte(expiredFlow)
						c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&ceByteSlice[0])))
					} else {
						// First miss - track in even cycle set
						c.missingEntriesEvenCycleV6[localConntrackEntry] = true
					}
				} else {
					// Odd cycle: check if also missing in previous even cycle
					if _, existsInEven := c.missingEntriesEvenCycleV6[localConntrackEntry]; existsInEven {
						// Missing for 2 consecutive cycles - safe to delete
						log().Infof("Conntrack cleanup Delete (consecutive miss) - %s", key)
						ceByteSlice := utils.ConvConntrackV6ToByte(expiredFlow)
						c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&ceByteSlice[0])))
					} else {
						// First miss - track in odd cycle set
						c.missingEntriesOddCycleV6[localConntrackEntry] = true
					}
				}
			}
		}
		
		// Cycle management: clear previous cycle's tracking and toggle
		if c.isEvenCycle {
			// Clear previous odd cycle entries
			c.missingEntriesOddCycleV6 = make(map[utils.ConntrackKeyV6]bool)
		} else {
			// Clear previous even cycle entries
			c.missingEntriesEvenCycleV6 = make(map[utils.ConntrackKeyV6]bool)
		}
		// Toggle cycle for next cleanup
		c.isEvenCycle = !c.isEvenCycle
		
		//Lets cleanup all entries in cache
		c.localConntrackV6Cache = make(map[utils.ConntrackKeyV6]bool)
		log().Info("Done cleanup of conntrack map")
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
