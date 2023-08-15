package conntrack

import (
	"errors"
	"fmt"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"unsafe"
)

var (
	CONNTRACK_MAP_PIN_PATH = "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map"
)

type ConntrackKey struct {
	Source_ip   uint32
	Source_port uint16
	Dest_ip     uint32
	Dest_port   uint16
	Protocol    uint8
}

type ConntrackVal struct {
	Value uint8
}

type ConntrackClient interface {
	CleanupConntrackMap()
	Cleanupv6ConntrackMap()
}

var _ ConntrackClient = (*conntrackClient)(nil)

type conntrackClient struct {
	conntrackMap goebpfmaps.BpfMap
	enableIPv6   bool
	logger       logr.Logger
}

func NewConntrackClient(conntrackMap goebpfmaps.BpfMap, enableIPv6 bool, logger logr.Logger) *conntrackClient {
	return &conntrackClient{
		conntrackMap: conntrackMap,
		enableIPv6:   enableIPv6,
		logger:       logger,
	}
}

func (c *conntrackClient) CleanupConntrackMap() {
	bpfMapApi := &goebpfmaps.BpfMap{}
	mapInfo, err := bpfMapApi.GetMapFromPinPath(CONNTRACK_MAP_PIN_PATH)
	if err != nil {
		c.logger.Info("Failed to get mapInfo for conntrack pinpath")
		return
	}
	mapID := int(mapInfo.Id)

	//Read from kernel conntrack table
	conntrackFlows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
	if err != nil {
		c.logger.Info("Failed to read from conntrack table")
		return
	}

	localConntrackCache := make(map[ConntrackKey]bool)
	// Build local conntrack cache
	for _, conntrackFlow := range conntrackFlows {
		//Check fwd flow
		fwdFlow := ConntrackKey{}
		fwdFlow.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
		fwdFlow.Source_port = conntrackFlow.Forward.SrcPort
		fwdFlow.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.DstIP)
		fwdFlow.Dest_port = conntrackFlow.Forward.DstPort
		fwdFlow.Protocol = conntrackFlow.Forward.Protocol

		localConntrackCache[fwdFlow] = true
	}

	//Check if the entry is expired..
	iterKey := ConntrackKey{}
	iterNextKey := ConntrackKey{}
	expiredList := make(map[ConntrackKey]bool)
	err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
	if err != nil {
		return
	} else {
		for {
			iterValue := ConntrackVal{}
			err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
			if err != nil {
				return
			} else {
				newKey := ConntrackKey{}
				newKey.Source_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(iterKey.Source_ip))
				newKey.Source_port = iterKey.Source_port
				newKey.Dest_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(iterKey.Dest_ip))
				newKey.Dest_port = iterKey.Dest_port
				newKey.Protocol = iterKey.Protocol
				_, ok := localConntrackCache[newKey]
				if !ok {
					//Delete the entry in local cache
					retrievedKey := fmt.Sprintf("Expired/Delete Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d", utils.ConvIntToIPv4(iterKey.Source_ip).String(), iterKey.Source_port, utils.ConvIntToIPv4(iterKey.Dest_ip).String(), iterKey.Dest_port, iterKey.Protocol)
					c.logger.Info("Conntrack cleanup", "Entry - ", retrievedKey)
					expiredList[iterKey] = true
				}
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

	//Delete entries in conntrack table
	//TODO use bulk delete
	for expiredFlow, _ := range expiredList {
		c.logger.Info("Conntrack cleanup", "Delete - ", expiredFlow)
		c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&expiredFlow)))
	}

	c.logger.Info("Done cleanup of conntrack map")
	return
}

func (c *conntrackClient) Cleanupv6ConntrackMap() {
	bpfMapApi := &goebpfmaps.BpfMap{}
	mapInfo, err := bpfMapApi.GetMapFromPinPath(CONNTRACK_MAP_PIN_PATH)
	if err != nil {
		c.logger.Info("Failed to get mapInfo for conntrack pinpath")
		return
	}
	mapID := int(mapInfo.Id)

	//Read from kernel conntrack table
	conntrackFlows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET6)
	if err != nil {
		c.logger.Info("Failed to read from conntrack table")
		return
	}

	localConntrackCache := make(map[utils.ConntrackKeyV6]bool)
	// Build local conntrack cache
	for _, conntrackFlow := range conntrackFlows {
		//Check fwd flow
		fwdFlow := utils.ConntrackKeyV6{}
		sip := utils.ConvIPv6ToByte(conntrackFlow.Forward.SrcIP)
		copy(fwdFlow.Source_ip[:], sip)
		fwdFlow.Source_port = conntrackFlow.Forward.SrcPort
		dip := utils.ConvIPv6ToByte(conntrackFlow.Forward.DstIP)
		copy(fwdFlow.Dest_ip[:], dip)
		fwdFlow.Dest_port = conntrackFlow.Forward.DstPort
		fwdFlow.Protocol = conntrackFlow.Forward.Protocol

		localConntrackCache[fwdFlow] = true
	}

	//Check if the entry is expired..
	iterKey := utils.ConntrackKeyV6{}
	iterNextKey := utils.ConntrackKeyV6{}

	expiredList := make(map[utils.ConntrackKeyV6]bool)
	byteSlice := utils.ConvConntrackV6ToByte(iterKey)
	nextbyteSlice := utils.ConvConntrackV6ToByte(iterNextKey)

	err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
	if err != nil {
		return
	} else {
		for {
			iterValue := ConntrackVal{}
			err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
			if err != nil {
				return
			} else {
				newKey := utils.ConntrackKeyV6{}
				connKey := utils.ConvByteToConntrackV6(byteSlice)

				utils.CopyV6Bytes(&newKey.Source_ip, connKey.Source_ip)
				utils.CopyV6Bytes(&newKey.Dest_ip, connKey.Dest_ip)

				newKey.Source_port = connKey.Source_port
				newKey.Dest_port = connKey.Dest_port
				newKey.Protocol = connKey.Protocol
				_, ok := localConntrackCache[newKey]
				if !ok {
					//Delete the entry in local cache
					retrievedKey := fmt.Sprintf("Expired/Delete Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d", utils.ConvByteToIPv6(newKey.Source_ip).String(), newKey.Source_port, utils.ConvByteToIPv6(newKey.Dest_ip).String(), newKey.Dest_port, newKey.Protocol)
					c.logger.Info("Conntrack cleanup", "Entry - ", retrievedKey)
					expiredList[newKey] = true
				}
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

	//Delete entries in conntrack table
	//TODO use bulk delete
	for expiredFlow, _ := range expiredList {
		c.logger.Info("Conntrack cleanup", "Delete - ", expiredFlow)
		ceByteSlice := utils.ConvConntrackV6ToByte(expiredFlow)
		c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&ceByteSlice[0])))
	}

	c.logger.Info("Done cleanup of conntrack map")
	return
}
