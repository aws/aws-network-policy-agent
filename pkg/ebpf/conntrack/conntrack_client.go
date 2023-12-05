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
	c.logger.Info("Start cleanup of conntrack map")
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

	localConntrackCache := make(map[utils.ConntrackKey]bool)
	// Build local conntrack cache
	for _, conntrackFlow := range conntrackFlows {
		//Check fwd flow with SIP as owner
		fwdFlowWithSIP := utils.ConntrackKey{}
		fwdFlowWithSIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
		fwdFlowWithSIP.Source_port = conntrackFlow.Forward.SrcPort
		fwdFlowWithSIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.DstIP)
		fwdFlowWithSIP.Dest_port = conntrackFlow.Forward.DstPort
		fwdFlowWithSIP.Protocol = conntrackFlow.Forward.Protocol
		fwdFlowWithSIP.Owner_ip = fwdFlowWithSIP.Source_ip

		localConntrackCache[fwdFlowWithSIP] = true

		//Check fwd flow with DIP as owner
		fwdFlowWithDIP := utils.ConntrackKey{}
		fwdFlowWithDIP.Source_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.SrcIP)
		fwdFlowWithDIP.Source_port = conntrackFlow.Forward.SrcPort
		fwdFlowWithDIP.Dest_ip = utils.ConvIPv4ToInt(conntrackFlow.Forward.DstIP)
		fwdFlowWithDIP.Dest_port = conntrackFlow.Forward.DstPort
		fwdFlowWithDIP.Protocol = conntrackFlow.Forward.Protocol
		fwdFlowWithDIP.Owner_ip = fwdFlowWithSIP.Dest_ip

		localConntrackCache[fwdFlowWithDIP] = true

	}

	//Check if the entry is expired..
	iterKey := utils.ConntrackKey{}
	iterNextKey := utils.ConntrackKey{}
	expiredList := make(map[utils.ConntrackKey]bool)
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
				newKey.Source_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(iterKey.Source_ip))
				newKey.Source_port = iterKey.Source_port
				newKey.Dest_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(iterKey.Dest_ip))
				newKey.Dest_port = iterKey.Dest_port
				newKey.Protocol = iterKey.Protocol
				newKey.Owner_ip = utils.ConvIPv4ToInt(utils.ConvIntToIPv4(iterKey.Owner_ip))

				_, ok := localConntrackCache[newKey]
				if !ok {
					//Delete the entry in local cache
					retrievedKey := fmt.Sprintf("Expired/Delete Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s", utils.ConvIntToIPv4(iterKey.Source_ip).String(), iterKey.Source_port, utils.ConvIntToIPv4(iterKey.Dest_ip).String(), iterKey.Dest_port, iterKey.Protocol, utils.ConvIntToIPv4(iterKey.Owner_ip).String())
					c.logger.Info("Conntrack cleanup", "Entry - ", retrievedKey)

					// Copy from iterKey since we will replace the value
					nKey := utils.ConntrackKey{}
					nKey.Source_ip = iterKey.Source_ip
					nKey.Source_port = iterKey.Source_port
					nKey.Dest_ip = iterKey.Dest_ip
					nKey.Dest_port = iterKey.Dest_port
					nKey.Protocol = iterKey.Protocol
					nKey.Owner_ip = iterKey.Owner_ip
					expiredList[nKey] = true
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
	c.logger.Info("Start cleanup of conntrack map")
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

		localConntrackCache[fwdFlowWithSIP] = true

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

		localConntrackCache[fwdFlowWithDIP] = true
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
				_, ok := localConntrackCache[newKey]
				if !ok {
					//Delete the entry in local cache
					retrievedKey := fmt.Sprintf("Expired/Delete Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s", utils.ConvByteToIPv6(newKey.Source_ip).String(), newKey.Source_port, utils.ConvByteToIPv6(newKey.Dest_ip).String(), newKey.Dest_port, newKey.Protocol, utils.ConvByteToIPv6(newKey.Owner_ip).String())
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
		c.printByteArray(ceByteSlice)
		c.conntrackMap.DeleteMapEntry(uintptr(unsafe.Pointer(&ceByteSlice[0])))
	}

	c.logger.Info("Done cleanup of conntrack map")
	return
}

func (c *conntrackClient) printByteArray(byteArray []byte) {
	for _, b := range byteArray {
		c.logger.Info("CONNTRACK VAL", "->", b)
	}
	c.logger.Info("DONE")
}
