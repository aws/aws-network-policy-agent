package clihelper

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfpgms "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	goebpfutils "github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

type PodState struct {
	State uint8
}

// Show - Displays all loaded AWS BPF Programs and their associated maps
func Show() error {

	bpfSDKclient := goelf.New()
	bpfState, err := bpfSDKclient.GetAllBpfProgramsAndMaps()
	if err != nil {
		return err
	}

	for pinPath, bpfEntry := range bpfState {
		podIdentifier, direction := utils.GetPodIdentifierFromBPFPinPath(pinPath)
		fmt.Println("PinPath: ", pinPath)
		line := fmt.Sprintf("Pod Identifier : %s  Direction : %s \n", podIdentifier, direction)
		fmt.Print(line)
		bpfProg := bpfEntry.Program
		fmt.Println("Prog ID: ", bpfProg.ProgID)
		fmt.Println("Associated Maps -> ")
		bpfMaps := bpfEntry.Maps
		for k, v := range bpfMaps {
			fmt.Println("Map Name: ", k)
			fmt.Println("Map ID: ", v.MapID)
		}
		fmt.Println("========================================================================================")
	}
	return nil
}

// ProgShow - Lists out all programs created by AWS Network Policy Agent
func ProgShow() error {
	loadedPgms, err := goebpfpgms.BpfGetAllProgramInfo()
	if err != nil {
		return err
	}

	fmt.Println("Programs currently loaded : ")
	for _, loadedPgm := range loadedPgms {
		progInfo := fmt.Sprintf("Type : %d ID : %d Associated maps count : %d", loadedPgm.Type, loadedPgm.ID, loadedPgm.NrMapIDs)
		fmt.Println(progInfo)
		fmt.Println("========================================================================================")
	}
	return nil
}

// MapShow - Lists out all active maps created by AWS Network Policy Agent
func MapShow() error {
	loadedMaps, err := goebpfmaps.BpfGetAllMapInfo()
	if err != nil {
		return err
	}

	fmt.Println("Maps currently loaded : ")
	for _, loadedMap := range loadedMaps {
		mapInfo := fmt.Sprintf("Type : %d ID : %d", loadedMap.Type, loadedMap.Id)
		fmt.Println(mapInfo)
		mapInfo = fmt.Sprintf("Keysize %d Valuesize %d MaxEntries %d", loadedMap.KeySize, loadedMap.ValueSize, loadedMap.MaxEntries)
		fmt.Println(mapInfo)
		fmt.Println("========================================================================================")
	}
	return nil
}

// MapWalk - Displays content of individual maps (IPv4)
func MapWalk(mapID int) error {
	if mapID <= 0 {
		return fmt.Errorf("Invalid mapID")
	}

	mapFD, err := goebpfutils.GetMapFDFromID(mapID)
	if err != nil {
		return err
	}

	mapInfo, err := goebpfmaps.GetBPFmapInfo(mapFD)
	if err != nil {
		return err
	}
	unix.Close(mapFD)

	if mapInfo.Type != constdef.BPF_MAP_TYPE_LPM_TRIE.Index() && mapInfo.Type != constdef.BPF_MAP_TYPE_LRU_HASH.Index() && mapInfo.Type != constdef.BPF_MAP_TYPE_HASH.Index() {
		return fmt.Errorf("Unsupported map type, should be - LPM trie (egress/ingress maps) or LRU hash (Conntrack table)")
	}

	if mapInfo.Type == constdef.BPF_MAP_TYPE_LPM_TRIE.Index() {
		iterKey := utils.BPFTrieKey{}
		iterNextKey := utils.BPFTrieKey{}

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				fmt.Println("No Entries found, Empty map")
				return nil
			}
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {

				iterValue := [24]utils.BPFTrieVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					retrievedKey := fmt.Sprintf("Key : IP/Prefixlen - %s/%d ", utils.ConvIntToIPv4(iterKey.IP).String(), iterKey.PrefixLen)
					fmt.Println(retrievedKey)
					for i := 0; i < len(iterValue); i++ {
						if iterValue[i].Protocol == 0 {
							continue
						}
						fmt.Println("-------------------")
						fmt.Println("Value Entry : ", i)
						fmt.Println("Protocol - ", utils.GetProtocol(int(iterValue[i].Protocol)))
						fmt.Println("StartPort - ", iterValue[i].StartPort)
						fmt.Println("Endport - ", iterValue[i].EndPort)
						fmt.Println("-------------------")
					}
					fmt.Println("*******************************")
				}

				err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)), mapID)
				if errors.Is(err, unix.ENOENT) {
					fmt.Println("Done reading all entries")
					break
				}
				if err != nil {
					fmt.Println("Failed to get next entry Done searching")
					break
				}
				iterKey = iterNextKey
			}
		}
	}

	if mapInfo.Type == constdef.BPF_MAP_TYPE_LRU_HASH.Index() {
		iterKey := utils.ConntrackKey{}
		iterNextKey := utils.ConntrackKey{}
		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				fmt.Println("No Entries found, Empty map")
				return nil
			}
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {
				iterValue := utils.ConntrackVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					retrievedKey := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s", utils.ConvIntToIPv4(iterKey.Source_ip).String(), iterKey.Source_port, utils.ConvIntToIPv4(iterKey.Dest_ip).String(), iterKey.Dest_port, iterKey.Protocol, utils.ConvIntToIPv4(iterKey.Owner_ip).String())
					fmt.Println(retrievedKey)
					fmt.Println("Value : ")
					fmt.Println("Conntrack Val - ", iterValue.Value)
					fmt.Println("Added At (ns) - ", iterValue.AddedAtNs)
					fmt.Println("*******************************")
				}

				err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)), mapID)
				if errors.Is(err, unix.ENOENT) {
					fmt.Println("Done reading all entries")
					break
				}
				if err != nil {
					fmt.Println("Failed to get next entry Done searching")
					break
				}
				iterKey = iterNextKey
			}
		}
	}

	if mapInfo.Type == constdef.BPF_MAP_TYPE_HASH.Index() {
		var key, nextKey uint32
		// Get the first entry
		err = goebpfmaps.GetFirstMapEntryByID(
			uintptr(unsafe.Pointer(&key)),
			mapID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				fmt.Println("No entries found, empty HASH map (pod_state_map?)")
				return nil
			}
			return fmt.Errorf("unable to get first key (HASH): %v", err)
		}

		for {
			var val PodState
			err = goebpfmaps.GetMapEntryByID(
				uintptr(unsafe.Pointer(&key)),
				uintptr(unsafe.Pointer(&val)),
				mapID)
			if err != nil {
				return fmt.Errorf("unable to get HASH entry for key=%d: %v", key, err)
			}

			fmt.Println("Key : ", key)
			fmt.Println("State - ", val.State)
			fmt.Println("*******************************")

			err = goebpfmaps.GetNextMapEntryByID(
				uintptr(unsafe.Pointer(&key)),
				uintptr(unsafe.Pointer(&nextKey)),
				mapID)
			if errors.Is(err, unix.ENOENT) {
				fmt.Println("Done reading all entries in BPF_MAP_TYPE_HASH")
				break
			}
			if err != nil {
				fmt.Println("Failed to get next entry, done searching")
				break
			}
			key = nextKey
		}
		return nil
	}

	return nil
}

// MapWalkv6 - Displays contents of individual maps (IPv6)
func MapWalkv6(mapID int) error {
	if mapID <= 0 {
		return fmt.Errorf("Invalid mapID")
	}

	mapFD, err := goebpfutils.GetMapFDFromID(mapID)
	if err != nil {
		return err
	}

	mapInfo, err := goebpfmaps.GetBPFmapInfo(mapFD)
	if err != nil {
		return err
	}
	unix.Close(mapFD)
	if mapInfo.Type != constdef.BPF_MAP_TYPE_LPM_TRIE.Index() && mapInfo.Type != constdef.BPF_MAP_TYPE_LRU_HASH.Index() {
		return fmt.Errorf("Unsupported map type, should be - LPM trie (egress/ingress maps) or LRU hash (Conntrack table)")
	}

	if mapInfo.Type == constdef.BPF_MAP_TYPE_LPM_TRIE.Index() {
		iterKey := utils.BPFTrieKeyV6{}
		iterNextKey := utils.BPFTrieKeyV6{}

		byteSlice := utils.ConvTrieV6ToByte(iterKey)
		nextbyteSlice := utils.ConvTrieV6ToByte(iterNextKey)

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {

				iterValue := [24]utils.BPFTrieVal{}

				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					v6key := utils.ConvByteToTrieV6(byteSlice)
					retrievedKey := fmt.Sprintf("Key : IP/Prefixlen - %s/%d ", utils.ConvByteToIPv6(v6key.IP).String(), v6key.PrefixLen)
					fmt.Println(retrievedKey)
					for i := 0; i < len(iterValue); i++ {
						if iterValue[i].Protocol == 0 {
							continue
						}
						fmt.Println("-------------------")
						fmt.Println("Value Entry : ", i)
						fmt.Println("Protocol - ", utils.GetProtocol(int(iterValue[i].Protocol)))
						fmt.Println("StartPort - ", iterValue[i].StartPort)
						fmt.Println("Endport - ", iterValue[i].EndPort)
						fmt.Println("-------------------")
					}
					fmt.Println("*******************************")
				}

				err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&nextbyteSlice[0])), mapID)
				if errors.Is(err, unix.ENOENT) {
					fmt.Println("Done reading all entries")
					break
				}
				if err != nil {
					fmt.Println("Failed to get next entry Done searching")
					break
				}
				copy(byteSlice, nextbyteSlice)
			}
		}
	}

	if mapInfo.Type == constdef.BPF_MAP_TYPE_LRU_HASH.Index() {
		iterKey := utils.ConntrackKeyV6{}
		iterNextKey := utils.ConntrackKeyV6{}

		byteSlice := utils.ConvConntrackV6ToByte(iterKey)
		nextbyteSlice := utils.ConvConntrackV6ToByte(iterNextKey)

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {
				iterValue := utils.ConntrackVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					v6key := utils.ConvByteToConntrackV6(byteSlice)
					retrievedKey := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s", utils.ConvByteToIPv6(v6key.Source_ip).String(), v6key.Source_port, utils.ConvByteToIPv6(v6key.Dest_ip).String(), v6key.Dest_port, v6key.Protocol, utils.ConvByteToIPv6(v6key.Owner_ip).String())
					fmt.Println(retrievedKey)
					fmt.Println("Value : ")
					fmt.Println("Conntrack Val - ", iterValue.Value)
					fmt.Println("*******************************")
				}

				err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&nextbyteSlice[0])), mapID)
				if errors.Is(err, unix.ENOENT) {
					fmt.Println("Done reading all entries")
					break
				}
				if err != nil {
					fmt.Println("Failed to get next entry Done searching")
					break
				}
				copy(byteSlice, nextbyteSlice)
			}
		}
	}

	return nil
}
