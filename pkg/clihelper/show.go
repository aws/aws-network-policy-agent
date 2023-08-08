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

type BPFTrieKey struct {
	PrefixLen uint32
	IP        uint32
}

type BPFTrieKeyV6 struct {
	PrefixLen uint32
	IP        [16]byte
}

type BPFTrieVal struct {
	Protocol  uint32
	StartPort uint32
	EndPort   uint32
}

type ConntrackKey struct {
	Source_ip   uint32
	Source_port uint16
	Dest_ip     uint32
	Dest_port   uint16
	Protocol    uint8
}

type ConntrackKeyV6 struct {
	Source_ip   [16]byte //16
	Source_port uint16   // 2
	Dest_ip     [16]byte //16
	Dest_port   uint16   // 2
	Protocol    uint8    // 1
}

type ConntrackVal struct {
	Value uint8
}

func convTrieV6ToByte(key BPFTrieKeyV6) []byte {
	ipSize := unsafe.Sizeof(key)
	byteArray := (*[20]byte)(unsafe.Pointer(&key))
	byteSlice := byteArray[:ipSize]
	return byteSlice
}

func convByteToTrieV6(keyByte []byte) BPFTrieKeyV6 {
	var v6key BPFTrieKeyV6
	byteArray := (*[unsafe.Sizeof(v6key)]byte)(unsafe.Pointer(&v6key))
	copy(byteArray[:], keyByte)
	return v6key
}

func convConntrackV6ToByte(key ConntrackKeyV6) []byte {
	ipSize := unsafe.Sizeof(key)
	byteArray := (*[38]byte)(unsafe.Pointer(&key))
	byteSlice := byteArray[:ipSize]
	return byteSlice
}

func convByteToConntrackV6(keyByte []byte) ConntrackKeyV6 {
	var v6key ConntrackKeyV6
	byteArray := (*[unsafe.Sizeof(v6key)]byte)(unsafe.Pointer(&v6key))
	copy(byteArray[:], keyByte)
	return v6key
}

// Show - Displays all loaded AWS BPF Programs and their associated maps
func Show() error {

	bpfState, err := goelf.RecoverAllBpfProgramsAndMaps()
	if err != nil {
		return err
	}

	for pinPath, bpfEntry := range bpfState {
		podIdentifier, direction := utils.GetPodIdentifierFromBPFPinPath(pinPath)
		fmt.Println("PinPath: ", pinPath)
		line := fmt.Sprintf("Pod Identifier : %s  Direction : %s \n", podIdentifier, direction)
		fmt.Print(line)
		bpfProg := bpfEntry.Program
		fmt.Println("Prog FD: ", bpfProg.ProgFD)
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

	if mapInfo.Type != constdef.BPF_MAP_TYPE_LPM_TRIE.Index() && mapInfo.Type != constdef.BPF_MAP_TYPE_LRU_HASH.Index() {
		return fmt.Errorf("Unsupported map type, should be - LPM trie (egress/ingress maps) or LRU hash (Conntrack table)")
	}

	if mapInfo.Type == constdef.BPF_MAP_TYPE_LPM_TRIE.Index() {
		iterKey := BPFTrieKey{}
		iterNextKey := BPFTrieKey{}

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {

				iterValue := BPFTrieVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					retrievedKey := fmt.Sprintf("Key : IP/Prefixlen - %s/%d ", utils.ConvIntToIPv4(iterKey.IP).String(), iterKey.PrefixLen)
					fmt.Println(retrievedKey)
					fmt.Println("Value : ")
					fmt.Println("Protocol - ", iterValue.Protocol)
					fmt.Println("StartPort - ", iterValue.StartPort)
					fmt.Println("Endport - ", iterValue.EndPort)
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
		iterKey := ConntrackKey{}
		iterNextKey := ConntrackKey{}
		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {
				iterValue := ConntrackVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					retrievedKey := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d", utils.ConvIntToIPv4(iterKey.Source_ip).String(), iterKey.Source_port, utils.ConvIntToIPv4(iterKey.Dest_ip).String(), iterKey.Dest_port, iterKey.Protocol)
					fmt.Println(retrievedKey)
					fmt.Println("Value : ")
					fmt.Println("Conntrack Val - ", iterValue.Value)
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
		iterKey := BPFTrieKeyV6{}
		iterNextKey := BPFTrieKeyV6{}

		byteSlice := convTrieV6ToByte(iterKey)
		nextbyteSlice := convTrieV6ToByte(iterNextKey)

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {

				iterValue := BPFTrieVal{}

				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					v6key := convByteToTrieV6(byteSlice)
					retrievedKey := fmt.Sprintf("Key : IP/Prefixlen - %s/%d ", utils.ConvByteToIPv6(v6key.IP).String(), v6key.PrefixLen)
					fmt.Println(retrievedKey)
					fmt.Println("Value : ")
					fmt.Println("Protocol - ", iterValue.Protocol)
					fmt.Println("StartPort - ", iterValue.StartPort)
					fmt.Println("Endport - ", iterValue.EndPort)
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
		iterKey := ConntrackKeyV6{}
		iterNextKey := ConntrackKeyV6{}

		byteSlice := convConntrackV6ToByte(iterKey)
		nextbyteSlice := convConntrackV6ToByte(iterNextKey)

		err = goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get First key: %v", err)
		} else {
			for {
				iterValue := ConntrackVal{}
				err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
				if err != nil {
					return fmt.Errorf("Unable to get map entry: %v", err)
				} else {
					v6key := convByteToConntrackV6(byteSlice)
					retrievedKey := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d", utils.ConvByteToIPv6(v6key.Source_ip).String(), v6key.Source_port, utils.ConvByteToIPv6(v6key.Dest_ip).String(), v6key.Dest_port, v6key.Protocol)
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
