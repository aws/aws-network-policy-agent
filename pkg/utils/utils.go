package utils

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/achevuru/aws-network-policy-agent/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

var (
	TCP_PROTOCOL_NUMBER             = 6
	UDP_PROTOCOL_NUMBER             = 17
	SCTP_PROTOCOL_NUMBER            = 132
	ICMP_PROTOCOL_NUMBER            = 1
	RESERVED_IP_PROTOCOL_NUMBER     = 255 // 255 is a reserved protocol value in the IP header
	ANY_IP_PROTOCOL                 = 254
	TRIE_KEY_LENGTH                 = 8
	TRIE_V6_KEY_LENGTH              = 20
	TRIE_VALUE_LENGTH               = 96
	BPF_PROGRAMS_PIN_PATH_DIRECTORY = "/sys/fs/bpf/globals/aws/programs/"
	BPF_MAPS_PIN_PATH_DIRECTORY     = "/sys/fs/bpf/globals/aws/maps/"
	TC_INGRESS_PROG                 = "handle_ingress"
	TC_EGRESS_PROG                  = "handle_egress"
	TC_INGRESS_MAP                  = "ingress_map"
	TC_EGRESS_MAP                   = "egress_map"

	CATCH_ALL_PROTOCOL   corev1.Protocol = "ANY_IP_PROTOCOL"
	DEFAULT_CLUSTER_NAME                 = "k8s-cluster"
	ErrFileExists                        = " file exists"
	ErrInvalidFilterList                 = "failed to get filter list"
	ErrMissingFilter                     = "no active filter to detach"
)

func GetPodNamespacedName(podName, podNamespace string) string {
	return podName + podNamespace
}

func GetPodIdentifier(podName, podNamespace string) string {
	podIdentifierPrefix := podName
	if strings.Contains(string(podName), "-") {
		tmpName := strings.Split(podName, "-")
		podIdentifierPrefix = strings.Join(tmpName[:len(tmpName)-1], "-")
	}
	return podIdentifierPrefix + "-" + podNamespace
}

func GetPodIdentifierFromBPFPinPath(pinPath string) (string, string) {
	pinPathName := strings.Split(pinPath, "/")
	fmt.Println("pinPathName: ", pinPathName[7])
	podIdentifier := strings.Split(pinPathName[7], "_")
	return podIdentifier[0], podIdentifier[2]
}

func GetBPFPinPathFromPodIdentifier(podIdentifier string, direction string) string {
	progName := TC_INGRESS_PROG
	if direction == "egress" {
		progName = TC_EGRESS_PROG
	}
	pinPath := BPF_PROGRAMS_PIN_PATH_DIRECTORY + podIdentifier + "_" + progName
	return pinPath
}

func GetBPFMapPinPathFromPodIdentifier(podIdentifier string, direction string) string {
	mapName := TC_INGRESS_MAP
	if direction == "egress" {
		mapName = TC_EGRESS_MAP
	}
	pinPath := BPF_MAPS_PIN_PATH_DIRECTORY + podIdentifier + "_" + mapName
	return pinPath
}

func GetPolicyEndpointIdentifier(policyName, policyNamespace string) string {
	return policyName + policyNamespace
}

func GetHostVethName(podName, podNamespace string) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", podNamespace, podName)))
	return fmt.Sprintf("%s%s", "eni", hex.EncodeToString(h.Sum(nil))[:11])
}

func ComputeTrieKey(n net.IPNet, isIPv6Enabled bool) []byte {
	prefixLen, _ := n.Mask.Size()
	var key []byte

	if isIPv6Enabled {
		// Key format: Prefix length (4 bytes) followed by 16 byte IP
		key = make([]byte, TRIE_V6_KEY_LENGTH)
	} else {
		// Key format: Prefix length (4 bytes) followed by 4 byte IP
		key = make([]byte, TRIE_KEY_LENGTH)

	}

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	return key
}

func ComputeTrieValue(l4Info []v1alpha1.Port, log logr.Logger, allowAll, denyAll bool) []byte {
	var startPort, endPort, protocol int

	value := make([]byte, TRIE_VALUE_LENGTH)
	startOffset := 0

	if len(l4Info) == 0 {
		allowAll = true
	}

	if allowAll || denyAll {
		protocol = deriveProtocolValue(v1alpha1.Port{}, allowAll, denyAll)
		binary.LittleEndian.PutUint32(value[startOffset:startOffset+4], uint32(protocol))
		startOffset += 4
		binary.LittleEndian.PutUint32(value[startOffset:startOffset+4], uint32(startPort))
		startOffset += 4
		binary.LittleEndian.PutUint32(value[startOffset:startOffset+4], uint32(endPort))
		startOffset += 4
		log.Info("L4 values: ", "protocol: ", protocol, "startPort: ", startPort, "endPort: ", endPort)
	}

	for _, l4Entry := range l4Info {
		if startOffset >= TRIE_VALUE_LENGTH {
			return value
		}
		endPort = 0
		protocol = deriveProtocolValue(l4Entry, allowAll, denyAll)
		if l4Entry.Port != nil {
			startPort = int(*l4Entry.Port)
		}

		if l4Entry.EndPort != nil {
			endPort = int(*l4Entry.EndPort)
		}
		log.Info("L4 values: ", "protocol: ", protocol, "startPort: ", startPort, "endPort: ", endPort)
		binary.LittleEndian.PutUint32(value[startOffset:startOffset+4], uint32(protocol))
		startOffset += 4
		binary.LittleEndian.PutUint32(value[startOffset:startOffset+4], uint32(startPort))
		startOffset += 4
		binary.LittleEndian.PutUint32(value[startOffset:startOffset+4], uint32(endPort))
		startOffset += 4
	}

	return value
}

func deriveProtocolValue(l4Info v1alpha1.Port, allowAll, denyAll bool) int {
	protocol := TCP_PROTOCOL_NUMBER //ProtocolTCP

	if denyAll {
		return RESERVED_IP_PROTOCOL_NUMBER
	}

	if allowAll {
		return ANY_IP_PROTOCOL
	}

	if l4Info.Protocol == nil {
		return protocol //Protocol defaults TCP if not specified
	}

	if *l4Info.Protocol == corev1.ProtocolUDP {
		protocol = UDP_PROTOCOL_NUMBER
	} else if *l4Info.Protocol == corev1.ProtocolSCTP {
		protocol = SCTP_PROTOCOL_NUMBER
	} else if *l4Info.Protocol == CATCH_ALL_PROTOCOL {
		protocol = ANY_IP_PROTOCOL
	}

	return protocol
}

func IsFileExistsError(error string) bool {
	errCode := strings.Split(error, ":")
	if errCode[1] == ErrFileExists {
		return true
	}
	return false
}

func IsInvalidFilterListError(error string) bool {
	errCode := strings.Split(error, ":")
	if errCode[0] == ErrInvalidFilterList {
		return true
	}
	return false
}

func IsMissingFilterError(error string) bool {
	errCode := strings.Split(error, "-")
	if errCode[0] == ErrMissingFilter {
		return true
	}
	return false
}

func IsCatchAllIPEntry(ipAddr string) bool {
	ipSplit := strings.Split(ipAddr, "/")
	if ipSplit[1] == "0" { //if ipSplit[0] == "0.0.0.0" && ipSplit[1] == "0" {
		return true
	}
	return false
}

func IsNonHostCIDR(ipAddr string) bool {
	ipSplit := strings.Split(ipAddr, "/")
	//Ignore Catch All IP entry as well
	if ipSplit[1] != "32" && ipSplit[1] != "128" && ipSplit[1] != "0" {
		return true
	}
	return false
}

func ConvByteArrayToIP(ipInInt uint32) string {
	hexIPString := fmt.Sprintf("%x", ipInInt)

	if len(hexIPString)%2 != 0 {
		hexIPString = "0" + hexIPString
	}

	byteData, _ := hex.DecodeString(hexIPString)
	reverseByteData := reverseByteArray(byteData)

	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(reverseByteData)), "."), "[]")
}

func reverseByteArray(input []byte) []byte {
	if len(input) == 0 {
		return input
	}
	return append(reverseByteArray(input[1:]), input[0])
}

func ConvIntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipaddr)
	return ip
}

func ConvIPv4ToInt(ipaddr net.IP) uint32 {
	return uint32(ipaddr[0])<<24 | uint32(ipaddr[1])<<16 | uint32(ipaddr[2])<<8 | uint32(ipaddr[3])
}

func ConvIntToIPv4NetworkOrder(ipaddr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func ConvByteToIPv6(ipaddr [16]byte) net.IP {
	ip := net.IP(ipaddr[:])
	return ip
}

func ConvIPv6ToByte(ipaddr net.IP) []byte {
	ipaddrBytes := ipaddr.To16()
	return ipaddrBytes
}

type ConntrackKeyV6 struct {
	Source_ip   [16]byte
	Source_port uint16
	Dest_ip     [16]byte
	Dest_port   uint16
	Protocol    uint8
}

type ConntrackVal struct {
	Value uint8
}

func ConvConntrackV6ToByte(key ConntrackKeyV6) []byte {
	ipSize := unsafe.Sizeof(key)
	byteArray := (*[38]byte)(unsafe.Pointer(&key))
	byteSlice := byteArray[:ipSize]
	return byteSlice
}

func ConvByteToConntrackV6(keyByte []byte) ConntrackKeyV6 {
	var v6key ConntrackKeyV6
	byteArray := (*[unsafe.Sizeof(v6key)]byte)(unsafe.Pointer(&v6key))
	copy(byteArray[:], keyByte)
	return v6key
}

func CopyV6Bytes(dest *[16]byte, src [16]byte) {
	for i := 0; i < len(src); i++ {
		dest[i] = src[i]
	}
}
