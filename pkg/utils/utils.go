package utils

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/vishvananda/netlink"
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
	TRIE_VALUE_LENGTH               = 288
	BPF_PROGRAMS_PIN_PATH_DIRECTORY = "/sys/fs/bpf/globals/aws/programs/"
	BPF_MAPS_PIN_PATH_DIRECTORY     = "/sys/fs/bpf/globals/aws/maps/"
	TC_INGRESS_PROG                 = "handle_ingress"
	TC_EGRESS_PROG                  = "handle_egress"
	TC_INGRESS_MAP                  = "ingress_map"
	TC_EGRESS_MAP                   = "egress_map"
	TC_INGRESS_POD_STATE_MAP        = "ingress_pod_state_map"
	TC_EGRESS_POD_STATE_MAP         = "egress_pod_state_map"

	CATCH_ALL_PROTOCOL   corev1.Protocol = "ANY_IP_PROTOCOL"
	DENY_ALL_PROTOCOL    corev1.Protocol = "RESERVED_IP_PROTOCOL_NUMBER"
	DEFAULT_CLUSTER_NAME                 = "k8s-cluster"
	ErrFileExists                        = "file exists"
	ErrInvalidFilterList                 = "failed to get filter list"
	ErrMissingFilter                     = "no active filter to detach"
)

func log() logger.Logger {
	return logger.Get()
}

// NetworkPolicyEnforcingMode is the mode of network policy enforcement
type NetworkPolicyEnforcingMode string

const (
	// Strict : strict network policy enforcement
	Strict NetworkPolicyEnforcingMode = "strict"
	// Standard :standard network policy enforcement
	Standard NetworkPolicyEnforcingMode = "standard"
)

// IsValidNetworkPolicyEnforcingMode checks if the input string matches any of the enum values
func IsValidNetworkPolicyEnforcingMode(input string) bool {
	switch strings.ToLower(input) {
	case string(Strict), string(Standard):
		return true
	default:
		return false
	}
}

// IsStrictMode checks if NP enforcing mode is strict
func IsStrictMode(input string) bool {
	return strings.ToLower(input) == string(Strict)
}

// IsStandardMode checks if NP enforcing mode is standard
func IsStandardMode(input string) bool {
	return strings.ToLower(input) == string(Standard)
}

func GetProtocol(protocolNum int) string {
	protocolStr := "UNKNOWN"
	if protocolNum == TCP_PROTOCOL_NUMBER {
		protocolStr = "TCP"
	} else if protocolNum == UDP_PROTOCOL_NUMBER {
		protocolStr = "UDP"
	} else if protocolNum == SCTP_PROTOCOL_NUMBER {
		protocolStr = "SCTP"
	} else if protocolNum == ICMP_PROTOCOL_NUMBER {
		protocolStr = "ICMP"
	} else if protocolNum == RESERVED_IP_PROTOCOL_NUMBER {
		protocolStr = "RESERVED"
	} else if protocolNum == ANY_IP_PROTOCOL {
		protocolStr = "ANY PROTOCOL"
	}
	return protocolStr
}

var getLinkByNameFunc = netlink.LinkByName

type VerdictType int

const (
	DENY VerdictType = iota
	ACCEPT
	EXPIRED_DELETED
)

func (verdictType VerdictType) Index() int {
	return int(verdictType)
}

func GetPodNamespacedName(podName, podNamespace string) string {
	return podName + podNamespace
}

func GetPodIdentifier(podName, podNamespace string) string {
	if strings.Contains(podName, ".") {
		log().Debug("Replacing '.' character with '_' for pod pin path.")
		podName = strings.Replace(podName, ".", "_", -1)
	}
	podIdentifierPrefix := podName
	if strings.Contains(string(podName), "-") {
		tmpName := strings.Split(podName, "-")
		podIdentifierPrefix = strings.Join(tmpName[:len(tmpName)-1], "-")
	}
	return podIdentifierPrefix + "-" + podNamespace
}

func GetPodIdentifierFromBPFPinPath(pinPath string) (string, string) {
	pinPathName := strings.Split(pinPath, "/")
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

func GetPodStateBPFMapPinPathFromPodIdentifier(podIdentifier string, direction string) string {
	mapName := TC_INGRESS_POD_STATE_MAP
	if direction == "egress" {
		mapName = TC_EGRESS_POD_STATE_MAP
	}
	pinPath := BPF_MAPS_PIN_PATH_DIRECTORY + podIdentifier + "_" + mapName
	return pinPath
}

func GetPolicyEndpointIdentifier(policyName, policyNamespace string) string {
	return policyName + policyNamespace
}

func GetParentNPNameFromPEName(policyEndpointName string) string {
	return policyEndpointName[0:strings.LastIndex(policyEndpointName, "-")]
}

func getHostLinkByName(name string) (netlink.Link, error) {
	return getLinkByNameFunc(name)
}

var GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
	var interfaceName string
	var errors error

	if interfaceIndex > 0 {
		podName = fmt.Sprintf("%s.%s", podName, strconv.Itoa(interfaceIndex))
	}

	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", podNamespace, podName)))

	for _, prefix := range interfacePrefixes {
		interfaceName = fmt.Sprintf("%s%s", prefix, hex.EncodeToString(h.Sum(nil))[:11])
		if _, err := getHostLinkByName(interfaceName); err == nil {
			return interfaceName, nil
		} else {
			errors = multierror.Append(errors, fmt.Errorf("failed to find link %s: %w", interfaceName, err))
		}
	}

	log().Errorf("Not found any interface starting with prefixes and the hash. Prefixes searched %v hash %v error %v", interfacePrefixes, hex.EncodeToString(h.Sum(nil))[:11], errors)
	return "", errors
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

func ComputeTrieValue(l4Info []v1alpha1.Port, allowAll, denyAll bool) []byte {
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
		log().Debugf("L4 values: protocol: %v startPort: %v endPort: %v", protocol, startPort, endPort)
	}

	for _, l4Entry := range l4Info {
		if startOffset >= TRIE_VALUE_LENGTH {
			log().Error("No.of unique port/protocol combinations supported for a single endpoint exceeded the supported maximum of 24")
			return value
		}
		endPort = 0
		startPort = 0

		protocol = deriveProtocolValue(l4Entry, allowAll, denyAll)
		if l4Entry.Port != nil {
			startPort = int(*l4Entry.Port)
		}

		if l4Entry.EndPort != nil {
			endPort = int(*l4Entry.EndPort)
		}
		log().Debugf("L4 values: protocol: %v startPort: %v endPort: %v", protocol, startPort, endPort)
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
	protocol := ANY_IP_PROTOCOL

	if denyAll {
		return RESERVED_IP_PROTOCOL_NUMBER
	}

	if allowAll {
		return ANY_IP_PROTOCOL
	}

	if l4Info.Protocol == nil {
		return protocol //Protocol defaults to ANY_IP_PROTOCOL if not specified
	}

	if *l4Info.Protocol == corev1.ProtocolTCP {
		protocol = TCP_PROTOCOL_NUMBER
	} else if *l4Info.Protocol == corev1.ProtocolUDP {
		protocol = UDP_PROTOCOL_NUMBER
	} else if *l4Info.Protocol == corev1.ProtocolSCTP {
		protocol = SCTP_PROTOCOL_NUMBER
	} else if *l4Info.Protocol == CATCH_ALL_PROTOCOL {
		protocol = ANY_IP_PROTOCOL
	} else if *l4Info.Protocol == DENY_ALL_PROTOCOL {
		protocol = RESERVED_IP_PROTOCOL_NUMBER
	}

	return protocol
}

func IsFileExistsError(error string) bool {
	if error == ErrFileExists {
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

func IsNodeIP(nodeIP string, ipCidr string) bool {
	ipAddr, _, _ := net.ParseCIDR(ipCidr)
	if net.ParseIP(nodeIP).Equal(ipAddr) {
		return true
	}
	return false
}

func IsNonHostCIDR(ipAddr string) bool {
	ipSplit := strings.Split(ipAddr, "/")
	//Ignore Catch All IP entry as well
	if ipSplit[1] != "32" && ipSplit[1] != "128" {
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
	_           uint16 //Padding
	Dest_ip     [16]byte
	Dest_port   uint16
	Protocol    uint8
	_           uint8    //Padding
	Owner_ip    [16]byte //16
}

type ConntrackKey struct {
	Source_ip   uint32
	Source_port uint16
	_           uint16 //Padding
	Dest_ip     uint32
	Dest_port   uint16
	Protocol    uint8
	_           uint8 //Padding
	Owner_ip    uint32
}

type ConntrackVal struct {
	Value uint8
}

func ConvConntrackV6ToByte(key ConntrackKeyV6) []byte {
	ipSize := unsafe.Sizeof(key)
	byteArray := (*[unsafe.Sizeof(key)]byte)(unsafe.Pointer(&key))
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

func ConvTrieV6ToByte(key BPFTrieKeyV6) []byte {
	ipSize := unsafe.Sizeof(key)
	byteArray := (*[20]byte)(unsafe.Pointer(&key))
	byteSlice := byteArray[:ipSize]
	return byteSlice
}

func ConvByteToTrieV6(keyByte []byte) BPFTrieKeyV6 {
	var v6key BPFTrieKeyV6
	byteArray := (*[unsafe.Sizeof(v6key)]byte)(unsafe.Pointer(&v6key))
	copy(byteArray[:], keyByte)
	return v6key
}
