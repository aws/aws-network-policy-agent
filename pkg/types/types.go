package types

import (
	"fmt"
	"net"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

const L4RULE_VALUES_LENGTH = 384

type Pod struct {
	types.NamespacedName
	PodIP policyk8sawsv1.NetworkAddress
}

type IPCacheVal struct {
	ExpiryTime uint64
	Ports      [L4RULE_VALUES_LENGTH]byte // 24 * 16 bytes = 384 bytes (24 entries of lmp_cp_trie_val)
}

type DomainRules struct {
	DomainName string
	L4Info     []policyk8sawsv1.Port
}

// IPWithTTL represents an IP address with its associated TTL from DNS response
type IPWithTTL struct {
	IP  net.IP
	TTL uint32
}

// L4Rule represents a Layer 4 rule with port/protocol information and priority
type L4Rule struct {
	L4PortProtocolInfo policyk8sawsv1.Port
	Priority           int
}

// Equal checks if this L4Rule is equal to another L4Rule
func (l L4Rule) Equal(other L4Rule) bool {
	if l.Priority != other.Priority {
		return false
	}

	port1 := l.L4PortProtocolInfo
	port2 := other.L4PortProtocolInfo

	// Compare protocols
	if (port1.Protocol == nil) != (port2.Protocol == nil) {
		return false
	}
	if port1.Protocol != nil && port2.Protocol != nil && *port1.Protocol != *port2.Protocol {
		return false
	}

	// Compare ports
	if (port1.Port == nil) != (port2.Port == nil) {
		return false
	}
	if port1.Port != nil && port2.Port != nil && *port1.Port != *port2.Port {
		return false
	}

	// Compare end ports
	if (port1.EndPort == nil) != (port2.EndPort == nil) {
		return false
	}
	if port1.EndPort != nil && port2.EndPort != nil && *port1.EndPort != *port2.EndPort {
		return false
	}

	return true
}

// String returns a human-readable representation of the L4Rule
func (l L4Rule) String() string {
	var protocol string
	if l.L4PortProtocolInfo.Protocol != nil {
		protocol = string(*l.L4PortProtocolInfo.Protocol)
	} else {
		protocol = "ANY"
	}

	var portRange string
	if l.L4PortProtocolInfo.Port != nil {
		if l.L4PortProtocolInfo.EndPort != nil {
			// Port range
			portRange = fmt.Sprintf("%d-%d", *l.L4PortProtocolInfo.Port, *l.L4PortProtocolInfo.EndPort)
		} else {
			// Single port
			portRange = fmt.Sprintf("%d", *l.L4PortProtocolInfo.Port)
		}
	} else {
		portRange = "ANY"
	}

	return fmt.Sprintf("L4Rule{Protocol:%s, Port:%s, Priority:%d}", protocol, portRange, l.Priority)
}
