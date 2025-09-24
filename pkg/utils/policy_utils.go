package utils

import (
	"hash/fnv"
	"net"
	"time"

	v1alpha1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
)

// PolicyInfo contains metadata about a network policy
type PolicyInfo struct {
	Name              string
	Namespace         string
	CreationTimestamp int64
	PolicyType        uint8 // 1=Ingress, 2=Egress, 3=Both
}

// Policy type constants
const (
	PolicyTypeIngress = uint8(1)
	PolicyTypeEgress  = uint8(2)
	PolicyTypeBoth    = uint8(3)
)

// GeneratePolicyID creates a unique hash for a policy based on name and namespace
func GeneratePolicyID(policyName, policyNamespace string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(policyNamespace))
	h.Write([]byte(":"))
	h.Write([]byte(policyName))
	return h.Sum32()
}

// CalculatePrecedence calculates rule precedence based on CIDR specificity,
// port specificity, and policy age
func CalculatePrecedence(cidr string, ports []v1alpha1.Port, policy PolicyInfo) uint8 {
	precedence := uint8(0)

	// CIDR specificity (0-32 for IPv4, 0-128 for IPv6)
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// If not a valid CIDR, treat as host address
		if net.ParseIP(cidr) != nil {
			precedence += 128 // Maximum specificity for host address
		}
	} else {
		cidrBits, _ := ipNet.Mask.Size()
		// Scale to 0-128 range
		precedence += uint8(cidrBits * 4)
		if precedence > 128 {
			precedence = 128
		}
	}

	// Port specificity
	if len(ports) == 0 {
		precedence += 16 // All ports
	} else if len(ports) == 1 {
		port := ports[0]
		if port.Port != nil && port.EndPort == nil {
			precedence += 64 // Single port
		} else if port.Port != nil && port.EndPort != nil {
			precedence += 32 // Port range
		} else {
			precedence += 16 // All ports
		}
	} else {
		precedence += 48 // Multiple specific ports
	}

	// Age bonus (older policies get slight advantage for stability)
	age := time.Now().Unix() - policy.CreationTimestamp
	if age > 3600 { // More than 1 hour old
		precedence += 8
	} else if age > 300 { // More than 5 minutes old
		precedence += 4
	}

	// precedence is already uint8, so it's automatically capped at 255

	return precedence
}

// DeterminePolicyType determines if a policy is ingress, egress, or both
func DeterminePolicyType(hasIngress, hasEgress bool) uint8 {
	if hasIngress && hasEgress {
		return PolicyTypeBoth
	} else if hasIngress {
		return PolicyTypeIngress
	} else if hasEgress {
		return PolicyTypeEgress
	}
	return PolicyTypeIngress // Default
}

// TruncatePolicyName truncates policy name to fit in eBPF map constraints
func TruncatePolicyName(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	return name[:maxLen]
}

// PolicyIDCollisionDetector tracks policy ID collisions
type PolicyIDCollisionDetector struct {
	idToPolicy map[uint32]PolicyInfo
}

// NewPolicyIDCollisionDetector creates a new collision detector
func NewPolicyIDCollisionDetector() *PolicyIDCollisionDetector {
	return &PolicyIDCollisionDetector{
		idToPolicy: make(map[uint32]PolicyInfo),
	}
}

// CheckAndRegister checks for ID collision and registers the policy
func (d *PolicyIDCollisionDetector) CheckAndRegister(id uint32, policy PolicyInfo) bool {
	if existing, exists := d.idToPolicy[id]; exists {
		// Collision detected
		if existing.Name != policy.Name || existing.Namespace != policy.Namespace {
			log().Warnf("Policy ID collision detected: ID %d used by both %s/%s and %s/%s",
				id, existing.Namespace, existing.Name, policy.Namespace, policy.Name)
			return false
		}
		// Same policy, update timestamp
		d.idToPolicy[id] = policy
		return true
	}

	// No collision, register new policy
	d.idToPolicy[id] = policy
	return true
}

// Remove removes a policy from collision tracking
func (d *PolicyIDCollisionDetector) Remove(id uint32) {
	delete(d.idToPolicy, id)
}

// GetPolicy retrieves policy info by ID
func (d *PolicyIDCollisionDetector) GetPolicy(id uint32) (PolicyInfo, bool) {
	policy, exists := d.idToPolicy[id]
	return policy, exists
}
