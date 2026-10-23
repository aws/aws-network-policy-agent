package discovery

import (
	"fmt"
	"net"
	"os"
)

// kubelet injects the kube-dns Service IP into the node agent through this service link variable.
const kubeDNSServiceHostEnv = "KUBE_DNS_SERVICE_HOST"

// ResolveDNSPolicyUpstream reports whether DNS policy can run on this node and, if it can, the
// address its proxy forwards queries to. It returns a reason to log whenever DNS policy is unavailable.
//
// DNS policy is IPv4 only for now, and it needs the address of the cluster DNS service. When
// either is missing the agent keeps enforcing everything else instead of failing: it serves the
// socket the CNI plugin calls on every pod setup, so exiting here would stop new pods from
// starting on the node. The controllers then skip domainName entries, as before DNS policy
// support, and an operator sees the reason in the agent log.
func ResolveDNSPolicyUpstream(enableIPv6 bool) (upstreamIP net.IP, available bool, reason string) {
	if enableIPv6 {
		return nil, false, "DNS policy is not supported on IPv6 clusters"
	}
	upstreamIP, err := getKubeDNSServiceIP(os.Getenv)
	if err != nil {
		return nil, false, fmt.Sprintf("the upstream DNS server could not be discovered: %v", err)
	}
	return upstreamIP, true, ""
}

func getKubeDNSServiceIP(getenv func(string) string) (net.IP, error) {
	value := getenv(kubeDNSServiceHostEnv)
	if value == "" {
		return nil, fmt.Errorf("%s is not set: kubelet sets it only when the kube-dns Service exists in the node agent's namespace "+
			"when the container starts, and the pod does not disable enableServiceLinks", kubeDNSServiceHostEnv)
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("%s=%q is not an IPv4 address", kubeDNSServiceHostEnv, value)
	}
	return ip, nil
}
