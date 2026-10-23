// Package nodeinspect reads node state that pods and the Kubernetes API cannot see: nftables rules and
// conntrack entries in the host network namespace, and BPF maps pinned on the host. Tests use it to check
// how the agent programs a node, not only the connectivity it produces.
package nodeinspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/pod"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	image = "public.ecr.aws/amazonlinux/amazonlinux:2023"
	// The tools run in the container; hostNetwork gives them the host network namespace.
	setup     = "dnf install -y -q nftables conntrack-tools bpftool iproute >/tmp/setup.log 2>&1 && touch /tmp/ready; sleep infinity"
	hostRoot  = "/host"
	mapsDir   = "/sys/fs/bpf/globals/aws/maps/"
	readyWait = 5 * time.Minute

	// DNSRedirectTable is the nftables table the agent uses to redirect pod DNS to its proxy.
	DNSRedirectTable = "dns_redirect"
	// ProxyListenerPort is the port of the agent's DNS proxy listener.
	ProxyListenerPort = 50052
)

// Inspector runs commands in a privileged host-network pod on one node.
type Inspector struct {
	pods      pod.Manager
	namespace string
	name      string
}

// Start creates the inspector pod on nodeName and waits until its tools are installed.
func Start(ctx context.Context, pods pod.Manager, namespace, nodeName string) (*Inspector, error) {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	p := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("node-inspect-%d", time.Now().UnixNano()), Namespace: namespace},
		Spec: v1.PodSpec{
			NodeName: nodeName, HostNetwork: true, RestartPolicy: v1.RestartPolicyNever,
			TerminationGracePeriodSeconds: new(int64),
			Containers: []v1.Container{{
				Name: "inspect", Image: image, Command: []string{"/bin/sh", "-c", setup},
				SecurityContext: &v1.SecurityContext{Privileged: &privileged},
				VolumeMounts:    []v1.VolumeMount{{Name: "host-root", MountPath: hostRoot, ReadOnly: true}},
			}},
			Volumes: []v1.Volume{{
				Name:         "host-root",
				VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/", Type: &hostPathDir}},
			}},
		},
	}
	if _, err := pods.CreateAndWaitTillPodIsRunning(ctx, p, readyWait); err != nil {
		return nil, fmt.Errorf("start inspector on %s: %w", nodeName, err)
	}
	i := &Inspector{pods: pods, namespace: namespace, name: p.Name}
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, readyWait, true, func(context.Context) (bool, error) {
		_, err := i.Exec("test", "-f", "/tmp/ready")
		return err == nil, nil
	})
	if err != nil {
		log, _ := i.Exec("cat", "/tmp/setup.log")
		return nil, fmt.Errorf("inspector tools not installed on %s: %w: %s", nodeName, err, log)
	}
	return i, nil
}

// Stop deletes the inspector pod.
func (i *Inspector) Stop(ctx context.Context) error {
	return i.pods.DeleteAndWaitTillPodIsDeleted(ctx, &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: i.name, Namespace: i.namespace}})
}

// Exec runs a command in the inspector pod.
func (i *Inspector) Exec(command ...string) (string, error) {
	return i.pods.ExecInPod(i.namespace, i.name, command)
}

// HostVeth returns the host interface the node routes podIP to.
func (i *Inspector) HostVeth(podIP string) (string, error) {
	out, err := i.Exec("ip", "-o", "route", "get", podIP)
	if err != nil {
		return "", fmt.Errorf("route to %s: %w", podIP, err)
	}
	return parseRouteDev(out)
}

// DNSRedirectInterfaces returns the interfaces that have a DNS redirection rule, or none when the
// table does not exist.
func (i *Inspector) DNSRedirectInterfaces() ([]string, error) {
	out, err := i.Exec("nft", "list", "table", "ip", DNSRedirectTable)
	if err != nil {
		if strings.Contains(out+err.Error(), "No such file or directory") {
			return nil, nil
		}
		return nil, fmt.Errorf("list nftables table %s: %w: %s", DNSRedirectTable, err, out)
	}
	return parseNftInterfaces(out), nil
}

// DNSQueryRedirected reports whether conntrack shows a DNS query from podIP translated to the proxy.
func (i *Inspector) DNSQueryRedirected(podIP string) (bool, error) {
	out, err := i.Exec("conntrack", "-L", "-p", "udp", "--orig-src", podIP, "--orig-port-dst", "53")
	if err != nil {
		return false, fmt.Errorf("conntrack for %s: %w: %s", podIP, err, out)
	}
	return strings.Contains(out, "sport="+strconv.Itoa(ProxyListenerPort)), nil
}

// IPCacheEntry is a learned address in a pod identifier's ipcache map.
type IPCacheEntry struct {
	// ExpiryNs is the CLOCK_BOOTTIME time, in nanoseconds, after which the entry is ignored.
	ExpiryNs uint64
}

// IPCache returns the entries of podIdentifier's ipcache map by IPv4 address, or none when the map
// does not exist.
func (i *Inspector) IPCache(podIdentifier string) (map[string]IPCacheEntry, error) {
	path := hostRoot + mapsDir + podIdentifier + "_ipcache_map"
	if _, err := i.Exec("test", "-e", path); err != nil {
		return nil, nil
	}
	out, err := i.Exec("bpftool", "-j", "map", "dump", "pinned", path)
	if err != nil {
		return nil, fmt.Errorf("dump %s: %w: %s", path, err, out)
	}
	return parseIPCacheDump(out)
}

// BootTimeNs returns the node's CLOCK_BOOTTIME, the clock ipcache expiry times use.
func (i *Inspector) BootTimeNs() (uint64, error) {
	out, err := i.Exec("cat", "/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0, fmt.Errorf("unexpected /proc/uptime %q", out)
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/uptime %q: %w", out, err)
	}
	return uint64(seconds * 1e9), nil
}

func parseRouteDev(out string) (string, error) {
	fields := strings.Fields(out)
	for k := 0; k+1 < len(fields); k++ {
		if fields[k] == "dev" {
			return fields[k+1], nil
		}
	}
	return "", fmt.Errorf("no device in route %q", out)
}

// parseNftInterfaces returns the interface names of `iifname "<name>"` matches. The agent matches the
// name as a prefix, which nft prints with a trailing `*`.
func parseNftInterfaces(out string) []string {
	var names []string
	seen := map[string]bool{}
	for _, field := range strings.Fields(out) {
		if !strings.HasPrefix(field, `"`) {
			continue
		}
		name := strings.TrimSuffix(strings.Trim(field, `"`), "*")
		if name != "" && !seen[name] && strings.Contains(out, `iifname `+field) {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// parseIPCacheDump parses `bpftool -j map dump` of an ipcache map without BTF: the key is the IPv4
// address in network byte order, and the value starts with the expiry time as a little-endian uint64.
func parseIPCacheDump(out string) (map[string]IPCacheEntry, error) {
	var dump []struct {
		Key   []string `json:"key"`
		Value []string `json:"value"`
	}
	if err := json.Unmarshal([]byte(out), &dump); err != nil {
		return nil, fmt.Errorf("parse ipcache dump: %w", err)
	}
	entries := make(map[string]IPCacheEntry, len(dump))
	for _, e := range dump {
		key, err := hexBytes(e.Key)
		if err != nil || len(key) != net.IPv4len {
			return nil, fmt.Errorf("unexpected ipcache key %v", e.Key)
		}
		value, err := hexBytes(e.Value)
		if err != nil || len(value) < 8 {
			return nil, fmt.Errorf("unexpected ipcache value %v", e.Value)
		}
		var expiry uint64
		for b := 7; b >= 0; b-- {
			expiry = expiry<<8 | uint64(value[b])
		}
		entries[net.IP(key).String()] = IPCacheEntry{ExpiryNs: expiry}
	}
	return entries, nil
}

func hexBytes(in []string) ([]byte, error) {
	out := make([]byte, len(in))
	for k, h := range in {
		v, err := strconv.ParseUint(strings.TrimPrefix(h, "0x"), 16, 8)
		if err != nil {
			return nil, err
		}
		out[k] = byte(v)
	}
	return out, nil
}
