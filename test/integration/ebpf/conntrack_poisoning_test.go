package ebpf

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*
Conntrack Poisoning Security Test

Validates that the ifindex-scoped conntrack key prevents cross-pod conntrack
map poisoning via AF_PACKET (CAP_NET_RAW). The attack sends a spoofed L2 frame
with src_ip=victim to write a conntrack entry on the attacker's veth. On ingress
to the victim, the reverse-flow lookup now includes skb->ifindex which won't match
the attacker's veth ifindex, so the poisoned entry is never found.

Runs on IPv4 and IPv6: both datapaths write the conntrack key with skb->ifindex
and look the reverse flow up with it, so only the forged frame differs by family.
The family comes from the pod IPs, not from the --ip-family flag.
*/
var _ = Describe("Conntrack Poisoning Prevention", func() {

	var (
		victimPod    *v1.Pod
		attackerPod  *v1.Pod
		denyPolicy   *network.NetworkPolicy
		egressPolicy *network.NetworkPolicy
		victimIP     string
		attackerIP   string
	)

	BeforeEach(func() {
		By("Creating victim pod (nginx)")
		victimPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "victim", Namespace: namespace,
				Labels: map[string]string{"app": "victim"},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
					Ports:   []v1.ContainerPort{{ContainerPort: victimPort}},
					Command: []string{"sh", "-c"},
					// printf '%s' rather than printf <conf>: as a format string, the
					// config's \n would be expanded and any % treated as a conversion.
					Args: []string{fmt.Sprintf(
						"printf '%%s' %s > /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'",
						shellQuote(victimConf))},
				}},
			},
		}
		var err error
		victimPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, victimPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		victimIP = victimPod.Status.PodIP
		Expect(victimIP).ToNot(BeEmpty(), "victim pod must have an IP to be attacked")

		By("Creating attacker pod (python with CAP_NET_RAW)")
		attackerPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "attacker", Namespace: namespace,
				Labels: map[string]string{"app": "attacker"},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "attacker", Image: "public.ecr.aws/docker/library/python:3.11-slim",
					// Idle: the pod reports Running as soon as this starts, so anything
					// installed here would still be in flight when the first spec execs.
					Command: []string{"sleep", "infinity"},
					SecurityContext: &v1.SecurityContext{
						Capabilities: &v1.Capabilities{
							Add: []v1.Capability{"NET_RAW"},
						},
					},
				}},
				// Schedule on same node as victim
				Affinity: &v1.Affinity{PodAffinity: &v1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []v1.PodAffinityTerm{{
						LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "victim"}},
						TopologyKey:   "kubernetes.io/hostname",
					}},
				}},
			},
		}
		attackerPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, attackerPod, 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		attackerIP = attackerPod.Status.PodIP
		Expect(attackerIP).ToNot(BeEmpty(), "attacker pod must have an IP to spoof from")
		// A cross-family pair would never share a 5-tuple, so no spec would mean anything.
		Expect(isV6(attackerIP)).To(Equal(isV6(victimIP)),
			"victim and attacker must share an IP family for the poisoned key to line up")

		By("Applying deny-all ingress to victim")
		denyPolicy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all-ingress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "victim"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyPolicy)).To(Succeed())

		By("Applying egress policy to attacker (ensures egress conntrack entries are created)")
		egressPolicy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "attacker-egress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "attacker"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeEgress},
				Egress:      []network.NetworkPolicyEgressRule{{}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, egressPolicy)).To(Succeed())

		By("Waiting until the deny-all is enforced")
		// Polled, not slept past: enforcement that lands late would otherwise be
		// indistinguishable from the bypass these specs exist to catch.
		Eventually(func() (string, error) {
			return tryConnect(namespace, "attacker", victimIP, victimPort, 0)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal(blocked),
			"deny-all never took effect on the victim")
	})

	AfterEach(func() {
		if denyPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, denyPolicy)
		}
		if egressPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, egressPolicy)
		}
		if victimPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, victimPod)
		}
		if attackerPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, attackerPod)
		}
	})

	It("should block conntrack poisoning via AF_PACKET [Security][CVE]", func() {
		By("Sending spoofed AF_PACKET frame to poison conntrack map")
		Eventually(func() (string, error) {
			return sendPoison(namespace, "attacker", victimIP, attackerIP, victimPort, 31337)
		}, utils.ProbeTimeout, utils.ProbeInterval).Should(ContainSubstring("POISON_SENT"))

		By("Verifying exploit is BLOCKED (ifindex mismatch prevents cross-pod lookup)")
		// Consistently, not Eventually: a path that opens for even one probe is the
		// vulnerability, and Eventually would pass on any later probe that closed.
		Consistently(func() (string, error) {
			return tryConnect(namespace, "attacker", victimIP, victimPort, 31337)
		}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal(blocked))
	})

	It("should block multi-port poisoning attempts [Security]", func() {
		for _, port := range poisonPorts {
			// Per port: a frame that never left would pass the check below unattacked.
			Eventually(func() (string, error) {
				return sendPoison(namespace, "attacker", victimIP, attackerIP, port, 40000+port)
			}, utils.ProbeTimeout, utils.ProbeInterval).Should(ContainSubstring("POISON_SENT"),
				fmt.Sprintf("port %d poison not sent", port))
			Consistently(func() (string, error) {
				return tryConnect(namespace, "attacker", victimIP, port, 40000+port)
			}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal(blocked),
				fmt.Sprintf("port %d bypass", port))
		}
	})

	It("should allow legitimate traffic when policy permits [Regression]", func() {
		allowPolicy := &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-attacker", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "victim"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					From: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "attacker"}},
					}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, allowPolicy)).To(Succeed())
		Eventually(func() (string, error) {
			return tryConnect(namespace, "attacker", victimIP, victimPort, 0)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal(connected))
		fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, allowPolicy)
	})
})

const (
	// The port the single-flow specs use.
	victimPort = 80

	// Not PodManager.TCPProbe's OPEN/CLOSE: nc cannot bind a source port, and these
	// probes must leave from the port named in the forged frame.
	connected = "CONNECTED"
	blocked   = "BLOCKED"

	execAttempts = 3
)

// Every port the specs attack, so a BLOCKED verdict always means policy denied a
// port that was being served. A port with nothing behind it would report BLOCKED
// whatever the datapath did.
var poisonPorts = []int{victimPort, 443, 8080, 3306}

// Generated from poisonPorts so the two cannot drift, and listening on both families
// because the stock image's `listen 80;` binds IPv4 alone: on an IPv6 cluster every
// connection would be refused and the security specs would pass unconsulted.
var victimConf = "server { " + listenDirectives() + `location / { return 200 "ok\n"; } }`

func listenDirectives() string {
	directives := make([]string, 0, len(poisonPorts))
	for _, p := range poisonPorts {
		directives = append(directives, fmt.Sprintf("listen %d; listen [::]:%d;", p, p))
	}
	return strings.Join(directives, " ") + " "
}

func isV6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// tryConnect connects from pod to ip:port, optionally from a fixed source port so the
// caller can line the connection up with a poisoned conntrack entry.
func tryConnect(ns, pod, ip string, port, srcPort int) (string, error) {
	family, anyAddr := "AF_INET", "0.0.0.0"
	if isV6(ip) {
		family, anyAddr = "AF_INET6", "::"
	}
	bind := ""
	if srcPort > 0 {
		// SO_REUSEADDR: a probe that connected leaves the port in TIME_WAIT, and
		// Consistently reuses it on the next poll.
		bind = fmt.Sprintf("s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('%s',%d));", anyAddr, srcPort)
	}
	script := fmt.Sprintf(`import socket;s=socket.socket(socket.%s,socket.SOCK_STREAM);s.settimeout(3);%s
try:
 s.connect(('%s',%d));s.send(b'GET / HTTP/1.0\r\n\r\n');s.recv(512);print('CONNECTED')
except:
 print('BLOCKED')
finally:
 s.close()`, family, bind, ip, port)
	out, err := execInPod(ns, pod, "tryConnect", script)
	if err != nil {
		return "", err
	}
	if strings.Contains(out, connected) {
		return connected, nil
	}
	return blocked, nil
}

// sendPoison sends a spoofed AF_PACKET frame: src=victimIP:vPort -> dst=attackerIP:aPort.
// On the attacker's egress TC, this creates a conntrack entry:
//
//	key={src=victimIP, port=vPort, dst=attackerIP, port=aPort, owner=victimIP, ifindex=attacker_veth}
//
// When the attacker later connects to victimIP:vPort from aPort, the victim's ingress
// builds a reverse-flow key with ifindex=victim_veth. Since attacker_veth != victim_veth,
// the poisoned entry is never found and policy evaluation proceeds normally (denied).
func sendPoison(ns, pod, victimIP, attackerIP string, vPort, aPort int) (string, error) {
	return execInPod(ns, pod, "sendPoison", poisonScript(victimIP, attackerIP, vPort, aPort))
}

// execInPod retries the exec itself: it reaches the kubelet through the apiserver and
// fails transiently, and a Consistently that read that as a verdict would report a
// bypass that never happened.
func execInPod(ns, pod, what, script string) (string, error) {
	var out string
	var err error
	for attempt := 1; attempt <= execAttempts; attempt++ {
		out, err = fw.PodManager.ExecInPod(ns, pod, []string{"python3", "-c", script})
		if err == nil {
			return out, nil
		}
		GinkgoWriter.Printf("%s exec attempt %d/%d failed: %v\n", what, attempt, execAttempts, err)
		time.Sleep(utils.PollIntervalShort)
	}
	return "", err
}

// Both scripts leave the TCP header unchecksummed, since the datapath keys on the
// 5-tuple; IPv4 packs twice only to fill its own header checksum.
//
// The interface is the family's default-route device from /proc, so no image needs
// iproute2, and the MAC comes from sysfs rather than an AF_INET ioctl that assumes an
// IPv4 stack. Taking the sole non-lo interface would be wrong: pods on an IPv6 cluster
// also carry the egress-CNI's v4if0.
const poisonV4Script = `import socket,struct
iface=next(f[0] for f in (l.split() for l in open('/proc/net/route')) if f[1]=='00000000')
sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));sock.bind((iface,0))
mac=bytes.fromhex(open('/sys/class/net/'+iface+'/address').read().strip().replace(':',''))
eth=b'\xff\xff\xff\xff\xff\xff'+mac+b'\x08\x00'
src=socket.inet_pton(socket.AF_INET,'%[1]s');dst=socket.inet_pton(socket.AF_INET,'%[2]s')
def cksum(d):
 if len(d)&1:d+=b'\x00'
 s=sum(struct.unpack('!'+str(len(d)//2)+'H',d));s=(s>>16)+(s&0xffff);s+=s>>16
 return ~s&0xffff
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x1234,0,64,6,0,src,dst)
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x1234,0,64,6,cksum(ip),src,dst)
tcp=struct.pack('!HHLLBBHHH',%[3]d,%[4]d,0,0,5<<4,0x12,65535,0,0)
sock.send(eth+ip+tcp);print('POISON_SENT');sock.close()`

// 6<<28 is version 6 with zero traffic class and flow label; then payload length 20
// (the TCP header alone), next header 6, hop limit 64. lo is skipped as it carries a
// ::/0 route of its own.
const poisonV6Script = `import socket,struct
iface=next(f[-1] for f in (l.split() for l in open('/proc/net/ipv6_route')) if f[0]=='0'*32 and f[1]=='00' and f[-1]!='lo')
sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86DD));sock.bind((iface,0))
mac=bytes.fromhex(open('/sys/class/net/'+iface+'/address').read().strip().replace(':',''))
eth=b'\xff\xff\xff\xff\xff\xff'+mac+b'\x86\xdd'
src=socket.inet_pton(socket.AF_INET6,'%[1]s');dst=socket.inet_pton(socket.AF_INET6,'%[2]s')
ip=struct.pack('!IHBB16s16s',6<<28,20,6,64,src,dst)
tcp=struct.pack('!HHLLBBHHH',%[3]d,%[4]d,0,0,5<<4,0x12,65535,0,0)
sock.send(eth+ip+tcp);print('POISON_SENT');sock.close()`

func poisonScript(victimIP, attackerIP string, vPort, aPort int) string {
	script := poisonV4Script
	if isV6(victimIP) {
		script = poisonV6Script
	}
	return fmt.Sprintf(script, victimIP, attackerIP, vPort, aPort)
}
