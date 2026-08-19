package ebpf

import (
	"fmt"
	"net"
	"strings"
	"time"

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

Runs on IPv4 and IPv6 clusters. The datapath is the same shape in both families:
tc.v4egress/tc.v6egress write the conntrack key with skb->ifindex and
tc.v4ingress/tc.v6ingress build the reverse-flow key with it, so the attack and
the assertions carry over unchanged. Only the forged frame differs — EtherType
and L3 header — and every address the specs handle comes from the pods
themselves, so the family is read off those addresses rather than off the
--ip-family flag.
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
					// The stock image's default server block is `listen 80;`, which
					// binds IPv4 only — on an IPv6 cluster every connection to the
					// victim would be refused, so the [Regression] spec would fail and
					// the security specs would report BLOCKED without the datapath
					// having decided anything. This server block listens on both
					// families so the same manifest works either way.
					//
					// printf '%s' rather than printf <conf>: as a format string, the
					// config's \n would be expanded and any future % treated as a
					// conversion. Passing it as an argument writes it verbatim.
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
					Command: []string{"bash", "-c", "apt-get update -qq && apt-get install -y -qq iproute2 >/dev/null 2>&1 && sleep infinity"},
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
		// A cross-family pair would make every spec meaningless: the forged frame
		// and the connection would never share a 5-tuple with each other.
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
		time.Sleep(15 * time.Second)
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
		By("Verifying baseline: deny-all blocks attacker->victim")
		Expect(tryConnect(namespace, "attacker", victimIP, victimPort, 0)).To(Equal("BLOCKED"))

		By("Sending spoofed AF_PACKET frame to poison conntrack map")
		out := sendPoison(namespace, "attacker", victimIP, attackerIP, victimPort, 31337)
		Expect(out).To(ContainSubstring("POISON_SENT"))

		By("Verifying exploit is BLOCKED (ifindex mismatch prevents cross-pod lookup)")
		Expect(tryConnect(namespace, "attacker", victimIP, victimPort, 31337)).To(Equal("BLOCKED"))
	})

	It("should block multi-port poisoning attempts [Security]", func() {
		for _, port := range []int{80, 443, 8080, 3306} {
			sendPoison(namespace, "attacker", victimIP, attackerIP, port, 40000+port)
			result := tryConnect(namespace, "attacker", victimIP, port, 40000+port)
			Expect(result).To(Equal("BLOCKED"), fmt.Sprintf("port %d bypass", port))
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
		time.Sleep(10 * time.Second)
		Expect(tryConnect(namespace, "attacker", victimIP, victimPort, 0)).To(Equal("CONNECTED"))
		fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, allowPolicy)
	})
})

// The one port the victim actually serves on, so it is also the port the
// [Regression] spec expects to reach and the port the nginx config binds in
// both families.
const victimPort = 80

// victimConf listens on both families, see the victim container's Args.
var victimConf = fmt.Sprintf(
	"server { listen %d; listen [::]:%d; location / { return 200 \"ok\\n\"; } }",
	victimPort, victimPort)

// isV6 reports whether addr is an IPv6 address. The family is derived from the
// addresses the pods were actually given rather than from the --ip-family flag:
// if the two disagreed, the forged frame and the connection would be built for
// a family the pods don't run, and every spec would report BLOCKED for the wrong
// reason.
func isV6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// shellQuote wraps s in single quotes for `sh -c`, escaping any embedded quotes,
// so a config can be passed through a shell without the shell reinterpreting it.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// tryConnect opens a TCP connection from pod to ip:port, optionally from a fixed
// source port so the caller can line the connection up with a poisoned conntrack
// entry. The socket family follows the target address, so the same helper works
// in either family.
func tryConnect(ns, pod, ip string, port, srcPort int) string {
	family, anyAddr := "AF_INET", "0.0.0.0"
	if isV6(ip) {
		family, anyAddr = "AF_INET6", "::"
	}
	bind := ""
	if srcPort > 0 {
		bind = fmt.Sprintf("s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('%s',%d));", anyAddr, srcPort)
	}
	script := fmt.Sprintf(`import socket;s=socket.socket(socket.%s,socket.SOCK_STREAM);s.settimeout(3);%s
try:
 s.connect(('%s',%d));s.send(b'GET / HTTP/1.0\r\n\r\n');s.recv(512);print('CONNECTED')
except:
 print('BLOCKED')
finally:
 s.close()`, family, bind, ip, port)
	out, err := fw.PodManager.ExecInPod(ns, pod, []string{"python3", "-c", script})
	Expect(err).ToNot(HaveOccurred(), "tryConnect exec failed")
	if strings.Contains(out, "CONNECTED") {
		return "CONNECTED"
	}
	return "BLOCKED"
}

// sendPoison sends a spoofed AF_PACKET frame: src=victimIP:vPort -> dst=attackerIP:aPort.
// On the attacker's egress TC, this creates a conntrack entry:
//
//	key={src=victimIP, port=vPort, dst=attackerIP, port=aPort, owner=victimIP, ifindex=attacker_veth}
//
// When the attacker later connects to victimIP:vPort from aPort, the victim's ingress
// builds a reverse-flow key with ifindex=victim_veth. Since attacker_veth != victim_veth,
// the poisoned entry is never found and policy evaluation proceeds normally (denied).
func sendPoison(ns, pod, victimIP, attackerIP string, vPort, aPort int) string {
	out, err := fw.PodManager.ExecInPod(ns, pod,
		[]string{"python3", "-c", poisonScript(victimIP, attackerIP, vPort, aPort)})
	Expect(err).ToNot(HaveOccurred(), "sendPoison exec failed")
	return out
}

// poisonFrame forges the frame sendPoison writes to the attacker's veth. Only
// the EtherType and the L3 header vary by family (%[2]s and %[6]s); the TCP
// header and the send are identical, because what the datapath keys on is the
// 5-tuple and not any L4 checksum.
//
// The interface is resolved from the route to the victim rather than from a
// hardcoded off-cluster address so the lookup works in either family, and the
// MAC is read from sysfs rather than through an AF_INET ioctl, which would tie
// the frame to the IPv4 stack in a pod that may only hold an IPv6 address.
const poisonFrame = `import socket,struct,subprocess
iface=subprocess.check_output(['ip','route','get','%[1]s']).decode().split('dev ')[1].split()[0]
sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(%[2]s));sock.bind((iface,0))
mac=bytes.fromhex(open('/sys/class/net/'+iface+'/address').read().strip().replace(':',''))
eth=b'\xff\xff\xff\xff\xff\xff'+mac+%[3]s
src=socket.inet_pton(socket.%[4]s,'%[1]s');dst=socket.inet_pton(socket.%[4]s,'%[5]s')
%[6]s
tcp=struct.pack('!HHLLBBHHH',%[7]d,%[8]d,0,0,5<<4,0x12,65535,0,0)
sock.send(eth+ip+tcp);print('POISON_SENT');sock.close()`

// IPv4: 20-byte header, and its own checksum has to be filled in — pack once to
// checksum over the header, then repack with the result.
const poisonIPv4Hdr = `def cksum(d):
 if len(d)&1:d+=b'\x00'
 s=sum(struct.unpack('!'+str(len(d)//2)+'H',d));s=(s>>16)+(s&0xffff);s+=s>>16
 return ~s&0xffff
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x1234,0,64,6,0,src,dst)
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x1234,0,64,6,cksum(ip),src,dst)`

// IPv6: 40-byte fixed header with no checksum. 6<<28 is version 6 with traffic
// class and flow label zero; then payload length 20 (the TCP header alone), next
// header 6 (TCP) and hop limit 64.
const poisonIPv6Hdr = `ip=struct.pack('!IHBB16s16s',6<<28,20,6,64,src,dst)`

func poisonScript(victimIP, attackerIP string, vPort, aPort int) string {
	ethProto, ethType, family, l3 := "0x0800", `b'\x08\x00'`, "AF_INET", poisonIPv4Hdr
	if isV6(victimIP) {
		ethProto, ethType, family, l3 = "0x86DD", `b'\x86\xdd'`, "AF_INET6", poisonIPv6Hdr
	}
	return fmt.Sprintf(poisonFrame, victimIP, ethProto, ethType, family, attackerIP, l3, vPort, aPort)
}
