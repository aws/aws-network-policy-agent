package ebpf

import (
	"fmt"
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
*/
var _ = Describe("Conntrack Poisoning Prevention", func() {

	BeforeEach(func() {
		if fw.Options.IpFamily == "IPv6" {
			Skip("IPv4-only test: AF_PACKET poisoning uses IPv4 headers and EtherType 0x0800")
		}
	})

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
					Ports: []v1.ContainerPort{{ContainerPort: 80}},
				}},
			},
		}
		var err error
		victimPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, victimPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		victimIP = victimPod.Status.PodIP

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
		Expect(tryConnect(namespace, "attacker", victimIP, 80, 0)).To(Equal("BLOCKED"))

		By("Sending spoofed AF_PACKET frame to poison conntrack map")
		out := sendPoison(namespace, "attacker", victimIP, attackerIP, 80, 31337)
		Expect(out).To(ContainSubstring("POISON_SENT"))

		By("Verifying exploit is BLOCKED (ifindex mismatch prevents cross-pod lookup)")
		Expect(tryConnect(namespace, "attacker", victimIP, 80, 31337)).To(Equal("BLOCKED"))
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
		Expect(tryConnect(namespace, "attacker", victimIP, 80, 0)).To(Equal("CONNECTED"))
		fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, allowPolicy)
	})
})

func tryConnect(ns, pod, ip string, port, srcPort int) string {
	bind := ""
	if srcPort > 0 {
		bind = fmt.Sprintf("s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',%d));", srcPort)
	}
	script := fmt.Sprintf(`import socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(3);%s
try:
 s.connect(('%s',%d));s.send(b'GET / HTTP/1.0\r\n\r\n');s.recv(512);print('CONNECTED')
except:
 print('BLOCKED')
finally:
 s.close()`, bind, ip, port)
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
	script := fmt.Sprintf(`import socket,struct,fcntl,subprocess
iface=subprocess.check_output(['ip','route','get','1.1.1.1']).decode().split('dev ')[1].split()[0]
sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));sock.bind((iface,0))
s2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
mac=fcntl.ioctl(s2.fileno(),0x8927,struct.pack('256s',iface[:15].encode()))[18:24]
dst=b'\xff\xff\xff\xff\xff\xff'
def ip2b(ip):return bytes(int(x) for x in ip.split('.'))
def cksum(d):
 if len(d)%%2:d+=b'\x00'
 s=sum(struct.unpack('!%%dH'%%(len(d)//2),d));s=(s>>16)+(s&0xffff);s+=s>>16
 return ~s&0xffff
eth=dst+mac+b'\x08\x00'
src=ip2b('%s');dst2=ip2b('%s')
h=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x1234,0,64,6,0,src,dst2)
c=cksum(h);h=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x1234,0,64,6,c,src,dst2)
t=struct.pack('!HHLLBBHHH',%d,%d,0,0,5<<4,0x12,65535,0,0)
sock.send(eth+h+t);print('POISON_SENT');sock.close()`, victimIP, attackerIP, vPort, aPort)
	out, err := fw.PodManager.ExecInPod(ns, pod, []string{"python3", "-c", script})
	Expect(err).ToNot(HaveOccurred(), "sendPoison exec failed")
	return out
}
