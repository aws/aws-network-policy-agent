package ebpf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*
ICMPv6 behind a Hop-by-Hop header (#681)

MLD reports carry a Router Alert option, so ip->nexthdr is 0 (Hop-by-Hop) rather than
58. Under a deny-all policy they must still pass like any other ICMPv6, while a
non-ICMPv6 protocol behind the same header must still be denied.

The sender uses IPV6_HOPOPTS so the kernel builds and routes the packet; the receiver
records markers it sees on its interface with an AF_PACKET socket, so "seen" means the
datapath delivered the packet.
*/
var _ = Describe("ICMPv6 behind a Hop-by-Hop header", func() {

	var (
		receiverPod *v1.Pod
		senderPod   *v1.Pod
		receiverIP  string
		policy      *network.NetworkPolicy
	)

	BeforeEach(func() {
		if framework.GlobalOptions.IpFamily != "IPv6" {
			Skip("Hop-by-Hop handling is IPv6 only")
		}

		By("Creating receiver pod")
		var err error
		receiverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx,
			hbhPod("hbh-receiver", []string{"python3", "-c", receiverScript}, nil), 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		receiverIP = receiverPod.Status.PodIP
		Expect(isV6(receiverIP)).To(BeTrue(), "receiver must have an IPv6 address")

		By("Creating sender pod on the same node")
		senderPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx,
			hbhPod("hbh-sender", []string{"sleep", "infinity"}, &v1.Affinity{PodAffinity: &v1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []v1.PodAffinityTerm{{
					LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "hbh-receiver"}},
					TopologyKey:   "kubernetes.io/hostname",
				}},
			}}), 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
			policy = nil
		}
		if senderPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, senderPod)
		}
		if receiverPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, receiverPod)
		}
	})

	enforce := func(app string, policyType network.PolicyType) {
		policy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "hbh-deny-all", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
				PolicyTypes: []network.PolicyType{policyType},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
		Eventually(func() (string, error) {
			return tryConnect(namespace, "hbh-sender", receiverIP, receiverPort, 0)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal(blocked),
			"deny-all never took effect")
	}

	verify := func() {
		By("Plain ICMPv6 passes, so the path and the capture work")
		Eventually(func() (bool, error) {
			return probeDelivered(receiverIP, plainICMPv6)
		}, utils.ProbeTimeout, utils.ProbeInterval).Should(BeTrue())

		By("MLD behind Hop-by-Hop passes")
		Eventually(func() (bool, error) {
			return probeDelivered(receiverIP, hbhMLD)
		}, utils.ProbeTimeout, utils.ProbeInterval).Should(BeTrue())

		By("UDP behind Hop-by-Hop is still denied")
		Consistently(func() (bool, error) {
			return probeDelivered(receiverIP, hbhUDP)
		}, utils.StabilityWindow, utils.ProbeInterval).Should(BeFalse())
	}

	It("allows ICMPv6 behind Hop-by-Hop under deny-all ingress", func() {
		enforce("hbh-receiver", network.PolicyTypeIngress)
		verify()
	})

	It("allows ICMPv6 behind Hop-by-Hop under deny-all egress", func() {
		enforce("hbh-sender", network.PolicyTypeEgress)
		verify()
	})
})

const (
	receiverPort = 80

	plainICMPv6 = "icmp"
	hbhMLD      = "mld"
	hbhUDP      = "udp"
)

func hbhPod(name string, command []string, affinity *v1.Affinity) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels: map[string]string{"app": name},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name: name, Image: "public.ecr.aws/docker/library/python:3.11-slim",
				Command: command,
				SecurityContext: &v1.SecurityContext{
					Capabilities: &v1.Capabilities{Add: []v1.Capability{"NET_RAW"}},
				},
			}},
			Affinity: affinity,
		},
	}
}

// probeDelivered sends one packet of the given kind with a fresh marker and reports
// whether the receiver captured it.
func probeDelivered(receiverIP, kind string) (bool, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return false, err
	}
	marker := hex.EncodeToString(buf)
	if _, err := execInPod(namespace, "hbh-sender", "sendHBH", fmt.Sprintf(senderScript, receiverIP, kind, marker)); err != nil {
		return false, err
	}
	time.Sleep(time.Second)
	out, err := execInPod(namespace, "hbh-receiver", "readSeen",
		`import os;print(open('/tmp/seen').read() if os.path.exists('/tmp/seen') else '')`)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, marker), nil
}

// Serves TCP on receiverPort for the enforcement check and appends every marker seen on
// any interface to /tmp/seen.
const receiverScript = `import socket,threading
def serve():
 s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind(('::',80));s.listen(16)
 while True:
  c,_=s.accept()
  try:c.recv(512);c.send(b'HTTP/1.0 200 OK\r\n\r\nok\n')
  finally:c.close()
threading.Thread(target=serve,daemon=True).start()
r=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86DD))
while True:
 f=r.recv(65535);i=f.find(b'NPAHBH')
 if i>=0:
  with open('/tmp/seen','a') as o:o.write(f[i+6:i+14].decode(errors='replace')+'\n')`

// The Hop-by-Hop header is a Router Alert (MLD) plus PadN; the kernel fills in its
// next-header byte. ICMPv6 checksums are computed by the kernel for raw ICMPv6 sockets.
const senderScript = `import socket,struct
dst,kind,m='%s','%s',b'NPAHBH'+b'%s'
hbh=b'\x00\x00\x05\x02\x00\x00\x01\x00'
if kind=='udp':
 s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
 s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_HOPOPTS,hbh);s.sendto(m,(dst,9999))
else:
 s=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
 if kind=='mld':
  s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_HOPOPTS,hbh);msg=struct.pack('!BBHHH',143,0,0,0,0)
 else:
  msg=struct.pack('!BBHHH',128,0,0,0,0)
 s.sendto(msg+m,(dst,0))
s.close();print('SENT')`
