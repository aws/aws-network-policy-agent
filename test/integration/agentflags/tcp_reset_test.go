package agentflags

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	pkgutils "github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*
TCP Reset on Deny

With --enable-tcp-reset-on-deny the server pod's ingress program answers a TCP
SYN that policy denies with a RST, which the client sees as "connection
refused". Without the flag the SYN is dropped and the client's connect times
out. The kernel test (pkg/ebpf) checks the RST's bytes; these specs check what
it can't: that the RST reaches a client on the same node, on another node and
through a ClusterIP Service, that the flag reaches programs pods already run,
and that the server's own egress policy neither blocks the RST nor lets the
client's retries in.

The flag is set on the aws-node DaemonSet, so each change is a rollout. The
specs run in order and share one deny policy: flag off, on, then off again.
*/
var _ = Describe("TCP Reset on Deny", Ordered, func() {

	var (
		checkPod        *v1.Pod
		serverPod       *v1.Pod
		sameNodeClient  *v1.Pod
		otherNodeClient *v1.Pod
		allowedClient   *v1.Pod
		serverIP        string
		serverVIP       string
		originalArgs    []string
	)

	BeforeAll(func() {
		originalArgs = agentArgs()
		// Registered first, so it runs after the pods and policies are gone,
		// and the flag never leaks into the specs that run after these.
		DeferCleanup(func() {
			By("Restoring the agent's original args")
			setAgentArgs(originalArgs)
		})

		nodes, err := utils.SchedulableNodes(ctx, fw.K8sClient)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodes)).To(BeNumerically(">=", 2), "a client on another node than the server needs two nodes")
		serverNode, otherNode := nodes[0], nodes[1]

		By("Creating the pods: the server and a client on node " + serverNode + ", two clients on node " + otherNode)
		check := utils.BuildBPFCheckPod(namespace, serverNode)
		// The specs span two agent rollouts, longer than the default sleep.
		check.Spec.Containers[0].Command = []string{"sleep", "1800"}
		checkPod = createPod(check)
		serverPod = createDeployment(rstDeployment("rst-server", "rst-server", serverNode))
		serverIP = serverPod.Status.PodIP
		sameNodeClient = createDeployment(rstDeployment("rst-same", "rst-client", serverNode))
		otherNodeClient = createDeployment(rstDeployment("rst-other", "rst-client", otherNode))
		allowedClient = createDeployment(rstDeployment("rst-allowed", "rst-allowed", otherNode))

		By("Creating a ClusterIP Service for the server")
		svc, err := fw.ServiceManager.CreateService(ctx, &v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "rst-server", Namespace: namespace},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{"app": "rst-server"},
				Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: rstServicePort,
					TargetPort: intstr.FromInt(rstServerPort)}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(fw.ServiceManager.DeleteService(ctx, svc)).To(Succeed()) })
		serverVIP = svc.Spec.ClusterIP
		Expect(serverVIP).ToNot(BeEmpty())

		By("Applying the server's ingress policy: from the allowed client only")
		createPolicy(&network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "rst-server-ingress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "rst-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					From: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "rst-allowed"}},
					}},
				}},
			},
		})
	})

	It("times a denied connection out with the flag off", func() {
		// Also waits for the policy to take effect: the client connects until then.
		Eventually(func() ([]string, error) {
			return connectResults(otherNodeClient.Name, serverIP, rstServerPort, 0, 1)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal([]string{timedOut}))
	})

	It("applies the flag to the programs pods already run", func() {
		identifier := pkgutils.GetPodIdentifier(serverPod.Name, namespace)
		before := podProgIDs(checkPod.Name, identifier)
		GinkgoWriter.Printf("server's programs before the flag change: %v\n", before)
		Expect(before).ToNot(BeEmpty(), "no programs found for %s", identifier)

		By("Turning the flag on")
		setAgentArgs(withTCPResetOnDeny(originalArgs))

		// The agent writes the flag into a map the programs share, and only
		// recovering that map at startup, instead of creating a new one,
		// reaches programs it doesn't reload. Unchanged program IDs show it
		// didn't reload them; the refused connects in the next spec show the
		// flag reached them.
		Expect(podProgIDs(checkPod.Name, identifier)).To(Equal(before), "the agent reloaded the server's programs")
		// The agent container has no readiness probe, so the rollout can finish
		// before the new agent has logged its startup.
		Eventually(func() string { return agentLogSinceStart(checkPod.Name, sharedMapsRecovered) },
			utils.ProbeTimeout, utils.PollIntervalShort).Should(ContainSubstring(sharedMapsRecovered))
	})

	It("refuses a denied connection from the same node, another node and a ClusterIP", func() {
		// Several connects from one source port: had the RST recorded a flow,
		// the client's next SYN would match it as a reply and be let in.
		for _, client := range []*v1.Pod{sameNodeClient, otherNodeClient} {
			Expect(connectResults(client.Name, serverIP, rstServerPort, rstSrcPort, sameTupleTries)).
				To(Equal(repeated(refused, sameTupleTries)), "from %s on %s", client.Name, client.Spec.NodeName)
		}
		// The RST leaves the pod with the pod's address, and the host's
		// conntrack must rewrite it to the Service's for the client to match it.
		Expect(connectResults(otherNodeClient.Name, serverVIP, rstServicePort, 0, 1)).To(Equal([]string{refused}))
	})

	It("still connects allowed traffic", func() {
		Expect(connectResults(allowedClient.Name, serverIP, rstServerPort, 0, 1)).To(Equal([]string{connected}))
	})

	It("keeps a denied client out after a burst of SYNs on one tuple", func() {
		// Back-to-back SYNs on one tuple are denied before the first RST
		// reaches the server's egress program, so some RSTs find no pending
		// entry and are evaluated as the server's own. The server's egress
		// allows them here. Had one of them recorded a flow, the connect
		// below would match it as a reply and get in.
		sendSYNBurst(otherNodeClient.Name, serverIP, rstServerPort, burstSrcPort, burstSYNs)
		Expect(connectResults(otherNodeClient.Name, serverIP, rstServerPort, burstSrcPort, 1)).To(Equal([]string{refused}))
	})

	It("gets the RST out of a pod whose egress denies everything", func() {
		createPolicy(&network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "rst-server-egress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "rst-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeEgress},
			},
		})
		// The allowed client serves too, and no policy selects it, so only the
		// server's egress policy can stop this connect.
		Eventually(func() ([]string, error) {
			return connectResults(serverPod.Name, allowedClient.Status.PodIP, rstServerPort, 0, 1)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal([]string{timedOut}),
			"the server's egress policy never took effect")

		Expect(connectResults(otherNodeClient.Name, serverIP, rstServerPort, rstSrcPort, sameTupleTries)).
			To(Equal(repeated(refused, sameTupleTries)))
		// Each RST passes egress on a record its SYN left; the server's own
		// connects have none and stay denied.
		Expect(connectResults(serverPod.Name, allowedClient.Status.PodIP, rstServerPort, 0, 1)).
			To(Equal([]string{timedOut}))
	})

	It("times a denied connection out again with the flag off", func() {
		By("Restoring the agent's original args")
		setAgentArgs(originalArgs)
		Expect(connectResults(otherNodeClient.Name, serverIP, rstServerPort, 0, 1)).To(Equal([]string{timedOut}))
	})
})

const (
	tcpResetOnDenyArg = "--enable-tcp-reset-on-deny"

	// The agent logs this at startup when it kept the shared TC maps it
	// found pinned.
	sharedMapsRecovered = "Recovered the shared TC maps"

	rstServerPort  = 8080
	rstServicePort = 80

	// A fixed source port, so retries reuse the 5-tuple.
	rstSrcPort     = 34569
	sameTupleTries = 3

	// The burst spec's source port, and how many SYNs it sends on it. With a
	// few dozen SYNs sent back to back, several are denied before the first
	// RST reaches egress.
	burstSrcPort = 34570
	burstSYNs    = 64

	// Long enough for a SYN to be answered across nodes, short enough that a
	// dropped SYN costs little.
	connectTimeoutSeconds = 3

	connected = "CONNECTED"
	refused   = "REFUSED"
	timedOut  = "TIMEOUT"

	execAttempts = 3

	// Logged by every agent version at startup. The log outlives the agent,
	// so lines before the last one belong to an earlier agent.
	agentStarted = "Network Policy is enabled, registering controllers"
	npaLog       = "/host/var/log/aws-routed-eni/network-policy-agent.log"
)

// rstDeployment runs one pod on node that serves HTTP on rstServerPort, on
// both families: http.server's dual-stack server accepts IPv4 on an IPv6
// socket. Every pod serves, so the server's egress spec has an allowed
// destination.
func rstDeployment(name, app, node string) *appsv1.Deployment {
	dp := manifest.NewDefaultDeploymentBuilder().
		Name(name).
		Namespace(namespace).
		Replicas(1).
		AddLabel("app", app).
		// Two client Deployments share an app label, so each also selects on
		// its own name: createDeployment finds a Deployment's pod by its
		// selector, and Deployments with overlapping selectors may conflict.
		AddLabel("deployment", name).
		// python as PID 1 ignores SIGTERM.
		TerminationGracePeriod(0).
		Container(v1.Container{
			Name: "server", Image: "public.ecr.aws/docker/library/python:3.11-slim",
			Command: []string{"python3", "-m", "http.server", strconv.Itoa(rstServerPort), "--bind", "::"},
		}).
		Build()
	dp.Spec.Template.Spec.NodeName = node
	return dp
}

// withTCPResetOnDeny returns args with the flag on.
func withTCPResetOnDeny(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, tcpResetOnDenyArg) {
			out = append(out, a)
		}
	}
	return append(out, tcpResetOnDenyArg+"=true")
}

// connectResults connects from pod to ip:port tries times, optionally from a
// fixed source port, and returns how each attempt ended: connected, refused
// (a RST) or timedOut (no answer). The ebpf suite's tryConnect can't be
// used: it reports refused and timed out alike.
func connectResults(pod, ip string, port, srcPort, tries int) ([]string, error) {
	family, anyAddr := "AF_INET", "0.0.0.0"
	if isV6(ip) {
		family, anyAddr = "AF_INET6", "::"
	}
	bind := ""
	if srcPort > 0 {
		// SO_REUSEADDR: a connect that succeeded leaves the port in TIME_WAIT.
		bind = fmt.Sprintf("s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('%s',%d))", anyAddr, srcPort)
	}
	script := fmt.Sprintf(`import socket
for _ in range(%d):
 s=socket.socket(socket.%s,socket.SOCK_STREAM);s.settimeout(%d)
 %s
 try:
  s.connect(('%s',%d));print('%s')
 except ConnectionRefusedError:
  print('%s')
 except TimeoutError:
  print('%s')
 finally:
  s.close()`, tries, family, connectTimeoutSeconds, bind, ip, port, connected, refused, timedOut)
	out, err := execInPod(namespace, pod, "connectResults", script)
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// sendSYNBurst sends count bare SYNs from srcPort to ip:port through a raw
// socket, as fast as the pod can, without waiting for answers. A connecting
// socket sends one SYN per try and waits, so it never overlaps two on one
// tuple. The client's kernel has no socket on srcPort and ignores the RSTs.
func sendSYNBurst(pod, ip string, port, srcPort, count int) {
	family := "AF_INET"
	if isV6(ip) {
		family = "AF_INET6"
	}
	script := fmt.Sprintf(`import socket, struct
fam, dst, dport, sport = socket.%s, '%s', %d, %d
u = socket.socket(fam, socket.SOCK_DGRAM); u.connect((dst, dport)); src = u.getsockname()[0]; u.close()
addrs = socket.inet_pton(fam, src) + socket.inet_pton(fam, dst)
# The TCP checksum covers a pseudo-header, which differs by family (RFC 9293, RFC 8200).
pseudo = addrs + (struct.pack('!BBH', 0, socket.IPPROTO_TCP, 20) if fam == socket.AF_INET else struct.pack('!I3xB', 20, socket.IPPROTO_TCP))
def csum(b):
    s = sum(struct.unpack('!%%dH' %% (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    return ~(s + (s >> 16)) & 0xffff
r = socket.socket(fam, socket.SOCK_RAW, socket.IPPROTO_TCP)
for seq in range(1, %d + 1):
    # 20-byte header, no options: data offset 5, flags SYN, window 64240.
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 5 << 4, 0x02, 64240, 0, 0)
    r.sendto(tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:], (dst, 0))
print('sent')`, family, ip, port, srcPort, count)
	out, err := execInPod(namespace, pod, "sendSYNBurst", script)
	Expect(err).ToNot(HaveOccurred(), "SYN burst from %s", pod)
	Expect(strings.TrimSpace(out)).To(Equal("sent"))
}

func repeated(result string, n int) []string {
	results := make([]string, n)
	for i := range results {
		results[i] = result
	}
	return results
}

// podProgIDs returns the IDs of the programs the agent loaded for the pod
// identifier, by their pin names, on the check pod's node. The agent installs
// its CLI under the same host path on both families.
func podProgIDs(checkPodName, identifier string) map[string]int {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred(), "failed to read the node's BPF programs")
	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata output")
	ids := map[string]int{}
	for pin, id := range state.ProgIDs {
		if strings.HasPrefix(pin, identifier+"_") {
			ids[pin] = id
		}
	}
	return ids
}

// Each suite is its own package, so the helpers below are copies of the ebpf
// suite's, cut to what these specs use, as soak/port-reuse keeps its own
// shellQuote.

// execInPod retries the exec itself: it reaches the kubelet through the
// apiserver and fails transiently, and a spec would read that as a result.
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

func isV6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// agentLogSinceStart returns the agent's log lines from its last startup on
// that contain pattern. Unlike the ebpf suite's copy it doesn't read the
// rotated backups: the specs call it right after a rollout restarted the
// agent, and the log rotates at 200 MB by default (pkg/logger), so the
// startup line is still in the current log.
func agentLogSinceStart(checkPodName, pattern string) string {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"grep", "-h", "-e", agentStarted, "-e", pattern, npaLog})
	Expect(err).ToNot(HaveOccurred(), "failed to read the agent log")
	if i := strings.LastIndex(out, agentStarted); i >= 0 {
		out = out[i:]
	}
	return out
}
