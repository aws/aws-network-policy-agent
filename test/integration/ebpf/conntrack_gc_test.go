package ebpf

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*
Conntrack GC

Every half --conntrack-cache-cleanup-period the agent's conntrack GC either
snapshots its BPF conntrack map or, on the next run, deletes the snapshot's
entries that no kernel conntrack flow matches and that the datapath has not
touched since the run started (#746). These specs set the period to 2 s, so an
entry is checked against the kernel every 2 s.

A pod's replies under a deny-all egress policy pass only because of the entry
its ingress program wrote for the connection. If the GC wrongly deletes the
entry of an idle connection, the pod's next packet on it is dropped. So the
server sends first after each idle period: when the client sends first, its
packet is allowed by the ingress policy and writes the entry again, which would
hide the delete.

All pods run on one node, so a connection through a Service has its DNAT flow
in the same kernel table and conntrack map as the server's entry.
*/
var _ = Describe("Conntrack GC", Ordered, func() {

	var (
		checkPod   *v1.Pod
		serverPod  *v1.Pod
		clientPod  *v1.Pod
		hairpinPod *v1.Pod
		serverVIP  string
		hairpinVIP string
	)

	BeforeAll(func() {
		By("Setting the agent's conntrack cleanup period to 2 s")
		original := agentArgs()
		setAgentArgs(withCleanupPeriod(original, gcCleanupPeriod))
		// Registered first, so it runs after the pods and policies are gone.
		DeferCleanup(func() {
			By("Restoring the agent's original args")
			setAgentArgs(original)
		})

		node := agentNode()
		By("Creating the pods on node " + node)
		check := utils.BuildBPFCheckPod(namespace, node)
		check.Spec.Containers[0].Command = []string{"sleep", "1800"}
		// Registered before the wait, so a pod that never starts is still deleted.
		DeferCleanup(func() { Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, check)).To(Succeed()) })
		var err error
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, check, 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		// Each deletion is registered before its create, so a Deployment that never
		// becomes ready is still deleted. It waits for the pod to go, which the
		// args restore registered above relies on.
		serverDeployment := pingerDeployment("gc-server", node)
		DeferCleanup(fw.DeleteDeploymentAndWaitForPodGone, ctx, serverDeployment)
		serverPod = fw.CreateSingleReplicaAndGetPod(ctx, serverDeployment)
		clientDeployment := pingerDeployment("gc-client", node)
		DeferCleanup(fw.DeleteDeploymentAndWaitForPodGone, ctx, clientDeployment)
		clientPod = fw.CreateSingleReplicaAndGetPod(ctx, clientDeployment)
		hairpinDeployment := pingerDeployment("gc-hairpin", node)
		DeferCleanup(fw.DeleteDeploymentAndWaitForPodGone, ctx, hairpinDeployment)
		hairpinPod = fw.CreateSingleReplicaAndGetPod(ctx, hairpinDeployment)

		By("Creating a ClusterIP Service for the server and one for the hairpin pod")
		serverVIP = createService("gc-server")
		hairpinVIP = createService("gc-hairpin")

		By("Applying the server's policy: ingress from the client only, no egress")
		createPolicy(&network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "gc-server", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "gc-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress, network.PolicyTypeEgress},
				Ingress: []network.NetworkPolicyIngressRule{{
					From: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "gc-client"}},
					}},
				}},
			},
		})

		By("Applying the hairpin pod's policy: no ingress, egress to its own Service only")
		// The egress program sees the packet before DNAT, so the rule names the
		// Service IP. With no ingress allowed, the replies the pod gets from its
		// Service pass only because of the entry its egress program wrote.
		tcp, svcPort := v1.ProtocolTCP, intstr.FromInt(gcServicePort)
		createPolicy(&network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "gc-hairpin", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "gc-hairpin"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress, network.PolicyTypeEgress},
				Egress: []network.NetworkPolicyEgressRule{{
					To:    []network.NetworkPolicyPeer{{IPBlock: &network.IPBlock{CIDR: hostCIDR(hairpinVIP)}}},
					Ports: []network.NetworkPolicyPort{{Protocol: &tcp, Port: &svcPort}},
				}},
			},
		})

		By("Waiting until both policies are enforced")
		// Polled rather than slept past: a policy that is not in place yet would let
		// the specs pass without depending on the agent's conntrack entries.
		expectVerdict(serverPod.Name, clientPod.Status.PodIP, gcServerPort, blocked)   // server egress denied
		expectVerdict(clientPod.Name, serverPod.Status.PodIP, gcServerPort, connected) // server ingress allowed
		expectVerdict(clientPod.Name, hairpinPod.Status.PodIP, gcServerPort, blocked)  // hairpin ingress denied
		expectVerdict(hairpinPod.Name, hairpinVIP, gcServicePort, connected)           // hairpin egress allowed
	})

	It("keeps busy and idle connections working through GC cycles [ConntrackGC]", func() {
		serverIP := serverPod.Status.PodIP
		By("Holding connections to the server's pod IP and its Service, busy and idle")
		startHolder(clientPod.Name, []holdSpec{
			{"direct-busy", serverIP, gcServerPort, busyEvery},
			{"direct-idle", serverIP, gcServerPort, idleEvery},
			{"service-busy", serverVIP, gcServicePort, busyEvery},
			{"service-idle", serverVIP, gcServicePort, idleEvery},
		})

		By(fmt.Sprintf("Waiting for the server to reach the idle connections after %d s", idleEvery))
		Eventually(func() []int {
			states := holderStates(clientPod.Name)
			return []int{states["direct-idle"].roundTrips, states["service-idle"].roundTrips}
		}, idleEvery*time.Second+30*time.Second, utils.PollIntervalShort).Should(HaveEach(BeNumerically(">=", 1)),
			"an idle connection made no round trip after the server's first packet")

		By("Checking that the busy connections are still exchanging data")
		states := holderStates(clientPod.Name)
		GinkgoWriter.Printf("held connections: %+v\n", states)
		for _, name := range []string{"direct-busy", "service-busy"} {
			Expect(states[name].closed).To(BeFalse(), "%s closed", name)
			// A stalled connection stops counting round trips. A floor on the
			// count would also fail when a loaded node or API server delays
			// the pings or the log reads, so wait for the count to grow instead.
			Eventually(func() int { return holderStates(clientPod.Name)[name].roundTrips },
				30*time.Second, utils.PollIntervalShort).Should(BeNumerically(">", states[name].roundTrips), "%s stalled", name)
		}
	})

	It("removes the entries of reset connections and keeps those of open ones [ConntrackGC]", func() {
		clientIP, serverIP := clientPod.Status.PodIP, serverPod.Status.PodIP

		By("Opening connections to the pod IP and the Service and closing them with a reset")
		// A reset moves the kernel entry to CLOSE, which expires in 10 s
		// (nf_conntrack_tcp_timeout_close), where a FIN would leave it in TIME_WAIT
		// for 120 s.
		resetPorts := resetConnections(clientPod.Name, []string{
			net.JoinHostPort(serverIP, strconv.Itoa(gcServerPort)),
			net.JoinHostPort(serverVIP, strconv.Itoa(gcServicePort)),
		})
		// Seen right after the reset, so finding none later means the GC removed them.
		keys := conntrackMapKeys(checkPod.Name)
		for _, port := range resetPorts {
			Expect(keysOfClientPort(keys, clientIP, port)).ToNot(BeEmpty(),
				"no conntrack map entry for the reset connection from port %d", port)
		}

		By("Waiting for the GC to remove the reset connections' entries")
		Eventually(func() []ctMapKey {
			keys := conntrackMapKeys(checkPod.Name)
			var left []ctMapKey
			for _, port := range resetPorts {
				left = append(left, keysOfClientPort(keys, clientIP, port)...)
			}
			return left
		}, time.Minute, utils.PollIntervalShort).Should(BeEmpty())

		By("Checking that the idle connections from the previous spec still have the server's entry")
		// This is the entry the server's replies depend on.
		states := holderStates(clientPod.Name)
		keys = conntrackMapKeys(checkPod.Name)
		for _, name := range []string{"direct-idle", "service-idle"} {
			Expect(states[name].closed).To(BeFalse(), "%s closed", name)
			want := ctMapKey{src: net.ParseIP(clientIP), sport: states[name].sport,
				dst: net.ParseIP(serverIP), dport: gcServerPort, owner: net.ParseIP(serverIP)}
			Expect(keys).To(ContainElement(want), "%s lost the server's entry", name)
		}
	})

	It("keeps a pod's idle connection to its own Service working [ConntrackGC][Hairpin]", func() {
		// The Service's only backend is the pod itself, so kube-proxy rewrites both
		// the destination and the source (to a node address) of the connection.
		hairpinIP := hairpinPod.Status.PodIP
		By("Holding an idle connection from the hairpin pod to its own Service")
		startHolder(hairpinPod.Name, []holdSpec{{"hairpin", hairpinVIP, gcServicePort, hairpinIdleEvery}})
		var sport int
		Eventually(func() int {
			sport = holderStates(hairpinPod.Name)["hairpin"].sport
			return sport
		}, utils.ProbeTimeout, utils.PollIntervalShort).ShouldNot(BeZero())
		GinkgoWriter.Printf("hairpin entries after connecting:\n%s", hairpinKeys(checkPod.Name, hairpinIP, sport))

		By("Waiting for the pod's server side to send first on the idle connection")
		Eventually(func() int { return holderStates(hairpinPod.Name)["hairpin"].roundTrips },
			hairpinIdleEvery*time.Second+30*time.Second, utils.PollIntervalShort).Should(BeNumerically(">=", 1),
			"the hairpin connection made no round trip after %d s idle", hairpinIdleEvery)
	})
})

const (
	// The agent container in the aws-node DaemonSet, and the flag the specs set.
	agentDaemonSet   = "aws-node"
	agentNamespace   = "kube-system"
	agentContainer   = "aws-eks-nodeagent"
	cleanupPeriodArg = "--conntrack-cache-cleanup-period"
	gcCleanupPeriod  = 2 // seconds, so a compare run every 2 s
	rolloutTimeout   = 10 * time.Minute

	// The pinger's port, and the port its Services expose.
	gcServerPort  = 8080
	gcServicePort = 80

	// Seconds the server waits between pings on a connection.
	busyEvery        = 1
	idleEvery        = 60 // about 30 compare runs
	hairpinIdleEvery = 20 // about 10 compare runs

	holderLog = "/tmp/holder.log"
	cliPath   = "/opt/cni/bin/aws-eks-na-cli"
)

// pingServer runs in every pod. Per connection it reads how many seconds to
// wait between pings, then loops: wait, send "ping", expect "pong", send "ok".
// So after each wait the server sends first, and "ok" reaching the client shows
// data went both ways. A first line that is not a number, such as tryConnect's
// probe, gets a reply, and the server then reads until the client closes:
// closing with unread data would send a reset, which tryConnect reports as
// BLOCKED.
const pingServer = `import os, socket, threading, time
def serve(c):
    with c, c.makefile('rwb', buffering=0) as f:
        try:
            line = f.readline()
            if not line.strip().isdigit():
                f.write(b'?\n')
                while f.read(512):
                    pass
                return
            while True:
                time.sleep(int(line))
                f.write(b'ping\n')
                if f.readline() != b'pong\n':
                    return
                f.write(b'ok\n')
        except OSError:
            pass
family = socket.AF_INET6 if ':' in os.environ['POD_IP'] else socket.AF_INET
server = socket.create_server(('', %d), family=family, backlog=64)
while True:
    threading.Thread(target=serve, args=(server.accept()[0],), daemon=True).start()
`

// holderScript holds one connection per argument "name,ip,port,every" and
// answers the server's pings on it. It logs "<name> sport <port>" once
// connected, "<name> roundtrips <n>" after each round trip, and "<name> closed"
// if the connection ends.
const holderScript = `import socket, sys, threading
lock = threading.Lock()
def log(*a):
    with lock:
        print(*a, flush=True)
def hold(name, ip, port, every):
    s = socket.create_connection((ip, int(port)))
    f = s.makefile('rwb', buffering=0)
    f.write(every.encode() + b'\n')
    log(name, 'sport', s.getsockname()[1])
    n = 0
    while f.readline() == b'ping\n':
        f.write(b'pong\n')
        if f.readline() != b'ok\n':
            break
        n += 1
        log(name, 'roundtrips', n)
    log(name, 'closed')
for arg in sys.argv[1:]:
    threading.Thread(target=hold, args=arg.split(',')).start()
`

// resetScript connects to each "ip port" argument pair, prints the local port
// and closes the connection with a reset (SO_LINGER with a zero timeout).
const resetScript = `import socket, struct, sys
args = sys.argv[1:]
for ip, port in zip(args[::2], args[1::2]):
    s = socket.create_connection((ip, int(port)), timeout=5)
    print(s.getsockname()[1])
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    s.close()
`

// pingerDeployment returns a single-replica Deployment that runs pingServer on
// node, with its pod labeled app=name.
func pingerDeployment(name, node string) *appsv1.Deployment {
	dp := manifest.NewDefaultDeploymentBuilder().
		Namespace(namespace).
		Name(name).
		Replicas(1).
		AddLabel("app", name).
		TerminationGracePeriod(0). // python as PID 1 ignores SIGTERM
		Container(v1.Container{
			Name: "pinger", Image: utils.PythonImage,
			Command: []string{"python3", "-c", fmt.Sprintf(pingServer, gcServerPort)},
			Env: []v1.EnvVar{{Name: "POD_IP", ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "status.podIP"}}}},
		}).
		Build()
	dp.Spec.Template.Spec.NodeName = node
	return dp
}

// createService creates a ClusterIP Service named app for the pods labeled
// app=app and returns its IP.
func createService(app string) string {
	svc, err := fw.ServiceManager.CreateService(ctx, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{"app": app},
			Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: gcServicePort,
				TargetPort: intstr.FromInt(gcServerPort)}},
		},
	})
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() { Expect(fw.ServiceManager.DeleteService(ctx, svc)).To(Succeed()) })
	Expect(svc.Spec.ClusterIP).ToNot(BeEmpty())
	return svc.Spec.ClusterIP
}

func createPolicy(policy *network.NetworkPolicy) {
	Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
	DeferCleanup(func() { Expect(fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)).To(Succeed()) })
}

func expectVerdict(fromPod, ip string, port int, want string) {
	Eventually(func() (string, error) {
		return tryConnect(namespace, fromPod, ip, port, 0)
	}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal(want),
		"%s to %s:%d never became %s", fromPod, ip, port, want)
}

func hostCIDR(ip string) string {
	if isV6(ip) {
		return ip + "/128"
	}
	return ip + "/32"
}

type holdSpec struct {
	name  string
	ip    string
	port  int
	every int // seconds
}

// startHolder runs holderScript in the background in pod, logging to holderLog.
func startHolder(pod string, conns []holdSpec) {
	args := make([]string, 0, len(conns))
	for _, c := range conns {
		args = append(args, shellQuote(fmt.Sprintf("%s,%s,%d,%d", c.name, c.ip, c.port, c.every)))
	}
	cmd := fmt.Sprintf("nohup python3 -c %s %s > %s 2>&1 &", shellQuote(holderScript), strings.Join(args, " "), holderLog)
	_, err := fw.PodManager.ExecInPod(namespace, pod, []string{"sh", "-c", cmd})
	Expect(err).ToNot(HaveOccurred())
}

type holdState struct {
	sport      int
	roundTrips int
	closed     bool
}

// holderStates reads the holder's log in pod, per connection name.
func holderStates(pod string) map[string]holdState {
	out, err := fw.PodManager.ExecInPod(namespace, pod, []string{"cat", holderLog})
	Expect(err).ToNot(HaveOccurred())
	states := map[string]holdState{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		s := states[f[0]]
		switch {
		case len(f) == 3 && f[1] == "sport":
			s.sport, _ = strconv.Atoi(f[2])
		case len(f) == 3 && f[1] == "roundtrips":
			s.roundTrips, _ = strconv.Atoi(f[2])
		case len(f) == 2 && f[1] == "closed":
			s.closed = true
		default:
			Fail("unexpected line in the holder's log: " + line)
		}
		states[f[0]] = s
	}
	return states
}

// resetConnections runs resetScript from pod to each host:port and returns
// the local ports it used.
func resetConnections(pod string, targets []string) []int {
	args := []string{"python3", "-c", resetScript}
	for _, t := range targets {
		host, port, err := net.SplitHostPort(t)
		Expect(err).ToNot(HaveOccurred())
		args = append(args, host, port)
	}
	out, err := fw.PodManager.ExecInPod(namespace, pod, args)
	Expect(err).ToNot(HaveOccurred())
	var ports []int
	for _, f := range strings.Fields(out) {
		port, err := strconv.Atoi(f)
		Expect(err).ToNot(HaveOccurred(), "unexpected output from the reset script: %s", out)
		ports = append(ports, port)
	}
	Expect(ports).To(HaveLen(len(targets)))
	return ports
}

// ctMapKey is an entry key of the agent's conntrack map, without ifindex.
type ctMapKey struct {
	src   net.IP
	sport int
	dst   net.IP
	dport int
	owner net.IP
}

// For example:
//
//	Conntrack Key : Source IP - 10.0.1.5 Source port - 34567 Dest IP - 10.0.1.7 Dest port - 8080 Protocol - 6 Owner IP - 10.0.1.7 Ifindex - 12
var ctMapKeyLine = regexp.MustCompile(`Conntrack Key : Source IP - (\S+) Source port - (\d+) Dest IP - (\S+) Dest port - (\d+) Protocol - \d+ Owner IP - (\S+) Ifindex`)

// conntrackMapKeys lists the keys of the node's conntrack map with the agent's
// CLI, which the agent installs on the node (the v6 build under the same name).
// The nodes have no bpftool.
func conntrackMapKeys(checkPodName string) []ctMapKey {
	out, err := hostShell(checkPodName, cliPath+" ebpf loaded-ebpfdata")
	Expect(err).ToNot(HaveOccurred())
	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred())
	mapID := state.GlobalMaps["aws_conntrack_map"]
	Expect(mapID).ToNot(BeZero(), "no aws_conntrack_map in loaded-ebpfdata")

	out, err = hostShell(checkPodName, fmt.Sprintf("%s ebpf dump-maps %d", cliPath, mapID))
	Expect(err).ToNot(HaveOccurred())
	var keys []ctMapKey
	for _, m := range ctMapKeyLine.FindAllStringSubmatch(out, -1) {
		sport, _ := strconv.Atoi(m[2])
		dport, _ := strconv.Atoi(m[4])
		keys = append(keys, ctMapKey{src: net.ParseIP(m[1]), sport: sport, dst: net.ParseIP(m[3]), dport: dport, owner: net.ParseIP(m[5])})
	}
	return keys
}

// keysOfClientPort returns the keys of the connections from ip:port, in either
// direction and whatever the other end (a pod or a Service IP).
func keysOfClientPort(keys []ctMapKey, ip string, port int) []ctMapKey {
	addr := net.ParseIP(ip)
	var found []ctMapKey
	for _, k := range keys {
		if (k.src.Equal(addr) && k.sport == port) || (k.dst.Equal(addr) && k.dport == port) {
			found = append(found, k)
		}
	}
	return found
}

// hairpinKeys formats, one per line, the keys of the hairpin connection: those
// from the pod's client port and those to its server port.
func hairpinKeys(checkPodName, ip string, sport int) string {
	addr := net.ParseIP(ip)
	var b strings.Builder
	for _, k := range conntrackMapKeys(checkPodName) {
		if (k.src.Equal(addr) && k.sport == sport) || (k.dst.Equal(addr) && k.dport == gcServerPort) {
			fmt.Fprintf(&b, "  %s:%d -> %s:%d owner %s\n", k.src, k.sport, k.dst, k.dport, k.owner)
		}
	}
	return b.String()
}

func agentArgs() []string {
	ds := agentDaemonSetObject()
	return append([]string(nil), agentContainerOf(ds).Args...)
}

// withCleanupPeriod returns args with the cleanup period flag set to seconds.
func withCleanupPeriod(args []string, seconds int) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, cleanupPeriodArg+"=") {
			out = append(out, a)
		}
	}
	return append(out, fmt.Sprintf("%s=%d", cleanupPeriodArg, seconds))
}

// setAgentArgs sets the agent container's args and waits for the DaemonSet to
// roll out.
func setAgentArgs(args []string) {
	ds := agentDaemonSetObject()
	agentContainerOf(ds).Args = args
	Expect(fw.K8sClient.Update(ctx, ds)).To(Succeed())
	Eventually(func() bool {
		ds := agentDaemonSetObject()
		s := ds.Status
		return s.ObservedGeneration >= ds.Generation && s.UpdatedNumberScheduled == s.DesiredNumberScheduled &&
			s.NumberReady == s.DesiredNumberScheduled && s.NumberAvailable == s.DesiredNumberScheduled
	}, rolloutTimeout, 5*time.Second).Should(BeTrue(), "aws-node did not roll out")
}

func agentDaemonSetObject() *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: agentNamespace, Name: agentDaemonSet}, ds)).To(Succeed())
	return ds
}

func agentContainerOf(ds *appsv1.DaemonSet) *v1.Container {
	for i := range ds.Spec.Template.Spec.Containers {
		if ds.Spec.Template.Spec.Containers[i].Name == agentContainer {
			return &ds.Spec.Template.Spec.Containers[i]
		}
	}
	Fail("no " + agentContainer + " container in the " + agentDaemonSet + " DaemonSet")
	return nil
}
