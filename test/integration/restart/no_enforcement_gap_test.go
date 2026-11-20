package restart

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
)

/*
No Enforcement Gap While the Agent Re-attaches

The agent keeps which pods have programs attached in memory only. After a
restart it attaches every selected pod's programs again while the pod's
filters are still on the hooks, and the attach swaps each filter's program in
place. A deny policy must hold through that: a prober that opens connections
to the denied server in a tight loop must never connect, across several
restarts.
*/

const (
	gapRestarts = 3
	// Together about 3,000 connection attempts a second.
	gapProbers = 4
	// Logged by every agent version at startup. The log outlives the agent, so
	// only lines at or after a restart's start time count.
	agentStarted = "Network Policy is enabled, registering controllers"
	// Logs in /var/log/aws-routed-eni on the node, by file name without ".log".
	npaLogName = "network-policy-agent"
	sdkLogName = "ebpf-sdk"
	proberOut  = "/tmp/gap-prober-%d.out"
	proberStop = "/tmp/gap-prober.stop"
)

// gapProber opens non-blocking connections to ip:port in a loop until
// proberStop exists, and gives each one 300 ms. A SYN the policy drops times
// out, so each attempt samples the hook once, at the time it was sent. It
// prints a line per connection that got through.
const gapProber = `
import os, selectors, socket, sys, time
ip, port = sys.argv[1], int(sys.argv[2])
family = socket.AF_INET6 if ':' in ip else socket.AF_INET
sel = selectors.DefaultSelector()
pending = {}
attempts = connected = 0
while not os.path.exists(sys.argv[3]):
    now = time.monotonic()
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setblocking(False)
    s.connect_ex((ip, port))
    attempts += 1
    sel.register(s, selectors.EVENT_WRITE)
    pending[s] = now
    for key, _ in sel.select(timeout=0.001):
        c = key.fileobj
        if c.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
            connected += 1
            print('CONNECTED %.6f' % time.time(), flush=True)
        sel.unregister(c); c.close(); del pending[c]
    for c, t in list(pending.items()):
        if now - t > 0.3:
            sel.unregister(c); c.close(); del pending[c]
print('DONE attempts=%d connected=%d' % (attempts, connected), flush=True)
`

var _ = Describe("Deny policy through agent restarts", Ordered, func() {
	var (
		networkPolicy *network.NetworkPolicy
		serverPod     *v1.Pod
		clientPod     *v1.Pod
		checkPod      *v1.Pod
		nodeName      string
	)

	It("never lets a connection through while the agent re-attaches the server's programs", func() {
		By("Deploying the server and a client on the same node")
		serverPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gap-server", Namespace: namespace,
				Labels: map[string]string{"app": "gap-server"},
			},
			Spec: v1.PodSpec{Containers: []v1.Container{{
				Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
			}}},
		}
		var err error
		serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		nodeName = serverPod.Spec.NodeName
		serverIP := serverPod.Status.PodIP

		clientPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gapclient", Namespace: namespace,
				Labels: map[string]string{"app": "gapclient"},
			},
			Spec: v1.PodSpec{
				NodeName:   nodeName,
				Containers: []v1.Container{{Name: "prober", Image: "public.ecr.aws/docker/library/python:3.11-slim", Command: []string{"sleep", "3600"}}},
			},
		}
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		checkPod = utils.BuildBPFCheckPod(namespace, nodeName)
		checkPod.Spec.Containers[0].Command = []string{"sleep", "3600"}
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("CONNECTED"))

		By("Denying all ingress to the server")
		networkPolicy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "gap-deny", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "gap-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
		Eventually(func() string {
			return execConnect(namespace, clientPod.Name, serverIP, 80)
		}, time.Minute, bpfSettleInterval).Should(Equal("BLOCKED"))

		By("Starting the prober")
		startProber(clientPod.Name, serverIP, 80)

		// The SDK logs each filter call with the host hook and veth. Every restart
		// must replace both of the server's filters and add none.
		veth := podHostVeth(serverPod)
		sdkCalls := map[string]string{
			"egress replace":  "TC host egress filter replace done " + veth,
			"ingress replace": "TC host ingress filter replace done " + veth,
			"add":             "filter add done " + veth,
		}
		// Logged after both of the server's programs are attached.
		attached := "Successfully attached Egress TC probe for pod: " + serverPod.Name + " "
		replacedAfter := 0
		for i := 1; i <= gapRestarts; i++ {
			By(fmt.Sprintf("Restarting the agent on the server's node (%d/%d)", i, gapRestarts))
			since := nodeTime(checkPod.Name)
			restartAgentOn(nodeName)
			waitForDaemonSetRollout()
			Eventually(func() []string { return logSince(checkPod.Name, npaLogName, since, agentStarted) }, 2*time.Minute, 5*time.Second).
				ShouldNot(BeEmpty(), "the agent did not start again")
			// The re-attach runs when the agent reconciles the policy, after it is ready.
			Eventually(func() []string { return logSince(checkPod.Name, npaLogName, since, attached) }, 2*time.Minute, 5*time.Second).
				ShouldNot(BeEmpty(), "the agent did not attach the server's programs after restart %d", i)
			// A binary change takes the upgrade path, which detaches first.
			Expect(logSince(checkPod.Name, npaLogName, since, "change detected in")).To(BeEmpty(),
				"restart %d reloaded the programs instead of replacing them", i)
			got := map[string]int{}
			for k, line := range sdkCalls {
				got[k] = len(logSince(checkPod.Name, sdkLogName, since, line))
			}
			GinkgoWriter.Printf("restart %d: SDK calls on %s: %v\n", i, veth, got)
			if got["egress replace"] == 1 && got["ingress replace"] == 1 && got["add"] == 0 {
				replacedAfter++
			}
		}
		time.Sleep(bpfSettleInterval)

		By("Stopping the prober")
		attempts, connected, lines := stopProber(clientPod.Name)
		GinkgoWriter.Printf("prober: %d attempts, %d connected\n%s\n", attempts, connected, lines)
		// Too few attempts would pass without sampling the restarts.
		Expect(attempts).To(BeNumerically(">", 10000*gapProbers), "the probers made too few attempts to cover the restarts")
		Expect(connected).To(BeZero(), "connections got through the deny policy:\n%s", lines)
		// The deterministic check: the probers can miss a gap of a millisecond.
		Expect(replacedAfter).To(Equal(gapRestarts), "a restart did not replace both of the server's filters (see the SDK calls above)")

		By("Checking the policy still holds")
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		for _, p := range []*v1.Pod{serverPod, clientPod, checkPod} {
			if p != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
	})
})

// podHostVeth is the VPC CNI's host veth name for a single-NIC pod.
func podHostVeth(pod *v1.Pod) string {
	h := sha1.Sum([]byte(pod.Namespace + "." + pod.Name))
	return "eni" + hex.EncodeToString(h[:])[:11]
}

func restartAgentOn(nodeName string) {
	pods := &v1.PodList{}
	Expect(fw.K8sClient.List(ctx, pods, client.InNamespace(agentNamespace),
		client.MatchingLabels{"k8s-app": "aws-node"})).To(Succeed())
	deleted := false
	for _, p := range pods.Items {
		if p.Spec.NodeName == nodeName {
			Expect(fw.K8sClient.Delete(ctx, &p)).To(Succeed())
			deleted = true
		}
	}
	Expect(deleted).To(BeTrue(), "no aws-node pod on %s", nodeName)
}

// nodeTime is the node's UTC clock, as the logs' "ts" field has it.
func nodeTime(checkPodName string) string {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName, []string{"date", "-u", "+%Y-%m-%dT%H:%M:%S.%3N"})
	Expect(err).ToNot(HaveOccurred())
	return strings.TrimSpace(out)
}

// logSince returns the lines of a node log logged at or after since that
// contain pattern. It also reads the backups rotated since then, so a rotation
// during a restart loses nothing.
func logSince(checkPodName, name, since, pattern string) []string {
	// The current log is read first: if it is rotated meanwhile, its lines are
	// in the backup read next, and sort -u drops the copies. A backup is renamed
	// to .log and compressed to .log.gz afterwards, so a .gz whose .log still
	// exists is incomplete. Each file ends with a newline so a cut-off last line
	// can't join the next file's first.
	script := fmt.Sprintf(`cd /var/log/aws-routed-eni && { cat %[1]s.log 2>/dev/null; echo; find . \( -name '%[1]s-*.log' -o -name '%[1]s-*.log.gz' \) -newermt '%[2]s' -exec sh -c 'for f; do case $f in *.gz) [ -e "${f%%.gz}" ] && continue;; esac; zcat -f "$f"; echo; done' _ {} +; } |
grep -F -e '%[4]s' | LC_ALL=C sort -u | awk -v s='%[3]s' 'match($0, /"ts":"[^"]*"/) && substr($0, RSTART+6, RLENGTH-7) >= s'`,
		name, strings.Replace(since, "T", " ", 1)+" UTC", since, pattern)
	var out string
	// A read can race the rotation; ExecInPod returns stderr in the output.
	Eventually(func() (string, error) {
		var err error
		out, err = fw.PodManager.ExecInPod(namespace, checkPodName, []string{"chroot", "/host", "sh", "-c", script})
		return out, err
	}, 30*time.Second, time.Second).ShouldNot(ContainSubstring("STDERR:"), "failed to read %s logs", name)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func startProber(podName, ip string, port int) {
	script := fmt.Sprintf("rm -f /tmp/gap-prober-*.out %[1]s; cat > /tmp/gap-prober.py <<'EOF'\n%[2]s\nEOF\n", proberStop, gapProber)
	for i := 0; i < gapProbers; i++ {
		script += fmt.Sprintf("nohup python3 /tmp/gap-prober.py %s %d %s > "+proberOut+" 2>&1 &\n", ip, port, proberStop, i)
	}
	_, err := fw.PodManager.ExecInPod(namespace, podName, []string{"sh", "-c", script})
	Expect(err).ToNot(HaveOccurred())
}

var proberDone = regexp.MustCompile(`DONE attempts=(\d+) connected=(\d+)`)

// stopProber returns the attempt and connection counts of all probers, and
// the lines of the connections that got through.
func stopProber(podName string) (attempts, connected int, lines string) {
	var connectedLines []string
	_, err := fw.PodManager.ExecInPod(namespace, podName, []string{"touch", proberStop})
	Expect(err).ToNot(HaveOccurred())
	for i := 0; i < gapProbers; i++ {
		var out string
		Eventually(func() bool {
			out, err = fw.PodManager.ExecInPod(namespace, podName, []string{"cat", fmt.Sprintf(proberOut, i)})
			return err == nil && proberDone.MatchString(out)
		}, 30*time.Second, time.Second).Should(BeTrue(), "prober %d did not finish: %s", i, out)
		m := proberDone.FindStringSubmatch(out)
		a, _ := strconv.Atoi(m[1])
		c, _ := strconv.Atoi(m[2])
		attempts += a
		connected += c
		if l := strings.TrimSpace(proberDone.ReplaceAllString(out, "")); l != "" {
			connectedLines = append(connectedLines, fmt.Sprintf("prober %d:\n%s", i, l))
		}
	}
	return attempts, connected, strings.Join(connectedLines, "\n")
}
