package ebpf

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
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
Conntrack Shortening for Denied Connections

A TCP SYN that policy denies still leaves a kernel conntrack entry on the
destination node, in SYN_SENT for nf_conntrack_tcp_timeout_syn_sent (120 s by
default). On kernels with the nf_conntrack kfuncs the agent loads the ct-deny
ingress program, which shortens that entry to NPA_DENIED_CT_TIMEOUT_MS (1 s).

The specs read the destination node's conntrack table from /proc/net/nf_conntrack
right after a denied attempt from a fixed source port. Which ingress program the
agent chose on that node comes from its log, so on a kernel without the kfuncs,
or where the ct-deny program failed its startup probe, the denied spec skips
rather than fails.
*/
var _ = Describe("Conntrack Shortening for Denied Connections", func() {

	var (
		serverPod  *v1.Pod
		clientPod  *v1.Pod
		checkPod   *v1.Pod
		denyPolicy *network.NetworkPolicy
		serverIP   string
		clientIP   string
	)

	BeforeEach(func() {
		By("Creating server pod (nginx)")
		serverPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ct-server", Namespace: namespace,
				Labels: map[string]string{"app": "ct-server"},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
					Ports:   []v1.ContainerPort{{ContainerPort: victimPort}},
					Command: []string{"sh", "-c"},
					// Same config as the poisoning specs, so the server listens on both families.
					Args: []string{fmt.Sprintf(
						"printf '%%s' %s > /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'",
						shellQuote(victimConf))},
				}},
			},
		}
		var err error
		serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		serverIP = serverPod.Status.PodIP
		Expect(serverIP).ToNot(BeEmpty())

		By("Creating client pod (python, for connects from a fixed source port)")
		clientPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ct-client", Namespace: namespace,
				Labels: map[string]string{"app": "ct-client"},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "client", Image: "public.ecr.aws/docker/library/python:3.11-slim",
					Command: []string{"sleep", "infinity"},
				}},
			},
		}
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		clientIP = clientPod.Status.PodIP
		Expect(clientIP).ToNot(BeEmpty())

		By("Creating a check pod on the server's node to read its conntrack table")
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx,
			utils.BuildBPFCheckPod(namespace, serverPod.Spec.NodeName), 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())

		By("Applying deny-all ingress to the server")
		denyPolicy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "ct-server-deny-all", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "ct-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyPolicy)).To(Succeed())
		Eventually(func() (string, error) {
			return tryConnect(namespace, clientPod.Name, serverIP, victimPort, 0)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal(blocked),
			"deny-all never took effect on the server")
	})

	AfterEach(func() {
		if denyPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, denyPolicy)
		}
		for _, pod := range []*v1.Pod{checkPod, clientPod, serverPod} {
			if pod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
			}
		}
	})

	It("should shorten the conntrack entry of a denied connection [CtDeny]", func() {
		GinkgoWriter.Printf("server on node %s\n", serverPod.Spec.NodeName)
		switch variant := ingressVariant(checkPod.Name); variant {
		case ctDenyLoaded:
		case "":
			Fail("the running agent's log on " + serverPod.Spec.NodeName + " does not say which ingress program it loaded")
		default:
			Skip("ct-deny ingress program not in use on " + serverPod.Spec.NodeName + ": " + variant)
		}

		By("Attempting a denied connection from a fixed source port")
		// The 3 s connect timeout covers the SYN and its retransmit at 1 s, each of
		// which sets the entry back to the SYN_SENT timeout before the program shortens it.
		Expect(tryConnect(namespace, clientPod.Name, serverIP, victimPort, ctDenySrcPort)).To(Equal(blocked))

		By("Checking that no entry for the flow has its 120 s SYN_SENT timeout")
		// With the program in place the entry has at most 1 s left, or is already gone.
		// Without it, the entry would still have close to 120 s.
		entries := flowEntries(checkPod.Name, clientIP, serverIP, ctDenySrcPort, victimPort)
		GinkgoWriter.Printf("conntrack entries for the denied flow: %+v\n", entries)
		for _, e := range entries {
			Expect(e.timeout).To(BeNumerically("<=", maxShortenedTimeout),
				"denied flow's conntrack entry was not shortened: %s", e.line)
		}
	})

	It("should leave the conntrack entry of an allowed connection alone [CtDeny][Regression]", func() {
		allowPolicy := &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "ct-server-allow-client", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "ct-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					From: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "ct-client"}},
					}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, allowPolicy)).To(Succeed())
		defer fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, allowPolicy)
		Eventually(func() (string, error) {
			return tryConnect(namespace, clientPod.Name, serverIP, victimPort, 0)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal(connected))

		By("Connecting from a fixed source port")
		Expect(tryConnect(namespace, clientPod.Name, serverIP, victimPort, ctAllowSrcPort)).To(Equal(connected))

		By("Checking that the flow's entry keeps a regular timeout")
		// The closed connection sits in TIME_WAIT (120 s by default). Finding it also
		// shows the check pod sees this node's table, which the denied spec relies on
		// when it finds no entry at all.
		entries := flowEntries(checkPod.Name, clientIP, serverIP, ctAllowSrcPort, victimPort)
		GinkgoWriter.Printf("conntrack entries for the allowed flow: %+v\n", entries)
		Expect(entries).ToNot(BeEmpty(), "no conntrack entry found for the allowed flow")
		for _, e := range entries {
			Expect(e.timeout).To(BeNumerically(">", maxShortenedTimeout),
				"allowed flow's conntrack entry was shortened: %s", e.line)
		}
	})
})

const (
	// Fixed source ports, so a flow's entry can be told apart from the probes'.
	// Distinct per spec, so one spec's TIME_WAIT entry cannot show up in the other.
	ctDenySrcPort  = 34567
	ctAllowSrcPort = 34568

	// Seconds left on a shortened entry, with margin for the read happening after
	// the timeout was set. Well below the 120 s an unshortened entry would show.
	maxShortenedTimeout = 5

	// The agent's log lines for the ingress program it chose at startup on
	// this node. It logs one of them per start.
	ctDenyLoaded      = "conntrack entries shortened"
	ctDenyNoKfuncs    = "Kernel lacks the conntrack kfuncs"
	ctDenyProbeFailed = "failed to load, using the regular ingress binary"
	// Logged by every agent version at startup, before the ingress program is
	// selected. The log outlives the agent, so lines before the last startup
	// belong to an earlier agent, which may have been a different version.
	agentStarted = "Network Policy is enabled, registering controllers"

	// The agent's current log, and the directory its rotated backups are in.
	// Backups are gzip compressed (pkg/logger) and their names sort oldest
	// first.
	npaLogDir     = "/host/var/log/aws-routed-eni"
	npaLog        = npaLogDir + "/network-policy-agent.log"
	npaBackupGlob = npaLogDir + "/network-policy-agent-*.log.gz"
)

// ingressVariant returns which of the agent's ingress program log lines the
// running agent on the check pod's node logged last, or "" if it logged none.
func ingressVariant(checkPodName string) string {
	variant := ""
	for _, line := range strings.Split(agentLogSinceStart(checkPodName), "\n") {
		for _, v := range []string{ctDenyLoaded, ctDenyNoKfuncs, ctDenyProbeFailed} {
			if strings.Contains(line, v) {
				variant = v
			}
		}
	}
	return variant
}

// agentLogSinceStart returns the agent's log lines from its last startup on,
// limited to the ones ingressVariant looks for. If the startup line has
// rotated out of the current log, it reads the compressed backups, newest
// first, until it finds one.
func agentLogSinceStart(checkPodName string) string {
	grep := fmt.Sprintf("grep -h -e %s -e %s -e %s -e %s",
		shellQuote(agentStarted), shellQuote(ctDenyLoaded), shellQuote(ctDenyNoKfuncs), shellQuote(ctDenyProbeFailed))
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"sh", "-c", grep + " " + npaLog + " || true"})
	Expect(err).ToNot(HaveOccurred(), "failed to read the agent log")
	lines := out

	backups, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"sh", "-c", "ls -1 " + npaBackupGlob + " 2>/dev/null || true"})
	Expect(err).ToNot(HaveOccurred(), "failed to list the agent's rotated logs")
	names := strings.Fields(backups)
	for i := len(names) - 1; i >= 0 && !strings.Contains(lines, agentStarted); i-- {
		// The check pod's image has no gzip, so copy the backup out as base64.
		enc, err := fw.PodManager.ExecInPod(namespace, checkPodName, []string{"base64", "-w0", names[i]})
		Expect(err).ToNot(HaveOccurred(), "failed to read %s", names[i])
		lines = matchingLines(gunzipBase64(enc, names[i])) + "\n" + lines
	}

	// Lines before the last startup belong to an earlier agent.
	if i := strings.LastIndex(lines, agentStarted); i >= 0 {
		lines = lines[i:]
	}
	return lines
}

// gunzipBase64 decodes and decompresses a base64 encoded gzip file.
func gunzipBase64(enc, name string) string {
	gz, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	Expect(err).ToNot(HaveOccurred(), "failed to decode %s", name)
	r, err := gzip.NewReader(bytes.NewReader(gz))
	Expect(err).ToNot(HaveOccurred(), "failed to decompress %s", name)
	data, err := io.ReadAll(r)
	Expect(err).ToNot(HaveOccurred(), "failed to decompress %s", name)
	return string(data)
}

// matchingLines keeps the log lines that agentLogSinceStart greps for.
func matchingLines(log string) string {
	var kept []string
	for _, line := range strings.Split(log, "\n") {
		for _, v := range []string{agentStarted, ctDenyLoaded, ctDenyNoKfuncs, ctDenyProbeFailed} {
			if strings.Contains(line, v) {
				kept = append(kept, line)
				break
			}
		}
	}
	return strings.Join(kept, "\n")
}

type ctEntry struct {
	timeout int // seconds left
	line    string
}

// flowEntries returns the conntrack entries on the check pod's node whose
// original direction is src:sport -> dst:dport over TCP. The check pod shares the
// host's network namespace, so /proc/net/nf_conntrack is the node's table.
func flowEntries(checkPodName, src, dst string, sport, dport int) []ctEntry {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName, []string{"cat", "/proc/net/nf_conntrack"})
	Expect(err).ToNot(HaveOccurred(), "failed to read /proc/net/nf_conntrack")

	srcIP, dstIP := net.ParseIP(src), net.ParseIP(dst)
	var entries []ctEntry
	for _, line := range strings.Split(out, "\n") {
		// For example:
		//   ipv4 2 tcp 6 117 SYN_SENT src=10.0.1.5 dst=10.0.2.7 sport=34567 dport=80 [UNREPLIED] src=...
		// Field 4 is the seconds left. The first src/dst/sport/dport are the original
		// direction, the second set the reply.
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[2] != "tcp" {
			continue
		}
		timeout, err := strconv.Atoi(fields[4])
		if err != nil {
			continue
		}
		tuple := map[string]string{}
		for _, f := range fields[5:] {
			k, v, ok := strings.Cut(f, "=")
			if _, seen := tuple[k]; ok && !seen {
				tuple[k] = v
			}
		}
		// Parsed rather than compared as strings: IPv6 addresses are printed in
		// full here, but the pod IPs come compressed.
		if net.ParseIP(tuple["src"]).Equal(srcIP) && net.ParseIP(tuple["dst"]).Equal(dstIP) &&
			tuple["sport"] == strconv.Itoa(sport) && tuple["dport"] == strconv.Itoa(dport) {
			entries = append(entries, ctEntry{timeout: timeout, line: line})
		}
	}
	return entries
}
