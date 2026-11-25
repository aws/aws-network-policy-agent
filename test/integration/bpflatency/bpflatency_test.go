package bpflatency

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	fwutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	opLoad   = "load"
	opAttach = "attach"

	agentContainer = "aws-eks-nodeagent"

	// No "-": the agent's pod identifier drops the last "-" segment of the
	// pod name, so bpflat<i>-0 is identifier bpflat<i>, unique per pod. Pods
	// that shared an identifier would reuse its loaded programs and nothing
	// would be measured after the first.
	podNamePrefix = "bpflat"

	podReadyTimeout = 2 * time.Minute
	// The agent loads and attaches a pod's programs during its CNI ADD, before
	// the pod is Running, so the observations are normally there by the first
	// scrape after the last pod; this only covers a slow scrape.
	observationTimeout = 1 * time.Minute
)

var (
	directions = []string{"ingress", "egress"}
	ops        = []string{opLoad, opAttach}
)

// A slower eBPF program load or attach holds the pod identifier's lock longer
// and leaves a new pod unprogrammed for longer, but fails no functional test.
// This spec creates pods with unique pod identifiers on one node, so the
// agent loads and attaches fresh ingress and egress programs for each during
// its CNI ADD, and holds the agent's own latency histogram for those calls to
// ceilings, per op and direction (#807).
var _ = Describe("eBPF program load and attach latency", Ordered, func() {
	var (
		node           *v1.Node
		agent          agentInfo
		scrapePod      *v1.Pod
		restartsBefore int32
		before         map[fwutils.ProbeKey]fwutils.ProbeHistogram
	)

	BeforeAll(func() {
		node = pickNode()
		agent = readAgentInfo()

		// In the host network, like the agent, so it reaches the agent's
		// /metrics on the node's loopback. A hostNetwork pod gets no CNI ADD,
		// so it adds no load or attach of its own.
		pod := manifest.NewDefaultPodBuilder().
			Namespace(namespace).Name("bpflatency-scrape").
			NodeName(node.Name).HostNetwork(true).TerminationGracePeriod(0).
			Container(manifest.NewBusyBoxContainerBuilder().
				Command([]string{"sleep", "1800"}).ImageRepository(fw.Options.TestImageRegistry).
				Build()).
			Build()
		DeferCleanup(func() {
			deleteCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(deleteCtx, pod)).To(Succeed())
		})
		var err error
		scrapePod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		restartsBefore = agentRestarts(node.Name)
		before, err = scrape(scrapePod.Name, agent.metricsURL)
		Expect(err).ToNot(HaveOccurred())
	})

	It("keeps p50 and p99 of each program load and attach under the ceilings", func() {
		n := *podCount
		var after map[fwutils.ProbeKey]fwutils.ProbeHistogram
		// Print the results even when a check below fails, so a slow or
		// failing run still leaves its numbers in the log.
		DeferCleanup(func() {
			if after == nil {
				var err error
				if after, err = scrape(scrapePod.Name, agent.metricsURL); err != nil {
					fmt.Fprintf(GinkgoWriter, "eBPF load latency: no result, final scrape failed: %v\n", err)
					return
				}
			}
			report(node, agent, before, after)
		})

		By(fmt.Sprintf("Creating %d pods with unique pod identifiers on node %s", n, node.Name))
		for i := 0; i < n; i++ {
			pod := manifest.NewDefaultPodBuilder().
				Namespace(namespace).Name(fmt.Sprintf("%s%d-0", podNamePrefix, i)).
				NodeName(node.Name).
				TerminationGracePeriod(0).
				Container(manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Build()).
				Build()
			DeferCleanup(func() {
				deleteCtx, cancel := context.WithTimeout(ctx, fwutils.CleanupTimeout)
				defer cancel()
				Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(deleteCtx, pod)).To(Succeed())
			})
			// One at a time: concurrent loads compete for CPU, which would
			// measure the node's load, not the program's.
			_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
		}

		// Each pod loads an ingress and an egress program and attaches each
		// once. Waiting for the counts also keeps the spec from passing on
		// observations that never happened. The counts are lower bounds: any
		// other pod that starts on the node between the two scrapes adds its
		// own calls, which the spec cannot tell apart from its pods'.
		By("Waiting for the agent to record the loads and attaches")
		Eventually(func(g Gomega) {
			var err error
			after, err = scrape(scrapePod.Name, agent.metricsURL)
			g.Expect(err).ToNot(HaveOccurred())
			d, err := deltas(before, after)
			g.Expect(err).ToNot(HaveOccurred())
			for _, op := range ops {
				for _, dir := range directions {
					g.Expect(d[fwutils.ProbeKey{Op: op, Direction: dir}].Count).To(BeNumerically(">=", n),
						"new %s %s observations; none at all means the agent image predates %s", dir, op, fwutils.ProbeLatencyMetric)
				}
			}
		}, observationTimeout, fwutils.PollIntervalShort).Should(Succeed())

		// A restart between the scrapes resets the histogram, so the
		// difference would miss the calls before it.
		Expect(agentRestarts(node.Name)).To(Equal(restartsBefore), "%s restarts on %s during the run", agentContainer, node.Name)

		d, err := deltas(before, after)
		Expect(err).ToNot(HaveOccurred())
		for _, op := range ops {
			for _, dir := range directions {
				Expect(d[fwutils.ProbeKey{Op: op, Direction: dir, Error: true}].Count).To(BeZero(), "%s %s calls that failed during the run", dir, op)
			}
		}

		ceilings := map[string][2]float64{
			opLoad:   {*maxLoadP50Ms, *maxLoadP99Ms},
			opAttach: {*maxAttachP50Ms, *maxAttachP99Ms},
		}
		// Per direction: egress takes longer to load than ingress, so one
		// direction getting slower could hide in a combined number.
		for _, op := range ops {
			for _, dir := range directions {
				h := d[fwutils.ProbeKey{Op: op, Direction: dir}]
				Expect(h.QuantileMs(0.5)).To(BeNumerically("<=", ceilings[op][0]), "%s %s p50 ms", dir, op)
				Expect(h.QuantileMs(0.99)).To(BeNumerically("<=", ceilings[op][1]), "%s %s p99 ms", dir, op)
			}
		}
	})
})

// deltas returns the observations between the before and after scrapes, per
// series.
func deltas(before, after map[fwutils.ProbeKey]fwutils.ProbeHistogram) (map[fwutils.ProbeKey]fwutils.ProbeHistogram, error) {
	out := make(map[fwutils.ProbeKey]fwutils.ProbeHistogram, len(after))
	for key, a := range after {
		d, err := a.Since(before[key])
		if err != nil {
			return nil, fmt.Errorf("%+v: %w", key, err)
		}
		out[key] = d
	}
	return out, nil
}

// report writes the measured values in one block, so runs can be compared
// across releases, kernels and address families, and as one JSON line
// prefixed with resultLinePrefix, so a script can collect them from the logs.
// It does not fail the spec: it also runs after a failed check.
func report(node *v1.Node, agent agentInfo, before, after map[fwutils.ProbeKey]fwutils.ProbeHistogram) {
	nodeInfo := node.Status.NodeInfo
	info := runInfo{Kernel: nodeInfo.KernelVersion, OS: nodeInfo.OSImage, Arch: nodeInfo.Architecture,
		InstanceType: node.Labels["node.kubernetes.io/instance-type"], AgentImage: agent.image,
		IPFamily: fw.Options.IpFamily, Pods: *podCount}
	fmt.Fprintf(GinkgoWriter, "eBPF load latency: node=%s kernel=%s os=%q arch=%s instanceType=%s agentImage=%s ipFamily=%s pods=%d\n",
		node.Name, info.Kernel, info.OS, info.Arch, info.InstanceType, info.AgentImage, info.IPFamily, info.Pods)
	line, results, err := resultLine(info, before, after)
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "  no result: %v\n", err)
		return
	}
	for _, op := range ops {
		for _, dir := range directions {
			r := results[resultName(op, dir)]
			fmt.Fprintf(GinkgoWriter, "  %-14s new=%d mean=%s p50=%s p99=%s\n",
				resultName(op, dir), r.New, formatMs(r.MeanMs), formatMs(r.P50Ms), formatMs(r.P99Ms))
		}
	}
	fmt.Fprintln(GinkgoWriter, line)
}

// resultLinePrefix starts the machine-readable result line.
const resultLinePrefix = "BPFLATENCY_RESULT "

type runInfo struct {
	Kernel       string `json:"kernel"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	InstanceType string `json:"instanceType"`
	AgentImage   string `json:"agentImage"`
	IPFamily     string `json:"ipFamily"`
	Pods         int    `json:"pods"`
}

// opResult is one op and direction's numbers in ms, over this run's
// observations. A value with no observations behind it is null.
type opResult struct {
	New    uint64   `json:"new"`
	MeanMs *float64 `json:"meanMs"`
	P50Ms  *float64 `json:"p50Ms"`
	P99Ms  *float64 `json:"p99Ms"`
}

func resultName(op, direction string) string { return op + "/" + direction }

// resultLine returns the run's numbers as resultLinePrefix plus one line of
// JSON: the run info, and per op and direction ("load/ingress", ...), the
// number of observations between the scrapes and their mean, p50 and p99.
func resultLine(info runInfo, before, after map[fwutils.ProbeKey]fwutils.ProbeHistogram) (string, map[string]opResult, error) {
	d, err := deltas(before, after)
	if err != nil {
		return "", nil, err
	}
	results := map[string]opResult{}
	for _, op := range ops {
		for _, dir := range directions {
			h := d[fwutils.ProbeKey{Op: op, Direction: dir}]
			results[resultName(op, dir)] = opResult{New: h.Count, MeanMs: msOrNull(h.MeanMs()),
				P50Ms: msOrNull(h.QuantileMs(0.5)), P99Ms: msOrNull(h.QuantileMs(0.99))}
		}
	}
	b, err := json.Marshal(struct {
		runInfo
		Results map[string]opResult `json:"results"`
	}{info, results})
	if err != nil {
		return "", nil, err
	}
	return resultLinePrefix + string(b), results, nil
}

// msOrNull rounds v to 0.01 ms, or returns nil for NaN (no observations) and
// +Inf (above the highest bucket), which JSON cannot encode.
func msOrNull(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	r := math.Round(v*100) / 100
	return &r
}

func formatMs(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2fms", *v)
}

// scrape reads the agent's /metrics from the scrape pod, which runs in the
// host network on the agent's node. It returns errors rather than failing,
// so a caller inside Eventually retries a failed exec or fetch.
func scrape(scrapePodName, url string) (map[fwutils.ProbeKey]fwutils.ProbeHistogram, error) {
	out, err := fw.PodManager.ExecInPod(namespace, scrapePodName,
		[]string{"wget", "-q", "-O", "-", "-T", "10", url})
	if err != nil {
		return nil, fmt.Errorf("scrape agent metrics: %w", err)
	}
	return fwutils.ParseProbeLatency(out)
}

type agentInfo struct {
	image      string
	metricsURL string
}

// readAgentInfo returns the agent container's image and the URL of its
// /metrics on the node, from --metrics-bind-addr or the default port.
func readAgentInfo() agentInfo {
	ds := &appsv1.DaemonSet{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: "aws-node"}, ds)).To(Succeed())
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name != agentContainer {
			continue
		}
		info := agentInfo{image: c.Image, metricsURL: metricsURL("", fwutils.AgentMetricsPort)}
		for _, arg := range c.Args {
			if addr, ok := strings.CutPrefix(arg, "--metrics-bind-addr="); ok {
				host, p, err := net.SplitHostPort(addr)
				Expect(err).ToNot(HaveOccurred(), "parse %s", arg)
				port, err := strconv.Atoi(p)
				Expect(err).ToNot(HaveOccurred(), "parse %s", arg)
				info.metricsURL = metricsURL(host, port)
			}
		}
		return info
	}
	Fail(fmt.Sprintf("aws-node has no %s container", agentContainer))
	return agentInfo{}
}

// metricsURL returns the agent's /metrics URL for its bind host and port. An
// empty or wildcard host listens on every address, so loopback reaches it.
func metricsURL(host string, port int) string {
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, strconv.Itoa(port)))
}

// agentRestarts returns the agent container's restart count on nodeName.
func agentRestarts(nodeName string) int32 {
	pods := &v1.PodList{}
	Expect(fw.K8sClient.List(ctx, pods, client.InNamespace("kube-system"), client.MatchingLabels{"k8s-app": "aws-node"})).To(Succeed())
	for _, p := range pods.Items {
		if p.Spec.NodeName != nodeName {
			continue
		}
		for _, s := range p.Status.ContainerStatuses {
			if s.Name == agentContainer {
				return s.RestartCount
			}
		}
	}
	Fail(fmt.Sprintf("no %s container on node %s", agentContainer, nodeName))
	return 0
}

// pickNode returns the first node the workload pods can be pinned to.
func pickNode() *v1.Node {
	nodes, err := fwutils.SchedulableNodes(ctx, fw.K8sClient)
	Expect(err).ToNot(HaveOccurred())
	Expect(nodes).ToNot(BeEmpty(), "no schedulable Linux node")
	node := &v1.Node{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Name: nodes[0]}, node)).To(Succeed())
	return node
}
