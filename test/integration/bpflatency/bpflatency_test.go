package bpflatency

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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
	loadAPI          = "LoadBpfFile"
	attachIngressAPI = "attachIngressBPFProbe"
	attachEgressAPI  = "attachEgressBPFProbe"

	// No "-": the agent's pod identifier drops the last "-" segment of the
	// pod name, so bpflat<i>-0 is identifier bpflat<i>, unique per pod. Pods
	// that shared an identifier would reuse its loaded programs and nothing
	// would be measured after the first.
	podNamePrefix = "bpflat"
	podLabelKey   = "test.npa/bpflatency"
	podLabelValue = "workload"

	podReadyTimeout = 2 * time.Minute
	// Observations land once the policy reaches each pod, after it is Running.
	observationTimeout = 3 * time.Minute
)

// A slower eBPF program load or attach holds the pod identifier's lock longer
// and leaves a new pod unprogrammed for longer, but fails no functional test.
// This spec creates pods with unique pod identifiers on one node, so each one
// loads fresh ingress and egress programs, and checks the agent's own latency
// metric for those loads and attaches against ceilings (#807).
var _ = Describe("eBPF program load and attach latency", Ordered, func() {
	var (
		node     *v1.Node
		checkPod *v1.Pod
		port     int
		before   map[fwutils.LatencyKey]fwutils.LatencySeries
	)

	BeforeAll(func() {
		node = pickNode()
		port = agentMetricsPort()

		checkPod = fwutils.BuildBPFCheckPod(namespace, node.Name)
		checkPod.Spec.Containers[0].Command = []string{"sleep", "1800"}
		grace := int64(0)
		checkPod.Spec.TerminationGracePeriodSeconds = &grace
		built := checkPod
		DeferCleanup(func() {
			deleteCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(deleteCtx, built)).To(Succeed())
		})
		var err error
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("Applying a policy that selects the workload pods, so the agent attaches probes to them")
		policy := manifest.NewNetworkPolicyBuilder().
			Namespace(namespace).Name("bpflatency").
			PodSelector(podLabelKey, podLabelValue).
			SetPolicyType(true, true).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
		DeferCleanup(fw.NetworkPolicyManager.DeleteNetworkPolicy, ctx, policy)

		before = scrape(checkPod.Name, port)
	})

	It("keeps p50 and p99 of LoadBpfFile and the probe attaches under the ceilings", func() {
		n := *podCount
		By(fmt.Sprintf("Creating %d pods with unique pod identifiers on node %s", n, node.Name))
		for i := 0; i < n; i++ {
			pod := manifest.NewDefaultPodBuilder().
				Namespace(namespace).Name(fmt.Sprintf("%s%d-0", podNamePrefix, i)).
				AddLabel(podLabelKey, podLabelValue).
				NodeName(node.Name).
				TerminationGracePeriod(0).
				Container(manifest.NewBusyBoxContainerBuilder().
					Name("sleep").Image(fwutils.NginxImage).ImageRepository(fw.Options.TestImageRegistry).
					Build()).
				Build()
			built := pod
			DeferCleanup(func() {
				deleteCtx, cancel := context.WithTimeout(ctx, fwutils.CleanupTimeout)
				defer cancel()
				Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(deleteCtx, built)).To(Succeed())
			})
			// One at a time: concurrent loads compete for CPU, which would
			// measure the node's load, not the program's.
			_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
		}

		// Each pod loads an ingress and an egress program and attaches each
		// once. Waiting for the counts also keeps the spec from passing on
		// observations that never happened.
		By("Waiting for the agent to record the loads and attaches")
		want := map[string]uint64{loadAPI: uint64(2 * n), attachIngressAPI: uint64(n), attachEgressAPI: uint64(n)}
		var after map[fwutils.LatencyKey]fwutils.LatencySeries
		Eventually(func(g Gomega) {
			after = scrape(checkPod.Name, port)
			for api, wantNew := range want {
				got, _ := after[fwutils.LatencyKey{API: api}].MeanMsSince(before[fwutils.LatencyKey{API: api}])
				g.Expect(got).To(BeNumerically(">=", wantNew), "new %s observations", api)
			}
		}, observationTimeout, fwutils.PollIntervalShort).Should(Succeed())

		for _, api := range []string{loadAPI, attachIngressAPI, attachEgressAPI} {
			failed, _ := after[fwutils.LatencyKey{API: api, Error: true}].MeanMsSince(before[fwutils.LatencyKey{API: api, Error: true}])
			Expect(failed).To(BeZero(), "%s calls that failed during the run", api)
		}

		report(node, before, after)

		ceilings := map[string][2]float64{
			loadAPI:          {*maxLoadP50Ms, *maxLoadP99Ms},
			attachIngressAPI: {*maxAttachP50Ms, *maxAttachP99Ms},
			attachEgressAPI:  {*maxAttachP50Ms, *maxAttachP99Ms},
		}
		for api, c := range ceilings {
			// The mean of this run's own observations: the difference of two
			// scrapes, so nothing the agent did before or beside the test
			// counts. Held to the p50 ceiling, as the typical cost.
			_, mean := after[fwutils.LatencyKey{API: api}].MeanMsSince(before[fwutils.LatencyKey{API: api}])
			Expect(mean).To(BeNumerically("<=", c[0]), "%s mean ms over this run's own calls", api)

			// The quantiles are the agent's, over its summary's rolling
			// 10-minute window, so they also hold any calls the agent made
			// in that window before or beside this run (an earlier suite on
			// the node, a pod that started meanwhile). That can pull them
			// either way; run on a node the agent has been idle on for 10
			// minutes, or just restarted on, to get this run's alone.
			q := after[fwutils.LatencyKey{API: api}].Quantiles
			Expect(q).To(HaveKey(0.5), "%s exports no p50: the agent image predates the summary objectives (#807)", api)
			Expect(q).To(HaveKey(0.99), "%s exports no p99: the agent image predates the summary objectives (#807)", api)
			Expect(q[0.5]).To(BeNumerically("<=", c[0]), "%s p50 ms", api)
			Expect(q[0.99]).To(BeNumerically("<=", c[1]), "%s p99 ms", api)
		}
	})
})

// report writes the measured values in one block, so runs can be compared
// across releases, kernels and address families, and as one JSON line
// prefixed with resultLinePrefix, so a script can collect them from the logs.
func report(node *v1.Node, before, after map[fwutils.LatencyKey]fwutils.LatencySeries) {
	info := node.Status.NodeInfo
	fmt.Fprintf(GinkgoWriter, "eBPF load latency: node=%s kernel=%s os=%q arch=%s ipFamily=%s pods=%d\n",
		node.Name, info.KernelVersion, info.OSImage, info.Architecture, fw.Options.IpFamily, *podCount)
	for _, api := range []string{loadAPI, attachIngressAPI, attachEgressAPI} {
		key := fwutils.LatencyKey{API: api}
		s := after[key]
		n, mean := s.MeanMsSince(before[key])
		fmt.Fprintf(GinkgoWriter, "  %-22s new=%d mean=%.2fms p50=%s p99=%s (quantiles over the agent's 10m window, %d observations in total)\n",
			api, n, mean, formatMs(s.Quantiles, 0.5), formatMs(s.Quantiles, 0.99), s.Count)
	}
	line, err := resultLine(runInfo{Kernel: info.KernelVersion, OS: info.OSImage, Arch: info.Architecture,
		IPFamily: fw.Options.IpFamily, Pods: *podCount}, before, after)
	Expect(err).ToNot(HaveOccurred())
	fmt.Fprintln(GinkgoWriter, line)
}

// resultLinePrefix starts the machine-readable result line.
const resultLinePrefix = "BPFLATENCY_RESULT "

type runInfo struct {
	Kernel   string `json:"kernel"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	IPFamily string `json:"ipFamily"`
	Pods     int    `json:"pods"`
}

// apiResult is one call's numbers in ms. A value the agent did not report
// (no observations in its window, or an agent without the quantiles) is null.
type apiResult struct {
	New    uint64   `json:"new"`
	MeanMs *float64 `json:"meanMs"`
	P50Ms  *float64 `json:"p50Ms"`
	P99Ms  *float64 `json:"p99Ms"`
}

// resultLine returns the run's numbers as resultLinePrefix plus one line of
// JSON: the run info, and per call, this run's observations and their mean,
// and the agent's p50 and p99.
func resultLine(info runInfo, before, after map[fwutils.LatencyKey]fwutils.LatencySeries) (string, error) {
	apis := map[string]apiResult{}
	for _, api := range []string{loadAPI, attachIngressAPI, attachEgressAPI} {
		key := fwutils.LatencyKey{API: api}
		n, mean := after[key].MeanMsSince(before[key])
		q := after[key].Quantiles
		apis[api] = apiResult{New: n, MeanMs: msOrNull(mean, true), P50Ms: msOrNull(q[0.5], hasKey(q, 0.5)),
			P99Ms: msOrNull(q[0.99], hasKey(q, 0.99))}
	}
	b, err := json.Marshal(struct {
		runInfo
		APIs map[string]apiResult `json:"apis"`
	}{info, apis})
	if err != nil {
		return "", err
	}
	return resultLinePrefix + string(b), nil
}

func hasKey(q map[float64]float64, k float64) bool {
	_, ok := q[k]
	return ok
}

// msOrNull rounds v to 0.01 ms, or returns nil when it is not present or NaN,
// which JSON cannot encode.
func msOrNull(v float64, present bool) *float64 {
	if !present || math.IsNaN(v) {
		return nil
	}
	r := math.Round(v*100) / 100
	return &r
}

func formatMs(q map[float64]float64, quantile float64) string {
	v, ok := q[quantile]
	if !ok || math.IsNaN(v) {
		return "n/a"
	}
	return fmt.Sprintf("%.2fms", v)
}

// scrape reads the agent's /metrics on the check pod's node. The check pod
// runs in the host network, like the agent.
func scrape(checkPodName string, port int) map[fwutils.LatencyKey]fwutils.LatencySeries {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"curl", "-sSf", "--max-time", "10", fmt.Sprintf("http://127.0.0.1:%d/metrics", port)})
	ExpectWithOffset(1, err).ToNot(HaveOccurred(), "scrape agent metrics")
	series, err := fwutils.ParseSDKLatency(out)
	ExpectWithOffset(1, err).ToNot(HaveOccurred())
	return series
}

// agentMetricsPort returns the port in the agent container's
// --metrics-bind-addr, or the default when the flag is not set.
func agentMetricsPort() int {
	ds := &appsv1.DaemonSet{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: "aws-node"}, ds)).To(Succeed())
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name != "aws-eks-nodeagent" {
			continue
		}
		for _, arg := range c.Args {
			if addr, ok := strings.CutPrefix(arg, "--metrics-bind-addr="); ok {
				_, p, _ := strings.Cut(addr, ":")
				port, err := strconv.Atoi(p)
				Expect(err).ToNot(HaveOccurred(), "parse %s", arg)
				return port
			}
		}
	}
	return fwutils.AgentMetricsPort
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
