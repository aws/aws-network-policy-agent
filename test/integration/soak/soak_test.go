package soak

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pod and policy names. The topology is faithful to GitHub #462: the protected
// pod is the one that makes OUTBOUND connections and carries an ingress policy, so
// its RETURN traffic depends on NPA's conntrack map. The cleanup race breaks that
// return path.
const (
	// openDestLabel is the openly-reachable destination the #462 driver connects
	// out to. It has no policy, so the driver's forward SYN always lands; only the
	// return path is policy-gated (at the driver).
	openDestLabel = "npa-soak-open-dest"

	// reuseDriverLabel is the protected pod that drives the #462 repro: it makes
	// short-lived port-reuse outbound connections to openDest while carrying an
	// ingress-deny policy, so its return traffic relies entirely on conntrack.
	reuseDriverLabel = "npa-soak-reuse-driver"

	// denyServerLabel is an ingress-denied server used for the false-allow check:
	// an unsolicited connection to it must be blocked.
	denyServerLabel = "npa-soak-deny-server"

	// proberLabel is the unrestricted pod the probe sweep connects from.
	proberLabel = "npa-soak-prober"

	podReadyTimeout = 2 * time.Minute
	bpfSettle       = 10 * time.Second

	agentDaemonSet = "aws-node"
	agentNamespace = "kube-system"

	serverPort = 80
)

var _ = Describe("NPA Soak", Ordered, func() {
	var (
		rec         *Recorder
		openDest    *v1.Pod
		denyServer  *v1.Pod
		prober      *v1.Pod
		reuseClient *v1.Pod
		driverDeny  *network.NetworkPolicy
		serverDeny  *network.NetworkPolicy
		workerNodes []v1.Node
	)

	BeforeAll(func() {
		rec = NewRecorder()

		By("selecting worker nodes to spread the soak across")
		nodes, err := getLinuxWorkerNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodes)).To(BeNumerically(">=", cfg.NodeCount),
			fmt.Sprintf("soak needs >= %d worker nodes, found %d", cfg.NodeCount, len(nodes)))
		workerNodes = nodes[:cfg.NodeCount]
		node0 := workerNodes[0].Name

		By("deploying the open destination for the #462 driver's outbound traffic")
		openDest, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildNginxPod(openDestLabel, node0), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		Expect(openDest.Status.PodIP).ToNot(BeEmpty())

		By("deploying the ingress-denied server and an unrestricted prober (false-allow check)")
		denyServer, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildNginxPod(denyServerLabel, node0), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		Expect(denyServer.Status.PodIP).ToNot(BeEmpty())
		prober, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildProberPod(node0), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("applying ingress-deny to the deny-server (false-allow target)")
		serverDeny = buildIngressDenyPolicy("soak-server-deny", denyServerLabel)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverDeny)).To(Succeed())

		By("applying ingress-deny to the #462 driver (its return traffic now relies on conntrack)")
		driverDeny = buildIngressDenyPolicy("soak-driver-deny", reuseDriverLabel)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, driverDeny)).To(Succeed())
		time.Sleep(bpfSettle)

		By("launching the #462 port-reuse driver (fixed source ports, short interval, outbound to open-dest)")
		reuseClient, err = launchPortReuseClient(node0, cfg.PortReuse(openDest.Status.PodIP, serverPort))
		Expect(err).ToNot(HaveOccurred())
	})

	It("sustains mixed traffic and churn without mis-enforcement, leaks, or the #462 race", func() {
		sched := cfg.Schedule()
		runCtx, cancel := contextForDuration(cfg.Duration)
		defer cancel()

		By(fmt.Sprintf("running the soak for %s", cfg.Duration))

		// Capture the baseline the leak and memory checks compare against. Taken
		// after warm-up so transient startup allocation does not count as growth.
		baseline := captureBaseline(workerNodes)

		// Per-node NPA-container memory growth tracker, fed by the trend-sample loop
		// and judged against the >50 MiB budget at the end.
		mem := newMemoryMonitor(clientset, uint64(cfg.MemoryGrowthLimit))

		// The concurrent activity loops. Each runs until runCtx expires and records
		// any violation into rec; none asserts directly, because Ginkgo assertions
		// are unsafe off the main goroutine.
		loops := newActivityLoops(rec, cfg, sched, workerNodes, denyServer, prober, baseline, mem)
		loops.start(runCtx)

		<-runCtx.Done()
		loops.wait()

		By("checking the #462 port-reuse driver sustained traffic without disruption")
		checkPortReuseClientHealth(rec, reuseClient.Name)

		By("scanning agent policy event logs for the #462 cleanup-race signature")
		scanForConntrackRace(rec, workerNodes)

		By("verifying BPF state returned to baseline after churn drained")
		assertNoBPFLeak(rec, baseline, workerNodes)

		By("verifying NPA container memory stayed within the growth budget")
		mem.finalize(rec)

		// Single point of judgment: every loop and post-run check funnels into the
		// recorder, so the whole soak verdict is one assertion with a full report.
		summary := rec.Summary()
		Expect(summary).To(BeEmpty(), "soak detected violations:\n"+summary)
	})

	AfterAll(func() {
		// Delete in reverse order of creation. Each guarded so a partial setup
		// still tears down what it created.
		for _, p := range []*v1.Pod{reuseClient, prober, denyServer, openDest} {
			if p != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
		for _, np := range []*network.NetworkPolicy{driverDeny, serverDeny} {
			if np != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			}
		}
	})
})

// buildNginxPod creates an nginx server pod with the given app label, pinned to a
// node. nginx gives a real listening port to probe against.
func buildNginxPod(label, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      label,
			Namespace: namespace,
			Labels:    map[string]string{"app": label},
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name:  "nginx",
				Image: "public.ecr.aws/nginx/nginx:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
			}},
		},
	}
}

// buildProberPod creates a long-lived pod the probe sweep execs curl from. It has
// no NetworkPolicy, so any block it observes comes from the target's policy, not
// its own.
func buildProberPod(nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proberLabel,
			Namespace: namespace,
			Labels:    map[string]string{"app": proberLabel},
		},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name:    "prober",
				Image:   driverImage, // amazonlinux:2023-minimal, ships curl
				Command: []string{"sleep", "infinity"},
			}},
		},
	}
}

// buildIngressDenyPolicy applies ingress enforcement with no ingress rules to the
// pods matching app=label. With PolicyTypeIngress and no rules, all unsolicited
// inbound is denied and only conntrack-tracked return traffic is allowed — the
// precondition for both the false-allow check and the #462 race.
func buildIngressDenyPolicy(name, label string) *network.NetworkPolicy {
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name(name).
		PodSelector("app", label).
		SetPolicyTypes([]network.PolicyType{network.PolicyTypeIngress}).
		Build()
}

// getLinuxWorkerNodes returns the AL2023 Linux worker nodes, mirroring the leak
// suite's selection so the soak runs on the same node shape NPA ships on.
func getLinuxWorkerNodes() ([]v1.Node, error) {
	nodeList := &v1.NodeList{}
	if err := fw.K8sClient.List(ctx, nodeList, client.MatchingLabels{"kubernetes.io/os": "linux"}); err != nil {
		return nil, err
	}
	var workers []v1.Node
	for _, n := range nodeList.Items {
		if strings.Contains(n.Status.NodeInfo.OSImage, "Amazon Linux") {
			workers = append(workers, n)
		}
	}
	return workers, nil
}
