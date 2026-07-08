package soak

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pod and policy topology. Distributed across N nodes so every node under test has
// enforced workload and its per-node signals (leak, memory, restart) are real.
const (
	// denyServerLabel: ingress-denied target for the false-allow probe.
	denyServerLabel = "npa-soak-deny-server"
	// allowServerLabel: explicitly-allowed target for the false-deny/liveness probe.
	allowServerLabel = "npa-soak-allow-server"
	// proberLabel: unrestricted pod that execs the probe sweeps.
	proberLabel = "npa-soak-prober"
	// reuseDriverLabel: #462 repro pod (only deployed when Enable462Guard).
	reuseDriverLabel = "npa-soak-reuse-driver"
	// openDestLabel: open destination the #462 driver connects to.
	openDestLabel = "npa-soak-open-dest"

	// denyPolicyName is the ingress-deny policy on the deny-server. Shared between
	// setup and the hot-update loop so the two can never drift to different names
	// (a drift silently turned hot-update into a no-op once).
	denyPolicyName = "soak-deny"

	podReadyTimeout = 2 * time.Minute
	bpfSettle       = 10 * time.Second

	agentDaemonSet = "aws-node"
	agentNamespace = "kube-system"

	serverPort = 80
)

var _ = Describe("NPA Soak", Ordered, func() {
	var (
		rec         *Recorder
		denyServer  *v1.Pod
		allowServer *v1.Pod
		prober      *v1.Pod
		liveness    *v1.Pod
		reuseClient *v1.Pod // nil unless Enable462Guard
		openDest    *v1.Pod // nil unless Enable462Guard
		denyPolicy  *network.NetworkPolicy
		allowPolicy *network.NetworkPolicy
		churnPolicy *network.NetworkPolicy
		driverDeny  *network.NetworkPolicy // nil unless Enable462Guard
		churnJobs   []*batchv1.CronJob
		workerNodes []v1.Node
		restartMon  *restartMonitor
		bpfBaseline baseline
	)

	BeforeAll(func() {
		rec = NewRecorder()

		By("selecting worker nodes to spread the soak across")
		nodes, err := getLinuxWorkerNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodes)).To(BeNumerically(">=", cfg.NodeCount),
			fmt.Sprintf("soak needs >= %d worker nodes, found %d", cfg.NodeCount, len(nodes)))
		workerNodes = nodes[:cfg.NodeCount]

		// Distribute pods across nodes so every node has enforced workload and its
		// per-node signals (BPF count, memory, restart) are real, not idle.
		nodeFor := func(i int) string { return workerNodes[i%len(workerNodes)].Name }

		By("deploying the deny-server (node 0) and allow-server (node 1) + prober (node 0)")
		denyServer, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildNginxPod(denyServerLabel, nodeFor(0)), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		allowServer, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildNginxPod(allowServerLabel, nodeFor(1)), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		prober, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildProberPod(nodeFor(0)), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("applying ingress-deny to deny-server (false-allow target)")
		denyPolicy = buildIngressDenyPolicy(denyPolicyName, denyServerLabel)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyPolicy)).To(Succeed())

		By("applying ingress-allow to allow-server from the prober and liveness client (false-deny target)")
		allowPolicy = buildIngressAllowPolicy("soak-allow", allowServerLabel, proberLabel, livenessClientLabel)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, allowPolicy)).To(Succeed())
		time.Sleep(bpfSettle)

		By("deploying the liveness client (liveness on node 0, allow-server on node 1: cross-node)")
		liveness, err = launchLivenessClient(nodeFor(0), allowServer.Status.PodIP, serverPort)
		Expect(err).ToNot(HaveOccurred())

		// Capture the leak/memory baseline BEFORE churn starts, so it reflects only
		// the stable topology. If we captured it with churn running, transient churn
		// pods would inflate the baseline and mask a real leak at the end (which is
		// measured churn-quiet). Settle first so agent programming has caught up.
		time.Sleep(bpfSettle)
		By("capturing the churn-quiet BPF/memory baseline")
		bpfBaseline = captureBaseline(workerNodes)

		By("deploying policy-selected pod churn across all nodes (makes leak gate non-vacuous)")
		churnPolicy = buildIngressDenyPolicy("soak-churn-deny", churnLabel)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, churnPolicy)).To(Succeed())
		churnJobs = deployChurnCronJobs(workerNodes)
		// Fail fast if churn produces nothing: otherwise the leak gate is vacuous.
		assertChurnActive(3 * time.Minute)

		By("starting the nodeagent restart monitor (Gate 3)")
		restartMon = newRestartMonitor(workerNodes)

		if cfg.Enable462Guard {
			By("deploying the #462 port-reuse driver (quarantined by default)")
			openDest, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildNginxPod(openDestLabel, nodeFor(0)), podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
			driverDeny = buildIngressDenyPolicy("soak-driver-deny", reuseDriverLabel)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, driverDeny)).To(Succeed())
			time.Sleep(bpfSettle)
			reuseClient, err = launchPortReuseClient(nodeFor(0), cfg.PortReuse(openDest.Status.PodIP, serverPort))
			Expect(err).ToNot(HaveOccurred())
		}
	})

	It("sustains mixed traffic and churn without mis-enforcement, leaks, or connection disruption", func() {
		sched := cfg.Schedule()
		runCtx, cancel := contextForDuration(cfg.Duration)
		defer cancel()

		By(fmt.Sprintf("running the soak for %s", cfg.Duration))

		// baseline was captured churn-quiet in BeforeAll (see M1 note there).
		mem := newMemoryMonitor(clientset, uint64(cfg.MemoryGrowthLimit))

		loops := newActivityLoops(rec, cfg, sched, workerNodes, denyServer, prober, bpfBaseline, mem, restartMon)
		loops.start(runCtx)

		<-runCtx.Done()
		loops.wait()

		By("checking the liveness client (Gate 2: no established-connection disruption)")
		checkLivenessClientHealth(rec)

		if cfg.Enable462Guard {
			By("checking the #462 port-reuse driver")
			checkPortReuseClientHealth(rec, reuseClient.Name)
			By("scanning agent policy event logs for the #462 cleanup-race signature")
			scanForConntrackRace(rec, workerNodes)
		}

		By("draining pod churn (quiet window for the leak gate)")
		deleteChurnCronJobs(churnJobs)

		By("verifying BPF state returned to baseline after churn drained")
		assertNoBPFLeak(rec, bpfBaseline, workerNodes)

		By("verifying NPA container memory stayed within the growth budget")
		mem.finalize(rec)

		By("verifying the nodeagent did not restart (Gate 3)")
		restartMon.finalize(rec, workerNodes)

		summary := rec.Summary()
		Expect(summary).To(BeEmpty(), "soak detected violations:\n"+summary)
	})

	AfterAll(func() {
		for _, p := range []*v1.Pod{reuseClient, openDest, liveness, prober, allowServer, denyServer} {
			if p != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
		for _, np := range []*network.NetworkPolicy{driverDeny, churnPolicy, allowPolicy, denyPolicy} {
			if np != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			}
		}
	})
})

// buildNginxPod creates an nginx server pod pinned to a node.
func buildNginxPod(label, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: label, Namespace: namespace,
			Labels: map[string]string{"app": label},
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
			}},
		},
	}
}

// buildProberPod creates the long-lived pod the probe sweep execs curl from.
func buildProberPod(nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: proberLabel, Namespace: namespace,
			Labels: map[string]string{"app": proberLabel},
		},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyAlways,
			Containers: []v1.Container{{
				Name: "prober", Image: driverImage,
				Command: []string{"sleep", "infinity"},
			}},
		},
	}
}

// buildIngressDenyPolicy denies all ingress to pods matching app=label.
func buildIngressDenyPolicy(name, label string) *network.NetworkPolicy {
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name(name).
		PodSelector("app", label).
		SetPolicyTypes([]network.PolicyType{network.PolicyTypeIngress}).
		Build()
}

// buildIngressAllowPolicy allows ingress from the given source labels to pods
// matching app=targetLabel, with an explicit Ingress rule. This makes the allowed
// server's return path depend on NPA's conntrack (not default-allow), so a kill
// that breaks conntrack also breaks the liveness client.
func buildIngressAllowPolicy(name, targetLabel string, sourceLabels ...string) *network.NetworkPolicy {
	var peers []network.NetworkPolicyPeer
	for _, src := range sourceLabels {
		peers = append(peers, network.NetworkPolicyPeer{
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": src}},
		})
	}
	return &network.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: network.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": targetLabel}},
			PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			Ingress:     []network.NetworkPolicyIngressRule{{From: peers}},
		},
	}
}

// getLinuxWorkerNodes returns Amazon Linux worker nodes.
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
