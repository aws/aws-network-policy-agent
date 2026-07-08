package npsoak

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	serverApp = "np-soak-server"
	clientApp = "np-soak-client"
	churnApp  = "np-soak-churn"

	serverPort      = 80
	podReadyTimeout = 2 * time.Minute
	probeInterval   = 30 * time.Second
)

var _ = Describe("Network Policy enforcement under sustained pod churn", Ordered, func() {
	var (
		server      *v1.Pod
		clientPod   *v1.Pod
		denyPolicy  *network.NetworkPolicy
		churnPolicy *network.NetworkPolicy
		churnJob    *batchv1.CronJob
		nodeName    string
	)

	BeforeAll(func() {
		By("deploying an nginx server and a client on the same node")
		server = buildNginxPod(serverApp)
		var err error
		server, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, server, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		Expect(server.Status.PodIP).ToNot(BeEmpty())
		nodeName = server.Spec.NodeName

		clientPod = buildClientPod(clientApp, nodeName)
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("verifying the server is reachable before any policy is applied")
		Expect(execConnect(clientPod.Name, server.Status.PodIP, serverPort)).To(Equal("CONNECTED"))
	})

	It("enforces a deny policy that holds while pods churn, without leaking BPF state", func() {
		serverIP := server.Status.PodIP

		By("applying an ingress-deny policy to the server")
		denyPolicy = buildIngressDeny("np-soak-deny", serverApp)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyPolicy)).To(Succeed())

		By("verifying enforcement becomes active (server BLOCKED) — proves policy really enforces")
		// Eventually, not a single probe: NPA programming can exceed a fixed settle
		// under load. A persistent CONNECTED here means enforcement never took hold.
		Eventually(func() string { return execConnect(clientPod.Name, serverIP, serverPort) },
			90*time.Second, probeInterval).Should(Equal("BLOCKED"),
			"deny policy never took effect; is network policy enabled and the controller producing PolicyEndpoints?")

		By("capturing the BPF baseline before churn")
		baselineProgs, baselineMaps := bpfCounts(nodeName)
		GinkgoWriter.Printf("baseline: progs=%d maps=%d\n", baselineProgs, baselineMaps)

		By("starting policy-selected pod churn on the node")
		churnPolicy = buildIngressDeny("np-soak-churn-deny", churnApp)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, churnPolicy)).To(Succeed())
		churnJob = buildChurnCronJob(nodeName)
		Expect(fw.K8sClient.Create(ctx, churnJob)).To(Succeed())

		By(fmt.Sprintf("re-verifying enforcement holds every %s for %s", probeInterval, soakDuration))
		deadline := time.Now().Add(soakDuration)
		sweeps, churnConfirmed := 0, false
		peakProgs := baselineProgs
		for time.Now().Before(deadline) {
			time.Sleep(probeInterval)
			// Enforcement must remain correct throughout the churn window.
			Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
				fmt.Sprintf("enforcement regressed to CONNECTED during churn at sweep %d", sweeps))
			sweeps++
			// Track whether churn actually caused NPA to program more BPF than the
			// baseline. Without an observed rise, the end<=baseline leak check below
			// is vacuous (it can't tell "no leak" from "churn never programmed").
			if p, _ := bpfCounts(nodeName); p > peakProgs {
				peakProgs = p
			}
			if !churnConfirmed && churnRanSuccessfully() {
				churnConfirmed = true
			}
		}
		Expect(sweeps).To(BeNumerically(">=", 1), "soak window too short to run a probe sweep")
		Expect(churnConfirmed).To(BeTrue(),
			"no churn pod ran successfully; the leak check would be vacuous")
		Expect(peakProgs).To(BeNumerically(">", baselineProgs),
			"churn never raised the BPF program count above baseline, so the leak check "+
				"would be vacuous; churn pods may be too short-lived for NPA to program them")

		By("stopping churn and waiting for BPF state to drain back to baseline")
		Expect(fw.K8sClient.Delete(ctx, churnJob)).To(Succeed())
		churnJob = nil
		// Poll rather than a fixed sleep: teardown latency varies, and a fixed wait
		// either flakes (too short) or wastes time (too long). The leak is a
		// SUSTAINED excess, so give it a bounded window to settle to baseline.
		var endProgs, endMaps int
		Eventually(func() int {
			endProgs, endMaps = bpfCounts(nodeName)
			GinkgoWriter.Printf("drain: progs=%d maps=%d (baseline progs=%d maps=%d)\n",
				endProgs, endMaps, baselineProgs, baselineMaps)
			return endProgs
		}, 4*time.Minute, 20*time.Second).Should(BeNumerically("<=", baselineProgs),
			"BPF program count did not return to baseline after churn drained (leak)")
		Expect(endMaps).To(BeNumerically("<=", baselineMaps),
			"BPF map count did not return to baseline after churn drained (leak)")

		By("proving the server is still alive and enforcement was the reason for BLOCKED")
		// Dropping the deny policy must restore reachability. If it does not, every
		// BLOCKED above may have been a dead/evicted server rather than enforcement:
		// this is the check that makes the enforcement assertions meaningful.
		//
		// Delete via the client directly (tolerating NotFound) rather than the
		// framework's DeleteNetworkPolicy, whose poll returns the terminal NotFound
		// as an error on successful deletion.
		//
		// Observed on a live cluster: removing a policy and re-allowing traffic can
		// take NPA over a minute to reprogram, especially right after a churn window,
		// so this window is generous (3m). It proves liveness, not teardown latency.
		Expect(client.IgnoreNotFound(fw.K8sClient.Delete(ctx, denyPolicy))).To(Succeed())
		denyPolicy = nil
		Eventually(func() string { return execConnect(clientPod.Name, serverIP, serverPort) },
			3*time.Minute, probeInterval).Should(Equal("CONNECTED"),
			"server unreachable even after removing the deny policy; the BLOCKED results "+
				"above cannot be attributed to enforcement (server may have died mid-run)")
	})

	AfterAll(func() {
		if churnJob != nil {
			fw.K8sClient.Delete(ctx, churnJob)
		}
		for _, np := range []*network.NetworkPolicy{churnPolicy, denyPolicy} {
			if np != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			}
		}
		for _, p := range []*v1.Pod{clientPod, server} {
			if p != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
	})
})
