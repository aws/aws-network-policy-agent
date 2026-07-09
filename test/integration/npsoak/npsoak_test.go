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
		// Eventually, not a single probe: NPA programming can exceed a fixed settle under load.
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
			Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
				fmt.Sprintf("enforcement regressed to CONNECTED during churn at sweep %d", sweeps))
			sweeps++
			// Track the peak so the end<=baseline leak check below is not vacuous: without
			// an observed rise it can't tell "no leak" from "churn never programmed".
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
		// Poll rather than a fixed sleep: teardown latency varies, and a leak is a
		// sustained excess, so give it a bounded window for both progs and maps to
		// settle to baseline (they can drain at slightly different times).
		Eventually(func() bool {
			endProgs, endMaps := bpfCounts(nodeName)
			GinkgoWriter.Printf("drain: progs=%d maps=%d (baseline progs=%d maps=%d)\n",
				endProgs, endMaps, baselineProgs, baselineMaps)
			return endProgs <= baselineProgs && endMaps <= baselineMaps
		}, 4*time.Minute, 20*time.Second).Should(BeTrue(),
			"BPF program/map count did not return to baseline after churn drained (leak)")

		By("proving the server is still alive and enforcement was the reason for BLOCKED")
		// Dropping the deny policy must restore reachability; otherwise the BLOCKED
		// results above could be a dead server, not enforcement. Delete via the client
		// (tolerating NotFound) since DeleteNetworkPolicy treats the terminal NotFound
		// as an error. The 3m window is generous: NPA can take over a minute to
		// reprogram after a churn window. It proves liveness, not teardown latency.
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
