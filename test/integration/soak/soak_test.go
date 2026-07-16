package soak

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
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
	// bpfSampleInterval is coarser than probeInterval: each bpfCounts spins up a
	// privileged pod, so sampling too often would pollute the BPF count it measures.
	bpfSampleInterval = 2 * time.Minute
)

var _ = Describe("Network Policy enforcement under sustained pod churn", Ordered, func() {
	var (
		serverDeploy *appsv1.Deployment
		serverIP     string
		clientPod    *v1.Pod
		denyPolicy   *network.NetworkPolicy
		churnPolicy  *network.NetworkPolicy
		churnJob     *batchv1.CronJob
		nodeName     string
	)

	BeforeAll(func() {
		By("deploying an nginx server (Deployment) and a client on the same node")
		// The server is a 1-replica Deployment, not a bare Pod: EKS network policy is
		// documented to apply only to owner-referenced pods, and NPA's per-pod identity
		// (last "-<segment>" stripped) would collide between bare pods sharing a prefix.
		serverDeploy = buildNginxDeployment(serverApp)
		_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeploy)
		Expect(err).ToNot(HaveOccurred())

		// Resolve the Deployment's single pod for its IP, node, and exec target.
		serverPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", serverApp)
		Expect(err).ToNot(HaveOccurred())
		Expect(serverPods).To(HaveLen(1), "expected exactly one server pod")
		serverIP = serverPods[0].Status.PodIP
		Expect(serverIP).ToNot(BeEmpty())
		nodeName = serverPods[0].Spec.NodeName

		clientPod = buildClientPod(clientApp, nodeName)
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("verifying the server is reachable before any policy is applied")
		// Eventually, not a single probe: readiness guarantees the pod is Running, not
		// that nginx is accepting connections yet, so the first probe can race the
		// listener coming up. Symmetric with the enforcement check.
		Eventually(func() string { return execConnect(clientPod.Name, serverIP, serverPort) },
			90*time.Second, probeInterval).Should(Equal("CONNECTED"),
			"server never became reachable before any policy was applied")
	})

	It("enforces a deny policy that holds while pods churn, without leaking BPF state", func() {

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
		// bpfCounts spins up a privileged pod, so sampling it every 30s alongside the
		// probe would add scheduling load; sample on a coarser cadence. But do not
		// rely on wall-clock luck to catch the churn peak: the reliable moment is
		// right after a churn Job first completes, when its pods are still in their
		// TTL window and NPA still has them programmed (it detaches on delete, not on
		// completion). So force one sample there, and take periodic ones after.
		sampleBPF := func() {
			if p, _ := bpfCounts(nodeName); p > peakProgs {
				peakProgs = p
			}
		}
		nextBPFSample := time.Now().Add(bpfSampleInterval)
		for time.Now().Before(deadline) {
			time.Sleep(probeInterval)
			Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
				fmt.Sprintf("enforcement regressed to CONNECTED during churn at sweep %d", sweeps))
			sweeps++
			if !churnConfirmed && churnRanSuccessfully() {
				churnConfirmed = true
				sampleBPF() // churn just landed: pods are programmed right now
			}
			if time.Now().After(nextBPFSample) {
				sampleBPF()
				nextBPFSample = time.Now().Add(bpfSampleInterval)
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

		By("confirming enforcement still holds after churn drained")
		// The drain check uses `endProgs <= baseline`, so a server whose own BPF
		// program was wrongly detached mid-run (enforcement lost) would come in BELOW
		// baseline and still pass the leak check — and the CONNECTED check below would
		// then expect exactly that regression. Probe once here, while the deny policy
		// is still applied, to catch a silent enforcement loss the count comparison can't.
		Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
			"enforcement regressed after churn drained: server reachable while deny policy still applied")

		By("proving the server is still alive and enforcement was the reason for BLOCKED")
		// Restored reachability confirms the BLOCKED results above were enforcement,
		// not a dead server. Delete via the client (tolerating NotFound) since
		// DeleteNetworkPolicy reports the terminal NotFound as an error.
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
		if clientPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		}
		if serverDeploy != nil {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeploy)
		}
	})
})
