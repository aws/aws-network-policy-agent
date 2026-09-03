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
	serverApp  = "np-soak-server"
	clientApp  = "np-soak-client"
	churnApp   = "np-soak-churn"
	controlApp = "np-soak-open"

	serverPort      = 80
	podReadyTimeout = 2 * time.Minute
	probeInterval   = 30 * time.Second
	// bpfCounts spins up a privileged pod, so sample coarser than the probe sweep.
	bpfSampleInterval = 2 * time.Minute

	// Enforcement-latency SLO: in standard (non-strict) mode a brand-new selected pod
	// may briefly accept traffic before programming completes, so the fail-open
	// assertion is "not CONNECTED past this age" — NOT "never CONNECTED".
	churnConvergenceDeadline = 10 * time.Second

	// Skip probing pods older than this: near activeDeadlineSeconds (45s) a pod can
	// be deleted DURING the probe pair — NPA detaches while nginx serves through
	// termination grace, reading CONNECTED twice (false fail-open). 45s minus two 3s
	// probe timeouts plus slack.
	churnProbeMaxAge = 35 * time.Second

	// Floor of churn-pod deny verifications per this much soak time, so the
	// fail-open check can't pass vacuously.
	churnVerifiedPerWindow = 5 * time.Minute
)

var _ = Describe("Network Policy enforcement under sustained pod churn", Ordered, func() {
	var (
		serverDeploy  *appsv1.Deployment
		controlDeploy *appsv1.Deployment
		serverIP      string
		controlIP     string
		clientPod     *v1.Pod
		denyPolicy    *network.NetworkPolicy
		churnPolicy   *network.NetworkPolicy
		churnJob      *batchv1.CronJob
		nodeName      string
	)

	BeforeAll(func() {
		By("deploying an nginx server (Deployment) and a client on the same node")
		serverDeploy = buildNginxDeployment(serverApp)
		_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeploy)
		Expect(err).ToNot(HaveOccurred())

		serverPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", serverApp)
		Expect(err).ToNot(HaveOccurred())
		Expect(serverPods).To(HaveLen(1), "expected exactly one server pod")
		serverIP = serverPods[0].Status.PodIP
		Expect(serverIP).ToNot(BeEmpty())
		nodeName = serverPods[0].Spec.NodeName

		clientPod = buildClientPod(clientApp, nodeName)
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("deploying a negative-control nginx (no policy selects it) on the same node")
		// Over-enforcement detector, real-time attribution oracle, and — same image as
		// the churn pods — the listener canary behind their BLOCKED verdicts.
		controlDeploy = buildNginxDeploymentOnNode(controlApp, nodeName)
		_, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, controlDeploy)
		Expect(err).ToNot(HaveOccurred())
		controlPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", controlApp)
		Expect(err).ToNot(HaveOccurred())
		Expect(controlPods).To(HaveLen(1), "expected exactly one control pod")
		controlIP = controlPods[0].Status.PodIP
		Expect(controlIP).ToNot(BeEmpty())

		By("verifying the server is reachable before any policy is applied")
		// Eventually: pod readiness doesn't guarantee nginx is accepting yet.
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
		churnVerified := 0
		peakProgs := baselineProgs
		// Sample coarsely (privileged pod per sample), but don't rely on wall-clock
		// luck for the churn peak: force one sample when churn pods are first observed
		// Running — they're programmed while Running (NPA detaches on delete).
		sampleBPF := func() {
			if p, _ := bpfCounts(nodeName); p > peakProgs {
				peakProgs = p
			}
		}
		nextBPFSample := time.Now().Add(bpfSampleInterval)
		for time.Now().Before(deadline) {
			time.Sleep(probeInterval)
			now := time.Now()

			// Per-sweep invariants (target / selected-by-policy / expected):
			//   server  | yes | BLOCKED   -> else enforcement regressed
			//   control | no  | CONNECTED -> else over-enforcement
			//   churn (age in window) | yes | BLOCKED -> else fail-open on new pod
			// Re-resolve IPs first: a Deployment replacement mid-soak otherwise
			// leaves both probes on a stale IP (see currentPodIP).
			serverIP = currentPodIP(serverApp, serverIP)
			controlIP = currentPodIP(controlApp, controlIP)
			Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
				fmt.Sprintf("enforcement regressed to CONNECTED during churn at sweep %d", sweeps))
			verifyControlReachable(clientPod.Name, controlIP)
			churnVerified += verifyChurnPodsEnforced(clientPod.Name, now)
			sweeps++

			if !churnConfirmed && churnPodsRunning() {
				churnConfirmed = true
				sampleBPF() // churn just landed: pods are Running/programmed right now
			}
			if now.After(nextBPFSample) {
				sampleBPF()
				nextBPFSample = now.Add(bpfSampleInterval)
			}
		}
		Expect(sweeps).To(BeNumerically(">=", 1), "soak window too short to run a probe sweep")
		Expect(churnConfirmed).To(BeTrue(),
			"no churn pod was ever observed Running; churn never landed and the leak check would be vacuous")
		Expect(peakProgs).To(BeNumerically(">", baselineProgs),
			"churn never raised the BPF program count above baseline, so the leak check "+
				"would be vacuous; churn pods may be too short-lived for NPA to program them")
		// Non-vacuity: enough past-deadline churn pods must actually have been probed.
		minChurnVerified := int(soakDuration / churnVerifiedPerWindow)
		if minChurnVerified < 1 {
			minChurnVerified = 1
		}
		Expect(churnVerified).To(BeNumerically(">=", minChurnVerified), fmt.Sprintf(
			"only %d churn pods were probed past the convergence deadline (want >= %d); the "+
				"fail-open check is vacuous — churn pods may not be living long enough", churnVerified, minChurnVerified))

		By("stopping churn and waiting for BPF state to drain back to baseline")
		Expect(fw.K8sClient.Delete(ctx, churnJob)).To(Succeed())
		churnJob = nil
		// Poll, not a fixed sleep: teardown latency varies and a leak is a sustained excess.
		Eventually(func() bool {
			endProgs, endMaps := bpfCounts(nodeName)
			GinkgoWriter.Printf("drain: progs=%d maps=%d (baseline progs=%d maps=%d)\n",
				endProgs, endMaps, baselineProgs, baselineMaps)
			return endProgs <= baselineProgs && endMaps <= baselineMaps
		}, 4*time.Minute, 20*time.Second).Should(BeTrue(),
			"BPF program/map count did not return to baseline after churn drained (leak)")

		By("confirming enforcement still holds after churn drained")
		// The drain check uses `<= baseline`, so a wrongly-detached server program
		// would pass it; this probe catches that silent enforcement loss. Refresh the
		// IP: drain polling can take minutes.
		serverIP = currentPodIP(serverApp, serverIP)
		Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
			"enforcement regressed after churn drained: server reachable while deny policy still applied")

		By("removing the deny policy and confirming the server unprograms back to reachable")
		// The per-sweep control probe already ruled out a dead server/node in real
		// time, so a failure here isolates to the unprogram path.
		Expect(client.IgnoreNotFound(fw.K8sClient.Delete(ctx, denyPolicy))).To(Succeed())
		denyPolicy = nil
		Eventually(func() string {
			// Refresh per poll: this runs minutes after the sweep loop stopped
			// maintaining serverIP.
			serverIP = currentPodIP(serverApp, serverIP)
			return execConnect(clientPod.Name, serverIP, serverPort)
		},
			3*time.Minute, probeInterval).Should(Equal("CONNECTED"),
			"server did not become reachable after removing the deny policy; NPA may not have "+
				"unprogrammed the ingress-deny (control stayed reachable throughout, so the node is healthy)")
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
		for _, d := range []*appsv1.Deployment{serverDeploy, controlDeploy} {
			if d != nil {
				fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, d)
			}
		}
	})
})
