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
	// bpfSampleInterval is coarser than probeInterval: each bpfCounts spins up a
	// privileged pod, so sampling too often would pollute the BPF count it measures.
	bpfSampleInterval = 2 * time.Minute

	// churnConvergenceDeadline encodes an enforcement-latency SLO: in standard
	// (non-strict) mode a brand-new policy-selected pod may briefly accept traffic
	// before NPA finishes programming it, so the fail-open assertion is "no churn
	// pod is still CONNECTED once its age exceeds this deadline" — NOT "never
	// CONNECTED". Tightening this constant tightens the programming-latency the soak
	// gate will catch regressions against.
	churnConvergenceDeadline = 10 * time.Second

	// churnProbeMaxAge caps how old a churn pod may be and still be probed. A pod
	// approaching its activeDeadlineSeconds (45s) can be deleted DURING the probe:
	// NPA detaches on the delete event while nginx keeps serving through termination
	// grace, so a probe pair (~3s each) spanning the deadline reads CONNECTED twice
	// and would fail the spec as fail-open on a pod that was correctly enforced its
	// whole life. Cohorts of 5 are probed sequentially with each BLOCKED probe
	// burning its full 3s timeout, so a sweep reaching the cohort at age ~30s probes
	// the last pod at ~42-45s — inside that band. Capping at activeDeadline minus
	// two probe timeouts plus slack keeps every probe pair strictly inside the pod's
	// lifetime; the probeable window (10s-35s) still comfortably spans the 30s sweep.
	churnProbeMaxAge = 35 * time.Second

	// churnVerifiedPerWindow is the floor of successful churn-pod deny verifications
	// required per this much soak time, so the fail-open check can't pass vacuously
	// (e.g. if churn pods never lived long enough to be probed).
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

		By("deploying a negative-control nginx (no policy selects it) on the same node")
		// Selected by no policy, so it must stay CONNECTED for the whole run. It is the
		// over-enforcement detector (false-DENY), the real-time attribution oracle
		// (server BLOCKED + control CONNECTED = enforcement healthy), and — since it
		// runs the same nginx image as the churn pods — the listener canary that proves
		// a BLOCKED churn verdict means "enforced", not "listener never came up".
		controlDeploy = buildNginxDeploymentOnNode(controlApp, nodeName)
		_, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, controlDeploy)
		Expect(err).ToNot(HaveOccurred())
		controlPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", controlApp)
		Expect(err).ToNot(HaveOccurred())
		Expect(controlPods).To(HaveLen(1), "expected exactly one control pod")
		controlIP = controlPods[0].Status.PodIP
		Expect(controlIP).ToNot(BeEmpty())

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
		churnVerified := 0
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
			now := time.Now()

			// Per-sweep invariant table (target / selected-by-policy / expected):
			//   server  | yes (ingress deny) | BLOCKED   -> else enforcement regressed
			//   control | no                 | CONNECTED -> else over-enforcement
			//   churn (age > deadline) | yes | BLOCKED   -> else fail-open on new pod
			//
			// Re-resolve the server/control IPs first: a Deployment replacement
			// mid-soak otherwise leaves both probes on a stale IP (see currentPodIP).
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
		// Non-vacuity for the fail-open detector: require enough past-deadline churn
		// pods to have been probed, else the "no churn pod stayed CONNECTED" result is
		// meaningless (churn pods may never have lived long enough to probe).
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
		// (Drain polling can take minutes; refresh the IP in case the pod was replaced.)
		serverIP = currentPodIP(serverApp, serverIP)
		Expect(execConnect(clientPod.Name, serverIP, serverPort)).To(Equal("BLOCKED"),
			"enforcement regressed after churn drained: server reachable while deny policy still applied")

		By("removing the deny policy and confirming the server unprograms back to reachable")
		// Exercises the unprogram path: after the deny is removed the server must go
		// CONNECTED again. The per-sweep control probe already ruled out "server (or
		// node) died mid-run" in real time, so a failure here isolates to the unprogram
		// path rather than the old ambiguous "server may have died" guess.
		Expect(client.IgnoreNotFound(fw.K8sClient.Delete(ctx, denyPolicy))).To(Succeed())
		denyPolicy = nil
		Eventually(func() string {
			// Refresh per poll: this check runs up to 3 minutes after the sweep loop
			// stopped maintaining serverIP, so a replacement here would otherwise
			// false-fail the unprogram check against a stale IP.
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
