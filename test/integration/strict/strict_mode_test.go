package strict

import (
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

const serverPort = 8080

var _ = Describe("Strict Mode Test Cases", func() {
	Context("when pod is launched", func() {
		var clientPod *v1.Pod
		var podName = "clientpod"

		BeforeEach(func() {
			By("Creating an idle client pod", func() {
				clientPod = deployIdlePod(podName, namespace)
			})
		})

		It("by default should not have connectivity to external network", func() {
			host, port := externalProbeTarget(fw.Options.IpFamily)
			By("verifying egress to the external endpoint is denied", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, podName, host, port)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"strict mode should deny egress from a pod with no network policy")
			})
			By("verifying the deny persists", func() {
				Consistently(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, podName, host, port)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
					"deny should not flap while no policy allows the traffic")
			})
		})

		AfterEach(func() {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		})
	})

	Context("when a network policy is applied which allows communication between client and server", func() {
		var (
			serverPod           *v1.Pod
			clientDeployment    *appsv1.Deployment
			serverPodIP         string
			serverName          = "serverpod"
			clientName          = "clientdeploy"
			serverNetworkPolicy *network.NetworkPolicy
			clientNetworkPolicy *network.NetworkPolicy
		)

		BeforeEach(func() {
			By("Deploying a server pod with allow all ingress network policy", func() {
				ingressPeer := manifest.NewIngressRuleBuilder().
					AddPeer(nil, nil, "0.0.0.0/0").
					AddPeer(nil, nil, "::/0").
					AddPort(serverPort, v1.ProtocolTCP).
					Build()

				serverNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("server-ingress-policy").
					PodSelector("app", serverName).
					AddIngressRule(ingressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())

				serverContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: serverPort}).
					Build()

				serverPod = manifest.NewDefaultPodBuilder().
					Name(serverName).
					Namespace(namespace).
					AddLabel("app", serverName).
					Container(serverContainer).
					Build()

				pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 1*time.Minute)
				Expect(err).ToNot(HaveOccurred())
				serverPodIP = pod.Status.PodIP
			})

			By("Deploying an idle client deployment and an egress policy to allow communication with server", func() {
				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": serverName}, "").
					AddPort(serverPort, v1.ProtocolTCP).
					Build()

				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("client-egress-policy").
					PodSelector("app", clientName).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())

				clientDeployment = deployIdleDeployment(clientName, namespace, 1)
			})
		})

		It("allows egress once the policy is enforced, and a second replica sharing the policy is also allowed", func() {
			var firstPod, secondPod string

			By("resolving the first client replica", func() {
				firstPod = podNameForReplica(namespace, clientName, "")
			})

			// First pod cold-starts in strict default-deny; allowed once the egress rule is programmed.
			By("verifying the first replica eventually reaches the server", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, firstPod, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"first replica should reach the server once the egress policy is programmed")
			})

			By("scaling the client deployment to 2", func() {
				err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, clientName, 2)
				Expect(err).ToNot(HaveOccurred())
				secondPod = podNameForReplica(namespace, clientName, firstPod)
			})

			// The second replica shares the pod identifier's already-programmed maps, so it should
			// be allowed without a cold-start deny. Consistently from the first poll asserts that
			// instantaneous property: a replica that wrongly cold-started would probe CLOSE early.
			// (We do not assert the first replica's initial deny window; catching it depends on
			// racing the probe against datapath programming, which is the flake this rewrite removes.)
			By("verifying the second replica reaches the server without a cold-start deny", func() {
				Consistently(stableProbe(namespace, secondPod, serverPodIP, serverPort),
					utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
					"second replica should reach the server immediately via the shared policy maps")
			})

			By("verifying connectivity is stable for the first replica", func() {
				Consistently(stableProbe(namespace, firstPod, serverPodIP, serverPort),
					utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
					"allow should not flap once the policy is enforced")
			})
		})

		AfterEach(func() {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, clientDeployment)
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverNetworkPolicy)
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
		})
	})
})

// externalProbeTarget returns an off-cluster host and port for the cluster's IP family.
func externalProbeTarget(ipFamily string) (string, int) {
	if ipFamily == "IPv6" {
		return "2001:4860:4860::8888", 53
	}
	return "8.8.8.8", 53
}

// deployIdlePod creates a running busybox pod that sleeps, so probes can be exec'd on demand.
func deployIdlePod(name, ns string) *v1.Pod {
	ctnr := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()

	pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, manifest.NewDefaultPodBuilder().
		Name(name).
		Namespace(ns).
		Container(ctnr).
		Build(), 2*time.Minute)
	Expect(err).ToNot(HaveOccurred())
	return pod
}

// deployIdleDeployment creates a busybox deployment whose pods sleep, so probes can be exec'd on demand.
func deployIdleDeployment(name, ns string, replicas int) *appsv1.Deployment {
	ctnr := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()

	deployment := manifest.NewDefaultDeploymentBuilder().
		Name(name).
		Replicas(replicas).
		Namespace(ns).
		AddLabel("app", name).
		Container(ctnr).
		Build()

	dp, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
	Expect(err).ToNot(HaveOccurred())
	return dp
}

// podNameForReplica polls for a pod with app=name, skipping excludeName, since scaling
// does not block until the new pod registers.
func podNameForReplica(ns, name, excludeName string) string {
	var podName string
	Eventually(func() bool {
		pods, err := fw.PodManager.GetPodsWithLabel(ctx, ns, "app", name)
		if err != nil {
			return false
		}
		for _, pod := range pods {
			if pod.Name != excludeName {
				podName = pod.Name
				return true
			}
		}
		return false
	}, utils.ProbeTimeout, utils.ProbeInterval).Should(BeTrue(), "expected a client replica with app=%s", name)
	return podName
}

// stableProbe returns a Consistently poll function that treats a transient exec error as
// the last observed verdict rather than a failure. Consistently aborts on the first non-nil
// error, so an isolated kubelet/API exec hiccup would otherwise flake the stability check.
// The first verdict is seeded eagerly (tolerating a few early exec errors) so the initial
// poll never fails purely because exec was briefly unavailable.
func stableProbe(ns, podName, host string, port int) func() string {
	var last string
	Eventually(func() error {
		verdict, err := fw.PodManager.TCPProbe(ns, podName, host, port)
		if err != nil {
			return err
		}
		last = verdict
		return nil
	}, utils.ProbeTimeout, utils.ProbeInterval).Should(Succeed(), "probe exec never succeeded for pod %s", podName)

	return func() string {
		verdict, err := fw.PodManager.TCPProbe(ns, podName, host, port)
		if err != nil {
			GinkgoWriter.Printf("stableProbe %s:%d exec error (using last verdict %q): %v\n", host, port, last, err)
			return last
		}
		last = verdict
		return verdict
	}
}
