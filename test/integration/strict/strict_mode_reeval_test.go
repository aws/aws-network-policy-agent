package strict

import (
	"strconv"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const streamLogPath = "/tmp/strict-reeval-stream.log"

var _ = Describe("Strict Mode Re-evaluation Test Cases", func() {
	// Scenario 1 of 4: removing the last ClusterNetworkPolicy.
	Context("when the final ClusterNetworkPolicy allowing an established connection is removed", func() {
		var (
			serverPod           *v1.Pod
			clientPod           *v1.Pod
			serverNetworkPolicy *network.NetworkPolicy
			clientCNP           *unstructured.Unstructured
			serverPodIP         string
			serverName          = "reevalcnpserver"
			clientName          = "reevalcnpclient"
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
					Name("strict-reeval-server-ingress").
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

			By("Deploying an idle client pod without a network policy", func() {
				clientContainer := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"sleep 1000000"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Name(clientName).
					Namespace(namespace).
					AddLabel("app", clientName).
					Container(clientContainer).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating an egress ClusterNetworkPolicy to allow communication with the server", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-server").
					AddPort(serverPort, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(map[string]string{}, map[string]string{"app": serverName}),
					})

				clientCNP = manifest.NewClusterNetworkPolicyBuilder().
					Name("strict-reeval-client-egress").
					SubjectPods(map[string]string{}, map[string]string{"app": clientName}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, clientCNP)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("denies traffic on an established connection after the ClusterNetworkPolicy is removed", func() {
			By("verifying the ClusterNetworkPolicy eventually allows a new connection", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"client should reach the server once the ClusterNetworkPolicy is programmed")
			})

			By("starting a persistent HTTP connection and verifying it receives responses", func() {
				startPersistentHTTPStream(clientName, serverPodIP, serverPort)
				Eventually(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(BeNumerically(">", 0),
					"persistent connection should receive a response before policy removal")
			})

			By("removing the final ClusterNetworkPolicy", func() {
				err := fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, clientCNP)
				Expect(err).ToNot(HaveOccurred())
			})

			By("verifying the established connection is re-evaluated and blocked", func() {
				responseCount := waitForPersistentHTTPResponseCountToStabilize(clientName)

				Consistently(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal(responseCount),
					"removing the ClusterNetworkPolicy must block the established connection")
			})

			By("verifying new connections are denied", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"new connections should be denied after the ClusterNetworkPolicy is removed")
			})
		})

		AfterEach(func() {
			if clientCNP != nil {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, clientCNP)
			}
			if clientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if serverNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverNetworkPolicy)
			}
		})
	})

	// Port that the test traffic never uses, so the "decoy" CNP below stays active without deciding the scenario's outcome.
	const decoyPort = 9999

	// Scenario 2 of 4: removing the last NetworkPolicy.
	Context("when the last NetworkPolicy allowing an established connection is removed", func() {
		var (
			serverPod           *v1.Pod
			clientPod           *v1.Pod
			serverNetworkPolicy *network.NetworkPolicy
			clientNetworkPolicy *network.NetworkPolicy
			decoyCNP            *unstructured.Unstructured
			serverPodIP         string
			serverName          = "reevalnpserver"
			clientName          = "reevalnpclient"
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
					Name(serverName+"-ingress").
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

			By("Deploying an idle client pod", func() {
				clientContainer := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"sleep 1000000"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Name(clientName).
					Namespace(namespace).
					AddLabel("app", clientName).
					Container(clientContainer).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a NetworkPolicy allowing the client to reach the server", func() {
				egressRule := manifest.NewEgressRuleBuilder().
					AddPeer(map[string]string{}, map[string]string{"app": serverName}, "").
					AddPort(serverPort, v1.ProtocolTCP).
					Build()

				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name(clientName+"-egress").
					PodSelector("app", clientName).
					AddEgressRule(egressRule).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a decoy Baseline-tier ClusterNetworkPolicy", func() {
				// Baseline tier and an unrelated port: this CNP must stay active but
				// must not itself decide whether the client can reach the server, or
				// removing the NetworkPolicy below would have no observable effect.
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("decoy-allow").
					AddPort(decoyPort, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(map[string]string{}, map[string]string{"app": serverName}),
					})

				decoyCNP = manifest.NewClusterNetworkPolicyBuilder().
					Name(clientName+"-decoy").
					Tier("Baseline").
					SubjectPods(map[string]string{}, map[string]string{"app": clientName}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, decoyCNP)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("denies traffic on an established connection after the last NetworkPolicy is removed", func() {
			By("verifying the NetworkPolicy eventually allows a new connection", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"client should reach the server once the NetworkPolicy is programmed")
			})

			By("starting a persistent HTTP connection and verifying it receives responses", func() {
				startPersistentHTTPStream(clientName, serverPodIP, serverPort)
				Eventually(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(BeNumerically(">", 0),
					"persistent connection should receive a response before policy removal")
			})

			By("removing the last NetworkPolicy", func() {
				err := fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("verifying the established connection is re-evaluated and blocked", func() {
				responseCount := waitForPersistentHTTPResponseCountToStabilize(clientName)

				Consistently(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal(responseCount),
					"removing the last NetworkPolicy must block the established connection")
			})

			By("verifying new connections are denied", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"new connections should be denied after the last NetworkPolicy is removed")
			})
		})

		AfterEach(func() {
			if decoyCNP != nil {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, decoyCNP)
			}
			if clientNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
			}
			if clientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if serverNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverNetworkPolicy)
			}
		})
	})

	// Scenario 3 of 4: adding a NetworkPolicy.
	Context("when a NetworkPolicy is added while an established connection exists", func() {
		var (
			serverPod           *v1.Pod
			clientPod           *v1.Pod
			serverNetworkPolicy *network.NetworkPolicy
			clientNetworkPolicy *network.NetworkPolicy
			allowCNP            *unstructured.Unstructured
			serverPodIP         string
			serverName          = "reevaladdnpserver"
			clientName          = "reevaladdnpclient"
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
					Name(serverName+"-ingress").
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

			By("Deploying an idle client pod without a NetworkPolicy", func() {
				clientContainer := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"sleep 1000000"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Name(clientName).
					Namespace(namespace).
					AddLabel("app", clientName).
					Container(clientContainer).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a Baseline-tier ClusterNetworkPolicy to allow communication with the server", func() {
				// Baseline tier so it yields once the NetworkPolicy below is added;
				// an Admin-tier CNP would keep allowing the traffic regardless, and
				// the added policy would never be observed to have any effect.
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-server").
					AddPort(serverPort, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(map[string]string{}, map[string]string{"app": serverName}),
					})

				allowCNP = manifest.NewClusterNetworkPolicyBuilder().
					Name(clientName+"-egress").
					Tier("Baseline").
					SubjectPods(map[string]string{}, map[string]string{"app": clientName}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, allowCNP)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("denies traffic on an established connection after a restrictive NetworkPolicy is added", func() {
			By("verifying the ClusterNetworkPolicy eventually allows a new connection", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"client should reach the server once the ClusterNetworkPolicy is programmed")
			})

			By("starting a persistent HTTP connection and verifying it receives responses", func() {
				startPersistentHTTPStream(clientName, serverPodIP, serverPort)
				Eventually(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(BeNumerically(">", 0),
					"persistent connection should receive a response before the NetworkPolicy is added")
			})

			By("adding a NetworkPolicy that denies all egress from the client", func() {
				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name(clientName+"-deny-all-egress").
					PodSelector("app", clientName).
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("verifying the established connection is re-evaluated and blocked", func() {
				responseCount := waitForPersistentHTTPResponseCountToStabilize(clientName)

				Consistently(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal(responseCount),
					"adding the restrictive NetworkPolicy must block the established connection")
			})

			By("verifying new connections are denied", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"new connections should be denied after the restrictive NetworkPolicy is added")
			})
		})

		AfterEach(func() {
			if clientNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
			}
			if allowCNP != nil {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, allowCNP)
			}
			if clientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if serverNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverNetworkPolicy)
			}
		})
	})

	// Scenario 4 of 4: removing both the NetworkPolicy and ClusterNetworkPolicy at once.
	Context("when both the NetworkPolicy and ClusterNetworkPolicy allowing an established connection are removed at once", func() {
		var (
			serverPod           *v1.Pod
			clientPod           *v1.Pod
			serverNetworkPolicy *network.NetworkPolicy
			clientNetworkPolicy *network.NetworkPolicy
			clientCNP           *unstructured.Unstructured
			serverPodIP         string
			serverName          = "reevalbothserver"
			clientName          = "reevalbothclient"
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
					Name(serverName+"-ingress").
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

			By("Deploying an idle client pod", func() {
				clientContainer := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"sleep 1000000"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Name(clientName).
					Namespace(namespace).
					AddLabel("app", clientName).
					Container(clientContainer).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a NetworkPolicy allowing the client to reach the server", func() {
				egressRule := manifest.NewEgressRuleBuilder().
					AddPeer(map[string]string{}, map[string]string{"app": serverName}, "").
					AddPort(serverPort, v1.ProtocolTCP).
					Build()

				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name(clientName+"-egress").
					PodSelector("app", clientName).
					AddEgressRule(egressRule).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a Baseline-tier ClusterNetworkPolicy also allowing the client to reach the server", func() {
				// Tier doesn't matter for the outcome here (the NetworkPolicy tier's
				// ALLOW already takes precedence over a Baseline-tier CNP), only for
				// pinning entry 1 = POLICIES_APPLIED before both policies are removed.
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-server").
					AddPort(serverPort, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(map[string]string{}, map[string]string{"app": serverName}),
					})

				clientCNP = manifest.NewClusterNetworkPolicyBuilder().
					Name(clientName+"-egress").
					Tier("Baseline").
					SubjectPods(map[string]string{}, map[string]string{"app": clientName}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, clientCNP)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("denies traffic on an established connection after both policies are removed at once", func() {
			By("verifying the policies eventually allow a new connection", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"client should reach the server once the policies are programmed")
			})

			By("starting a persistent HTTP connection and verifying it receives responses", func() {
				startPersistentHTTPStream(clientName, serverPodIP, serverPort)
				Eventually(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(BeNumerically(">", 0),
					"persistent connection should receive a response before policy removal")
			})

			By("removing both the NetworkPolicy and the ClusterNetworkPolicy", func() {
				err := fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
				err = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, clientCNP)
				Expect(err).ToNot(HaveOccurred())
			})

			By("verifying the established connection is re-evaluated and blocked", func() {
				responseCount := waitForPersistentHTTPResponseCountToStabilize(clientName)

				Consistently(func() (int, error) {
					return persistentHTTPResponseCount(clientName)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal(responseCount),
					"removing both policies at once must block the established connection")
			})

			By("verifying new connections are denied", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"new connections should be denied after both policies are removed")
			})
		})

		AfterEach(func() {
			if clientCNP != nil {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, clientCNP)
			}
			if clientNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
			}
			if clientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if serverNetworkPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverNetworkPolicy)
			}
		})
	})
})

// startPersistentHTTPStream opens one HTTP/1.1 connection and sends a request every second.
// The response log only advances when the server receives the request and returns its echo.
func startPersistentHTTPStream(podName, host string, port int) {
	const script = `
log="$3"
rm -f "$log"
(
	sequence=0
	while true; do
		sequence=$((sequence + 1))
		printf 'GET /echo?msg=strict-reeval-response-%s HTTP/1.1\r\nHost: netexec\r\n\r\n' "$sequence"
		sleep 1
	done | nc "$1" "$2"
) < /dev/null > "$log" 2>&1 &
`

	_, err := fw.PodManager.ExecInPod(namespace, podName, []string{
		"/bin/sh", "-c", script, "sh", host, strconv.Itoa(port), streamLogPath,
	})
	Expect(err).ToNot(HaveOccurred())
}

// persistentHTTPResponseCount returns the number of responses received on the persistent stream.
func persistentHTTPResponseCount(podName string) (int, error) {
	output, err := fw.PodManager.ExecInPod(namespace, podName, []string{
		"/bin/sh", "-c", `grep -c 'strict-reeval-response-' "$1" 2>/dev/null || true`, "sh", streamLogPath,
	})
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(output)
}

// Polls the persistent stream's response count until two consecutive reads (one utils.ProbeInterval apart) agree -> then returns that value 
func waitForPersistentHTTPResponseCountToStabilize(podName string) int {
	var stableCount int
	Eventually(func() (bool, error) {
		first, err := persistentHTTPResponseCount(podName)
		if err != nil {
			return false, err
		}
		time.Sleep(utils.ProbeInterval)
		second, err := persistentHTTPResponseCount(podName)
		if err != nil {
			return false, err
		}
		if first == second {
			stableCount = second
			return true, nil
		}
		return false, nil
	}, utils.EnforcementTimeout, utils.ProbeInterval).Should(BeTrue(),
		"persistent connection's response count should stabilize once the policy change is enforced")
	return stableCount
}
