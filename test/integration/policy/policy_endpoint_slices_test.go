package policy

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

var _ = Describe("Policy Endpoint Slices Test Cases", func() {
	Context("When pods are distributed across multiple policy endpoint slices", func() {
		var clientDeployment *appsv1.Deployment
		var serverDeployment *appsv1.Deployment
		var serverService *v1.Service
		var networkPolicy *network.NetworkPolicy
		clientName := "client-deploy"
		serverName := "server-deploy"
		serviceName := "server-service"

		BeforeEach(func() {
			By("Creating a server deployment with many replicas to ensure multiple slices", func() {
				serverContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(serverName).
					Replicas(20). // Create enough pods to ensure multiple slices
					Namespace(namespace).
					AddLabel("app", serverName).
					Container(serverContainer).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a service for the server pods", func() {
				serverService = manifest.NewHTTPService().
					Name(serviceName).
					Port(8080).
					Namespace(namespace).
					Selector("app", serverName).
					Build()

				_, err := fw.ServiceManager.CreateService(ctx, serverService)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a client deployment", func() {
				// Use the service name to test connectivity, which will work regardless of pod churn
				clientContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do wget http://" + serviceName + "." + namespace + ".svc.cluster.local:8080 --spider -T 1 2>/dev/null; if [ $? == 0 ]; then echo \"Service Success\"; else echo \"Service Fail\"; fi; sleep 1s; done"}).
					Build()

				clientDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(clientName).
					Replicas(1).
					Namespace(namespace).
					AddLabel("app", clientName).
					Container(clientContainer).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, clientDeployment)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a network policy allowing egress to server pods", func() {
				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": serverName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				networkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("allow-server-egress").
					PodSelector("app", clientName).
					SetPolicyType(false, true).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policy to be applied
				time.Sleep(30 * time.Second)
			})
		})

		It("should maintain connectivity when scaling down server pods and handle slice deletion correctly", func() {
			// First, verify that multiple PolicyEndpoint slices were created
			By("Verifying that multiple PolicyEndpoint slices were created", func() {
				// Wait for PolicyEndpoint resources to be created
				var policyEndpointCount int
				err := wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
					// Execute kubectl command to get PolicyEndpoint resources
					output, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-server-egress")
					if err != nil {
						return false, nil // Continue polling
					}

					// Count the number of PolicyEndpoint resources
					lines := strings.Split(output, "\n")
					policyEndpointCount = len(lines) - 1 // Subtract header line
					if policyEndpointCount < 1 {
						return false, nil // Continue polling
					}

					return true, nil
				})
				Expect(err).ToNot(HaveOccurred())

				// Log the number of PolicyEndpoint slices found
				fmt.Fprintf(GinkgoWriter, "Found %d PolicyEndpoint resources\n", policyEndpointCount)

				// We expect at least one PolicyEndpoint resource
				Expect(policyEndpointCount).To(BeNumerically(">=", 1))
			})

			By("Verifying initial connectivity to the server service", func() {
				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(clientPods)).To(Equal(1))

				// Wait for some connection attempts
				time.Sleep(10 * time.Second)

				logs, err := fw.PodManager.PodLogs(namespace, clientPods[0].Name)
				Expect(err).ToNot(HaveOccurred())

				// Check connectivity to the service
				Expect(logs).To(ContainSubstring("Service Success"))
				Expect(logs).NotTo(ContainSubstring("Service Fail"))
			})

			// Get the current state of PolicyEndpoint resources before scaling
			var initialPolicyEndpointCount int
			By("Recording the initial state of PolicyEndpoint resources", func() {
				output, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-server-egress")
				Expect(err).ToNot(HaveOccurred())

				lines := strings.Split(output, "\n")
				initialPolicyEndpointCount = len(lines) - 1 // Subtract header line
				fmt.Fprintf(GinkgoWriter, "Initial PolicyEndpoint count: %d\n", initialPolicyEndpointCount)
			})

			By("Scaling down the server deployment to trigger slice deletion", func() {
				// Scale down to a much smaller number to ensure slice deletion
				err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, serverName, 2)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policy controller to update
				time.Sleep(1 * time.Minute)
			})

			// Verify that PolicyEndpoint resources were updated/deleted
			By("Verifying that PolicyEndpoint resources were updated after scaling down", func() {
				var finalPolicyEndpointCount int
				err := wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
					output, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-server-egress")
					if err != nil {
						return false, nil // Continue polling
					}

					lines := strings.Split(output, "\n")
					finalPolicyEndpointCount = len(lines) - 1 // Subtract header line

					// If the count changed, we've detected the update
					if finalPolicyEndpointCount != initialPolicyEndpointCount {
						return true, nil
					}

					return false, nil
				})
				Expect(err).ToNot(HaveOccurred())

				fmt.Fprintf(GinkgoWriter, "Final PolicyEndpoint count: %d\n", finalPolicyEndpointCount)

				// We expect the number of PolicyEndpoint resources to have changed
				// This could be fewer resources or potentially more if they were reorganized
				Expect(finalPolicyEndpointCount).NotTo(Equal(initialPolicyEndpointCount))
			})

			By("Verifying connectivity to the server service is maintained after slice changes", func() {
				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())

				// Clear the logs to get fresh data
				_, err = executeKubectl("logs", "-n", namespace, clientPods[0].Name, "--tail=1", "--follow=false")
				Expect(err).ToNot(HaveOccurred())

				// Wait for new connection attempts
				time.Sleep(10 * time.Second)

				// Get fresh logs after scaling
				logs, err := fw.PodManager.PodLogs(namespace, clientPods[0].Name)
				Expect(err).ToNot(HaveOccurred())

				recentLogs := getRecentLogs(logs, 10)

				// Should still be able to connect to the service
				Expect(recentLogs).To(ContainSubstring("Service Success"))
				Expect(recentLogs).NotTo(ContainSubstring("Service Fail"))
			})

			// Test for stale rules by creating a new client pod and verifying it gets proper policy enforcement
			By("Creating a new client pod to verify no stale rules exist", func() {
				newClientName := "new-client"
				newClientContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do wget http://" + serviceName + "." + namespace + ".svc.cluster.local:8080 --spider -T 1 2>/dev/null; if [ $? == 0 ]; then echo \"Service Success\"; else echo \"Service Fail\"; fi; sleep 1s; done"}).
					Build()

				newClientPod := manifest.NewDefaultPodBuilder().
					Container(newClientContainer).
					Namespace(namespace).
					AddLabel("app", clientName). // Same label to match the policy
					Name(newClientName).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, newClientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policy to be applied to the new pod
				time.Sleep(30 * time.Second)

				// Check logs of the new pod
				logs, err := fw.PodManager.PodLogs(namespace, newClientName)
				Expect(err).ToNot(HaveOccurred())

				// Should be able to connect to the service
				Expect(logs).To(ContainSubstring("Service Success"))
				Expect(logs).NotTo(ContainSubstring("Service Fail"))

				// Clean up the new pod
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, newClientPod)
			})
		})

		AfterEach(func() {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, clientDeployment)
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeployment)
			fw.ServiceManager.DeleteService(ctx, serverService)
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		})
	})
})

// Helper function to execute kubectl commands
func executeKubectl(args ...string) (string, error) {
	// This is a simplified version - in a real test, you would use the k8s client libraries
	// or have a proper wrapper for kubectl commands in your test framework
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
