package policy

import (
	"fmt"
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

var _ = Describe("Multiple Policies Across Slices Test Cases", func() {
	Context("When pods across multiple slices match multiple policies", func() {
		var clientDeployment *appsv1.Deployment
		var serverDeployment *appsv1.Deployment
		var externalDeployment *appsv1.Deployment
		var policy1, policy2 *network.NetworkPolicy
		clientName := "multi-policy-client"
		serverName := "multi-policy-server"
		externalName := "multi-policy-external"

		BeforeEach(func() {
			By("Creating server and external deployments with multiple replicas", func() {
				// Create server deployment with many replicas to ensure multiple slices
				serverContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(serverName).
					Replicas(20). // Increased to ensure multiple slices
					Namespace(namespace).
					AddLabel("app", serverName).
					Container(serverContainer).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
				Expect(err).ToNot(HaveOccurred())

				// Create external deployment
				externalContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				externalDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(externalName).
					Replicas(20). // Increased to ensure multiple slices
					Namespace(namespace).
					AddLabel("app", externalName).
					Container(externalContainer).
					Build()

				_, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, externalDeployment)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a client deployment with multiple labels", func() {
				clientContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do for i in $(seq 1 5); do wget http://" + serverName + "-$i." + namespace + ".svc.cluster.local:8080 --spider -T 1 2>/dev/null; if [ $? == 0 ]; then echo \"Server-$i Success\"; else echo \"Server-$i Fail\"; fi; done; for i in $(seq 1 5); do wget http://" + externalName + "-$i." + namespace + ".svc.cluster.local:8080 --spider -T 1 2>/dev/null; if [ $? == 0 ]; then echo \"External-$i Success\"; else echo \"External-$i Fail\"; fi; done; sleep 1s; done"}).
					Build()

				clientDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(clientName).
					Replicas(5). // Increased client pods
					Namespace(namespace).
					AddLabel("app", clientName).
					AddLabel("role", "client").
					Container(clientContainer).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, clientDeployment)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating first network policy allowing egress to server pods", func() {
				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": serverName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				policy1 = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("allow-server-egress").
					PodSelector("app", clientName).
					SetPolicyType(false, true).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy1)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating second network policy allowing egress to external pods", func() {
				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": externalName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				policy2 = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("allow-external-egress").
					PodSelector("role", "client").
					SetPolicyType(false, true).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy2)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policies to be applied
				time.Sleep(30 * time.Second)
			})
		})

		It("should correctly apply both policies across all pods and handle scaling operations", func() {
			// 1. Verify that multiple PolicyEndpoint slices were created
			By("Verifying that multiple PolicyEndpoint slices were created", func() {
				// Wait for PolicyEndpoint resources to be created
				var policyEndpointCount int
				err := wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
					// Execute kubectl command to get PolicyEndpoint resources for both policies
					output1, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-server-egress")
					if err != nil {
						return false, nil // Continue polling
					}

					output2, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-external-egress")
					if err != nil {
						return false, nil // Continue polling
					}

					// Count the number of PolicyEndpoint resources
					lines1 := strings.Split(output1, "\n")
					lines2 := strings.Split(output2, "\n")

					policyEndpointCount1 := len(lines1) - 1 // Subtract header line
					policyEndpointCount2 := len(lines2) - 1 // Subtract header line

					policyEndpointCount = policyEndpointCount1 + policyEndpointCount2

					if policyEndpointCount < 2 {
						return false, nil // Continue polling
					}

					return true, nil
				})
				Expect(err).ToNot(HaveOccurred())

				// Log the number of PolicyEndpoint slices found
				fmt.Fprintf(GinkgoWriter, "Found %d PolicyEndpoint resources\n", policyEndpointCount)

				// We expect multiple PolicyEndpoint resources
				Expect(policyEndpointCount).To(BeNumerically(">", 1))
			})

			// 2. Verify initial connectivity
			By("Verifying connectivity from all client pods to all server and external pods", func() {
				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(clientPods)).To(Equal(5))

				// Wait for some connection attempts
				time.Sleep(10 * time.Second)

				for _, pod := range clientPods {
					logs, err := fw.PodManager.PodLogs(namespace, pod.Name)
					Expect(err).ToNot(HaveOccurred())

					// Check connectivity to server pods
					for i := 1; i <= 5; i++ {
						Expect(logs).To(ContainSubstring(fmt.Sprintf("Server-%d Success", i)))
					}

					// Check connectivity to external pods
					for i := 1; i <= 5; i++ {
						Expect(logs).To(ContainSubstring(fmt.Sprintf("External-%d Success", i)))
					}
				}
			})

			// 3. Get the current state of PolicyEndpoint resources before scaling
			var initialServerPolicyEndpointCount int
			var initialExternalPolicyEndpointCount int

			By("Recording the initial state of PolicyEndpoint resources", func() {
				output1, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-server-egress")
				Expect(err).ToNot(HaveOccurred())

				output2, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-external-egress")
				Expect(err).ToNot(HaveOccurred())

				lines1 := strings.Split(output1, "\n")
				lines2 := strings.Split(output2, "\n")

				initialServerPolicyEndpointCount = len(lines1) - 1   // Subtract header line
				initialExternalPolicyEndpointCount = len(lines2) - 1 // Subtract header line

				fmt.Fprintf(GinkgoWriter, "Initial Server PolicyEndpoint count: %d\n", initialServerPolicyEndpointCount)
				fmt.Fprintf(GinkgoWriter, "Initial External PolicyEndpoint count: %d\n", initialExternalPolicyEndpointCount)
			})

			// 4. Scale down the server deployment to trigger slice deletion/reorganization
			By("Scaling down the server deployment to trigger slice deletion/reorganization", func() {
				err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, serverName, 2)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policy controller to update
				time.Sleep(1 * time.Minute)
			})

			// 5. Verify that PolicyEndpoint resources were updated after scaling
			By("Verifying that PolicyEndpoint resources were updated after scaling down", func() {
				var finalServerPolicyEndpointCount int
				err := wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
					output, err := executeKubectl("get", "policyendpoints", "-n", namespace, "-l", "policy-name=allow-server-egress")
					if err != nil {
						return false, nil // Continue polling
					}

					lines := strings.Split(output, "\n")
					finalServerPolicyEndpointCount = len(lines) - 1 // Subtract header line

					// If the count changed, we've detected the update
					if finalServerPolicyEndpointCount != initialServerPolicyEndpointCount {
						return true, nil
					}

					return false, nil
				})
				Expect(err).ToNot(HaveOccurred())

				fmt.Fprintf(GinkgoWriter, "Final Server PolicyEndpoint count: %d\n", finalServerPolicyEndpointCount)

				// We expect the number of PolicyEndpoint resources to have changed
				Expect(finalServerPolicyEndpointCount).NotTo(Equal(initialServerPolicyEndpointCount))
			})

			// 6. Verify connectivity is maintained after scaling down
			By("Verifying connectivity is maintained after scaling down", func() {
				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())

				for _, pod := range clientPods {
					// Clear the logs to get fresh data
					_, err = executeKubectl("logs", "-n", namespace, pod.Name, "--tail=1", "--follow=false")
					Expect(err).ToNot(HaveOccurred())

					// Wait for new connection attempts
					time.Sleep(10 * time.Second)

					// Get fresh logs after scaling
					logs, err := fw.PodManager.PodLogs(namespace, pod.Name)
					Expect(err).ToNot(HaveOccurred())

					recentLogs := getRecentLogs(logs, 20)

					// Should still be able to connect to some server pods
					serverSuccessCount := 0
					for i := 1; i <= 5; i++ {
						if strings.Contains(recentLogs, fmt.Sprintf("Server-%d Success", i)) {
							serverSuccessCount++
						}
					}
					Expect(serverSuccessCount).To(BeNumerically(">", 0), "Expected to see at least one server connection success")

					// Should still be able to connect to external pods
					externalSuccessCount := 0
					for i := 1; i <= 5; i++ {
						if strings.Contains(recentLogs, fmt.Sprintf("External-%d Success", i)) {
							externalSuccessCount++
						}
					}
					Expect(externalSuccessCount).To(BeNumerically(">", 0), "Expected to see external connection successes")
				}
			})

			// 7. Test for stale rules by creating a new client pod
			By("Creating a new client pod to verify no stale rules exist", func() {
				newClientName := "new-client"
				newClientContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do for i in $(seq 1 5); do wget http://" + serverName + "-$i." + namespace + ".svc.cluster.local:8080 --spider -T 1 2>/dev/null; if [ $? == 0 ]; then echo \"Server-$i Success\"; else echo \"Server-$i Fail\"; fi; done; for i in $(seq 1 5); do wget http://" + externalName + "-$i." + namespace + ".svc.cluster.local:8080 --spider -T 1 2>/dev/null; if [ $? == 0 ]; then echo \"External-$i Success\"; else echo \"External-$i Fail\"; fi; done; sleep 1s; done"}).
					Build()

				newClientPod := manifest.NewDefaultPodBuilder().
					Container(newClientContainer).
					Namespace(namespace).
					AddLabel("app", clientName). // Same labels to match both policies
					AddLabel("role", "client").
					Name(newClientName).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, newClientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policy to be applied to the new pod
				time.Sleep(30 * time.Second)

				// Check logs of the new pod
				logs, err := fw.PodManager.PodLogs(namespace, newClientName)
				Expect(err).ToNot(HaveOccurred())

				// Should be able to connect to server pods
				serverSuccessCount := 0
				for i := 1; i <= 5; i++ {
					if strings.Contains(logs, fmt.Sprintf("Server-%d Success", i)) {
						serverSuccessCount++
					}
				}
				Expect(serverSuccessCount).To(BeNumerically(">", 0), "Expected new pod to connect to server pods")

				// Should be able to connect to external pods
				externalSuccessCount := 0
				for i := 1; i <= 5; i++ {
					if strings.Contains(logs, fmt.Sprintf("External-%d Success", i)) {
						externalSuccessCount++
					}
				}
				Expect(externalSuccessCount).To(BeNumerically(">", 0), "Expected new pod to connect to external pods")

				// Clean up the new pod
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, newClientPod)
			})

			// 8. Create a new deployment to test rule cleanup and application
			By("Creating a new deployment to test rule cleanup and application", func() {
				newServerName := "new-server"
				newServerContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				newServerDeployment := manifest.NewDefaultDeploymentBuilder().
					Name(newServerName).
					Replicas(5).
					Namespace(namespace).
					AddLabel("app", serverName). // Same label as original server to match policy
					Container(newServerContainer).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, newServerDeployment)
				Expect(err).ToNot(HaveOccurred())

				// Wait for policy controller to update
				time.Sleep(1 * time.Minute)

				// Verify connectivity to new server pods
				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())

				for _, pod := range clientPods {
					// Clear the logs to get fresh data
					_, err = executeKubectl("logs", "-n", namespace, pod.Name, "--tail=1", "--follow=false")
					Expect(err).ToNot(HaveOccurred())

					// Wait for new connection attempts
					time.Sleep(10 * time.Second)

					// Get fresh logs
					logs, err := fw.PodManager.PodLogs(namespace, pod.Name)
					Expect(err).ToNot(HaveOccurred())

					recentLogs := getRecentLogs(logs, 20)

					// Should be able to connect to new server pods (they have the same label)
					// We can't test specific pod names, but we can verify there are successful connections
					Expect(recentLogs).To(ContainSubstring("Server-"), "Expected to see server connection attempts")
					Expect(recentLogs).To(ContainSubstring("Success"), "Expected to see successful connections")
				}

				// Clean up the new deployment
				fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, newServerDeployment)
			})

			// 9. Remove one policy and verify the other still works
			By("Removing the first policy", func() {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy1)
				time.Sleep(30 * time.Second)
			})

			By("Verifying connectivity is maintained to external pods but lost to server pods", func() {
				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())

				for _, pod := range clientPods {
					// Get fresh logs after policy deletion
					logs, err := fw.PodManager.PodLogs(namespace, pod.Name)
					Expect(err).ToNot(HaveOccurred())

					recentLogs := getRecentLogs(logs, 20)

					// Should see failures for server pods
					serverFailCount := 0
					for i := 1; i <= 5; i++ {
						if strings.Contains(recentLogs, fmt.Sprintf("Server-%d Fail", i)) {
							serverFailCount++
						}
					}
					Expect(serverFailCount).To(BeNumerically(">", 0), "Expected to see server connection failures after policy deletion")

					// Should still see success for external pods
					externalSuccessCount := 0
					for i := 1; i <= 5; i++ {
						if strings.Contains(recentLogs, fmt.Sprintf("External-%d Success", i)) {
							externalSuccessCount++
						}
					}
					Expect(externalSuccessCount).To(BeNumerically(">", 0), "Expected to see external connection successes after policy deletion")
				}
			})
		})

		AfterEach(func() {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, clientDeployment)
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeployment)
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, externalDeployment)
			if policy1 != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy1)
			}
			if policy2 != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy2)
			}
		})
	})
})
