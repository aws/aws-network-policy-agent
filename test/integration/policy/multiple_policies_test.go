package policy

import (
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

var _ = Describe("Multiple Policies Test Cases", func() {
	Context("When a pod matches multiple network policies", func() {
		var clientPod *v1.Pod
		var serverPod *v1.Pod
		var externalPod *v1.Pod
		var policy1, policy2 *network.NetworkPolicy
		podName := "multi-policy-pod"
		serverName := "server-pod"
		externalName := "external-pod"

		BeforeEach(func() {
			By("Creating server and external pods", func() {
				// Create server pod
				serverContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverPod = manifest.NewDefaultPodBuilder().
					Name(serverName).
					Namespace(namespace).
					AddLabel("app", serverName).
					Container(serverContainer).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 1*time.Minute)
				Expect(err).ToNot(HaveOccurred())

				// Create external pod
				externalContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				externalPod = manifest.NewDefaultPodBuilder().
					Name(externalName).
					Namespace(namespace).
					AddLabel("app", externalName).
					Container(externalContainer).
					Build()

				_, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, externalPod, 1*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a client pod with multiple labels", func() {
				clientContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do wget http://" + serverName + ":8080 --spider -T 1; if [ $? == 0 ]; then echo \"Server Success\"; else echo \"Server Fail\"; fi; wget http://" + externalName + ":8080 --spider -T 1; if [ $? == 0 ]; then echo \"External Success\"; else echo \"External Fail\"; fi; sleep 1s; done"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Container(clientContainer).
					Namespace(namespace).
					AddLabel("app", podName).
					AddLabel("role", "client").
					Name(podName).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating first network policy allowing egress to server pod", func() {
				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": serverName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				policy1 = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("allow-server-egress").
					PodSelector("app", podName).
					SetPolicyType(false, true).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy1)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating second network policy allowing egress to external pod", func() {
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
			})
		})

		It("should correctly apply both policies", func() {
			By("Verifying that the pod can reach both server and external pod", func() {
				time.Sleep(1 * time.Minute)
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())

				// Check that both connections are successful
				Expect(logs).To(ContainSubstring("Server Success"))
				Expect(logs).To(ContainSubstring("External Success"))
			})

			By("Removing the first policy", func() {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy1)
				time.Sleep(30 * time.Second)
			})

			By("Verifying that the pod can only reach external pod", func() {
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())

				// Get only the recent logs after policy deletion
				recentLogs := getRecentLogs(logs, 10)

				// Should see failures for server and success for external
				Expect(recentLogs).To(ContainSubstring("Server Fail"))
				Expect(recentLogs).To(ContainSubstring("External Success"))
			})
		})

		AfterEach(func() {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, externalPod)
			if policy1 != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy1)
			}
			if policy2 != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy2)
			}
		})
	})
})

// Helper function to get only the most recent log entries
func getRecentLogs(logs string, numLines int) string {
	lines := strings.Split(logs, "\n")
	if len(lines) <= numLines {
		return logs
	}
	return strings.Join(lines[len(lines)-numLines:], "\n")
}
