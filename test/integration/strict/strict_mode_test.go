package strict

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
)

var _ = Describe("Strict Mode Test Cases", func() {
	Context("when pod is launched", func() {
		var clientPod *v1.Pod
		var podName = "clientpod"

		BeforeEach(func() {
			By("Creating a pod to which tries to reach to external network", func() {
				agnhostContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do wget https://www.google.com --spider -T 1; if [ $? == 0 ]; then echo \"Success\"; else echo \"Fail\"; fi; sleep 1s; done"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Container(agnhostContainer).
					Namespace(namespace).
					Name(podName).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("by default should not have connectivity to external network", func() {
			By("Verify pod does not have external connectivity", func() {
				time.Sleep(1 * time.Minute)
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())
				err = processLogs(logs, true, false, false)
				Expect(err).ToNot(HaveOccurred())
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
			newPod              string
			firstPod            string
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
					AddPort(8080, v1.ProtocolTCP).
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
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
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

			By("Deploying a client deployment and an egress policy to allow communication with server", func() {

				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": serverName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("client-egress-policy").
					PodSelector("app", clientName).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())

				clientContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{fmt.Sprintf("while true; do wget %s:8080 --spider -T 2; if [ $? == 0 ]; then echo \"Success\"; else echo \"Fail\"; fi; done", serverPodIP)}).
					Build()

				clientDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(clientName).
					Replicas(1).
					Namespace(namespace).
					AddLabel("app", clientName).
					Container(clientContainer).
					Build()

				_, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, clientDeployment)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("Traffic from first replica of client deployment must be denied initially before succeeding but second replica should be instantaneous", func() {
			By("Verify traffic probes are denied and then accepted from first replica of client pod", func() {
				time.Sleep(30 * time.Second)
				podList, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())

				firstPod = podList[0].Name
				podLog, err := fw.PodManager.PodLogs(namespace, firstPod)
				Expect(err).ToNot(HaveOccurred())

				err = processLogs(podLog, false, false, true)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Scaling the client deployment to 2", func() {
				err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, clientName, 2)
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(10 * time.Second)

				podList, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", clientName)
				Expect(err).ToNot(HaveOccurred())

				for _, pod := range podList {
					if pod.Name != firstPod {
						newPod = pod.Name
						break
					}
				}
				Expect(newPod).ToNot(BeEmpty())
			})

			By("Verify all traffic probes are accepted from second replica of client pod", func() {
				time.Sleep(30 * time.Second)

				podLog, err := fw.PodManager.PodLogs(namespace, newPod)
				Expect(err).ToNot(HaveOccurred())

				err = processLogs(podLog, false, true, false)
				Expect(err).ToNot(HaveOccurred())
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

func processLogs(podlogs string, allDeny bool, allAllow bool, mix bool) error {

	passFlag := false
	failFlag := false
	for _, log := range strings.Split(strings.TrimSuffix(podlogs, "\n"), "\n") {
		if log == "Fail" {
			if passFlag {
				return fmt.Errorf("Connection failed after initial success")
			}
			failFlag = true
		} else if log == "Success" {
			passFlag = true
		}
	}

	if !passFlag && !failFlag {
		return fmt.Errorf("Error generating traffic probes")
	} else if allDeny && passFlag {
		return fmt.Errorf("Failed as all traffic probes did not get DENY")
	} else if allAllow && failFlag {
		return fmt.Errorf("Failed as all traffic probes did not get ACCEPT")
	} else if mix && !(passFlag && failFlag) {
		return fmt.Errorf("Failed as traffic probes did not get DENY first and then ACCEPT")
	}

	return nil
}
