// Package policy — scale-up into existing NetworkPolicy test.
//
// What is tested:
//   - A 1-replica server deployment is created with an ingress NetworkPolicy
//     already in place (allow only from a labeled client). The initial replica
//     is confirmed to allow the authorized client and deny the unauthorized one.
//   - The deployment is scaled from 1 to 3 replicas. Once all replicas are
//     ready, every replica is checked: the unauthorized client must be blocked
//     and the authorized client must be allowed.
//   - This verifies that newly scheduled pods correctly inherit the shared eBPF
//     program (via podIdentifier) and have policy enforced from the first packet,
//     with no window where the new replicas accept unauthorized traffic.
package policy

import (
	"fmt"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

var _ = Describe("Scale-Up Into Existing Policy", func() {
	Context("when a deployment is scaled up while a NetworkPolicy is already in place", func() {
		var (
			serverDeployment *appsv1.Deployment
			authClientPod    *v1.Pod
			unauthClientPod  *v1.Pod
			serverPolicy     *network.NetworkPolicy
		)

		const (
			scaleServerName = "scale-server"
			scaleAuthName   = "scale-auth-client"
			scaleUnauthName = "scale-unauth-client"
		)

		BeforeEach(func() {
			By("Creating server deployment with 1 replica", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(scaleServerName).
					Namespace(namespace).
					Replicas(1).
					AddLabel("app", scaleServerName).
					Container(container).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating ingress policy allowing only the authorized client", func() {
				ingressRule := manifest.NewIngressRuleBuilder().
					AddPeer(nil, map[string]string{"app": scaleAuthName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				serverPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("scale-server-ingress").
					PodSelector("app", scaleServerName).
					AddIngressRule(ingressRule).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating authorized and unauthorized client pods", func() {
				for _, spec := range []struct{ name string }{
					{scaleAuthName},
					{scaleUnauthName},
				} {
					container := manifest.NewAgnHostContainerBuilder().
						ImageRepository(fw.Options.TestImageRegistry).
						Args([]string{"sleep 3600"}).
						Build()

					pod := manifest.NewDefaultPodBuilder().
						Name(spec.name).
						Namespace(namespace).
						AddLabel("app", spec.name).
						Container(container).
						Build()

					created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
					Expect(err).ToNot(HaveOccurred())
					if spec.name == scaleAuthName {
						authClientPod = created
					} else {
						unauthClientPod = created
					}
				}
			})

			time.Sleep(15 * time.Second)
		})

		It("should enforce policy on new replicas from the first packet", func() {
			By("Verifying the initial replica enforces the policy", func() {
				pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", scaleServerName)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(pods)).To(Equal(1))

				podIP := pods[0].Status.PodIP
				if fw.Options.IpFamily == "IPv6" {
					podIP = fmt.Sprintf("[%s]", podIP)
				}
				serverURL := fmt.Sprintf("http://%s:8080", podIP)

				_, err = fw.PodManager.ExecInPod(namespace, scaleAuthName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).ToNot(HaveOccurred(), "authorized client should reach replica 1")

				_, err = fw.PodManager.ExecInPod(namespace, scaleUnauthName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).To(HaveOccurred(), "unauthorized client should be blocked by replica 1")
			})

			By("Scaling up to 3 replicas", func() {
				err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, scaleServerName, 3)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Verifying all 3 replicas deny the unauthorized client immediately after scale-up", func() {
				// ScaleDeploymentAndWaitTillReady waits on deployment status, but the pod label
				// query can lag slightly behind. Retry until all 3 pods are visible.
				var pods []v1.Pod
				Eventually(func() int {
					p, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", scaleServerName)
					if err != nil {
						return 0
					}
					pods = p
					return len(p)
				}, 30*time.Second, 2*time.Second).Should(Equal(3), "expected 3 server replicas after scale-up")

				for _, pod := range pods {
					podIP := pod.Status.PodIP
					if fw.Options.IpFamily == "IPv6" {
						podIP = fmt.Sprintf("[%s]", podIP)
					}
					serverURL := fmt.Sprintf("http://%s:8080", podIP)

					// Use Eventually to tolerate the brief window between pod-ready and eBPF attach.
					Eventually(func() error {
						_, err := fw.PodManager.ExecInPod(namespace, scaleUnauthName,
							[]string{"wget", "--spider", "-T", "5", serverURL})
						return err
					}, 30*time.Second, 2*time.Second).Should(HaveOccurred(),
						"unauthorized client should be blocked by replica %s", pod.Name)
				}
			})

			By("Verifying all 3 replicas allow the authorized client", func() {
				pods, _ := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", scaleServerName)

				for _, pod := range pods {
					podIP := pod.Status.PodIP
					if fw.Options.IpFamily == "IPv6" {
						podIP = fmt.Sprintf("[%s]", podIP)
					}
					serverURL := fmt.Sprintf("http://%s:8080", podIP)

					_, err := fw.PodManager.ExecInPod(namespace, scaleAuthName,
						[]string{"wget", "--spider", "-T", "5", serverURL})
					Expect(err).ToNot(HaveOccurred(), "authorized client should reach replica %s", pod.Name)
				}
			})
		})

		AfterEach(func() {
			if serverPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverPolicy)
			}
			if serverDeployment != nil {
				fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeployment)
			}
			if authClientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, authClientPod)
			}
			if unauthClientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, unauthClientPod)
			}
		})
	})
})
