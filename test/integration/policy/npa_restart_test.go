// Package policy — NPA restart recovery test.
//
// What is tested:
//   - A server pod is protected by an ingress NetworkPolicy (allow only from
//     a labeled client on port 8080). Both the allow and deny paths are
//     verified before the restart.
//   - The aws-node DaemonSet pod on the server's node is deleted, forcing the
//     aws-eks-nodeagent container (NPA) to restart and re-run recoverBPFState.
//   - After the new aws-node pod is fully ready, the same allow/deny checks
//     are repeated to confirm that eBPF TC programs were correctly re-attached
//     to the existing pod veth and that policy enforcement survived the restart.
//   - A stress-ng workload is pinned to the same node throughout to simulate
//     realistic CPU/memory pressure during the recovery window.
package policy

import (
	"fmt"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("NPA Restart", func() {
	Context("when the NPA agent pod is deleted and restarts", func() {
		var (
			serverPod       *v1.Pod
			authClientPod   *v1.Pod
			unauthClientPod *v1.Pod
			stressPod       *v1.Pod
			serverPolicy    *network.NetworkPolicy
			serverPodIP     string
			serverNodeName  string
		)

		const (
			serverName       = "restart-server"
			authClientName   = "restart-auth-client"
			unauthClientName = "restart-unauth-client"
		)

		BeforeEach(func() {
			By("Creating the server pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverPod = manifest.NewDefaultPodBuilder().
					Name(serverName).
					Namespace(namespace).
					AddLabel("app", serverName).
					Container(container).
					Build()

				pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
				serverPodIP = pod.Status.PodIP
				serverNodeName = pod.Spec.NodeName
				if fw.Options.IpFamily == "IPv6" {
					serverPodIP = fmt.Sprintf("[%s]", serverPodIP)
				}
			})

			By("Running node-level CPU and memory stress before triggering NPA restart", func() {
				privileged := true
				// hostPID + hostNetwork + privileged places the workers in the node's own PID
				// and network namespaces so they compete with kubelet, containerd and NPA rather
				// than being throttled inside a pod cgroup slice.
				//
				// Uses only coreutils (yes, dd, sleep) — no package install required, so the
				// workers are confirmed running the moment the container reaches Running state:
				//   yes > /dev/null ×2  → ~2 CPUs worth of user-space spin (bounded by the
				//                         node scheduler, not pinned at 100 %)
				//   dd if=/dev/zero …   → continuous memory-bandwidth pressure (~64 MiB/s)
				stressContainer := v1.Container{
					Name:            "stress",
					Image:           "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
					ImagePullPolicy: v1.PullIfNotPresent,
					Command:         []string{"/bin/sh", "-c"},
					Args:            []string{"yes > /dev/null & yes > /dev/null & dd if=/dev/zero of=/dev/null bs=64M & sleep 600"},
					SecurityContext: &v1.SecurityContext{Privileged: &privileged},
				}
				stressPod = manifest.NewDefaultPodBuilder().
					Name("restart-stress").
					Namespace(namespace).
					NodeName(serverNodeName).
					Container(stressContainer).
					Build()
				stressPod.Spec.HostPID = true
				stressPod.Spec.HostNetwork = true

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, stressPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
				// Workers launch immediately on container start; a brief pause confirms
				// they are running before we trigger the NPA restart.
				time.Sleep(5 * time.Second)
			})

			By("Creating ingress policy allowing only the authorized client on port 8080", func() {
				ingressRule := manifest.NewIngressRuleBuilder().
					AddPeer(nil, map[string]string{"app": authClientName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				serverPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("restart-server-ingress").
					PodSelector("app", serverName).
					AddIngressRule(ingressRule).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating authorized client pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"sleep 3600"}).
					Build()

				pod := manifest.NewDefaultPodBuilder().
					Name(authClientName).
					Namespace(namespace).
					AddLabel("app", authClientName).
					Container(container).
					Build()

				var err error
				authClientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating unauthorized client pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"sleep 3600"}).
					Build()

				pod := manifest.NewDefaultPodBuilder().
					Name(unauthClientName).
					Namespace(namespace).
					AddLabel("app", unauthClientName).
					Container(container).
					Build()

				var err error
				unauthClientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			// Allow the network policy time to be programmed into eBPF maps.
			time.Sleep(15 * time.Second)
		})

		It("should continue to enforce network policy after NPA pod restarts", func() {
			serverURL := fmt.Sprintf("http://%s:8080", serverPodIP)

			By("Verifying policy enforcement before restart", func() {
				_, err := fw.PodManager.ExecInPod(namespace, authClientName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).ToNot(HaveOccurred(), "authorized client should reach server before restart")

				_, err = fw.PodManager.ExecInPod(namespace, unauthClientName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).To(HaveOccurred(), "unauthorized client should be blocked before restart")
			})

			By("Deleting the aws-node pod on the server's node to trigger NPA restart", func() {
				podList := &v1.PodList{}
				err := fw.K8sClient.List(ctx, podList,
					client.InNamespace("kube-system"),
					client.MatchingLabels{"k8s-app": "aws-node"},
				)
				Expect(err).ToNot(HaveOccurred())

				var awsNodePod *v1.Pod
				for i := range podList.Items {
					if podList.Items[i].Spec.NodeName == serverNodeName {
						awsNodePod = &podList.Items[i]
						break
					}
				}
				Expect(awsNodePod).ToNot(BeNil(), "aws-node pod not found on node %s", serverNodeName)

				deletedName := awsNodePod.Name
				Expect(fw.K8sClient.Delete(ctx, awsNodePod)).To(Succeed())

				Eventually(func() bool {
					newList := &v1.PodList{}
					if err := fw.K8sClient.List(ctx, newList,
						client.InNamespace("kube-system"),
						client.MatchingLabels{"k8s-app": "aws-node"},
					); err != nil {
						return false
					}
					for _, pod := range newList.Items {
						if pod.Spec.NodeName != serverNodeName || pod.Name == deletedName {
							continue
						}
						if pod.Status.Phase != v1.PodRunning {
							return false
						}
						allReady := true
						for _, cs := range pod.Status.ContainerStatuses {
							if !cs.Ready {
								allReady = false
								break
							}
						}
						return allReady
					}
					return false
				}, 3*time.Minute, 5*time.Second).Should(BeTrue(), "new aws-node pod should become fully ready")
			})

			// Allow the agent time to walk /sys/fs/bpf and re-attach eBPF programs.
			time.Sleep(30 * time.Second)

			By("Verifying policy enforcement is preserved after restart", func() {
				_, err := fw.PodManager.ExecInPod(namespace, authClientName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).ToNot(HaveOccurred(), "authorized client should still reach server after NPA restart")

				_, err = fw.PodManager.ExecInPod(namespace, unauthClientName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).To(HaveOccurred(), "unauthorized client should still be blocked after NPA restart")
			})

			By("Updating the policy to also allow the unauthorized client", func() {
				latest := &network.NetworkPolicy{}
				err := fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(serverPolicy), latest)
				Expect(err).ToNot(HaveOccurred())

				updatedRule := manifest.NewIngressRuleBuilder().
					AddPeer(nil, map[string]string{"app": authClientName}, "").
					AddPeer(nil, map[string]string{"app": unauthClientName}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()
				latest.Spec.Ingress = []network.NetworkPolicyIngressRule{updatedRule}

				err = fw.K8sClient.Update(ctx, latest)
				Expect(err).ToNot(HaveOccurred())
				serverPolicy = latest
			})

			By("Verifying updated policy is applied: previously-blocked client can now reach server", func() {
				Eventually(func() error {
					_, err := fw.PodManager.ExecInPod(namespace, unauthClientName,
						[]string{"wget", "--spider", "-T", "5", serverURL})
					return err
				}, 30*time.Second, 2*time.Second).ShouldNot(HaveOccurred(),
					"unauthorized client should reach server after policy update post-restart")
			})

			By("Verifying authorized client still reaches server after policy update", func() {
				_, err := fw.PodManager.ExecInPod(namespace, authClientName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).ToNot(HaveOccurred(), "authorized client should still reach server after policy update")
			})
		})

		AfterEach(func() {
			if serverPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverPolicy)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if authClientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, authClientPod)
			}
			if unauthClientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, unauthClientPod)
			}
			if stressPod != nil {
				fw.K8sClient.Delete(ctx, stressPod)
			}
		})
	})
})
