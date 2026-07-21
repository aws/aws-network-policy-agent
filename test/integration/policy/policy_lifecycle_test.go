// Package policy — NetworkPolicy mutation and delete/re-add lifecycle tests.
//
// What is tested:
//
// Peer selector update (BulkRefresh):
//   - A server pod has an ingress policy that initially allows only pods with
//     label role=authorized. The allow and deny paths are confirmed.
//   - The policy is updated in-place (K8sClient.Update) to allow role=unauth
//     instead. The test verifies that the eBPF LPM trie is refreshed via
//     BulkRefresh: the formerly-allowed client is now blocked and the
//     formerly-blocked client can now reach the server.
//
// Delete and re-add:
//   - A deny-all ingress policy blocks all traffic to a server pod. After the
//     policy is deleted, traffic is expected to be allowed (non-strict mode
//     default). When the identical policy is re-applied, traffic must be
//     blocked again. This exercises the full add/delete/add lifecycle on the
//     same LPM trie keys.
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

var _ = Describe("Policy Lifecycle", func() {

	Context("when a NetworkPolicy peer selector is updated in place", func() {
		var (
			serverPod    *v1.Pod
			clientA      *v1.Pod
			clientB      *v1.Pod
			serverPolicy *network.NetworkPolicy
			serverPodIP  string
		)

		const (
			lcServerName  = "lifecycle-server"
			lcClientAName = "lifecycle-client-a"
			lcClientBName = "lifecycle-client-b"
		)

		BeforeEach(func() {
			By("Creating server pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverPod = manifest.NewDefaultPodBuilder().
					Name(lcServerName).
					Namespace(namespace).
					AddLabel("app", lcServerName).
					Container(container).
					Build()

				pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
				serverPodIP = pod.Status.PodIP
				if fw.Options.IpFamily == "IPv6" {
					serverPodIP = fmt.Sprintf("[%s]", serverPodIP)
				}
			})

			By("Creating ingress policy allowing only client A (role=authorized)", func() {
				ingressRule := manifest.NewIngressRuleBuilder().
					AddPeer(nil, map[string]string{"role": "authorized"}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				serverPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("lifecycle-ingress").
					PodSelector("app", lcServerName).
					AddIngressRule(ingressRule).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating client A (role=authorized) and client B (role=unauth)", func() {
				for _, spec := range []struct {
					name, role string
					dest       **v1.Pod
				}{
					{lcClientAName, "authorized", &clientA},
					{lcClientBName, "unauth", &clientB},
				} {
					container := manifest.NewAgnHostContainerBuilder().
						ImageRepository(fw.Options.TestImageRegistry).
						Args([]string{"sleep 3600"}).
						Build()

					pod := manifest.NewDefaultPodBuilder().
						Name(spec.name).
						Namespace(namespace).
						AddLabel("app", spec.name).
						AddLabel("role", spec.role).
						Container(container).
						Build()

					created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
					Expect(err).ToNot(HaveOccurred())
					*spec.dest = created
				}
			})

			time.Sleep(15 * time.Second)
		})

		It("should update eBPF map entries when the peer selector changes", func() {
			serverURL := fmt.Sprintf("http://%s:8080", serverPodIP)

			By("Verifying initial state: client A allowed, client B blocked", func() {
				_, err := fw.PodManager.ExecInPod(namespace, lcClientAName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).ToNot(HaveOccurred(), "client A should reach server before update")

				_, err = fw.PodManager.ExecInPod(namespace, lcClientBName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).To(HaveOccurred(), "client B should be blocked before update")
			})

			By("Updating policy to allow client B (role=unauth) instead of client A", func() {
				// Re-fetch to get the current ResourceVersion; the NPA controller may have
				// updated the object since we created it, causing a 409 if we use the stale copy.
				latest := &network.NetworkPolicy{}
				err := fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(serverPolicy), latest)
				Expect(err).ToNot(HaveOccurred())

				updatedRule := manifest.NewIngressRuleBuilder().
					AddPeer(nil, map[string]string{"role": "unauth"}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()
				latest.Spec.Ingress = []network.NetworkPolicyIngressRule{updatedRule}

				err = fw.K8sClient.Update(ctx, latest)
				Expect(err).ToNot(HaveOccurred())
				serverPolicy = latest
			})

			By("Verifying client B can reach server after policy update (BulkRefresh applied)", func() {
				Eventually(func() error {
					_, err := fw.PodManager.ExecInPod(namespace, lcClientBName,
						[]string{"wget", "--spider", "-T", "5", serverURL})
					return err
				}, 30*time.Second, 2*time.Second).ShouldNot(HaveOccurred(),
					"client B should reach server after policy update")
			})

			By("Verifying client A is now blocked after policy update", func() {
				_, err := fw.PodManager.ExecInPod(namespace, lcClientAName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).To(HaveOccurred(), "client A should be blocked after policy update")
			})
		})

		AfterEach(func() {
			if serverPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverPolicy)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if clientA != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientA)
			}
			if clientB != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientB)
			}
		})
	})

	Context("when a NetworkPolicy is deleted and then re-added", func() {
		var (
			serverPod   *v1.Pod
			clientPod   *v1.Pod
			denyPolicy  *network.NetworkPolicy
			serverPodIP string
		)

		const (
			readd_serverName = "readd-server"
			readd_clientName = "readd-client"
		)

		BeforeEach(func() {
			By("Creating server pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverPod = manifest.NewDefaultPodBuilder().
					Name(readd_serverName).
					Namespace(namespace).
					AddLabel("app", readd_serverName).
					Container(container).
					Build()

				pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
				serverPodIP = pod.Status.PodIP
				if fw.Options.IpFamily == "IPv6" {
					serverPodIP = fmt.Sprintf("[%s]", serverPodIP)
				}
			})

			By("Creating deny-all ingress policy", func() {
				denyPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("readd-deny-all-ingress").
					PodSelector("app", readd_serverName).
					SetPolicyType(true, false).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating client pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"sleep 3600"}).
					Build()

				pod := manifest.NewDefaultPodBuilder().
					Name(readd_clientName).
					Namespace(namespace).
					AddLabel("app", readd_clientName).
					Container(container).
					Build()

				var err error
				clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			time.Sleep(15 * time.Second)
		})

		It("should restore deny rules when the same policy is re-applied", func() {
			serverURL := fmt.Sprintf("http://%s:8080", serverPodIP)

			By("Verifying client is blocked by the initial deny-all policy", func() {
				_, err := fw.PodManager.ExecInPod(namespace, readd_clientName,
					[]string{"wget", "--spider", "-T", "5", serverURL})
				Expect(err).To(HaveOccurred(), "client should be blocked by deny-all policy")
			})

			By("Deleting the network policy", func() {
				// Use K8sClient.Delete directly: the NetworkPolicyManager wrapper has a bug
				// where it surfaces the NotFound error from its post-delete poll as a failure.
				err := fw.K8sClient.Delete(ctx, denyPolicy)
				Expect(err).ToNot(HaveOccurred())
				denyPolicy = nil
			})

			By("Verifying client can reach server once policy is removed", func() {
				Eventually(func() error {
					_, err := fw.PodManager.ExecInPod(namespace, readd_clientName,
						[]string{"wget", "--spider", "-T", "5", serverURL})
					return err
				}, 30*time.Second, 2*time.Second).ShouldNot(HaveOccurred(),
					"client should reach server after policy deletion")
			})

			By("Re-applying the same deny-all ingress policy", func() {
				readdPolicy := manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("readd-deny-all-ingress").
					PodSelector("app", readd_serverName).
					SetPolicyType(true, false).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, readdPolicy)
				Expect(err).ToNot(HaveOccurred())
				denyPolicy = readdPolicy
			})

			By("Verifying client is blocked again after policy is re-applied", func() {
				Eventually(func() error {
					_, err := fw.PodManager.ExecInPod(namespace, readd_clientName,
						[]string{"wget", "--spider", "-T", "5", serverURL})
					return err
				}, 30*time.Second, 2*time.Second).Should(HaveOccurred(),
					"client should be blocked again after policy re-application")
			})
		})

		AfterEach(func() {
			if denyPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, denyPolicy)
			}
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if clientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			}
		})
	})
})
