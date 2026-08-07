package clusternetworkpolicy

import (
	"fmt"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// clusterPolicyEndpointListGVK identifies the ClusterPolicyEndpoint list kind. The type is not
// registered in the test scheme, so CPEs are listed as unstructured objects.
var clusterPolicyEndpointListGVK = schema.GroupVersionKind{
	Group:   "networking.k8s.aws",
	Version: "v1alpha1",
	Kind:    "ClusterPolicyEndpointList",
}

// These tests cover the cleanup path taken when a pod stops matching a ClusterNetworkPolicy
// while the CNP itself keeps existing - for example when the namespace label the CNP selects
// on is removed. The ClusterPolicyEndpoints stay around but no longer list the pod, so the
// agent has to notice that nothing selects the pod anymore and drop the rules it programmed.
// Previously the rules survived until the pod restarted, leaving traffic denied indefinitely.
var _ = Describe("ClusterNetworkPolicy Stale Rule Cleanup", Ordered, func() {
	Context("When a pod stops matching a ClusterNetworkPolicy but the policy still exists", func() {
		const (
			serverNamespace = "stale-server"
			clientNamespace = "stale-client"
			// Label the policies select on. Removing it is what makes the pod stop matching.
			subjectLabelKey = "stale-cleanup-subject"
			// Label selected by the unrelated parent CNP, used as a control: its rules must
			// survive the cleanup of the policy under test.
			unrelatedLabelKey = "stale-cleanup-unrelated"
		)

		var (
			serverDeployment *appsv1.Deployment
			clientDeployment *appsv1.Deployment
			policies         []*unstructured.Unstructured
			serverPodIP      string
			clientPodName    string
		)

		// waitForServerRolloutAndRefreshIP waits until the server deployment has finished rolling
		// out after a label patch and then re-reads the new pod's IP. Patching the pod template
		// recreates the pod, so the previously recorded IP goes stale.
		waitForServerRolloutAndRefreshIP := func() {
			Eventually(func(g Gomega) {
				observed := &appsv1.Deployment{}
				err := fw.K8sClient.Get(ctx, types.NamespacedName{
					Namespace: serverNamespace, Name: serverDeployment.Name,
				}, observed)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(observed.Status.ObservedGeneration).To(BeNumerically(">=", observed.Generation))
				g.Expect(observed.Status.UpdatedReplicas).To(Equal(*serverDeployment.Spec.Replicas))
				g.Expect(observed.Status.AvailableReplicas).To(Equal(*serverDeployment.Spec.Replicas))
			}, 180*time.Second, 5*time.Second).Should(Succeed())

			// Only one replica is expected, and the old pod is gone once the rollout completed.
			Eventually(func(g Gomega) {
				serverPods, err := fw.PodManager.GetPodsWithLabel(ctx, serverNamespace, "app", "stale-server")
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(serverPods).To(HaveLen(1))
				g.Expect(serverPods[0].Status.PodIP).ToNot(BeEmpty())
				serverPodIP = serverPods[0].Status.PodIP
			}, 60*time.Second, 5*time.Second).Should(Succeed())
		}

		// reachable reports whether the client pod can reach the server pod on 8080.
		reachable := func() bool {
			formatString := "http://%s:8080"
			if fw.Options.IpFamily == "IPv6" {
				formatString = "http://[%s]:8080"
			}
			_, err := fw.PodManager.ExecInPod(clientNamespace, clientPodName,
				[]string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, serverPodIP)})
			return err == nil
		}

		// listCPEsForParent returns the names of ClusterPolicyEndpoints sliced from the given
		// parent CNP. The CPE type is not registered in the test scheme, so list it as
		// unstructured.
		listCPEsForParent := func(parent string) []string {
			cpeList := &unstructured.UnstructuredList{}
			cpeList.SetGroupVersionKind(clusterPolicyEndpointListGVK)
			err := fw.K8sClient.List(ctx, cpeList)
			Expect(err).ToNot(HaveOccurred())

			var names []string
			for _, cpe := range cpeList.Items {
				refName, found, err := unstructured.NestedString(cpe.Object, "spec", "policyRef", "name")
				Expect(err).ToNot(HaveOccurred())
				if found && refName == parent {
					names = append(names, cpe.GetName())
				}
			}
			return names
		}

		// denyAllIngressFrom builds a Deny-all-ingress CNP selecting pods carrying labelKey.
		denyAllIngressFrom := func(name, labelKey string, priority int32) *unstructured.Unstructured {
			ingressRule := manifest.NewClusterIngressRuleBuilder().
				Name("deny-all-ingress").
				Action("Deny").
				BuildIngressRule([]map[string]interface{}{
					manifest.NewNetworksPeer([]string{matchAllCIDR}),
				})

			return manifest.NewClusterNetworkPolicyBuilder().
				Name(name).
				Priority(priority).
				Tier("Admin").
				SubjectPods(
					map[string]string{"kubernetes.io/metadata.name": serverNamespace},
					map[string]string{labelKey: "yes"},
				).
				AddIngressRule(ingressRule).
				Build()
		}

		BeforeAll(func() {
			By("Creating the server and client namespaces", func() {
				for _, ns := range []string{serverNamespace, clientNamespace} {
					err := fw.K8sClient.Create(ctx, &v1.Namespace{
						ObjectMeta: metaV1.ObjectMeta{
							Name:   ns,
							Labels: map[string]string{"kubernetes.io/metadata.name": ns},
						},
					})
					Expect(err).ToNot(HaveOccurred())
				}
			})

			By("Creating the server and client deployments", func() {
				serverContainer := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"while true; do { echo 'HTTP/1.1 200 OK\n\nServer Response'; } | nc -l -p 8080; done"}).
					Build()

				// The server carries both subject labels from the start. The policies select on
				// them, so removing a label is what makes the pod stop matching that policy.
				serverDeployment = manifest.NewDefaultDeploymentBuilder().
					Namespace(serverNamespace).
					Name("stale-server").
					Replicas(1).
					Container(serverContainer).
					AddLabel("app", "stale-server").
					AddLabel(subjectLabelKey, "yes").
					AddLabel(unrelatedLabelKey, "yes").
					Build()

				created, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
				Expect(err).ToNot(HaveOccurred())
				serverDeployment = created

				clientContainer := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"while true; do sleep 3600; done"}).
					Build()

				clientDeployment = manifest.NewDefaultDeploymentBuilder().
					Namespace(clientNamespace).
					Name("stale-client").
					Replicas(1).
					Container(clientContainer).
					AddLabel("app", "stale-client").
					Build()

				created, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, clientDeployment)
				Expect(err).ToNot(HaveOccurred())
				clientDeployment = created
			})

			By("Recording the server and client pod details", func() {
				serverPods, err := fw.PodManager.GetPodsWithLabel(ctx, serverNamespace, "app", "stale-server")
				Expect(err).ToNot(HaveOccurred())
				Expect(serverPods).ToNot(BeEmpty())
				serverPodIP = serverPods[0].Status.PodIP

				clientPods, err := fw.PodManager.GetPodsWithLabel(ctx, clientNamespace, "app", "stale-client")
				Expect(err).ToNot(HaveOccurred())
				Expect(clientPods).ToNot(BeEmpty())
				clientPodName = clientPods[0].Name
			})

			By("Verifying the server is reachable before any policy is applied", func() {
				Eventually(reachable, 30*time.Second, 5*time.Second).Should(BeTrue())
			})
		})

		BeforeEach(func() {
			policies = nil
		})

		It("removes all of a parent CNP's rules when its pod stops matching, keeping unrelated policies", func() {
			parentUnderTest := "stale-cleanup-under-test"
			unrelatedParent := "stale-cleanup-unrelated-parent"

			By("Creating the CNP under test and an unrelated CNP, both selecting the server pod", func() {
				underTest := denyAllIngressFrom(parentUnderTest, subjectLabelKey, 100)
				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, underTest)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, underTest)

				unrelated := denyAllIngressFrom(unrelatedParent, unrelatedLabelKey, 200)
				err = fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, unrelated)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, unrelated)
			})

			By("Waiting for both policies to deny traffic to the server", func() {
				Eventually(reachable, 60*time.Second, 5*time.Second).Should(BeFalse())
			})

			var cpesUnderTest []string
			By("Confirming the CNP under test produced at least one ClusterPolicyEndpoint", func() {
				Eventually(func() []string {
					cpesUnderTest = listCPEsForParent(parentUnderTest)
					return cpesUnderTest
				}, 60*time.Second, 5*time.Second).ShouldNot(BeEmpty())

				// When the parent CNP is sliced into several CPEs, every one of them has to be
				// dropped for the identifier. Log the count so a multi-CPE run is visible.
				GinkgoWriter.Printf("CNP %s produced %d ClusterPolicyEndpoint(s): %v\n",
					parentUnderTest, len(cpesUnderTest), cpesUnderTest)
			})

			By("Removing the label so the server pod stops matching the CNP under test", func() {
				patch := []byte(fmt.Sprintf(`{"spec":{"template":{"metadata":{"labels":{%q:null}}}}}`, subjectLabelKey))
				err := fw.K8sClient.Patch(ctx, serverDeployment, client.RawPatch(types.StrategicMergePatchType, patch))
				Expect(err).ToNot(HaveOccurred())

				waitForServerRolloutAndRefreshIP()
			})

			By("Verifying the CNP under test still exists with its ClusterPolicyEndpoints", func() {
				// The point of the test: the policy is not deleted, it simply stops selecting
				// the pod. The agent still has to drop the rules it programmed for it.
				_, err := fw.ClusterNetworkPolicyManager.GetClusterNetworkPolicy(ctx, parentUnderTest)
				Expect(err).ToNot(HaveOccurred())
				Expect(listCPEsForParent(parentUnderTest)).ToNot(BeEmpty())
			})

			By("Verifying the unrelated CNP's rules are preserved so traffic stays denied", func() {
				// The unrelated parent still selects the pod, so its Deny rule must keep
				// applying. A cleanup that wiped every rule for the identifier would open
				// traffic here.
				Consistently(reachable, 30*time.Second, 5*time.Second).Should(BeFalse())
				Expect(listCPEsForParent(unrelatedParent)).ToNot(BeEmpty())
			})

			By("Removing the unrelated label so no CNP selects the server pod anymore", func() {
				patch := []byte(fmt.Sprintf(`{"spec":{"template":{"metadata":{"labels":{%q:null}}}}}`, unrelatedLabelKey))
				err := fw.K8sClient.Patch(ctx, serverDeployment, client.RawPatch(types.StrategicMergePatchType, patch))
				Expect(err).ToNot(HaveOccurred())

				waitForServerRolloutAndRefreshIP()
			})

			By("Verifying traffic is restored once nothing selects the pod", func() {
				// Both CNPs still exist, and both still have ClusterPolicyEndpoints - only the
				// pod no longer matches them. Without the stale cleanup the Deny rules would
				// survive here and traffic would stay blocked.
				Eventually(reachable, 90*time.Second, 5*time.Second).Should(BeTrue())

				Expect(listCPEsForParent(parentUnderTest)).ToNot(BeEmpty())
				Expect(listCPEsForParent(unrelatedParent)).ToNot(BeEmpty())
			})
		})

		AfterEach(func() {
			for _, policy := range policies {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, policy)
			}
		})

		AfterAll(func() {
			By("Cleaning up deployments", func() {
				for _, deployment := range []*appsv1.Deployment{serverDeployment, clientDeployment} {
					if deployment != nil {
						fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployment)
					}
				}
			})

			By("Cleaning up namespaces", func() {
				for _, ns := range []string{serverNamespace, clientNamespace} {
					fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, ns)
				}
			})
		})
	})
})
