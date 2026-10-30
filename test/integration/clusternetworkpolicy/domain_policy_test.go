package clusternetworkpolicy

import (
	"math/rand"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ = Describe("Domain-based Cluster Network Policy Tests", Ordered, func() {
	Context("When testing domain name egress rules", func() {
		var deployments []*appsv1.Deployment
		var policies []*unstructured.Unstructured
		var networkPolicies []*network.NetworkPolicy
		var globalPolicies []*unstructured.Unstructured
		var testNamespace = "domain-test-ns"

		BeforeAll(func() {
			By("Creating test namespace", func() {
				namespaceObj := &v1.Namespace{
					ObjectMeta: metaV1.ObjectMeta{
						Name: testNamespace,
						Labels: map[string]string{
							"test": "domain-policy",
						},
					},
				}
				err := fw.K8sClient.Create(ctx, namespaceObj)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating DNS allow policy (priority 0)", func() {
				egressRuleBuilder := manifest.NewClusterEgressRuleBuilder().
					Name("allow-dns").
					Action("Accept").
					AddPort(53, "UDP").
					AddPort(53, "TCP")

				var egressRule map[string]interface{}
				if fw.Options.IsAutoCluster {
					egressRule = egressRuleBuilder.BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{dnsCIDRAddress}),
					})
				} else {
					egressRule = egressRuleBuilder.BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"kubernetes.io/metadata.name": "kube-system"},
							map[string]string{"k8s-app": "kube-dns"},
						),
					})
				}

				dnsPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-dns-policy").
					Priority(0).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, dnsPolicy)
				Expect(err).ToNot(HaveOccurred())
				globalPolicies = append(globalPolicies, dnsPolicy)
			})

			By("Creating test deployment", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"while true; do sleep 30; done"}).
					Build()

				deployment := manifest.NewDefaultDeploymentBuilder().
					Namespace(testNamespace).
					Name("test-app").
					Replicas(5).
					AddLabel("app", "test-app").
					Container(container).
					Build()

				createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
				Expect(err).ToNot(HaveOccurred())
				deployments = append(deployments, createdDeployment)
			})
		})

		BeforeEach(func() {
			policies = nil
			networkPolicies = nil
		})

		It("should allow access to specific domain", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating admin policy to allow google.com domain (priority 10)", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-google").
					Action("Accept").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"google.com"}),
					})

				policy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-google-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing access to google.com works from random pod", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(testPods)).To(Equal(5))

				// Select random pod
				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing with pod %s (index %d of %d)\n", selectedPod.Name, randomIndex, len(testPods))

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("google"))
			})

			By("Testing access to non-allowed domain is blocked from different random pod", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				// Select different random pod
				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing blocked access with pod %s (index %d of %d)\n", selectedPod.Name, randomIndex, len(testPods))

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://example.com", fw.Options.IpFamily)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should allow access to wildcard domains", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating policy to allow *.amazonaws.com wildcard domain", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-aws-wildcard").
					Action("Accept").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"*.amazonaws.com"}),
					})

				policy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-aws-wildcard-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing access to AWS subdomain works", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://s3.amazonaws.com", fw.Options.IpFamily)

				Expect(err).ToNot(HaveOccurred())
			})

			By("Testing access to non-AWS domain is blocked", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://amazon.com", fw.Options.IpFamily)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should allow access to multiple specific domains", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating policy to allow multiple domains", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-multiple-domains").
					Action("Accept").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"amazon.com", "stackoverflow.com", "kubernetes.io"}),
					})

				policy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-multiple-domains-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing access to each allowed domain works", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				domains := []string{"amazon.com", "stackoverflow.com", "kubernetes.io"}
				for _, domain := range domains {
					randomIndex := rand.Intn(len(testPods))
					selectedPod := testPods[randomIndex]

					result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://"+domain, fw.Options.IpFamily)

					Expect(err).ToNot(HaveOccurred())
					Expect(result).To(ContainSubstring(domain))
				}
			})

			By("Testing access to non-allowed domain is blocked", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should enforce port-specific domain policies", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating policy to allow HTTPS for amazon.com", func() {
				httpsRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-https").
					Action("Accept").
					AddPort(443, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"amazon.com"}),
					})

				policy := manifest.NewClusterNetworkPolicyBuilder().
					Name("port-specific-amazon-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(httpsRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing HTTPS access is successful", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://amazon.com", fw.Options.IpFamily)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Testing HTTP access is failed", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://amazon.com", fw.Options.IpFamily)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should enforce domain priority correctly", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating high priority allow policy (priority 10)", func() {
				allowRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-example").
					Action("Accept").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"example.com"}),
					})

				allowPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-example-priority-10").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(allowRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, allowPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, allowPolicy)
			})

			// we can't DENY domains, thus DENY entire internet
			By("Creating low priority deny all policy (priority 20)", func() {
				denyRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-example").
					Action("Deny").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{"0.0.0.0/0"}),
					})

				denyPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("deny-example-priority-20").
					Priority(20).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(denyRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, denyPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, denyPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing that lower priority (10) wins over higher priority (20)", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://example.com", fw.Options.IpFamily)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("should enforce Admin tier over Baseline tier for domains", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating Baseline tier deny policy", func() {
				denyRule := manifest.NewClusterEgressRuleBuilder().
					Name("baseline-deny-all").
					Action("Deny").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{"0.0.0.0/0"}),
					})

				baselinePolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("baseline-deny-all").
					Priority(10).
					Tier("Baseline").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(denyRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, baselinePolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, baselinePolicy)
			})

			By("Creating Admin tier allow policy", func() {
				allowRule := manifest.NewClusterEgressRuleBuilder().
					Name("admin-allow-google").
					Action("Accept").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"google.com"}),
					})

				adminPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("admin-allow-google").
					Priority(20).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(allowRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, adminPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, adminPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing that Admin tier overrides Baseline tier", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("should allow HTTPS access to domains", func() {
			By("Creating network policy to deny all egress", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-egress").
					Namespace(testNamespace).
					PodSelector("app", "test-app").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
				networkPolicies = append(networkPolicies, networkPolicy)
			})

			By("Creating policy to allow HTTPS to amazon.com", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-amazon-https").
					Action("Accept").
					AddPort(443, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewDomainNamesPeer([]string{"amazon.com"}),
					})

				policy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-amazon-https-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing HTTPS access to amazon.com works", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://amazon.com", fw.Options.IpFamily)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Testing HTTP access to same domain is blocked", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://amazon.com", fw.Options.IpFamily)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should drop the domain rules of a workload whose pods left the node", func() {
			const app = "returning-app"
			// Waits until the workload has exactly n pods, all running.
			runningPods := func(n int) []v1.Pod {
				var running []v1.Pod
				Eventually(func(g Gomega) {
					pods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", app)
					g.Expect(err).ToNot(HaveOccurred())
					running = nil
					for _, pod := range pods {
						if pod.Status.Phase == v1.PodRunning && pod.DeletionTimestamp == nil {
							running = append(running, pod)
						}
					}
					g.Expect(pods).To(HaveLen(n))
					g.Expect(running).To(HaveLen(n))
				}, 2*time.Minute, 2*time.Second).Should(Succeed())
				return running
			}

			var nodes v1.NodeList
			Expect(fw.K8sClient.List(ctx, &nodes)).To(Succeed())
			container := manifest.NewAgnHostContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"while true; do sleep 30; done"}).
				Build()
			// One node, so the workload's last pod leaves it and its next pod comes back to it. No grace
			// period, so the pod can be gone from the node before the policy controller updates the policy.
			deployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, manifest.NewDefaultDeploymentBuilder().
				Namespace(testNamespace).
				Name(app).
				Replicas(1).
				TerminationGracePeriod(0).
				AddLabel("app", app).
				NodeSelector(map[string]string{"kubernetes.io/hostname": nodes.Items[0].Labels["kubernetes.io/hostname"]}).
				Container(container).
				Build())
			Expect(err).ToNot(HaveOccurred())
			deployments = append(deployments, deployment)

			networkPolicy := manifest.NewNetworkPolicyBuilder().
				Name("deny-all-egress-"+app).
				Namespace(testNamespace).
				PodSelector("app", app).
				SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
				Build()
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
			networkPolicies = append(networkPolicies, networkPolicy)
			adminPolicy := manifest.NewClusterNetworkPolicyBuilder().
				Name("admin-accept-example-"+app).
				Priority(10).
				Tier("Admin").
				SubjectPods(map[string]string{"test": "domain-policy"}, map[string]string{"app": app}).
				AddEgressRule(manifest.NewClusterEgressRuleBuilder().
					Name("accept-example").
					Action("Accept").
					AddPort(443, "TCP").
					BuildEgressRule([]map[string]interface{}{manifest.NewDomainNamesPeer([]string{"example.com"})})).
				Build()
			Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, adminPolicy)).To(Succeed())
			policies = append(policies, adminPolicy)
			time.Sleep(10 * time.Second)

			_, err = fw.PodManager.ValidateConnection(testNamespace, runningPods(1)[0].Name, "https://example.com", fw.Options.IpFamily)
			Expect(err).ToNot(HaveOccurred(), "the Admin domain rule allows example.com")

			Expect(fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, testNamespace, app, 0)).To(Succeed())
			runningPods(0)
			time.Sleep(5 * time.Second)
			Expect(fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, adminPolicy)).To(Succeed())
			time.Sleep(10 * time.Second)

			Expect(fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, testNamespace, app, 1)).To(Succeed())
			pod := runningPods(1)[0]
			time.Sleep(10 * time.Second)
			_, err = fw.PodManager.ValidateConnection(testNamespace, pod.Name, "https://example.com", fw.Options.IpFamily)
			Expect(err).To(HaveOccurred(), "the deleted Admin rule must not allow example.com to the workload's new pod")
		})

		It("should not let a Baseline domain rule override an Admin deny", func() {
			createPolicy := func(name, tier string, priority int32, rule map[string]interface{}) {
				policy := manifest.NewClusterNetworkPolicyBuilder().
					Name(name).
					Priority(priority).
					Tier(tier).
					SubjectNamespaces(map[string]string{"test": "domain-policy"}).
					AddEgressRule(rule).
					Build()
				Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)).To(Succeed())
				policies = append(policies, policy)
				time.Sleep(10 * time.Second)
			}
			acceptExample := manifest.NewClusterEgressRuleBuilder().
				Name("accept-example").
				Action("Accept").
				AddPort(443, "TCP").
				BuildEgressRule([]map[string]interface{}{manifest.NewDomainNamesPeer([]string{"example.com"})})
			denyHTTPS := manifest.NewClusterEgressRuleBuilder().
				Name("deny-https").
				Action("Deny").
				AddPort(443, "TCP").
				BuildEgressRule([]map[string]interface{}{manifest.NewNetworksPeer([]string{"0.0.0.0/0"})})

			testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app")
			Expect(err).ToNot(HaveOccurred())
			selectedPod := testPods[rand.Intn(len(testPods))]

			createPolicy("admin-deny-https", "Admin", 20, denyHTTPS)
			createPolicy("baseline-accept-example", "Baseline", 10, acceptExample)
			_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://example.com", fw.Options.IpFamily)
			Expect(err).To(HaveOccurred(), "the Admin deny must win over a Baseline domain rule")

			createPolicy("admin-accept-example", "Admin", 10, acceptExample)
			_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://example.com", fw.Options.IpFamily)
			Expect(err).ToNot(HaveOccurred(), "an Admin domain rule with a higher priority wins over the Admin deny")
		})

		AfterEach(func() {
			By("Cleaning up policies", func() {
				for _, policy := range policies {
					fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, policy)
				}
			})

			By("Cleaning up network policies", func() {
				for _, networkPolicy := range networkPolicies {
					fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
				}
			})

			time.Sleep(30 * time.Second)
		})

		AfterAll(func() {
			By("Cleaning up global policies", func() {
				for _, policy := range globalPolicies {
					fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, policy)
				}
			})

			By("Cleaning up deployments", func() {
				for _, deployment := range deployments {
					fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployment)
				}
			})

			By("Cleaning up namespace", func() {
				fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, testNamespace)
			})
		})
	})
})
