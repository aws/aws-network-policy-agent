package clusternetworkpolicy

import (
	"fmt"
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

var _ = Describe("Cluster Network Policy Tests", Ordered, func() {
	Context("When testing priority, tier precedence, and policy conflicts", func() {
		var deployments []*appsv1.Deployment
		var services []*v1.Service
		var policies []*unstructured.Unstructured
		var namespaces = []string{"test-ns1", "test-ns2", "quarantine-ns"}

		BeforeAll(func() {
			By("Creating test namespaces", func() {
				for _, ns := range namespaces {
					namespaceObj := &v1.Namespace{
						ObjectMeta: metaV1.ObjectMeta{
							Name: ns,
							Labels: map[string]string{
								"test": "advanced-policy",
								"name": ns,
							},
						},
					}
					err := fw.K8sClient.Create(ctx, namespaceObj)
					Expect(err).ToNot(HaveOccurred())
				}
			})

			By("Creating deployments and services", func() {
				deploymentConfigs := []struct {
					name      string
					namespace string
					labels    map[string]string
				}{
					{"web", "test-ns1", map[string]string{"app": "web", "tier": "frontend"}},
					{"api", "test-ns1", map[string]string{"app": "api", "tier": "backend"}},
					{"db", "test-ns2", map[string]string{"app": "db", "tier": "database"}},
					{"compromised", "quarantine-ns", map[string]string{"app": "compromised", "status": "quarantined"}},
				}

				for _, config := range deploymentConfigs {
					container := manifest.NewBusyBoxContainerBuilder().
						ImageRepository(fw.Options.TestImageRegistry).
						Command([]string{"/bin/sh", "-c"}).
						Args([]string{"(while true; do { echo -e 'HTTP/1.1 200 OK\n\nServer Response'; } | nc -l -p 8080; done) & (while true; do { echo 'UDP Server Response'; } | nc -u -l -p 5353; done)"}).
						Build()

					deploymentBuilder := manifest.NewDefaultDeploymentBuilder().
						Namespace(config.namespace).
						Name(config.name).
						Replicas(1).
						Container(container)

					for key, value := range config.labels {
						deploymentBuilder = deploymentBuilder.AddLabel(key, value)
					}

					deployment := deploymentBuilder.Build()

					createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
					Expect(err).ToNot(HaveOccurred())
					deployments = append(deployments, createdDeployment)

					var service *v1.Service
					if config.labels["app"] == "db" {
						service = &v1.Service{
							ObjectMeta: metaV1.ObjectMeta{
								Name:      config.name + "-service",
								Namespace: config.namespace,
							},
							Spec: v1.ServiceSpec{
								Selector: map[string]string{"app": config.labels["app"]},
								Ports: []v1.ServicePort{
									{Port: 8080, Name: "port8080", Protocol: v1.ProtocolTCP},
									{Port: 5353, Name: "port5353", Protocol: v1.ProtocolUDP},
								},
							},
						}
					} else {
						service = manifest.NewHTTPService().
							Name(config.name+"-service").
							Namespace(config.namespace).
							Port(8080).
							Selector("app", config.labels["app"]).
							Build()
					}

					err = fw.K8sClient.Create(ctx, service)
					Expect(err).ToNot(HaveOccurred())
					services = append(services, service)
				}
			})
		})

		BeforeEach(func() {
			policies = nil
		})

		// Test 1: Priority Override Test
		It("should enforce lower priority Admin policy over higher priority Admin policy", func() {
			By("Creating high priority deny policy (priority 50)", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-all-high-priority").
					Action("Deny").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{},
						),
					})

				denyPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("high-priority-deny").
					Priority(50).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, denyPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, denyPolicy)
			})

			By("Creating low priority allow policy (priority 10)", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-specific-low-priority").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				allowPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("low-priority-allow").
					Priority(10).
					Tier("Admin").
					SubjectPods(
						map[string]string{"name": "test-ns1"},
						map[string]string{"app": "api"},
					).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, allowPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, allowPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing that lower priority policy takes precedence", func() {
				apiPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "api")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(apiPods)).To(BeNumerically(">", 0))

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(dbPods)).To(BeNumerically(">", 0))
				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				result, err := fw.PodManager.ExecInPod("test-ns1", apiPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("Server Response"))
			})
		})

		// Test 2: Tier Precedence Test
		It("should enforce Admin tier over Baseline tier regardless of priority", func() {
			By("Creating high priority Baseline deny policy", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("baseline-deny-all").
					Action("Deny").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{matchAllCIDR}),
					})

				baselinePolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("baseline-high-priority-deny").
					Priority(1).
					Tier("Baseline").
					SubjectNamespaces(map[string]string{"test": "advanced-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, baselinePolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, baselinePolicy)
			})

			By("Creating low priority Admin allow policy", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("admin-allow-specific").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{},
						),
					})

				adminPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("admin-low-priority-allow").
					Priority(100).
					Tier("Admin").
					SubjectPods(
						map[string]string{"name": "test-ns1"},
						map[string]string{"app": "web"},
					).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, adminPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, adminPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing that Admin tier overrides Baseline tier", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(webPods)).To(BeNumerically(">", 0))

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(dbPods)).To(BeNumerically(">", 0))

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				result, err := fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("Server Response"))
			})
		})

		// Test 3: Network Policy overrides baseline cluster network policy
		It("should enforce Network policy over baseline cluster policies", func() {
			By("Creating baseline cluster policy to allow traffic", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("cluster-allow-all").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{matchAllCIDR}),
					})

				clusterPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("cluster-allow-policy").
					Priority(1).
					Tier("Baseline").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, clusterPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, clusterPolicy)
			})

			By("Creating network policy to deny traffic", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("network-deny-policy").
					Namespace("test-ns1").
					PodSelector("app", "web").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing that network policy overrides the baseline cluster policy", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(webPods)).To(BeNumerically(">", 0))

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(dbPods)).To(BeNumerically(">", 0))

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				_, err = fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
				Expect(err).To(HaveOccurred())
			})
		})

		// Test 4: Admin Tier overrides Network Policy
		It("should enforce Admin tier cluster policy over network policy", func() {
			By("Creating network policy to deny traffic", func() {
				networkPolicy := manifest.NewNetworkPolicyBuilder().
					Name("network-deny-all-policy").
					Namespace("test-ns1").
					PodSelector("app", "web").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating Admin tier cluster policy to allow traffic", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("admin-allow-override").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				adminPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("admin-override-network-policy").
					Priority(50).
					Tier("Admin").
					SubjectPods(
						map[string]string{"name": "test-ns1"},
						map[string]string{"app": "web"},
					).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, adminPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, adminPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing that Admin tier overrides Network Policy", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(webPods)).To(BeNumerically(">", 0))

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(dbPods)).To(BeNumerically(">", 0))

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				result, err := fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("Server Response"))
			})
		})

		// Test 5: Same Priority DENY vs ALLOW Test
		It("should enforce DENY over ALLOW when both have same priority", func() {
			By("Creating same priority ALLOW and DENY policies", func() {
				allowRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-db").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				allowPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("same-priority-allow").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(allowRule).
					Build()

				denyRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-db").
					Action("Deny").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				denyPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("same-priority-deny").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(denyRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, allowPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, allowPolicy)

				err = fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, denyPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, denyPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing DENY precedence over ALLOW", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				By("Verifying traffic is denied (DENY should win over ALLOW at same priority)", func() {
					_, err = fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})
			})
		})

		// Test 6: Same Priority ALLOW vs PASS Test
		It("should enforce ALLOW over PASS when both have same priority", func() {
			By("Creating same priority ALLOW and PASS policies", func() {
				allowRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-db").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				allowPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("same-priority-allow-vs-pass").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(allowRule).
					Build()

				passRule := manifest.NewClusterEgressRuleBuilder().
					Name("pass-db").
					Action("Pass").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				passPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("same-priority-pass").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(passRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, allowPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, allowPolicy)

				err = fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, passPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, passPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing ALLOW precedence over PASS", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				By("Verifying traffic is allowed (ALLOW should win over PASS at same priority)", func() {
					result, err := fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
					Expect(err).ToNot(HaveOccurred())
					Expect(result).To(ContainSubstring("Server Response"))
				})
			})
		})

		// Test 6: UDP Traffic Test
		It("should handle UDP and TCP traffic differently", func() {
			By("Creating policy to allow UDP but deny TCP", func() {
				udpRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-udp").
					Action("Accept").
					AddPort(5353, "UDP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{},
						),
					})

				tcpRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-tcp").
					Action("Deny").
					AddPort(8080, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{},
						),
					})

				protocolPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("protocol-specific-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(udpRule).
					AddEgressRule(tcpRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, protocolPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, protocolPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing protocol-specific enforcement", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				By("Verifying TCP traffic is denied (should be DENIED by TCP deny rule)", func() {
					_, err = fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})
			})
		})

		// Test 8: Multi-Port Test
		It("should enforce different policies for different ports", func() {
			By("Creating multi-port policy", func() {
				allowHTTPRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-http").
					Action("Accept").
					AddPort(80, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{},
						),
					})

				denyHTTPSRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-https").
					Action("Deny").
					AddPort(443, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{},
						),
					})

				allowCustomRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-custom").
					Action("Accept").
					AddPort(8080, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				multiPortPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("multi-port-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(allowHTTPRule).
					AddEgressRule(denyHTTPSRule).
					AddEgressRule(allowCustomRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, multiPortPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, multiPortPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing multi-port enforcement", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())

				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				// Port 8080 to db should work
				result, err := fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("Server Response"))
			})
		})

		// Test 9: Zero Trust Test with baseline policy
		It("should implement zero trust with baseline deny-all and specific admin allows", func() {
			By("Creating baseline deny-all policy", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("zero-trust-deny").
					Action("Deny").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{matchAllCIDR}),
					})

				baselinePolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("zero-trust-baseline").
					Priority(100).
					Tier("Baseline").
					SubjectNamespaces(map[string]string{"test": "advanced-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, baselinePolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, baselinePolicy)
			})

			By("Creating admin allow for DNS priority 10", func() {
				egressRuleBuilder := manifest.NewClusterEgressRuleBuilder().
					Name("allow-dns").
					Action("Accept").
					AddPort(53, "UDP")

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
					Name("zero-trust-dns").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "advanced-policy"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, dnsPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, dnsPolicy)
			})

			By("Creating admin allow for api to db priority 20", func() {
				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-api-to-db").
					Action("Accept").
					AddPort(8080, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				apiPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("zero-trust-api").
					Priority(20).
					Tier("Admin").
					SubjectPods(
						map[string]string{"name": "test-ns1"},
						map[string]string{"app": "api"},
					).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, apiPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, apiPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing zero trust enforcement", func() {
				apiPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "api")
				Expect(err).ToNot(HaveOccurred())

				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying API pod can access DB (should be ALLOWED by admin policy)", func() {
					result, err := fw.PodManager.ExecInPod("test-ns1", apiPods[0].Name, []string{"wget", "-qO-", "--timeout=5", "http://db-service.test-ns2.svc.cluster.local:8080"})
					Expect(err).ToNot(HaveOccurred())
					Expect(result).To(ContainSubstring("Server Response"))
				})

				By("Verifying Web pod cannot access DB (should be DENIED by baseline policy)", func() {
					_, err = fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", "http://db-service.test-ns2.svc.cluster.local:8080"})
					Expect(err).To(HaveOccurred())
				})
			})
		})

		// Test 10: Protocol-Specific Allow with Deny-All Fallback
		It("should allow specific protocol with priority 1 and deny everything else with priority 100", func() {
			By("Creating high priority TCP allow policy (priority 1)", func() {
				allowTCPRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-tcp-only").
					Action("Accept").
					AddPort(8080, "TCP").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				allowPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-tcp-priority-1").
					Priority(1).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(allowTCPRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, allowPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, allowPolicy)
			})

			By("Creating low priority deny-all policy (priority 100)", func() {
				denyAllRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-all-protocols").
					Action("Deny").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "test-ns2"},
							map[string]string{"app": "db"},
						),
					})

				denyPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("deny-all-priority-100").
					Priority(100).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "test-ns1"}).
					AddEgressRule(denyAllRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, denyPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, denyPolicy)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing protocol-specific allow with deny-all fallback", func() {
				webPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns1", "app", "web")
				Expect(err).ToNot(HaveOccurred())

				dbPods, err := fw.PodManager.GetPodsWithLabel(ctx, "test-ns2", "app", "db")
				Expect(err).ToNot(HaveOccurred())
				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}

				By("Verifying TCP traffic is allowed (should be ALLOWED by priority 1 policy)", func() {
					result, err := fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, dbPods[0].Status.PodIP)})
					Expect(err).ToNot(HaveOccurred())
					Expect(result).To(ContainSubstring("Server Response"))
				})
				formatString = "%s"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "[%s]"
				}

				By("Verifying UDP traffic is denied (should be DENIED by priority 100 deny-all policy)", func() {
					_, err = fw.PodManager.ExecInPod("test-ns1", webPods[0].Name, []string{"timeout", "5", "nc", "-u", fmt.Sprint(formatString, dbPods[0].Status.PodIP), "5353"})
					Expect(err).To(HaveOccurred())
				})
			})
		})

		AfterEach(func() {
			for _, policy := range policies {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, policy)
			}

			// Clean up any network policies
			networkPolicies := []string{"network-deny-policy", "network-deny-all-policy"}
			for _, policyName := range networkPolicies {
				networkPolicy := &network.NetworkPolicy{
					ObjectMeta: metaV1.ObjectMeta{
						Name:      policyName,
						Namespace: "test-ns1",
					},
				}
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
			}
		})

		AfterAll(func() {
			By("Cleaning up services", func() {
				for _, service := range services {
					fw.K8sClient.Delete(ctx, service)
				}
			})

			By("Cleaning up deployments", func() {
				for _, deployment := range deployments {
					fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployment)
				}
			})

			By("Cleaning up namespaces", func() {
				for _, ns := range namespaces {
					fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, ns)
				}
			})
		})
	})
})
