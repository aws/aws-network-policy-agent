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

var _ = Describe("Multi-Deployment ClusterNetworkPolicy Tests", Ordered, func() {
	Context("When multiple deployments across namespaces with tiered policies", func() {
		var deployments []*appsv1.Deployment
		var services []*v1.Service
		var policies []*unstructured.Unstructured
		var namespaces = []string{"ns1", "ns2", "ns3", "ns4"}

		BeforeAll(func() {
			By("Creating test namespaces", func() {
				for _, ns := range namespaces {
					namespaceObj := &v1.Namespace{
						ObjectMeta: metaV1.ObjectMeta{
							Name: ns,
							Labels: map[string]string{
								"test": "multi-deployment",
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
					{"app1", "ns1", map[string]string{"app": "app1", "tier": "frontend"}},
					{"app2", "ns1", map[string]string{"app": "app2", "tier": "backend"}},
					{"app3", "ns2", map[string]string{"app": "app3", "tier": "database"}},
					{"app4", "ns3", map[string]string{"app": "app4", "tier": "cache"}},
					{"app5", "ns4", map[string]string{"app": "app5", "tier": "worker"}},
				}

				for _, config := range deploymentConfigs {
					container := manifest.NewBusyBoxContainerBuilder().
						ImageRepository(fw.Options.TestImageRegistry).
						Command([]string{"/bin/sh", "-c"}).
						Args([]string{"while true; do { echo 'HTTP/1.1 200 OK\n\nServer Response'; } | nc -l -p 8080; done"}).
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

					service := &v1.Service{
						ObjectMeta: metaV1.ObjectMeta{
							Name:      config.name + "-service",
							Namespace: config.namespace,
						},
						Spec: v1.ServiceSpec{
							Selector: map[string]string{"app": config.labels["app"]},
							Ports: []v1.ServicePort{
								{
									Port:     8080,
									Protocol: v1.ProtocolTCP,
								},
							},
						},
					}
					err = fw.K8sClient.Create(ctx, service)
					Expect(err).ToNot(HaveOccurred())
					services = append(services, service)
				}
			})
		})

		BeforeEach(func() {
			// Reset policies slice for each test
			policies = nil
		})

		It("should enforce tiered cluster network policies correctly", func() {
			By("Creating Admin tier policy - Allow CoreDNS (priority 10)", func() {
				egressRuleBuilder := manifest.NewClusterEgressRuleBuilder().
					Name("allow-coredns").
					Action("Accept").
					AddPort(53, "TCP").
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

				policy1 := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-coredns-policy").
					Priority(10).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "multi-deployment"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy1)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy1)
			})

			By("Creating Admin tier policy - Same namespace communication (priority 20)", func() {
				ingressRule := manifest.NewClusterIngressRuleBuilder().
					Name("allow-same-ns-ingress").
					Action("Accept").
					BuildIngressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "ns1"},
							map[string]string{},
						),
					})

				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-same-ns-egress").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "ns1"},
							map[string]string{},
						),
					})

				policy2 := manifest.NewClusterNetworkPolicyBuilder().
					Name("same-namespace-policy").
					Priority(20).
					Tier("Admin").
					SubjectPods(
						map[string]string{"name": "ns1"},
						map[string]string{},
					).
					AddIngressRule(ingressRule).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy2)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy2)
			})

			By("Creating Admin tier policy - ns2 to ns3 communication (priority 30)", func() {
				ingressRule := manifest.NewClusterIngressRuleBuilder().
					Name("allow-ns2-to-ns3-ingress").
					Action("Accept").
					BuildIngressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "ns2"},
							map[string]string{},
						),
					})

				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("allow-ns2-to-ns3-egress").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"name": "ns3"},
							map[string]string{},
						),
					})

				policyNs2ToNs3 := manifest.NewClusterNetworkPolicyBuilder().
					Name("ns2-to-ns3-policy").
					Priority(30).
					Tier("Admin").
					SubjectPods(
						map[string]string{"name": "ns2"},
						map[string]string{},
					).
					AddIngressRule(ingressRule).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policyNs2ToNs3)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policyNs2ToNs3)
			})

			By("Creating Admin tier policy - Default pass rule (priority 100)", func() {

				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("default-pass").
					Action("Pass").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{matchAllCIDR}),
					})

				policy3 := manifest.NewClusterNetworkPolicyBuilder().
					Name("default-pass-policy").
					Priority(100).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"test": "multi-deployment"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy3)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy3)
			})

			By("Creating Baseline tier policy - Deny all (priority 20)", func() {

				egressRule := manifest.NewClusterEgressRuleBuilder().
					Name("deny-all-baseline").
					Action("Deny").
					BuildEgressRule([]map[string]interface{}{
						manifest.NewNetworksPeer([]string{matchAllCIDR}),
					})

				policy4 := manifest.NewClusterNetworkPolicyBuilder().
					Name("baseline-deny-all").
					Priority(20).
					Tier("Baseline").
					SubjectNamespaces(map[string]string{"test": "multi-deployment"}).
					AddEgressRule(egressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy4)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, policy4)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Verifying network policy enforcement", func() {
				// Get pods for testing
				app1Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns1", "app", "app1")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(app1Pods)).To(BeNumerically(">", 0))

				app2Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns1", "app", "app2")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(app2Pods)).To(BeNumerically(">", 0))

				app3Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns2", "app", "app3")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(app3Pods)).To(BeNumerically(">", 0))

				app4Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns3", "app", "app4")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(app4Pods)).To(BeNumerically(">", 0))

				app5Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns4", "app", "app5")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(app5Pods)).To(BeNumerically(">", 0))

				// Test same namespace communication (should work)
				By("Testing same namespace communication (ns1 to ns1)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app1Pods[0].Status.PodIP, app2Pods[0].Status.PodIP, 8080)
					result, err := fw.PodManager.ExecInPod("ns1", app1Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app2Pods[0].Status.PodIP)})
					Expect(err).ToNot(HaveOccurred())
					Expect(result).To(ContainSubstring("Server Response"))
				})

				// Test ns2 to ns3 communication (should work)
				By("Testing ns2 to ns3 communication (allowed by policy)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app3Pods[0].Status.PodIP, app4Pods[0].Status.PodIP, 8080)
					result, err := fw.PodManager.ExecInPod("ns2", app3Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app4Pods[0].Status.PodIP)})
					Expect(err).ToNot(HaveOccurred())
					Expect(result).To(ContainSubstring("Server Response"))
				})

				// Test ns1 to ns2 communication (should be denied)
				By("Testing ns1 to ns2 communication (should be denied)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app1Pods[0].Status.PodIP, app3Pods[0].Status.PodIP, 8080)
					_, err := fw.PodManager.ExecInPod("ns1", app1Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app3Pods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})

				// Test ns3 to ns2 communication (should be denied - only ns2 to ns3 allowed)
				By("Testing ns3 to ns2 communication (should be denied)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app4Pods[0].Status.PodIP, app3Pods[0].Status.PodIP, 8080)
					_, err := fw.PodManager.ExecInPod("ns3", app4Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app3Pods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})

				// Test ns4 to any namespace (should be denied by baseline tier)
				By("Testing ns4 to ns1 communication (denied by baseline tier)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app5Pods[0].Status.PodIP, app1Pods[0].Status.PodIP, 8080)
					_, err := fw.PodManager.ExecInPod("ns4", app5Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app1Pods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})

				By("Testing ns4 to ns2 communication (denied by baseline tier)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app5Pods[0].Status.PodIP, app3Pods[0].Status.PodIP, 8080)
					_, err := fw.PodManager.ExecInPod("ns4", app5Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app3Pods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})

				// Test any namespace to ns4 (should be denied by baseline tier)
				By("Testing ns1 to ns4 communication (denied by baseline tier)", func() {
					formatString := "http://%s:8080"
					if fw.Options.IpFamily == "IPv6" {
						formatString = "http://[%s]:8080"
					}
					fmt.Printf("Src IP: %s Dest IP: %s Dest Port: %d Proto TCP Verdict\n", app1Pods[0].Status.PodIP, app5Pods[0].Status.PodIP, 8080)
					_, err := fw.PodManager.ExecInPod("ns1", app1Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app5Pods[0].Status.PodIP)})
					Expect(err).To(HaveOccurred())
				})
			})
		})

		It("should allow DNS resolution while denying ns2 traffic", func() {
			By("Creating cluster network policy priority 5 to allow ingress/egress CoreDNS traffic for ns1", func() {
				egressRuleBuilder := manifest.NewClusterEgressRuleBuilder().
					Name("allow-coredns-egress").
					Action("Accept").
					AddPort(53, "TCP").
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

				ingressRule := manifest.NewClusterIngressRuleBuilder().
					Name("allow-coredns-ingress").
					Action("Accept").
					AddPort(53, "TCP").
					AddPort(53, "UDP").
					BuildIngressRule([]map[string]interface{}{
						manifest.NewPodsPeer(
							map[string]string{"kubernetes.io/metadata.name": "kube-system"},
							map[string]string{"k8s-app": "kube-dns"},
						),
					})

				corednsPolicy := manifest.NewClusterNetworkPolicyBuilder().
					Name("allow-coredns-cluster-policy").
					Priority(5).
					Tier("Admin").
					SubjectNamespaces(map[string]string{"name": "ns1"}).
					AddEgressRule(egressRule).
					AddIngressRule(ingressRule).
					Build()

				err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, corednsPolicy)
				Expect(err).ToNot(HaveOccurred())
				policies = append(policies, corednsPolicy)
			})

			By("Creating network policy to deny all ingress and egress for ns1", func() {
				denyAllPolicy := manifest.NewNetworkPolicyBuilder().
					Name("deny-all-ns1-policy").
					Namespace("ns1").
					PodSelector("app", "app1").
					SetPolicyTypes([]network.PolicyType{network.PolicyTypeIngress, network.PolicyTypeEgress}).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyAllPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing DNS resolution from ns1 to ns2 service (should be allowed)", func() {
				app1Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns1", "app", "app1")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(app1Pods)).To(BeNumerically(">", 0))

				result, err := fw.PodManager.ExecInPod("ns1", app1Pods[0].Name, []string{"nslookup", "app3-service.ns2.svc.cluster.local"})
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("app3-service.ns2.svc.cluster.local"))
			})

			By("Testing that other traffic from ns1 for ingress and egress (should be denied)", func() {
				formatString := "http://%s:8080"
				if fw.Options.IpFamily == "IPv6" {
					formatString = "http://[%s]:8080"
				}
				app1Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns1", "app", "app1")
				Expect(err).ToNot(HaveOccurred())

				app3Pods, err := fw.PodManager.GetPodsWithLabel(ctx, "ns2", "app", "app3")
				Expect(err).ToNot(HaveOccurred())

				_, err = fw.PodManager.ExecInPod("ns1", app1Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app3Pods[0].Status.PodIP)})
				Expect(err).To(HaveOccurred())

				_, err = fw.PodManager.ExecInPod("ns2", app3Pods[0].Name, []string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(formatString, app1Pods[0].Status.PodIP)})
				Expect(err).To(HaveOccurred())
			})
		})

		AfterEach(func() {
			// Clean up policies created in each test
			for _, policy := range policies {
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, policy)
			}

			// Clean up the standard network policy
			denyAllPolicy := &network.NetworkPolicy{
				ObjectMeta: metaV1.ObjectMeta{
					Name:      "deny-all-ns1-policy",
					Namespace: "ns1",
				},
			}
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, denyAllPolicy)
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
