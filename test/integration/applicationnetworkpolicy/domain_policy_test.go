package applicationnetworkpolicy

import (
	"math/rand"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ = Describe("Domain Based Application Network Policy Tests", Ordered, func() {
	Context("When testing domain name egress rules with application network policies", func() {
		var deployment1 *appsv1.Deployment
		var deployment2 *appsv1.Deployment
		var appNetworkPolicies []*unstructured.Unstructured
		var testNamespace = "app-domain-test-ns"

		BeforeAll(func() {
			By("Creating test namespace", func() {
				namespaceObj := &v1.Namespace{
					ObjectMeta: metaV1.ObjectMeta{
						Name: testNamespace,
						Labels: map[string]string{
							"test": "app-domain-policy",
						},
					},
				}
				err := fw.K8sClient.Create(ctx, namespaceObj)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating first deployment with 3 pods", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"while true; do sleep 30; done"}).
					Build()

				deployment := manifest.NewDefaultDeploymentBuilder().
					Namespace(testNamespace).
					Name("test-app-1").
					Replicas(3).
					AddLabel("app", "test-app-1").
					Container(container).
					Build()

				createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
				Expect(err).ToNot(HaveOccurred())
				deployment1 = createdDeployment
			})

			By("Creating second deployment with 3 pods", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"while true; do sleep 30; done"}).
					Build()

				deployment := manifest.NewDefaultDeploymentBuilder().
					Namespace(testNamespace).
					Name("test-app-2").
					Replicas(3).
					AddLabel("app", "test-app-2").
					Container(container).
					Build()

				createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
				Expect(err).ToNot(HaveOccurred())
				deployment2 = createdDeployment
			})
		})

		BeforeEach(func() {
			appNetworkPolicies = nil
		})

		It("should allow domain access only to deployment with application network policy", func() {
			By("Applying deny all except DNS network policy to both deployments", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Policy for deployment 1
				appPolicy1 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy1)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy1)

				// Policy for deployment 2
				appPolicy2 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-2").
					Namespace(testNamespace).
					PodSelector("app", "test-app-2").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err = fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy2)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy2)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS request from random pod in deployment 1", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(testPods)).To(Equal(3))

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS from deployment 1, pod %s (index %d of %d)\n", selectedPod.Name, randomIndex, len(testPods))

				command := []string{"nslookup", "google.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("res %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating DNS request from random pod in deployment 2", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-2")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(testPods)).To(Equal(3))

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS from deployment 2, pod %s (index %d of %d)\n", selectedPod.Name, randomIndex, len(testPods))

				command := []string{"nslookup", "google.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("res %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Applying application network policy to deployment 1 to allow egress to google.com", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Create domain-based egress rule for google.com
				httpPort := map[string]interface{}{
					"port":     int32(80),
					"protocol": "TCP",
				}
				httpsPort := map[string]interface{}{
					"port":     int32(443),
					"protocol": "TCP",
				}

				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{"google.com"})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort, httpsPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				// Delete old policy for deployment 1
				err := fw.ApplicationNetworkPolicyManager.DeleteApplicationNetworkPolicy(ctx, appNetworkPolicies[0])
				Expect(err).ToNot(HaveOccurred())

				// Create new policy with domain-based rule
				appNetworkPolicy := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-google-app-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					AddEgressRule(domainEgressRule).
					Build()

				err = fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies[0] = appNetworkPolicy
			})

			By("Waiting for new policy to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS request from random pod in deployment 1 still succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS from deployment 1 after policy update, pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				_, err = fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating DNS request from random pod in deployment 2 still succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-2")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS from deployment 2 after policy update, pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				_, err = fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTP request from random pod in deployment 1 succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP from deployment 1, pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result %s\n", result)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(ContainSubstring("google"))
			})

			By("Validating HTTP request from random pod in deployment 2 fails", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-2")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP from deployment 2 (should fail), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result %s\n", result)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should validate ANP with domains but DNS traffic not allowed fails connections", func() {
			By("Applying application network policy with domains only (no DNS rule) to deployment 1", func() {
				// Create domain-based egress rule for google.com and amazon.com
				httpPort := map[string]interface{}{
					"port":     int32(80),
					"protocol": "TCP",
				}
				httpsPort := map[string]interface{}{
					"port":     int32(443),
					"protocol": "TCP",
				}

				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{"google.com", "amazon.com"})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort, httpsPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				// Policy for deployment 1 - only domain rules, NO DNS
				appPolicy1 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-domains-no-dns-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy1)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy1)
			})

			By("Waiting for policy to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS resolution fails for google.com without DNS rule", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(testPods)).To(Equal(3))

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for google.com (should fail), pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				if err != nil {
					GinkgoWriter.Printf("error: %v\n", err)
				}
				Expect(err).To(HaveOccurred())
			})

			By("Validating DNS resolution fails for amazon.com without DNS rule", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for amazon.com (should fail), pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "amazon.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				if err != nil {
					GinkgoWriter.Printf("error: %v\n", err)
				}
				Expect(err).To(HaveOccurred())
			})

			By("Adding a separate DNS policy to allow DNS requests", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Create new separate policy with only DNS rule (keep the domain policy)
				appPolicyDNS := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-dns-only-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyDNS)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyDNS)
			})

			By("Waiting for updated policy to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS resolution succeeds for google.com with DNS rule", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for google.com (should succeed), pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating DNS resolution succeeds for amazon.com with DNS rule", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for amazon.com (should succeed), pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "amazon.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("should validate cluster service access with ANP domain-based rules", func() {
			var testService *v1.Service
			var serviceDeployment *appsv1.Deployment

			By("Creating deployment to back the service", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/agnhost"}).
					Args([]string{"netexec", "--http-port=80"}).
					Build()

				deployment := manifest.NewDefaultDeploymentBuilder().
					Namespace(testNamespace).
					Name("test-service-backend").
					Replicas(2).
					AddLabel("app", "test-service-backend").
					Container(container).
					Build()

				createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
				Expect(err).ToNot(HaveOccurred())
				serviceDeployment = createdDeployment
			})

			By("Applying deny all except DNS network policy to deployment 1", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Policy for deployment 1 - only DNS allowed
				appPolicy1 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy1)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy1)
			})

			By("Creating a test service backed by nginx deployment", func() {
				service := manifest.NewHTTPService().
					Name("test-cluster-service").
					Namespace(testNamespace).
					Port(80).
					Selector("app", "test-service-backend").
					Build()

				createdService, err := fw.ServiceManager.CreateService(ctx, service)
				Expect(err).ToNot(HaveOccurred())
				testService = createdService
			})

			By("Waiting for policies and service to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS resolution succeeds for cluster service", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for cluster service, pod %s\n", selectedPod.Name)

				serviceFQDN := "test-cluster-service." + testNamespace + ".svc.cluster.local"
				command := []string{"nslookup", serviceFQDN}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTP connection to cluster service fails without domain policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to cluster service (should fail), pod %s\n", selectedPod.Name)

				serviceURL := "http://test-cluster-service." + testNamespace + ".svc.cluster.local"
				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, serviceURL, fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Adding a separate ANP to allow access to cluster service using domain name", func() {
				// Create domain-based egress rule for cluster service
				httpPort := map[string]interface{}{
					"port":     int32(80),
					"protocol": "TCP",
				}

				serviceFQDN := "test-cluster-service." + testNamespace + ".svc.cluster.local"
				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{serviceFQDN})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				// Create new separate policy with domain-based rule for service (keep DNS policy)
				appPolicyService := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-cluster-service-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyService)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyService)
			})

			By("Waiting for new policy to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS resolution still succeeds for cluster service", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for cluster service after policy update, pod %s\n", selectedPod.Name)

				serviceFQDN := "test-cluster-service." + testNamespace + ".svc.cluster.local"
				command := []string{"nslookup", serviceFQDN}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTP connection to cluster service succeeds with domain policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to cluster service (should succeed), pod %s\n", selectedPod.Name)

				serviceURL := "http://test-cluster-service." + testNamespace + ".svc.cluster.local"
				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, serviceURL, fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Cleaning up test service and deployment", func() {
				if testService != nil {
					err := fw.ServiceManager.DeleteService(ctx, testService)
					Expect(err).ToNot(HaveOccurred())
				}
				if serviceDeployment != nil {
					err := fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serviceDeployment)
					Expect(err).ToNot(HaveOccurred())
				}
			})
		})

		It("should validate inter-service communication with ANP domain-based rules", func() {
			var serviceA *v1.Service
			var serviceB *v1.Service
			var deploymentA *appsv1.Deployment
			var deploymentB *appsv1.Deployment

			By("Creating service A deployment with HTTP server", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/agnhost"}).
					Args([]string{"netexec", "--http-port=80"}).
					Build()

				deployment := manifest.NewDefaultDeploymentBuilder().
					Namespace(testNamespace).
					Name("service-a").
					Replicas(2).
					AddLabel("app", "service-a").
					Container(container).
					Build()

				createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
				Expect(err).ToNot(HaveOccurred())
				deploymentA = createdDeployment
			})

			By("Creating service B deployment with HTTP server", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/agnhost"}).
					Args([]string{"netexec", "--http-port=80"}).
					Build()

				deployment := manifest.NewDefaultDeploymentBuilder().
					Namespace(testNamespace).
					Name("service-b").
					Replicas(2).
					AddLabel("app", "service-b").
					Container(container).
					Build()

				createdDeployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
				Expect(err).ToNot(HaveOccurred())
				deploymentB = createdDeployment
			})

			By("Creating Kubernetes service for service A", func() {
				service := manifest.NewHTTPService().
					Name("service-a").
					Namespace(testNamespace).
					Port(80).
					Selector("app", "service-a").
					Build()

				createdService, err := fw.ServiceManager.CreateService(ctx, service)
				Expect(err).ToNot(HaveOccurred())
				serviceA = createdService
			})

			By("Creating Kubernetes service for service B", func() {
				service := manifest.NewHTTPService().
					Name("service-b").
					Namespace(testNamespace).
					Port(80).
					Selector("app", "service-b").
					Build()

				createdService, err := fw.ServiceManager.CreateService(ctx, service)
				Expect(err).ToNot(HaveOccurred())
				serviceB = createdService
			})

			By("Applying deny all except DNS network policy to both services", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Policy for service A
				appPolicyA := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-service-a").
					Namespace(testNamespace).
					PodSelector("app", "service-a").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyA)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyA)

				// Policy for service B
				appPolicyB := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-service-b").
					Namespace(testNamespace).
					PodSelector("app", "service-b").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err = fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyB)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyB)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating service A cannot reach service B without domain policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "service-a")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(testPods)).To(BeNumerically(">", 0))

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP from service A to service B (should fail), pod %s\n", selectedPod.Name)

				serviceURL := "http://service-b." + testNamespace + ".svc.cluster.local"
				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, serviceURL, fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Validating service B cannot reach service A without domain policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "service-b")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(testPods)).To(BeNumerically(">", 0))

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP from service B to service A (should fail), pod %s\n", selectedPod.Name)

				serviceURL := "http://service-a." + testNamespace + ".svc.cluster.local"
				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, serviceURL, fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Adding ANP to allow service A to reach service B using domain name", func() {
				// Create domain-based egress rule for service B
				httpPort := map[string]interface{}{
					"port":     int32(80),
					"protocol": "TCP",
				}

				serviceBFQDN := "service-b." + testNamespace + ".svc.cluster.local"
				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{serviceBFQDN})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				// Create new policy for service A to reach service B
				appPolicyAtoB := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-service-a-to-b").
					Namespace(testNamespace).
					PodSelector("app", "service-a").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyAtoB)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyAtoB)
			})

			By("Adding ANP to allow service B to reach service A using domain name", func() {
				// Create domain-based egress rule for service A
				httpPort := map[string]interface{}{
					"port":     int32(80),
					"protocol": "TCP",
				}

				serviceAFQDN := "service-a." + testNamespace + ".svc.cluster.local"
				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{serviceAFQDN})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				// Create new policy for service B to reach service A
				appPolicyBtoA := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-service-b-to-a").
					Namespace(testNamespace).
					PodSelector("app", "service-b").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyBtoA)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyBtoA)
			})

			By("Waiting for new policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating service A can now reach service B with domain policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "service-a")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP from service A to service B (should succeed), pod %s\n", selectedPod.Name)

				serviceURL := "http://service-b." + testNamespace + ".svc.cluster.local"
				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, serviceURL, fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating service B can now reach service A with domain policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "service-b")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP from service B to service A (should succeed), pod %s\n", selectedPod.Name)

				serviceURL := "http://service-a." + testNamespace + ".svc.cluster.local"
				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, serviceURL, fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Cleaning up services and deployments", func() {
				if serviceA != nil {
					err := fw.ServiceManager.DeleteService(ctx, serviceA)
					Expect(err).ToNot(HaveOccurred())
				}
				if serviceB != nil {
					err := fw.ServiceManager.DeleteService(ctx, serviceB)
					Expect(err).ToNot(HaveOccurred())
				}
				if deploymentA != nil {
					err := fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deploymentA)
					Expect(err).ToNot(HaveOccurred())
				}
				if deploymentB != nil {
					err := fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deploymentB)
					Expect(err).ToNot(HaveOccurred())
				}
			})
		})

		It("should validate multiple ANPs with different ports and progressive deletion", func() {
			By("Applying deny all except DNS network policy to deployment 1", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Policy for deployment 1 - only DNS allowed
				appPolicy1 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy1)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy1)
			})

			By("Applying ANP for port 443 (HTTPS)", func() {
				httpsPort := map[string]interface{}{
					"port":     int32(443),
					"protocol": "TCP",
				}

				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{"google.com", "www.amazon.com"})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpsPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				appPolicy443 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-port-443").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy443)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy443)
			})

			By("Applying ANP for port 80 (HTTP)", func() {
				httpPort := map[string]interface{}{
					"port":     int32(80),
					"protocol": "TCP",
				}

				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{"google.com", "www.amazon.com"})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				appPolicy80 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-port-80").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy80)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy80)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating DNS resolution succeeds with both policies", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for google.com, pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to google.com succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to google.com, pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTP (port 80) connection to google.com succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to google.com, pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to amazon.com succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to amazon.com, pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://www.amazon.com", fw.Options.IpFamily)
				// GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTP (port 80) connection to amazon.com succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to amazon.com, pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://www.amazon.com", fw.Options.IpFamily)
				// GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Deleting port 443 policy", func() {
				// appNetworkPolicies[1] is the port 443 policy
				err := fw.ApplicationNetworkPolicyManager.DeleteApplicationNetworkPolicy(ctx, appNetworkPolicies[1])
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies[1] = nil
			})

			By("Waiting for policy deletion to take effect", func() {
				time.Sleep(5 * time.Second)
			})

			By("Validating DNS still succeeds after deleting port 443 policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for google.com after deleting 443 policy, pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				res, err := fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to google.com fails after deleting policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to google.com (should fail), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Validating HTTP (port 80) connection to google.com still succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to google.com (should succeed), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to amazon.com fails after deleting policy", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to amazon.com (should fail), pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://www.amazon.com", fw.Options.IpFamily)
				// GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Validating HTTP (port 80) connection to amazon.com still succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to amazon.com (should succeed), pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://www.amazon.com", fw.Options.IpFamily)
				// GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Deleting port 80 policy", func() {
				// appNetworkPolicies[2] is the port 80 policy
				err := fw.ApplicationNetworkPolicyManager.DeleteApplicationNetworkPolicy(ctx, appNetworkPolicies[2])
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies[2] = nil
			})

			By("Waiting for policy deletion to take effect and IP cache to purge", func() {
				time.Sleep(30 * time.Second)
			})

			By("Validating DNS still succeeds after deleting both port policies", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing DNS for google.com after deleting all policies, pod %s\n", selectedPod.Name)

				command := []string{"nslookup", "google.com"}
				_, err = fw.PodManager.ExecInPod(testNamespace, selectedPod.Name, command)
				// GinkgoWriter.Printf("stdout: %s\n", res)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to google.com fails after deleting all policies", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to google.com (should fail), pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://google.com", fw.Options.IpFamily)
				// GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Validating HTTP (port 80) connection to google.com fails after deleting all policies", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to google.com (should fail), pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				// GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to amazon.com fails after deleting all policies", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to amazon.com (should fail), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://www.amazon.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Validating HTTP (port 80) connection to amazon.com fails after deleting all policies", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to amazon.com (should fail), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://www.amazon.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should allow access to wildcard domains", func() {
			By("Applying deny all except DNS network policy to deployment 1", func() {
				// Create DNS egress rule
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				// Policy for deployment 1 - only DNS allowed
				appPolicy1 := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicy1)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicy1)
			})

			By("Creating policy to allow *.amazonaws.com wildcard domain", func() {
				httpPort := map[string]interface{}{
					"port":     int32(443),
					"protocol": "TCP",
				}

				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{"*.amazonaws.com", "*.api.aws"})

				domainEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{httpPort},
					"to":    []map[string]interface{}{domainPeer},
				}

				appPolicyWildcard := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-aws-wildcard").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyWildcard)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyWildcard)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Testing access to AWS subdomain s3.amazonaws.com works", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to s3.amazonaws.com (should succeed), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://s3.dualstack.us-west-2.amazonaws.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Testing access to AWS subdomain ec2 works", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to ec2.us-west-2.api.aws (should succeed), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://ec2.us-west-2.api.aws", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Testing access to non-AWS domain amazon.com is blocked", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to amazon.com (should fail), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://www.amazon.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})

			By("Testing access to non-AWS domain google.com is blocked", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to google.com (should fail), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).To(HaveOccurred())
			})
		})

		It("should allow traffic to all ports when domain rule has no ports specified", func() {
			By("Applying deny all except DNS network policy to deployment 1", func() {
				dnsPortUDP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "UDP",
				}
				dnsPortTCP := map[string]interface{}{
					"port":     int32(53),
					"protocol": "TCP",
				}

				var dnsPeer map[string]interface{}
				if fw.Options.IsAutoCluster {
					dnsPeer = manifest.NewApplicationIPBlockPeer(dnsCIDRAddress, []string{})
				} else {
					dnsPeer = manifest.NewApplicationPodsPeer(
						map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						map[string]string{"k8s-app": "kube-dns"},
					)
				}

				dnsEgressRule := map[string]interface{}{
					"ports": []map[string]interface{}{dnsPortUDP, dnsPortTCP},
					"to":    []map[string]interface{}{dnsPeer},
				}

				appPolicyDNS := manifest.NewApplicationNetworkPolicyBuilder().
					Name("deny-all-except-dns-1").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(dnsEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyDNS)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyDNS)
			})

			By("Applying domain ANP for google.com with NO ports specified (should allow all ports)", func() {
				domainPeer := manifest.NewApplicationDomainNamesPeer([]string{"google.com"})

				// Intentionally omit "ports" so the rule applies to all ports
				domainEgressRule := map[string]interface{}{
					"to": []map[string]interface{}{domainPeer},
				}

				appPolicyNoPorts := manifest.NewApplicationNetworkPolicyBuilder().
					Name("allow-google-no-ports").
					Namespace(testNamespace).
					PodSelector("app", "test-app-1").
					SetPolicyTypes([]string{"Egress"}).
					AddEgressRule(domainEgressRule).
					Build()

				err := fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, appPolicyNoPorts)
				Expect(err).ToNot(HaveOccurred())
				appNetworkPolicies = append(appNetworkPolicies, appPolicyNoPorts)
			})

			By("Waiting for policies to take effect", func() {
				time.Sleep(10 * time.Second)
			})

			By("Validating HTTP (port 80) connection to google.com succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTP to google.com (no ports rule, should succeed), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "http://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating HTTPS (port 443) connection to google.com succeeds", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to google.com (no ports rule, should succeed), pod %s\n", selectedPod.Name)

				result, err := fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://google.com", fw.Options.IpFamily)
				GinkgoWriter.Printf("result: %s\n", result)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Validating connection to a non-allowed domain is still blocked", func() {
				testPods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", "test-app-1")
				Expect(err).ToNot(HaveOccurred())

				randomIndex := rand.Intn(len(testPods))
				selectedPod := testPods[randomIndex]
				GinkgoWriter.Printf("Testing HTTPS to amazon.com (should fail), pod %s\n", selectedPod.Name)

				_, err = fw.PodManager.ValidateConnection(testNamespace, selectedPod.Name, "https://www.amazon.com", fw.Options.IpFamily)
				Expect(err).To(HaveOccurred())
			})
		})

		AfterEach(func() {
			By("Cleaning up application network policies", func() {
				for _, appPolicy := range appNetworkPolicies {
					if appPolicy != nil {
						fw.ApplicationNetworkPolicyManager.DeleteApplicationNetworkPolicy(ctx, appPolicy)
					}
				}
			})

			time.Sleep(10 * time.Second)
		})

		AfterAll(func() {
			By("Cleaning up deployments", func() {
				if deployment1 != nil {
					fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployment1)
				}
				if deployment2 != nil {
					fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployment2)
				}
			})

			By("Cleaning up namespace", func() {
				fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, testNamespace)
			})
		})
	})
})
