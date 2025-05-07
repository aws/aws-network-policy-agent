package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	network "k8s.io/api/networking/v1"

	v1 "k8s.io/api/core/v1"
)

var _ = Describe("Default Allow Mode Test Cases", func() {
	Context("When a pod is first launched and traffic starts flowing", func() {
		var clientPod *v1.Pod
		var podName = "clientpod"
		var delayAppDeployment *appsv1.Deployment
		var delayService *v1.Service
		var clientNetworkPolicy *network.NetworkPolicy

		BeforeEach(func() {
			By("Creating a delay server and client pod", func() {
				delayApp := manifest.NewBusyBoxContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Command([]string{"/bin/sh", "-c"}).
					Args([]string{"while true; do { sleep 60; echo -e 'HTTP/1.1 200 OK\n\nResponse after 60 seconds'; } | nc -l -p 8080; done"}).
					Build()

				delayAppDeployment = manifest.NewDefaultDeploymentBuilder().
					Name("delay-app").
					Replicas(1).
					Namespace(namespace).
					AddLabel("app", "delay-app").
					Container(delayApp).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, delayAppDeployment)
				Expect(err).ToNot(HaveOccurred())

				delayService = manifest.NewHTTPService().
					Name("delay-service").
					Port(8080).
					Namespace(namespace).
					Selector("app", "delay-app").
					Build()

				_, err = fw.ServiceManager.CreateService(ctx, delayService)
				Expect(err).ToNot(HaveOccurred())

				clientApp := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do wget http://delay-service.policy.svc.cluster.local:8080 --spider -T 90; if [ $? == 0 ]; then echo \"Success\"; else echo \"Fail\"; fi; sleep 60; done "}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Container(clientApp).
					Namespace(namespace).
					AddLabel("app", "client-app").
					Name(podName).
					Build()

				_, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())

			})
		})

		It("by default should not have any drops", func() {
			By("Verify pod can reach the delay service", func() {
				time.Sleep(2 * time.Minute)
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())
				err = processDefaultAllowLogs(logs, true, false)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("if egress connection is made before network policy is applied the response packet should be accepted", func() {
			By("Creating a network policy which only allows ingress from a different client", func() {

				// Sleep so that the first probe is made before block rules are applied on ingress
				time.Sleep(10 * time.Second)

				ingressPeer := manifest.NewIngressRuleBuilder().
					AddPeer(nil, map[string]string{"app": "test-app"}, "").
					AddPort(8080, v1.ProtocolTCP).
					Build()

				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("client-egress-policy").
					PodSelector("app", "client-app").
					AddIngressRule(ingressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Check if the first response is accepted and following responses from server is denied", func() {
				time.Sleep(2 * time.Minute)
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())
				err = processDefaultAllowLogs(logs, false, true)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		AfterEach(func() {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			fw.ServiceManager.DeleteService(ctx, delayService)
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, delayAppDeployment)
		})
	})
})

func processDefaultAllowLogs(podlogs string, allAllow bool, deniedAfterAllow bool) error {

	passFlag := false
	failFlag := false
	trafficDeniedAfterAllow := false
	for _, log := range strings.Split(strings.TrimSuffix(podlogs, "\n"), "\n") {
		if log == "Fail" {
			if passFlag {
				trafficDeniedAfterAllow = true
			}
			failFlag = true
		} else if log == "Success" {
			passFlag = true
			if trafficDeniedAfterAllow {
				return fmt.Errorf("Failed as traffic was allowed after denied")
			}
		}
	}

	if !passFlag && !failFlag {
		return fmt.Errorf("Error generating traffic probes")
	} else if allAllow && failFlag {
		return fmt.Errorf("Failed as all traffic probes did not get ACCEPT")
	} else if deniedAfterAllow && trafficDeniedAfterAllow {
		return fmt.Errorf("Failed as traffic probes did not get DENY first and then ACCEPT")
	}

	return nil
}
