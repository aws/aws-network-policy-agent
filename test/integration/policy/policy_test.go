package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

var _ = Describe("Network Policy Test Cases", func() {
	Context("A network policy is applied against a pod with '.' in its pod name", func() {

		var clientPod *v1.Pod
		var clientNetworkPolicy *network.NetworkPolicy
		var podName = "this.pod.has.dots.in.its.name"

		BeforeEach(func() {
			By("Creating a network policy that denies all egress traffic", func() {
				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("deny-all-egress").
					PodSelector("app", podName).
					SetPolicyType(false, true).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating a pod which tries to reach external network", func() {
				agnhostContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"while true; do wget https://www.google.com --spider -T 1; if [ $? == 0 ]; then echo \"Success\"; else echo \"Fail\"; fi; sleep 1s; done"}).
					Build()

				clientPod = manifest.NewDefaultPodBuilder().
					Container(agnhostContainer).
					Namespace(namespace).
					AddLabel("app", podName).
					Name(podName).
					Build()

				_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		It("should be successfully applied and removed from the pod", func() {
			By("Verifying that the pod is unable to make an egress connection", func() {
				time.Sleep(1 * time.Minute)
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())
				err = validateState(logs, []string{"Success", "Fail"}, []string{"Success", "Fail"})
				Expect(err).ToNot(HaveOccurred())
			})

			By("Removing the network policy", func() {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
			})

			By("Verifying that the pod is once again able to make an egress connection", func() {
				time.Sleep(1 * time.Minute)
				logs, err := fw.PodManager.PodLogs(namespace, podName)
				Expect(err).ToNot(HaveOccurred())
				err = validateState(logs, []string{"Success", "Fail", "Success"}, []string{"Success", "Fail"})
				Expect(err).ToNot(HaveOccurred())
			})
		})

		AfterEach(func() {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		})

	})

})

func validateState(podlogs string, expectedStates []string, possibleStates []string) error {
	// convert states to a "set" so we can filter out non-state log messages
	stateSet := make(map[string]bool)
	for _, state := range possibleStates {
		stateSet[state] = true
	}

	stateIt := 0
	for _, log := range strings.Split(strings.TrimSuffix(podlogs, "\n"), "\n") {
		if stateSet[log] && expectedStates[stateIt] != log {
			stateIt++
			if stateIt >= len(expectedStates) {
				return fmt.Errorf("Connection changed to %s but we expected it to remain in %s", log, expectedStates[stateIt-1])
			}
		}
	}

	if stateIt != len(expectedStates)-1 {
		return fmt.Errorf("Expected connection to transition through states %v, but observed that it only transitioned through %v", expectedStates, expectedStates[:stateIt+1])
	}

	return nil
}
