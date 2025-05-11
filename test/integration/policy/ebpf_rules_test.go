package policy

import (
	"fmt"
	"time"
	"strings"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	network "k8s.io/api/networking/v1"
	v1 "k8s.io/api/core/v1"
)

var _ = Describe("Ebpf prog protocol and port evaluation test", func() {
	var (
		serverPod  *v1.Pod
		clientPod  *v1.Pod
		serverIP   string
		serverName = "server-pod"
		clientName = "client-pod"
		portA      = 8080
		portB      = 9090
		policy     *network.NetworkPolicy
	)

	BeforeEach(func() {
		By("Deploying a server listening on two ports", func() {
			cmd := fmt.Sprintf("while true; do nc -l -p %d & nc -l -p %d & wait; done", portA, portB)
			srv := manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{cmd}).
				Build()

			serverPod = manifest.NewDefaultPodBuilder().
				Name(serverName).
				Namespace(namespace).
				AddLabel("app", serverName).
				Container(srv).
				Build()

			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 1*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			serverIP = pod.Status.PodIP
		})
	})

	deployClient := func() *v1.Pod {
		script := fmt.Sprintf(`
	sleep 20;
	nc -z -w2 %s %d && echo "OPEN-%d" || echo "CLOSE-%d";
	nc -z -w2 %s %d && echo "OPEN-%d" || echo "CLOSE-%d";
	sleep 1000;
	`,
			serverIP, portA, portA, portA,
			serverIP, portB, portB, portB,
		)

		ctnr := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{script}).
			Build()

		clientPod = manifest.NewDefaultPodBuilder().
			Name(clientName).
			Namespace(namespace).
			AddLabel("app", clientName).
			Container(ctnr).
			Build()

		pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return pod
	}

	It("should allow traffic to both ports when policy uses ANY protocol and ANY port", func() {
		rule := manifest.NewEgressRuleBuilder().
			AddPeer(nil, nil, serverIP+"/32").
			AddPort(-1, "").
			Build()

		policy = manifest.NewNetworkPolicyBuilder().
			Namespace(namespace).
			Name("any-port-protocol-allow").
			PodSelector("app", clientName).
			AddEgressRule(rule).
			Build()

		printNetworkPolicyYAML(policy)
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
		deployClient()
		time.Sleep(1 * time.Minute)

		logs, err := fw.PodManager.PodLogs(namespace, clientName)
		Expect(err).ToNot(HaveOccurred())
		Expect(processLogs(logs, []int{portA, portB}, []int{})).To(Succeed())
	})

	It("should allow on portA and deny on portB when policy allows only portA and ANY protocol", func() {
		rule := manifest.NewEgressRuleBuilder().
			AddPeer(nil, nil, serverIP+"/32").
			AddPort(portA, "").
			Build()

		policy = manifest.NewNetworkPolicyBuilder().
			Namespace(namespace).
			Name("single-port-allow").
			PodSelector("app", clientName).
			AddEgressRule(rule).
			Build()

		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
		deployClient()
		time.Sleep(1 * time.Minute)

		logs, err := fw.PodManager.PodLogs(namespace, clientName)
		Expect(err).ToNot(HaveOccurred())
		Expect(processLogs(logs, []int{portA}, []int{portB})).To(Succeed())
	})

	AfterEach(func() {
		fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
		fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
	})
})

func processLogs(podlogs string, expectedOpenPorts []int, expectedClosedPorts []int) error {
	lines := strings.Split(strings.TrimSpace(podlogs), "\n")
	found := map[string]bool{}

	for _, line := range lines {
		found[line] = true
	}

	for _, port := range expectedOpenPorts {
		key := fmt.Sprintf("OPEN-%d", port)
		if !found[key] {
			return fmt.Errorf("expected %s but not found in logs", key)
		}
	}
	for _, port := range expectedClosedPorts {
		key := fmt.Sprintf("CLOSE-%d", port)
		if !found[key] {
			return fmt.Errorf("expected %s but not found in logs", key)
		}
	}
	return nil
}