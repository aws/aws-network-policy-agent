package policy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

func printNetworkPolicyYAML(np *network.NetworkPolicy) {
	bytes, err := yaml.Marshal(np)
	if err != nil {
		fmt.Printf("ERROR: Failed to marshal NetworkPolicy: %v\n", err)
		return
	}
	fmt.Printf("Applied NetworkPolicy YAML:\n%s\n", string(bytes))
}

// getPrefix computes the network prefix for the given IP and mask length.
func getPrefix(ipStr string, maskLen int) (string, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	mask := net.CIDRMask(maskLen, 32)
	network := ip.Mask(mask)
	return fmt.Sprintf("%s/%d", network.String(), maskLen), nil
}

var _ = Describe("IPBlock Except Test Cases", func() {
	var (
		serverPod       *v1.Pod
		clientPod       *v1.Pod
		serverIP        string
		serverName      = "ipblock-server"
		clientName      = "ipblock-client"
		serverNamespace = "server"
		clientNamespace = "client"
		policy          *network.NetworkPolicy
		allowPort       int = 3306
		blockPort       int = 3307
	)

	BeforeEach(func() {
		By("Deploying a sample TCP server on ports 3306 & 3307", func() {
			err := fw.NamespaceManager.CreateNamespace(ctx, serverNamespace)
			Expect(err).ToNot(HaveOccurred())
			// listening on two ports
			cmd := fmt.Sprintf(
				"while true; do nc -l -p %d & nc -l -p %d & wait; done",
				allowPort, blockPort,
			)
			srv := manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{cmd}).
				Build()

			serverPod = manifest.NewDefaultPodBuilder().
				Name(serverName).
				Namespace(serverNamespace).
				AddLabel("app", serverName).
				Container(srv).
				Build()

			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 1*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			serverIP = pod.Status.PodIP
		})
	})

	deployClient := func(clientName string) *v1.Pod {
		script := fmt.Sprintf(
			`sleep 30;
	nc -z -w1 %s %d && echo "OPEN-%d" || echo "CLOSE-%d";
	nc -z -w1 %s %d && echo "OPEN-%d" || echo "CLOSE-%d";
	nc -z -w2 8.8.8.8 53 && echo "OPEN-EXT" || echo "CLOSE-EXT";
	sleep 1000 `,
			serverIP, allowPort, allowPort, allowPort,
			serverIP, blockPort, blockPort, blockPort,
		)

		ctnr := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{script}).
			Build()

		clientPod = manifest.NewDefaultPodBuilder().
			Name(clientName).
			Namespace(clientNamespace).
			AddLabel("app", clientName).
			Container(ctnr).
			Build()

		pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return pod
	}

	Context("CIDR and Except overlap: /16 allow on 3306 + catch-all except /16", func() {
		BeforeEach(func() {
			By("Applying network policy with /16 allow and except rule")
			err := fw.NamespaceManager.CreateNamespace(ctx, clientNamespace)
			Expect(err).ToNot(HaveOccurred())
			// Compute the /16 prefix for the server IP
			p16, err := getPrefix(serverIP, 16)
			Expect(err).ToNot(HaveOccurred())

			firstRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, p16).
				AddPort(allowPort, v1.ProtocolTCP).
				Build()

			secondRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, "0.0.0.0/0", p16).
				Build()

			policy = manifest.NewNetworkPolicyBuilder().
				Namespace(clientNamespace).
				Name("egress-policy").
				PodSelector("app", clientName).
				AddEgressRule(firstRule).
				AddEgressRule(secondRule).
				Build()

			printNetworkPolicyYAML(policy)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())

			fmt.Printf("Creating client pod %s in namespace %s\n", clientName, clientNamespace)
			clientPod = deployClient(clientName)
		})

		It("should allow on /16 and 3006 port, deny on rest /16 ports, allow all on rest of endpoints", func() {
			time.Sleep(30 * time.Second)

			// fetch the logs
			logs, err := fw.PodManager.PodLogs(clientNamespace, clientName)
			Expect(err).ToNot(HaveOccurred())
			Expect(processIPBlockLogs(logs, allowPort, blockPort)).To(Succeed())
		})
	})

	AfterEach(func() {
		fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
		fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, serverNamespace)
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, clientNamespace)
	})
})

func processIPBlockLogs(podlogs string, allowPort, blockPort int) error {
	lines := strings.Split(strings.TrimSpace(podlogs), "\n")
	gotAllowPort := false
	gotBlockPort := false
	gotAllowExt := false

	for _, l := range lines {
		switch l {
		case fmt.Sprintf("OPEN-%d", allowPort):
			gotAllowPort = true
		case fmt.Sprintf("CLOSE-%d", blockPort):
			gotBlockPort = true
		case "OPEN-EXT":
			gotAllowExt = true
		}
	}

	if !gotAllowPort {
		return fmt.Errorf("Expected allow to server on port %d but got deny", allowPort)
	}
	if !gotBlockPort {
		return fmt.Errorf("Expected deny to server on port %d but got allow", blockPort)
	}
	if !gotAllowExt {
		return fmt.Errorf("Expected allow on all other to external endpoints but got deny")
	}
	return nil
}
