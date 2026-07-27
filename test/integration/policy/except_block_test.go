package policy

import (
	"fmt"
	"net"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
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

type ipFamilyConfig struct {
	maskLen    int
	catchAll   string
	extProbeIP string
}

// ipFamilyConfigForIP derives the except-block settings from the server pod IP.
// EKS clusters are single-stack, so the pod IP's family is the cluster's family.
func ipFamilyConfigForIP(ip string) ipFamilyConfig {
	if net.ParseIP(ip).To4() == nil {
		return ipFamilyConfig{
			maskLen:    64,
			catchAll:   "::/0",
			extProbeIP: "2001:4860:4860::8888",
		}
	}
	return ipFamilyConfig{
		maskLen:    16,
		catchAll:   "0.0.0.0/0",
		extProbeIP: "8.8.8.8",
	}
}

// getPrefix computes the network prefix for the given IP and mask length,
// masking against the address's native bit width (32 for IPv4, 128 for IPv6).
func getPrefix(ipStr string, maskLen int) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		bits = 32
	}
	mask := net.CIDRMask(maskLen, bits)
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
			// Per-port re-listen loop: busybox nc -l exits after one connection.
			cmd := fmt.Sprintf(
				"while true; do nc -l -p %d; done & while true; do nc -l -p %d; done & wait",
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

	// deployClient creates an idle pod we exec probes into via Eventually.
	deployClient := func(clientName string) *v1.Pod {
		ctnr := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{"sleep 1000000"}).
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

	Context("CIDR and Except overlap: server-prefix allow on 3306 + catch-all except server-prefix", func() {
		BeforeEach(func() {
			By("Applying network policy with server-prefix allow and except rule")
			err := fw.NamespaceManager.CreateNamespace(ctx, clientNamespace)
			Expect(err).ToNot(HaveOccurred())
			cfg := ipFamilyConfigForIP(serverIP)
			prefix, err := getPrefix(serverIP, cfg.maskLen)
			Expect(err).ToNot(HaveOccurred())

			firstRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, prefix).
				AddPort(allowPort, v1.ProtocolTCP).
				Build()

			secondRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, cfg.catchAll, prefix).
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

		It("should allow on server prefix and 3306 port, deny on rest server-prefix ports, allow all on rest of endpoints", func() {
			cfg := ipFamilyConfigForIP(serverIP)

			// Deny converging first proves enforcement is active.
			By(fmt.Sprintf("denying egress to the server on excepted port %d", blockPort), func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, blockPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"expected deny to server on excepted port %d", blockPort)
			})

			By(fmt.Sprintf("allowing egress to the server on allowed port %d", allowPort), func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, allowPort)
				}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"expected allow to server on port %d", allowPort)
			})

			By("allowing egress to endpoints outside the excepted prefix", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, cfg.extProbeIP, 53)
				}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"expected allow to external endpoint outside the excepted prefix")
			})

			// Consistently (not Eventually) ensures the deny didn't flap.
			By(fmt.Sprintf("confirming deny on excepted port %d still holds", blockPort), func() {
				Consistently(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, blockPort)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
					"deny on excepted port %d did not persist through the allow probes", blockPort)
			})
		})
	})

	AfterEach(func() {
		if clientPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		}
		if serverPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
		}
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		}
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, serverNamespace)
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, clientNamespace)
	})
})
