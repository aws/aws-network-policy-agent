package policy

import (
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

// Traffic from a pod's own node must bypass network policy so kubelet probes keep working (#56).
// Pod names keep distinct prefixes before the last "-" so they don't share eBPF maps.
var _ = Describe("Host Traffic Test Cases", Ordered, func() {
	const (
		serverPort  = 8080
		targetLabel = "hosttraffic-target"
	)

	var (
		nodeA, nodeB                       string
		serverPod, newServerPod, clientPod *v1.Pod
		proberA, proberB                   *v1.Pod
		policy                             *network.NetworkPolicy
	)

	pod := func(name, label, nodeName string, ctnr *manifest.Container) *manifest.PodBuilder {
		return manifest.NewDefaultPodBuilder().
			Name(name).
			Namespace(namespace).
			AddLabel("app", label).
			NodeName(nodeName).
			TerminationGracePeriod(1).
			Container(ctnr.ImageRepository(fw.Options.TestImageRegistry).Build())
	}

	createPod := func(b *manifest.PodBuilder) *v1.Pod {
		created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, b.Build(), 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return created
	}

	server := func(name, nodeName string) *v1.Pod {
		return createPod(pod(name, targetLabel, nodeName, manifest.NewNetExecContainerBuilder(serverPort)))
	}

	// Host probers are selected too; a selected hostNetwork pod must not break enforcement for the rest.
	hostProber := func(name, nodeName string) *v1.Pod {
		return createPod(pod(name, targetLabel, nodeName, manifest.NewBusyBoxContainerBuilder()).HostNetwork(true))
	}

	probe := func(from, to *v1.Pod) func() (string, error) {
		return func() (string, error) {
			return fw.PodManager.TCPProbe(namespace, from.Name, to.Status.PodIP, serverPort)
		}
	}

	ready := func(p *v1.Pod) func() (bool, error) {
		return func() (bool, error) { return fw.PodManager.IsPodReady(ctx, p) }
	}

	BeforeAll(func() {
		nodes, err := utils.SchedulableNodes(ctx, fw.K8sClient)
		Expect(err).ToNot(HaveOccurred())
		if len(nodes) < 2 {
			Skip("needs at least two ready worker nodes")
		}
		nodeA, nodeB = nodes[0], nodes[1]

		serverPod = server("hosttraffic-server-0", nodeA)
		clientPod = createPod(pod("hosttraffic-client", "hosttraffic-client", "", manifest.NewBusyBoxContainerBuilder()))
		proberA = hostProber("hosttraffic-nodea-prober", nodeA)
		proberB = hostProber("hosttraffic-nodeb-prober", nodeB)

		for _, from := range []*v1.Pod{clientPod, proberA, proberB} {
			Eventually(probe(from, serverPod), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s cannot reach the server before the policy", from.Name)
		}

		policy = manifest.NewNetworkPolicyBuilder().
			Namespace(namespace).
			Name("hosttraffic-deny-all").
			PodSelector("app", targetLabel).
			SetPolicyType(true, true).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
	})

	It("should keep a running pod ready and reachable only from its own node under deny-all", func() {
		Eventually(probe(clientPod, serverPod), utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"deny-all was not enforced on the server pod")
		Eventually(probe(proberB, serverPod), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"traffic from another node was not denied")

		Consistently(ready(serverPod), utils.StabilityWindow, time.Second).Should(BeTrue(),
			"kubelet readiness probe was blocked")
		Consistently(probe(proberA, serverPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic from the pod's own node was blocked")
	})

	It("should let a new replica on another node become ready under deny-all", func() {
		newServerPod = server("hosttraffic-server-1", nodeB)

		Consistently(probe(clientPod, newServerPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"deny-all was not enforced on the new replica")
		Consistently(probe(proberA, newServerPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"traffic from another node was not denied")
		Consistently(ready(newServerPod), utils.StabilityWindow, time.Second).Should(BeTrue(),
			"kubelet readiness probe was blocked")
		Consistently(probe(proberB, newServerPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic from the pod's own node was blocked")
	})

	AfterAll(func() {
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		}
		for _, p := range []*v1.Pod{newServerPod, proberB, proberA, clientPod, serverPod} {
			if p != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
	})
})
