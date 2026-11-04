package clusternetworkpolicy

import (
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Traffic between a pod and its own node must bypass an Admin deny-all, so kubelet probes keep
// working and the pod can still reach its node (#56). Pod names keep distinct prefixes before
// the last "-" so they don't share eBPF maps.
var _ = Describe("ClusterNetworkPolicy Host Traffic Test Cases", Ordered, func() {
	const (
		namespace   = "hosttraffic-cnp"
		targetLabel = "hosttraffic-target"
		serverPort  = 8080
		hostPort    = 18080
	)

	var (
		nodeA, nodeB                       string
		serverPod, newServerPod, clientPod *v1.Pod
		hostA, hostB                       *v1.Pod
		policy                             *unstructured.Unstructured
	)

	netexecPod := func(name, label, nodeName string, port int) *manifest.PodBuilder {
		return manifest.NewDefaultPodBuilder().
			Name(name).
			Namespace(namespace).
			AddLabel("app", label).
			NodeName(nodeName).
			TerminationGracePeriod(1).
			Container(manifest.NewNetExecContainerBuilder(port).ImageRepository(fw.Options.TestImageRegistry).Build())
	}

	createPod := func(b *manifest.PodBuilder) *v1.Pod {
		created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, b.Build(), 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return created
	}

	probe := func(from, to *v1.Pod, port int) func() (string, error) {
		return func() (string, error) {
			return fw.PodManager.TCPProbe(namespace, from.Name, to.Status.PodIP, port)
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

		_ = fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
		Expect(fw.NamespaceManager.CreateNamespace(ctx, namespace)).To(Succeed())

		serverPod = createPod(netexecPod("hosttraffic-server-0", targetLabel, nodeA, serverPort))
		clientPod = createPod(netexecPod("hosttraffic-client", "hosttraffic-client", "", serverPort))
		hostA = createPod(netexecPod("hosttraffic-nodea-listener", "hosttraffic-host", nodeA, hostPort).HostNetwork(true))
		hostB = createPod(netexecPod("hosttraffic-nodeb-listener", "hosttraffic-host", nodeB, hostPort).HostNetwork(true))

		for _, from := range []*v1.Pod{clientPod, hostA, hostB} {
			Eventually(probe(from, serverPod, serverPort), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s cannot reach the server before the policy", from.Name)
		}
		for _, to := range []*v1.Pod{hostA, hostB} {
			Eventually(probe(serverPod, to, hostPort), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"server cannot reach %s before the policy", to.Name)
		}

		policy = manifest.NewClusterNetworkPolicyBuilder().
			Name("hosttraffic-deny-all").
			Priority(100).
			Tier("Admin").
			SubjectPods(map[string]string{"kubernetes.io/metadata.name": namespace}, map[string]string{"app": targetLabel}).
			AddIngressRule(manifest.NewClusterIngressRuleBuilder().
				Name("deny-all-ingress").
				Action("Deny").
				BuildIngressRule([]map[string]interface{}{manifest.NewNamespacesPeer(map[string]string{})})).
			AddEgressRule(manifest.NewClusterEgressRuleBuilder().
				Name("deny-all-egress").
				Action("Deny").
				BuildEgressRule([]map[string]interface{}{manifest.NewNetworksPeer([]string{matchAllCIDR})})).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, policy)).To(Succeed())
	})

	It("should keep a running pod ready and connected to its own node under an Admin deny-all", func() {
		Eventually(probe(clientPod, serverPod, serverPort), utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"ingress deny was not enforced on the server pod")
		Eventually(probe(serverPod, hostB, hostPort), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"egress deny to another node was not enforced")
		// The controller lists hostNetwork pod IPs, i.e. node IPs, in the namespaces{} peer.
		Eventually(probe(hostB, serverPod, serverPort), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"ingress deny from another node was not enforced")

		Consistently(ready(serverPod), utils.StabilityWindow, time.Second).Should(BeTrue(),
			"kubelet readiness probe was blocked")
		Consistently(probe(hostA, serverPod, serverPort), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic from the pod's own node was blocked")
		Consistently(probe(serverPod, hostA, hostPort), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic to the pod's own node was blocked")
	})

	It("should let a new replica on another node become ready under an Admin deny-all", func() {
		newServerPod = createPod(netexecPod("hosttraffic-server-1", targetLabel, nodeB, serverPort))

		Consistently(probe(clientPod, newServerPod, serverPort), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"ingress deny was not enforced on the new replica")
		Consistently(probe(newServerPod, hostA, hostPort), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"egress deny to another node was not enforced")
		Consistently(probe(hostA, newServerPod, serverPort), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"ingress deny from another node was not enforced")
		Consistently(ready(newServerPod), utils.StabilityWindow, time.Second).Should(BeTrue(),
			"kubelet readiness probe was blocked")
		Consistently(probe(newServerPod, hostB, hostPort), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic to the pod's own node was blocked")
	})

	AfterAll(func() {
		if policy != nil {
			fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, policy)
		}
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
	})
})
