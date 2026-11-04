package policy

import (
	"fmt"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Traffic from a pod's own node must bypass network policy so kubelet probes keep working (#56).
// Pod names keep distinct prefixes before the last "-" so they don't share eBPF maps.
var _ = Describe("Host Traffic Test Cases", Ordered, func() {
	var (
		serverPod, newServerPod, clientPod *v1.Pod
		proberA, proberB                   *v1.Pod
		nodeA, nodeB                       string
		policy                             *network.NetworkPolicy
		serverPort                         = 8080
		targetLabel                        = "hosttraffic-target"
	)

	buildServerPod := func(name, nodeName string) *v1.Pod {
		ctnr := manifest.NewAgnHostContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Args([]string{fmt.Sprintf("/agnhost netexec --http-port=%d", serverPort)}).
			ReadinessProbe(&v1.Probe{
				ProbeHandler: v1.ProbeHandler{
					HTTPGet: &v1.HTTPGetAction{Path: "/", Port: intstr.FromInt(serverPort)},
				},
				PeriodSeconds:    1,
				TimeoutSeconds:   1,
				FailureThreshold: 3,
			}).
			Build()
		return manifest.NewDefaultPodBuilder().
			Name(name).
			Namespace(namespace).
			AddLabel("app", targetLabel).
			NodeName(nodeName).
			TerminationGracePeriod(1).
			Container(ctnr).
			Build()
	}

	buildIdlePod := func(name, label string) *manifest.PodBuilder {
		ctnr := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"sleep", "1000000"}).
			Build()
		return manifest.NewDefaultPodBuilder().
			Name(name).
			Namespace(namespace).
			AddLabel("app", label).
			TerminationGracePeriod(1).
			Container(ctnr)
	}

	// Host probers are selected too; a selected hostNetwork pod must not break enforcement for the rest.
	buildHostProber := func(name, nodeName string) *v1.Pod {
		return buildIdlePod(name, targetLabel).HostNetwork(true).NodeName(nodeName).Build()
	}

	// Exec through the apiserver fails transiently; retry so Consistently only sees verdicts.
	tcpProbe := func(prober, target *v1.Pod) func() (string, error) {
		return func() (string, error) {
			var out string
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				if out, err = fw.PodManager.TCPProbe(namespace, prober.Name, target.Status.PodIP, serverPort); err == nil {
					return out, nil
				}
				time.Sleep(utils.PollIntervalShort)
			}
			return "", err
		}
	}

	podReady := func(pod *v1.Pod) func() (bool, error) {
		return func() (bool, error) {
			current := &v1.Pod{}
			if err := fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
				return false, err
			}
			for _, c := range current.Status.Conditions {
				if c.Type == v1.PodReady {
					return c.Status == v1.ConditionTrue, nil
				}
			}
			return false, nil
		}
	}

	createPod := func(pod *v1.Pod) *v1.Pod {
		created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred(), "pod %s did not become ready", pod.Name)
		return created
	}

	BeforeAll(func() {
		// NodeName bypasses the scheduler, so skip nodes the agent does not run on or that
		// would evict the pods: non-Linux, Fargate, cordoned, NoExecute-tainted, not ready.
		nodes := &v1.NodeList{}
		Expect(fw.K8sClient.List(ctx, nodes, client.MatchingLabels{"kubernetes.io/os": "linux"})).To(Succeed())
		var ready []string
		for _, n := range nodes.Items {
			if n.Spec.Unschedulable || n.Labels["eks.amazonaws.com/compute-type"] == "fargate" {
				continue
			}
			if lo.ContainsBy(n.Spec.Taints, func(t v1.Taint) bool { return t.Effect == v1.TaintEffectNoExecute }) {
				continue
			}
			if lo.ContainsBy(n.Status.Conditions, func(c v1.NodeCondition) bool {
				return c.Type == v1.NodeReady && c.Status == v1.ConditionTrue
			}) {
				ready = append(ready, n.Name)
			}
		}
		if len(ready) < 2 {
			Skip("needs at least two ready worker nodes")
		}
		nodeA, nodeB = ready[0], ready[1]

		serverPod = createPod(buildServerPod("hosttraffic-server-0", nodeA))
		clientPod = createPod(buildIdlePod("hosttraffic-client", "hosttraffic-client").Build())
		proberA = createPod(buildHostProber("hosttraffic-nodea-prober", nodeA))
		proberB = createPod(buildHostProber("hosttraffic-nodeb-prober", nodeB))

		for _, prober := range []*v1.Pod{clientPod, proberA, proberB} {
			Eventually(tcpProbe(prober, serverPod), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s cannot reach the server before the policy", prober.Name)
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
		Eventually(tcpProbe(clientPod, serverPod), utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"deny-all was not enforced on the server pod")
		Eventually(tcpProbe(proberB, serverPod), utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
			"traffic from another node was not denied")

		Consistently(podReady(serverPod), utils.StabilityWindow, time.Second).Should(BeTrue(),
			"kubelet readiness probe was blocked")
		Consistently(tcpProbe(proberA, serverPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic from the pod's own node was blocked")
	})

	It("should let a new replica on another node become ready under deny-all", func() {
		newServerPod = createPod(buildServerPod("hosttraffic-server-1", nodeB))

		Consistently(tcpProbe(clientPod, newServerPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"deny-all was not enforced on the new replica")
		Consistently(tcpProbe(proberA, newServerPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
			"traffic from another node was not denied")
		Consistently(podReady(newServerPod), utils.StabilityWindow, time.Second).Should(BeTrue(),
			"kubelet readiness probe was blocked")
		Consistently(tcpProbe(proberB, newServerPod), utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
			"traffic from the pod's own node was blocked")
	})

	AfterAll(func() {
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		}
		for _, pod := range []*v1.Pod{newServerPod, proberB, proberA, clientPod, serverPod} {
			if pod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
			}
		}
	})
})
