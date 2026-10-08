package clusternetworkpolicy

import (
	"fmt"
	"time"

	policyk8sawsv1alpha1 "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A workload's last pod leaves a node while the workload keeps running elsewhere. Its eBPF
// programs on that node are torn down, but a second ClusterNetworkPolicy still selects it
// through the pod on the other node. The reconcile that cleans up after the departed pod
// must not stall: pods scheduled on that node afterwards must be enforced, and policy
// changes must still reach the pods already running there.
//
// The second policy selects only the sibling pod on the other node, so its
// ClusterPolicyEndpoint does not change when the pod departs and nothing else reconciles it.
// That is the shape that left the reconcile failing on every retry.
var _ = Describe("ClusterNetworkPolicy cleanup after a workload's last pod leaves a node", Ordered, func() {
	const (
		subjectNamespace = "departed-subject"
		serverNamespace  = "departed-server"
		underTest        = "departed-under-test"
		siblingPolicy    = "departed-sibling"
	)

	var (
		nodeA, nodeB             string
		server1IP, server2IP     string
		policies                 []*unstructured.Unstructured
		victimLocal, victimOther *v1.Pod
		resident, newcomer       *v1.Pod
	)

	// reachable reports whether a pod in the subject namespace can reach a server on 8080.
	reachable := func(podName, ip string) bool {
		format := "http://%s:8080"
		if fw.Options.IpFamily == "IPv6" {
			format = "http://[%s]:8080"
		}
		_, err := fw.PodManager.ExecInPod(subjectNamespace, podName,
			[]string{"wget", "-qO-", "--timeout=5", fmt.Sprintf(format, ip)})
		return err == nil
	}

	hostCIDR := func(ip string) string {
		if fw.Options.IpFamily == "IPv6" {
			return ip + "/128"
		}
		return ip + "/32"
	}

	sleeper := func(name, node string, labels map[string]string) *v1.Pod {
		b := manifest.NewDefaultPodBuilder().
			Namespace(subjectNamespace).
			Name(name).
			NodeName(node).
			TerminationGracePeriod(1).
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"while true; do sleep 3600; done"}).
				Build())
		for k, v := range labels {
			b = b.AddLabel(k, v)
		}
		pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, b.Build(), 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return pod
	}

	server := func(name, node string) string {
		pod := manifest.NewDefaultPodBuilder().
			Namespace(serverNamespace).
			Name(name).
			NodeName(node).
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"while true; do { echo 'HTTP/1.1 200 OK\n\nok'; } | nc -l -p 8080; done"}).
				Build()).
			Build()
		created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return created.Status.PodIP
	}

	cpeListsPod := func(parent, podName string) bool {
		cpeList := &policyk8sawsv1alpha1.ClusterPolicyEndpointList{}
		Expect(fw.K8sClient.List(ctx, cpeList)).To(Succeed())
		for _, cpe := range cpeList.Items {
			if cpe.Spec.PolicyRef.Name != parent {
				continue
			}
			for _, ep := range cpe.Spec.PodSelectorEndpoints {
				if ep.Name == podName {
					return true
				}
			}
		}
		return false
	}

	denyEgressTo := func(cidrs ...string) []map[string]interface{} {
		var rules []map[string]interface{}
		for i, cidr := range cidrs {
			rules = append(rules, manifest.NewClusterEgressRuleBuilder().
				Name(fmt.Sprintf("deny-%d", i)).
				Action("Deny").
				BuildEgressRule([]map[string]interface{}{manifest.NewNetworksPeer([]string{cidr})}))
		}
		return rules
	}

	underTestPolicy := func(cidrs ...string) *unstructured.Unstructured {
		b := manifest.NewClusterNetworkPolicyBuilder().
			Name(underTest).
			Priority(100).
			Tier("Admin").
			SubjectPods(map[string]string{"kubernetes.io/metadata.name": subjectNamespace},
				map[string]string{"departed-a": "yes"})
		for _, r := range denyEgressTo(cidrs...) {
			b = b.AddEgressRule(r)
		}
		return b.Build()
	}

	BeforeAll(func() {
		By("Picking two schedulable worker nodes", func() {
			nodes := &v1.NodeList{}
			Expect(fw.K8sClient.List(ctx, nodes)).To(Succeed())
			var ready []string
			for _, n := range nodes.Items {
				if n.Spec.Unschedulable {
					continue
				}
				for _, c := range n.Status.Conditions {
					if c.Type == v1.NodeReady && c.Status == v1.ConditionTrue {
						ready = append(ready, n.Name)
					}
				}
			}
			if len(ready) < 2 {
				Skip("needs at least two ready worker nodes")
			}
			nodeA, nodeB = ready[0], ready[1]
		})

		By("Creating the namespaces", func() {
			for _, ns := range []string{subjectNamespace, serverNamespace} {
				err := fw.K8sClient.Create(ctx, &v1.Namespace{ObjectMeta: metaV1.ObjectMeta{
					Name:   ns,
					Labels: map[string]string{"kubernetes.io/metadata.name": ns},
				}})
				Expect(err).ToNot(HaveOccurred())
			}
		})

		By("Starting two servers on the second node", func() {
			server1IP = server("server-1", nodeB)
			server2IP = server("server-2", nodeB)
		})

		By("Starting one workload on both nodes and a resident pod on the first node", func() {
			// victim-a and victim-b share a pod identifier, so eBPF state on each node is
			// shared by whichever of them runs there.
			victimLocal = sleeper("victim-a", nodeA, map[string]string{"departed-a": "yes"})
			victimOther = sleeper("victim-b", nodeB, map[string]string{"departed-a": "yes", "departed-b": "yes"})
			resident = sleeper("resident", nodeA, map[string]string{"departed-a": "yes"})
		})

		By("Applying the policy under test and a policy that selects only the sibling", func() {
			cnp := underTestPolicy(hostCIDR(server1IP))
			Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, cnp)).To(Succeed())
			policies = append(policies, cnp)

			sibling := manifest.NewClusterNetworkPolicyBuilder().
				Name(siblingPolicy).
				Priority(200).
				Tier("Admin").
				SubjectPods(map[string]string{"kubernetes.io/metadata.name": subjectNamespace},
					map[string]string{"departed-b": "yes"}).
				AddEgressRule(manifest.NewClusterEgressRuleBuilder().
					Name("allow-doc-range").
					Action("Accept").
					BuildEgressRule([]map[string]interface{}{manifest.NewNetworksPeer([]string{"192.0.2.0/24"})})).
				Build()
			Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, sibling)).To(Succeed())
			policies = append(policies, sibling)
		})

		By("Waiting for enforcement on the first node", func() {
			Eventually(func() bool { return reachable(resident.Name, server1IP) }, 90*time.Second, 5*time.Second).
				Should(BeFalse(), "resident must be denied server-1")
			Expect(reachable(resident.Name, server2IP)).To(BeTrue(), "server-2 is not denied yet")
		})
	})

	AfterAll(func() {
		for _, p := range policies {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, p)
		}
		for _, ns := range []string{subjectNamespace, serverNamespace} {
			_ = fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, ns)
		}
	})

	It("keeps enforcing on the node after the workload's last pod there leaves", func() {
		By("Deleting the workload's only pod on the first node while its sibling keeps running", func() {
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, victimLocal)).To(Succeed())
			Eventually(func() bool { return cpeListsPod(underTest, victimLocal.Name) }, 60*time.Second, 2*time.Second).
				Should(BeFalse())
			Expect(cpeListsPod(siblingPolicy, victimOther.Name)).To(BeTrue(),
				"the sibling policy must still select the workload through the other node")
		})

		By("Scheduling a new workload on the first node", func() {
			newcomer = sleeper("newcomer", nodeA, map[string]string{"departed-a": "yes"})
		})

		By("Changing the policy so it also denies server-2", func() {
			current, err := fw.ClusterNetworkPolicyManager.GetClusterNetworkPolicy(ctx, underTest)
			Expect(err).ToNot(HaveOccurred())
			current.Object["spec"] = underTestPolicy(hostCIDR(server1IP), hostCIDR(server2IP)).Object["spec"]
			Expect(fw.K8sClient.Update(ctx, current)).To(Succeed())
		})

		By("Verifying the new workload is enforced", func() {
			Eventually(func() bool { return reachable(newcomer.Name, server1IP) }, 90*time.Second, 5*time.Second).
				Should(BeFalse(), "a pod scheduled after the departure must not be left default-allow")
		})

		By("Verifying the policy change reached the pod already running there", func() {
			Eventually(func() bool { return reachable(resident.Name, server2IP) }, 90*time.Second, 5*time.Second).
				Should(BeFalse(), "a rule added after the departure must reach existing pods on the node")
			Expect(reachable(newcomer.Name, server2IP)).To(BeFalse())
		})
	})
})
