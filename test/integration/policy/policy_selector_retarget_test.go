package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*
Verifies that when a NetworkPolicy's podSelector is updated to target a different
set of pods, rules are removed from the originally-selected pods (restored to
default-allow) and applied to the newly-selected pods. Also verifies that if a
brand-new NetworkPolicy is later created that re-targets the original pods, the
correct rules are (re-)applied to them.

Sequence:
 1. Deny-all-ingress policy P targets pod A -> A blocked, B unaffected.
 2. P's selector is updated to target pod B -> A recovers (allow), B becomes blocked.
 3. A new policy Q targets pod A -> A blocked again by Q, B remains blocked by P.
*/
var _ = Describe("Network Policy Selector Retargeting", Ordered, func() {

	const (
		deployReadyTimeout = 2 * time.Minute
		bpfSettleInterval  = 15 * time.Second
	)

	var (
		deployA, deployB, deployProber *appsv1.Deployment
		podA, podB, proberPod          v1.Pod
		policyP, policyQ               *network.NetworkPolicy
	)

	BeforeAll(func() {
		By("Deploying target Deployments A and B")
		var err error
		deployA = manifest.NewDefaultDeploymentBuilder().
			Namespace(namespace).
			Name("retarget-deploy-a").
			Replicas(1).
			AddLabel("app", "retarget-a").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"nc -lk -p 80 -e echo ok"}).
				Build()).
			Build()
		deployA, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployA)
		Expect(err).ToNot(HaveOccurred())

		deployB = manifest.NewDefaultDeploymentBuilder().
			Namespace(namespace).
			Name("retarget-deploy-b").
			Replicas(1).
			AddLabel("app", "retarget-b").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"nc -lk -p 80 -e echo ok"}).
				Build()).
			Build()
		deployB, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployB)
		Expect(err).ToNot(HaveOccurred())

		By("Deploying prober Deployment")
		deployProber = manifest.NewDefaultDeploymentBuilder().
			Namespace(namespace).
			Name("retarget-deploy-prober").
			Replicas(1).
			AddLabel("app", "retarget-prober").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"sleep", "3600"}).
				Build()).
			Build()
		deployProber, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployProber)
		Expect(err).ToNot(HaveOccurred())

		podA = getSinglePod("retarget-a")
		podB = getSinglePod("retarget-b")
		proberPod = getSinglePod("retarget-prober")
	})

	AfterAll(func() {
		if policyQ != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policyQ)
		}
		if policyP != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policyP)
		}
		if deployProber != nil {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployProber)
		}
		if deployB != nil {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployB)
		}
		if deployA != nil {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployA)
		}
	})

	It("removes rules from the original pods and applies them to the newly-selected pods on selector update, and re-applies correctly when a new policy re-targets the original pods", func() {
		By("Creating deny-all-ingress policy P targeting pod A")
		policyP = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "retarget-policy-p", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "retarget-a"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policyP)).To(Succeed())
		time.Sleep(bpfSettleInterval)

		By("Verifying pod A is blocked and pod B is unaffected")
		Expect(retargetConnect(proberPod.Name, podA.Status.PodIP)).To(Equal("BLOCKED"))
		Expect(retargetConnect(proberPod.Name, podB.Status.PodIP)).To(Equal("CONNECTED"))

		By("Updating policy P's selector to target pod B instead of pod A")
		Eventually(func() error {
			current := &network.NetworkPolicy{}
			if err := fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(policyP), current); err != nil {
				return err
			}
			current.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "retarget-b"}}
			return fw.K8sClient.Update(ctx, current)
		}, 30*time.Second, 2*time.Second).Should(Succeed())
		time.Sleep(bpfSettleInterval)

		By("Verifying pod A recovered to allow and pod B is now blocked")
		Expect(retargetConnect(proberPod.Name, podA.Status.PodIP)).To(Equal("CONNECTED"))
		Expect(retargetConnect(proberPod.Name, podB.Status.PodIP)).To(Equal("BLOCKED"))

		By("Creating a new policy Q that re-targets pod A")
		policyQ = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "retarget-policy-q", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "retarget-a"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policyQ)).To(Succeed())
		time.Sleep(bpfSettleInterval)

		By("Verifying pod A is blocked again by Q and pod B remains blocked by P")
		Expect(retargetConnect(proberPod.Name, podA.Status.PodIP)).To(Equal("BLOCKED"))
		Expect(retargetConnect(proberPod.Name, podB.Status.PodIP)).To(Equal("BLOCKED"))
	})
})

func getSinglePod(appLabel string) v1.Pod {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", appLabel)
	Expect(err).ToNot(HaveOccurred())
	Expect(pods).To(HaveLen(1), fmt.Sprintf("expected exactly one pod for app=%s", appLabel))
	return pods[0]
}

func retargetConnect(proberPodName, ip string) string {
	cmd := fmt.Sprintf("nc -z -w3 %s 80 && echo CONNECTED || echo BLOCKED", ip)
	out, err := fw.PodManager.ExecInPod(namespace, proberPodName, []string{"/bin/sh", "-c", cmd})
	Expect(err).ToNot(HaveOccurred(), "retargetConnect exec failed")
	if strings.Contains(out, "CONNECTED") {
		return "CONNECTED"
	}
	return "BLOCKED"
}
