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
// Poll for the expected verdict instead of sleeping a fixed interval: eBPF programming
// latency varies with cluster size and reconcile backlog, so a fixed sleep is both flaky
// when slow and wasteful when fast.
const (
	bpfSettleTimeout = 90 * time.Second
	bpfPollInterval  = 2 * time.Second
	// Unprivileged port: the busybox test image runs as a non-root user and cannot bind
	// 80. Kept as a constant so the servers and the prober can't drift apart.
	retargetPort = 8080
)

var _ = Describe("Network Policy Selector Retargeting", Ordered, func() {

	// busybox `nc -l` serves one connection and exits, and `-e` is not available in all
	// busybox builds - so re-listen in a loop instead. Same shape as except_block_test.go.
	listenLoop := fmt.Sprintf("while true; do nc -l -p %d; done", retargetPort)

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
				Args([]string{listenLoop}).
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
				Args([]string{listenLoop}).
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
		By("Verifying both pods are reachable before any policy is applied")
		// Without this precondition a later BLOCKED result could mean a broken prober,
		// an unready server or a wrong IP rather than an enforced policy.
		expectConn(proberPod.Name, podA.Status.PodIP, "CONNECTED", "pod A before policy P")
		expectConn(proberPod.Name, podB.Status.PodIP, "CONNECTED", "pod B before policy P")

		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policyP)).To(Succeed())

		By("Verifying pod A is blocked and pod B is unaffected")
		expectConn(proberPod.Name, podA.Status.PodIP, "BLOCKED", "pod A after policy P")
		expectConn(proberPod.Name, podB.Status.PodIP, "CONNECTED", "pod B after policy P")

		By("Updating policy P's selector to target pod B instead of pod A")
		Eventually(func() error {
			current := &network.NetworkPolicy{}
			if err := fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(policyP), current); err != nil {
				return err
			}
			current.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "retarget-b"}}
			return fw.K8sClient.Update(ctx, current)
		}, 30*time.Second, 2*time.Second).Should(Succeed())

		By("Verifying pod A recovered to allow and pod B is now blocked")
		expectConn(proberPod.Name, podA.Status.PodIP, "CONNECTED", "pod A after P retargeted to B")
		expectConn(proberPod.Name, podB.Status.PodIP, "BLOCKED", "pod B after P retargeted to B")

		By("Creating a new policy Q that re-targets pod A")
		policyQ = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "retarget-policy-q", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "retarget-a"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policyQ)).To(Succeed())

		By("Verifying pod A is blocked again by Q and pod B remains blocked by P")
		expectConn(proberPod.Name, podA.Status.PodIP, "BLOCKED", "pod A after policy Q")
		expectConn(proberPod.Name, podB.Status.PodIP, "BLOCKED", "pod B still blocked by P")
	})
})

func getSinglePod(appLabel string) v1.Pod {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", appLabel)
	Expect(err).ToNot(HaveOccurred())
	Expect(pods).To(HaveLen(1), fmt.Sprintf("expected exactly one pod for app=%s", appLabel))
	return pods[0]
}

// retargetConnect probes ip:port from the prober pod and returns "CONNECTED" or
// "BLOCKED", or an error. It deliberately does not treat every non-CONNECTED outcome as
// BLOCKED: a missing nc, a failed exec or unrecognised output means the harness is broken,
// and reporting that as BLOCKED would let a policy assertion pass for the wrong reason.
func retargetConnect(proberPodName, ip string, port int) (string, error) {
	cmd := fmt.Sprintf(
		"command -v nc >/dev/null 2>&1 || { echo NO_NC; exit 0; }; "+
			"nc -z -w3 %s %d && echo CONNECTED || echo BLOCKED", ip, port)
	out, err := fw.PodManager.ExecInPod(namespace, proberPodName, []string{"/bin/sh", "-c", cmd})
	if err != nil {
		return "", fmt.Errorf("exec in prober pod %s: %w", proberPodName, err)
	}
	switch {
	case strings.Contains(out, "NO_NC"):
		return "", fmt.Errorf("prober image has no nc; cannot probe %s:%d", ip, port)
	case strings.Contains(out, "CONNECTED"):
		return "CONNECTED", nil
	case strings.Contains(out, "BLOCKED"):
		return "BLOCKED", nil
	}
	return "", fmt.Errorf("unrecognised probe output for %s:%d: %q", ip, port, out)
}

// expectConn polls until the probe reports want, so the test tracks actual eBPF
// programming latency instead of a fixed sleep. A probe error fails immediately rather
// than being retried into a timeout, since it means the harness is broken, not slow.
func expectConn(proberPodName, ip, want, desc string) {
	var last string
	EventuallyWithOffset(1, func() (string, error) {
		v, err := retargetConnect(proberPodName, ip, retargetPort)
		if err != nil {
			StopTrying(err.Error()).Now()
		}
		last = v
		return v, nil
	}, bpfSettleTimeout, bpfPollInterval).Should(Equal(want),
		"%s: expected %s, last observed %s", desc, want, &last)
}
