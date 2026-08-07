package restart

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
)

/*
Conntrack Map Behavior After Restart (Same Binary)

When the agent restarts with the same binary (pod delete, node reboot, OOM kill):
  - The global conntrack map (pinned) is preserved across restart
  - Map ID stays the same (same binary = same key_size = reuse pinned map)
  - BPF programs are reattached to pod veths
  - Policy enforcement continues without interruption
*/

const (
	agentDaemonSet    = "aws-node"
	agentNamespace    = "kube-system"
	rolloutTimeout    = 5 * time.Minute
	podReadyTimeout   = 2 * time.Minute
	bpfSettleInterval = 10 * time.Second
)

var _ = Describe("Conntrack Map Behavior After Agent Restart", Ordered, func() {

	var (
		networkPolicy *network.NetworkPolicy
		workloadPod   *v1.Pod
		clientPod     *v1.Pod
		nodeName      string
	)

	It("should preserve conntrack map and enforce policy across same-binary restart", func() {
		By("Deploying workload pod with deny-all ingress")
		workloadPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ct-restart-server", Namespace: namespace,
				Labels: map[string]string{"app": "ct-restart-server"},
			},
			Spec: v1.PodSpec{Containers: []v1.Container{{
				Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
			}}},
		}
		var err error
		workloadPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, workloadPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		nodeName = workloadPod.Spec.NodeName

		clientPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ct-restart-client", Namespace: namespace,
				Labels: map[string]string{"app": "ct-restart-client"},
			},
			Spec: v1.PodSpec{
				NodeName:   nodeName,
				Containers: []v1.Container{{Name: "curl", Image: "public.ecr.aws/docker/library/python:3.11-slim", Command: []string{"sleep", "3600"}}},
			},
		}
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("Verifying workload is reachable before applying policy")
		serverIP := workloadPod.Status.PodIP
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("CONNECTED"))

		networkPolicy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "ct-restart-deny", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "ct-restart-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
		time.Sleep(bpfSettleInterval)

		By("Verifying policy enforcement before restart")
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))

		By("Capturing pre-restart BPF state")
		preState := captureBPFState(nodeName)
		preMapID := preState.GlobalMaps["aws_conntrack_map"]
		preProgCount := len(preState.ProgIDs)
		GinkgoWriter.Printf("Pre-restart: conntrack map ID=%d, prog count=%d\n", preMapID, preProgCount)
		Expect(preMapID).To(BeNumerically(">", 0), "parser must capture aws_conntrack_map ID")
		Expect(preProgCount).To(BeNumerically(">", 0))

		By("Restarting aws-node pod on the target node")
		pods := &v1.PodList{}
		Expect(fw.K8sClient.List(ctx, pods, client.InNamespace(agentNamespace),
			client.MatchingLabels{"k8s-app": "aws-node"})).To(Succeed())
		for _, p := range pods.Items {
			if p.Spec.NodeName == nodeName {
				Expect(fw.K8sClient.Delete(ctx, &p)).To(Succeed())
			}
		}

		By("Waiting for agent to restart and become ready")
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-restart BPF state")
		postState := captureBPFState(nodeName)
		postMapID := postState.GlobalMaps["aws_conntrack_map"]
		postProgCount := len(postState.ProgIDs)
		GinkgoWriter.Printf("Post-restart: conntrack map ID=%d, prog count=%d\n", postMapID, postProgCount)
		Expect(postMapID).To(BeNumerically(">", 0), "parser must capture aws_conntrack_map ID post-restart")

		By("Validating: global conntrack map preserved (same binary = same key_size = reuse pinned map)")
		Expect(postMapID).To(Equal(preMapID),
			fmt.Sprintf("conntrack map should be preserved on same-binary restart (pre=%d post=%d)", preMapID, postMapID))

		By("Validating: BPF programs reattached for the same set of pods (no programs lost or leaked)")
		preNames := make([]string, 0, len(preState.ProgIDs))
		for name := range preState.ProgIDs {
			preNames = append(preNames, name)
		}
		postNames := make([]string, 0, len(postState.ProgIDs))
		for name := range postState.ProgIDs {
			postNames = append(postNames, name)
		}
		Expect(postNames).To(ConsistOf(preNames),
			fmt.Sprintf("BPF program set should match pre-restart (pre=%v post=%v)", preNames, postNames))

		By("Validating: policy enforcement continues after restart")
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		if workloadPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, workloadPod)
		}
		if clientPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		}
	})
})

func waitForDaemonSetRollout() {
	Eventually(func() bool {
		ds := &appsv1.DaemonSet{}
		if err := fw.K8sClient.Get(ctx, client.ObjectKey{Name: agentDaemonSet, Namespace: agentNamespace}, ds); err != nil {
			return false
		}
		return ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled &&
			ds.Status.NumberReady == ds.Status.DesiredNumberScheduled &&
			ds.Status.ObservedGeneration >= ds.Generation
	}, rolloutTimeout, 5*time.Second).Should(BeTrue())
}

func captureBPFState(nodeName string) utils.BPFState {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	var err error
	checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)

	output, err := fw.PodManager.ExecInPod(namespace, checkPod.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred(), "failed to exec bpf state capture")
	Expect(output).ToNot(BeEmpty(), "empty bpf state output")

	state, err := utils.ParseLoadedEBPFData(output)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata output")
	return state
}

func execConnect(ns, pod, ip string, port int) string {
	script := fmt.Sprintf(`import socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(3)
try:
 s.connect(('%s',%d));print('CONNECTED')
except:
 print('BLOCKED')
finally:
 s.close()`, ip, port)
	out, err := fw.PodManager.ExecInPod(ns, pod, []string{"python3", "-c", script})
	Expect(err).ToNot(HaveOccurred(), "execConnect exec failed")
	if strings.Contains(out, "CONNECTED") {
		return "CONNECTED"
	}
	return "BLOCKED"
}
