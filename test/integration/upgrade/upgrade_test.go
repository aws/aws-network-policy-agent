package upgrade

import (
	"fmt"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
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
Utility test to test upgrades and rollback.

Two scenarios:
 1. Binary unchanged (v1.3.2 -> v1.3.4): prog IDs, per-pod map IDs, and global map IDs all preserved.
 2. Binary changed (v1.2.7 -> v1.3.4): prog IDs change (new binary loaded). Global map IDs are also changed

todo - can improve this test to run as part of automated pipeline by injecting image tags as env vars.
*/
const (
	agentDaemonSet    = "aws-node"
	agentNamespace    = "kube-system"
	agentContainer    = "aws-eks-nodeagent"
	baseImage         = "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-network-policy-agent"
	rolloutTimeout    = 5 * time.Minute
	podReadyTimeout   = 2 * time.Minute
	bpfSettleInterval = 10 * time.Second
)

// Scenario 1: Binary unchanged (v1.3.2 <-> v1.3.4)
var _ = Describe("Agent Upgrade/Rollback - Binary Unchanged", Ordered, func() {
	const (
		fromTag = "v1.3.2"
		toTag   = "v1.3.4"
	)

	var (
		networkPolicy     *network.NetworkPolicy
		workloadPod       *v1.Pod
		nodeName          string
		preUpgradeState   utils.BPFState
		postUpgradeState  utils.BPFState
		preRollbackState  utils.BPFState
		postRollbackState utils.BPFState
	)

	It("should preserve all BPF state across upgrade", func() {
		By("Setting agent image to old version: " + fromTag)
		setAgentImage(baseImage + ":" + fromTag)
		waitForDaemonSetRollout()

		By("Deploying workload pod with network policy")
		workloadPod = buildWorkloadPod("binary-unchanged")
		var err error
		workloadPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, workloadPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		nodeName = workloadPod.Spec.NodeName

		networkPolicy = buildTestNetworkPolicy("binary-unchanged")
		err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
		Expect(err).ToNot(HaveOccurred())

		By("Waiting for BPF probes to be attached")
		time.Sleep(bpfSettleInterval)

		By("Capturing pre-upgrade BPF state")
		preUpgradeState = captureBPFState(nodeName)
		Expect(preUpgradeState.ProgIDs).ToNot(BeEmpty(), "should have BPF programs before upgrade")
		Expect(preUpgradeState.GlobalMaps).ToNot(BeEmpty(), "should have global maps before upgrade")
		GinkgoWriter.Printf("Pre-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			preUpgradeState.ProgIDs, preUpgradeState.MapIDs, preUpgradeState.GlobalMaps)

		By("Upgrading agent to: " + toTag)
		setAgentImage(baseImage + ":" + toTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-upgrade BPF state")
		postUpgradeState = captureBPFState(nodeName)
		Expect(postUpgradeState.ProgIDs).ToNot(BeEmpty(), "should have BPF programs after upgrade")
		GinkgoWriter.Printf("Post-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			postUpgradeState.ProgIDs, postUpgradeState.MapIDs, postUpgradeState.GlobalMaps)

		By("Validating: all IDs preserved (binary unchanged)")
		validateBPFState(preUpgradeState, postUpgradeState, false, "upgrade")
	})

	It("should preserve all BPF state across rollback", func() {
		By("Capturing pre-rollback BPF state (agent on " + toTag + ")")
		preRollbackState = captureBPFState(nodeName)
		Expect(preRollbackState.ProgIDs).ToNot(BeEmpty())
		GinkgoWriter.Printf("Pre-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			preRollbackState.ProgIDs, preRollbackState.MapIDs, preRollbackState.GlobalMaps)

		By("Rolling back agent to: " + fromTag)
		setAgentImage(baseImage + ":" + fromTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-rollback BPF state")
		postRollbackState = captureBPFState(nodeName)
		Expect(postRollbackState.ProgIDs).ToNot(BeEmpty())
		GinkgoWriter.Printf("Post-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			postRollbackState.ProgIDs, postRollbackState.MapIDs, postRollbackState.GlobalMaps)

		By("Validating: all IDs preserved (binary unchanged)")
		validateBPFState(preRollbackState, postRollbackState, false, "rollback")
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		if workloadPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, workloadPod)
		}
	})
})

// Scenario 2: Binary changed (v1.2.7 -> v1.3.4)
var _ = Describe("Agent Upgrade/Rollback - Binary Changed", Ordered, func() {
	const (
		fromTag = "v1.2.7"
		toTag   = "v1.3.4"
	)

	var (
		networkPolicy     *network.NetworkPolicy
		workloadPod       *v1.Pod
		nodeName          string
		preUpgradeState   utils.BPFState
		postUpgradeState  utils.BPFState
		preRollbackState  utils.BPFState
		postRollbackState utils.BPFState
	)

	It("should reload all BPF state across upgrade", func() {
		By("Setting agent image to old version: " + fromTag)
		setAgentImage(baseImage + ":" + fromTag)
		waitForDaemonSetRollout()

		By("Deploying workload pod with network policy")
		workloadPod = buildWorkloadPod("binary-changed")
		var err error
		workloadPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, workloadPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		nodeName = workloadPod.Spec.NodeName

		networkPolicy = buildTestNetworkPolicy("binary-changed")
		err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
		Expect(err).ToNot(HaveOccurred())

		By("Waiting for BPF probes to be attached")
		time.Sleep(bpfSettleInterval)

		By("Capturing pre-upgrade BPF state")
		preUpgradeState = captureBPFState(nodeName)
		Expect(preUpgradeState.ProgIDs).ToNot(BeEmpty(), "should have BPF programs before upgrade")
		Expect(preUpgradeState.GlobalMaps).ToNot(BeEmpty(), "should have global maps before upgrade")
		GinkgoWriter.Printf("Pre-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			preUpgradeState.ProgIDs, preUpgradeState.MapIDs, preUpgradeState.GlobalMaps)

		By("Upgrading agent to: " + toTag)
		setAgentImage(baseImage + ":" + toTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-upgrade BPF state")
		postUpgradeState = captureBPFState(nodeName)
		Expect(postUpgradeState.ProgIDs).ToNot(BeEmpty(), "should have BPF programs after upgrade")
		Expect(postUpgradeState.GlobalMaps).ToNot(BeEmpty(), "should have global maps after upgrade")
		GinkgoWriter.Printf("Post-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			postUpgradeState.ProgIDs, postUpgradeState.MapIDs, postUpgradeState.GlobalMaps)

		By("Validating: all BPF state reloaded (binary changed)")
		validateBPFState(preUpgradeState, postUpgradeState, true, "upgrade")
	})

	It("should reload all BPF state across rollback", func() {
		By("Capturing pre-rollback BPF state (agent on " + toTag + ")")
		preRollbackState = captureBPFState(nodeName)
		Expect(preRollbackState.ProgIDs).ToNot(BeEmpty())
		GinkgoWriter.Printf("Pre-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			preRollbackState.ProgIDs, preRollbackState.MapIDs, preRollbackState.GlobalMaps)

		By("Rolling back agent to: " + fromTag)
		setAgentImage(baseImage + ":" + fromTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-rollback BPF state")
		postRollbackState = captureBPFState(nodeName)
		Expect(postRollbackState.ProgIDs).ToNot(BeEmpty())
		Expect(postRollbackState.GlobalMaps).ToNot(BeEmpty())
		GinkgoWriter.Printf("Post-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			postRollbackState.ProgIDs, postRollbackState.MapIDs, postRollbackState.GlobalMaps)

		By("Validating: all BPF state reloaded (binary changed)")
		validateBPFState(preRollbackState, postRollbackState, true, "rollback")
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		if workloadPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, workloadPod)
		}
	})
})

func validateBPFState(before, after utils.BPFState, binaryChanged bool, operation string) {
	if binaryChanged {
		By("Binary changed: expecting all new IDs (programs, per-pod maps, global maps)")
		for name, oldID := range before.ProgIDs {
			newID, exists := after.ProgIDs[name]
			Expect(exists).To(BeTrue(), "program %s should still exist after %s", name, operation)
			Expect(newID).ToNot(Equal(oldID),
				fmt.Sprintf("program %s should have new ID after binary change (old=%d new=%d)", name, oldID, newID))
		}
		for name, oldID := range before.GlobalMaps {
			newID, exists := after.GlobalMaps[name]
			Expect(exists).To(BeTrue(), "global map %s should still exist after %s", name, operation)
			Expect(newID).ToNot(Equal(oldID),
				fmt.Sprintf("global map %s should have new ID after binary change (old=%d new=%d)", name, oldID, newID))
		}
	} else {
		By("Binary unchanged: expecting same program and map IDs")
		for name, oldID := range before.ProgIDs {
			newID, exists := after.ProgIDs[name]
			Expect(exists).To(BeTrue(), "program %s should still exist after %s", name, operation)
			Expect(newID).To(Equal(oldID),
				fmt.Sprintf("program %s should keep same ID when binary unchanged (old=%d new=%d)", name, oldID, newID))
		}
		for key, oldID := range before.MapIDs {
			newID, exists := after.MapIDs[key]
			Expect(exists).To(BeTrue(), "per-pod map %s should still exist after %s", key, operation)
			Expect(newID).To(Equal(oldID),
				fmt.Sprintf("per-pod map %s should keep same ID when binary unchanged (old=%d new=%d)", key, oldID, newID))
		}
		for name, oldID := range before.GlobalMaps {
			newID, exists := after.GlobalMaps[name]
			Expect(exists).To(BeTrue(), "global map %s should still exist after %s", name, operation)
			Expect(newID).To(Equal(oldID),
				fmt.Sprintf("global map %s should keep same ID when binary unchanged (old=%d new=%d)", name, oldID, newID))
		}
	}
}

func setAgentImage(image string) {
	ds := &appsv1.DaemonSet{}
	err := fw.K8sClient.Get(ctx, client.ObjectKey{
		Name:      agentDaemonSet,
		Namespace: agentNamespace,
	}, ds)
	Expect(err).ToNot(HaveOccurred())

	for i, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == agentContainer {
			ds.Spec.Template.Spec.Containers[i].Image = image
			break
		}
	}

	err = fw.K8sClient.Update(ctx, ds)
	Expect(err).ToNot(HaveOccurred())
}

func waitForDaemonSetRollout() {
	Eventually(func() bool {
		ds := &appsv1.DaemonSet{}
		err := fw.K8sClient.Get(ctx, client.ObjectKey{
			Name:      agentDaemonSet,
			Namespace: agentNamespace,
		}, ds)
		if err != nil {
			return false
		}
		return ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled &&
			ds.Status.NumberReady == ds.Status.DesiredNumberScheduled &&
			ds.Status.ObservedGeneration >= ds.Generation
	}, rolloutTimeout, 5*time.Second).Should(BeTrue(), "DaemonSet rollout should complete")
}

func buildWorkloadPod(suffix string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "upgrade-test-pod-" + suffix,
			Namespace: namespace,
			Labels:    map[string]string{"app": "upgrade-test-" + suffix},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "nginx",
					Image:   "public.ecr.aws/nginx/nginx:latest",
					Command: []string{"sleep", "3600"},
				},
			},
		},
	}
}

func buildTestNetworkPolicy(suffix string) *network.NetworkPolicy {
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name("upgrade-test-policy-"+suffix).
		PodSelector("app", "upgrade-test-"+suffix).
		SetPolicyType(true, true).
		Build()
}

func captureBPFState(nodeName string) utils.BPFState {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	var err error
	checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)

	output, err := fw.PodManager.ExecInPod(namespace, checkPod.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred())
	GinkgoWriter.Printf("loaded-ebpfdata output:\n%s\n", output)

	state, err := utils.ParseLoadedEBPFData(output)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata output")
	return state
}
