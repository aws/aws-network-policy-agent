package upgrade

import (
	"fmt"
	"strconv"
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

type bpfState struct {
	progIDs    map[string]int // pinPath basename -> prog ID
	mapIDs     map[string]int // "podIdentifier/mapName" -> map ID
	globalMaps map[string]int // global map name -> map ID (deduplicated)
}

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
		preUpgradeState   bpfState
		postUpgradeState  bpfState
		preRollbackState  bpfState
		postRollbackState bpfState
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
		Expect(preUpgradeState.progIDs).ToNot(BeEmpty(), "should have BPF programs before upgrade")
		Expect(preUpgradeState.globalMaps).ToNot(BeEmpty(), "should have global maps before upgrade")
		GinkgoWriter.Printf("Pre-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			preUpgradeState.progIDs, preUpgradeState.mapIDs, preUpgradeState.globalMaps)

		By("Upgrading agent to: " + toTag)
		setAgentImage(baseImage + ":" + toTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-upgrade BPF state")
		postUpgradeState = captureBPFState(nodeName)
		Expect(postUpgradeState.progIDs).ToNot(BeEmpty(), "should have BPF programs after upgrade")
		GinkgoWriter.Printf("Post-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			postUpgradeState.progIDs, postUpgradeState.mapIDs, postUpgradeState.globalMaps)

		By("Validating: all IDs preserved (binary unchanged)")
		validateBPFState(preUpgradeState, postUpgradeState, false, "upgrade")
	})

	It("should preserve all BPF state across rollback", func() {
		By("Capturing pre-rollback BPF state (agent on " + toTag + ")")
		preRollbackState = captureBPFState(nodeName)
		Expect(preRollbackState.progIDs).ToNot(BeEmpty())
		GinkgoWriter.Printf("Pre-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			preRollbackState.progIDs, preRollbackState.mapIDs, preRollbackState.globalMaps)

		By("Rolling back agent to: " + fromTag)
		setAgentImage(baseImage + ":" + fromTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-rollback BPF state")
		postRollbackState = captureBPFState(nodeName)
		Expect(postRollbackState.progIDs).ToNot(BeEmpty())
		GinkgoWriter.Printf("Post-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			postRollbackState.progIDs, postRollbackState.mapIDs, postRollbackState.globalMaps)

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
		preUpgradeState   bpfState
		postUpgradeState  bpfState
		preRollbackState  bpfState
		postRollbackState bpfState
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
		Expect(preUpgradeState.progIDs).ToNot(BeEmpty(), "should have BPF programs before upgrade")
		Expect(preUpgradeState.globalMaps).ToNot(BeEmpty(), "should have global maps before upgrade")
		GinkgoWriter.Printf("Pre-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			preUpgradeState.progIDs, preUpgradeState.mapIDs, preUpgradeState.globalMaps)

		By("Upgrading agent to: " + toTag)
		setAgentImage(baseImage + ":" + toTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-upgrade BPF state")
		postUpgradeState = captureBPFState(nodeName)
		Expect(postUpgradeState.progIDs).ToNot(BeEmpty(), "should have BPF programs after upgrade")
		Expect(postUpgradeState.globalMaps).ToNot(BeEmpty(), "should have global maps after upgrade")
		GinkgoWriter.Printf("Post-upgrade: progs=%v perPodMaps=%v globalMaps=%v\n",
			postUpgradeState.progIDs, postUpgradeState.mapIDs, postUpgradeState.globalMaps)

		By("Validating: all BPF state reloaded (binary changed)")
		validateBPFState(preUpgradeState, postUpgradeState, true, "upgrade")
	})

	It("should reload all BPF state across rollback", func() {
		By("Capturing pre-rollback BPF state (agent on " + toTag + ")")
		preRollbackState = captureBPFState(nodeName)
		Expect(preRollbackState.progIDs).ToNot(BeEmpty())
		GinkgoWriter.Printf("Pre-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			preRollbackState.progIDs, preRollbackState.mapIDs, preRollbackState.globalMaps)

		By("Rolling back agent to: " + fromTag)
		setAgentImage(baseImage + ":" + fromTag)
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		By("Capturing post-rollback BPF state")
		postRollbackState = captureBPFState(nodeName)
		Expect(postRollbackState.progIDs).ToNot(BeEmpty())
		Expect(postRollbackState.globalMaps).ToNot(BeEmpty())
		GinkgoWriter.Printf("Post-rollback: progs=%v perPodMaps=%v globalMaps=%v\n",
			postRollbackState.progIDs, postRollbackState.mapIDs, postRollbackState.globalMaps)

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

func validateBPFState(before, after bpfState, binaryChanged bool, operation string) {
	if binaryChanged {
		By("Binary changed: expecting all new IDs (programs, per-pod maps, global maps)")
		for name, oldID := range before.progIDs {
			newID, exists := after.progIDs[name]
			Expect(exists).To(BeTrue(), "program %s should still exist after %s", name, operation)
			Expect(newID).ToNot(Equal(oldID),
				fmt.Sprintf("program %s should have new ID after binary change (old=%d new=%d)", name, oldID, newID))
		}
		for name, oldID := range before.globalMaps {
			newID, exists := after.globalMaps[name]
			Expect(exists).To(BeTrue(), "global map %s should still exist after %s", name, operation)
			Expect(newID).ToNot(Equal(oldID),
				fmt.Sprintf("global map %s should have new ID after binary change (old=%d new=%d)", name, oldID, newID))
		}
	} else {
		By("Binary unchanged: expecting same program and map IDs")
		for name, oldID := range before.progIDs {
			newID, exists := after.progIDs[name]
			Expect(exists).To(BeTrue(), "program %s should still exist after %s", name, operation)
			Expect(newID).To(Equal(oldID),
				fmt.Sprintf("program %s should keep same ID when binary unchanged (old=%d new=%d)", name, oldID, newID))
		}
		for key, oldID := range before.mapIDs {
			newID, exists := after.mapIDs[key]
			Expect(exists).To(BeTrue(), "per-pod map %s should still exist after %s", key, operation)
			Expect(newID).To(Equal(oldID),
				fmt.Sprintf("per-pod map %s should keep same ID when binary unchanged (old=%d new=%d)", key, oldID, newID))
		}
		for name, oldID := range before.globalMaps {
			newID, exists := after.globalMaps[name]
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

func captureBPFState(nodeName string) bpfState {
	checkPod := buildBPFCheckPod(nodeName)
	var err error
	checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)

	output, err := fw.PodManager.ExecInPod(namespace, checkPod.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred())
	GinkgoWriter.Printf("loaded-ebpfdata output:\n%s\n", output)

	return parseLoadedEBPFData(output)
}

func buildBPFCheckPod(nodeName string) *v1.Pod {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("bpf-check-%d", time.Now().UnixNano()),
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			HostPID:       true,
			HostNetwork:   true,
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{
				{
					Name:    "check",
					Image:   "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
					Command: []string{"sleep", "300"},
					SecurityContext: &v1.SecurityContext{
						Privileged: &privileged,
					},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
						},
					},
				},
			},
			Volumes: []v1.Volume{
				{
					Name: "host-root",
					VolumeSource: v1.VolumeSource{
						HostPath: &v1.HostPathVolumeSource{
							Path: "/",
							Type: &hostPathDir,
						},
					},
				},
			},
		},
	}
}

// parseLoadedEBPFData parses the output of `aws-eks-na-cli ebpf loaded-ebpfdata`.
// Format:
//
//	PinPath:  /sys/fs/bpf/globals/aws/programs/podid_handle_ingress
//	Pod Identifier : podid  Direction : ingress
//	Prog ID:  1446
//	Associated Maps ->
//	Map Name:  ingress_map
//	Map ID:  517
//	Map Name:  aws_conntrack_map
//	Map ID:  514
//	===...===
func parseLoadedEBPFData(output string) bpfState {
	state := bpfState{
		progIDs:    make(map[string]int),
		mapIDs:     make(map[string]int),
		globalMaps: make(map[string]int),
	}

	var currentPinName string
	var currentPodID string
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.HasPrefix(line, "PinPath:") {
			pinPath := strings.TrimSpace(strings.TrimPrefix(line, "PinPath:"))
			segments := strings.Split(pinPath, "/")
			currentPinName = segments[len(segments)-1]
		}

		if strings.HasPrefix(line, "Pod Identifier :") {
			parts := strings.Split(line, "Direction")
			if len(parts) > 0 {
				currentPodID = strings.TrimSpace(strings.TrimPrefix(parts[0], "Pod Identifier :"))
			}
		}

		if strings.HasPrefix(line, "Prog ID:") {
			idStr := strings.TrimSpace(strings.TrimPrefix(line, "Prog ID:"))
			if id, err := strconv.Atoi(idStr); err == nil && currentPinName != "" {
				state.progIDs[currentPinName] = id
			}
		}

		if strings.HasPrefix(line, "Map Name:") {
			mapName := strings.TrimSpace(strings.TrimPrefix(line, "Map Name:"))
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				if strings.HasPrefix(nextLine, "Map ID:") {
					idStr := strings.TrimSpace(strings.TrimPrefix(nextLine, "Map ID:"))
					if id, err := strconv.Atoi(idStr); err == nil {
						if isGlobalMap(mapName) {
							state.globalMaps[mapName] = id
						} else if currentPodID != "" {
							state.mapIDs[currentPodID+"/"+mapName] = id
						}
					}
					i++
				}
			}
		}
	}
	return state
}

func isGlobalMap(name string) bool {
	return name == "aws_conntrack_map" || name == "policy_events"
}
