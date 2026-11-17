package upgrade

import (
	"fmt"
	"sort"
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

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
)

/*
Tests agent upgrade and rollback between a "from" image and the image under test.

Each -upgrade-from-image is one scenario: start on the from image, upgrade to
the image under test (or -upgrade-to-image), then roll back to the from image.

What the agent must keep or reload depends on whether its eBPF binaries
changed. At startup the agent byte-compares each .bpf.o it ships with the copy
the previous agent installed in /opt/cni/bin (checkAndUpdateBPFBinaries):
  - events binary changed: every program and the global maps are reloaded
  - shared binary (tc.shared.bpf.o) changed: every program is reloaded, and
    the global maps from the events binary are kept
  - only the ingress or egress binary changed: only that direction's programs
    are reloaded, and the global maps are kept
  - nothing changed: program, per-pod map and global map IDs are all kept

The test makes the same comparison on the host's installed binaries before and
after each transition, so the expectations follow the images actually being
tested instead of being assumed from a version pair.
*/
const (
	agentDaemonSet    = "aws-node"
	agentNamespace    = "kube-system"
	agentContainer    = "aws-eks-nodeagent"
	releasedImageRepo = "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-network-policy-agent"
	hostBinaryDir     = "/host/opt/cni/bin"
	rolloutTimeout    = 5 * time.Minute
	podReadyTimeout   = 2 * time.Minute
	bpfSettleInterval = 10 * time.Second
)

// Releases that start against current VPC CNI versions. Agents before v1.4
// never finish startup on VPC CNI v1.23 (aws/aws-network-policy-agent#784).
func defaultFromImages() []string {
	return []string{
		releasedImageRepo + ":v1.5.0",
		releasedImageRepo + ":v1.4.3",
	}
}

func fromImages() []string {
	if len(upgradeFromImages) > 0 {
		return upgradeFromImages
	}
	return defaultFromImages()
}

var _ = Describe("Agent Upgrade/Rollback", func() {
	for i, from := range fromImages() {
		describeUpgradeScenario(i, from)
	}
})

func describeUpgradeScenario(index int, fromImage string) {
	Describe("from "+fromImage, Ordered, func() {
		// Distinct first segment per scenario: the agent drops the last
		// "-" segment of a pod name to build its identifier, so names that
		// differ only at the end would share eBPF pins.
		suffix := fmt.Sprintf("upgrade%d", index)

		var (
			networkPolicy *network.NetworkPolicy
			workloadPod   *v1.Pod
			nodeName      string
		)

		BeforeAll(func() {
			By("Setting agent image to the from image: " + fromImage)
			setAgentImage(fromImage)
			waitForDaemonSetRollout()

			By("Deploying workload pod with network policy")
			workloadPod = buildWorkloadPod(suffix)
			running, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, workloadPod, podReadyTimeout)
			if err != nil {
				skipIfAgentRejectedSandbox(workloadPod, fromImage)
			}
			Expect(err).ToNot(HaveOccurred())
			workloadPod = running
			nodeName = workloadPod.Spec.NodeName

			networkPolicy = buildTestNetworkPolicy(suffix)
			err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
			Expect(err).ToNot(HaveOccurred())

			By("Waiting for BPF probes to be attached")
			time.Sleep(bpfSettleInterval)
		})

		It("should keep or reload BPF state on upgrade as the binary change requires", func() {
			runTransition(nodeName, toImage, "upgrade")
		})

		It("should keep or reload BPF state on rollback as the binary change requires", func() {
			runTransition(nodeName, fromImage, "rollback")
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
}

// runTransition moves the agent to image and checks the BPF state on nodeName
// against what the change in installed binaries requires.
func runTransition(nodeName, image, operation string) {
	By("Capturing BPF state before " + operation)
	before := captureBPFState(nodeName)
	Expect(before.ProgIDs).ToNot(BeEmpty(), "should have BPF programs before %s", operation)
	Expect(before.GlobalMaps).ToNot(BeEmpty(), "should have global maps before %s", operation)
	Expect(before.Binaries).ToNot(BeEmpty(), "should have eBPF binaries in %s before %s", hostBinaryDir, operation)
	GinkgoWriter.Printf("Before %s: progs=%v perPodMaps=%v globalMaps=%v binaries=%v\n",
		operation, before.ProgIDs, before.MapIDs, before.GlobalMaps, before.Binaries)

	By(operation + " agent to: " + image)
	setAgentImage(image)
	waitForDaemonSetRollout()
	time.Sleep(bpfSettleInterval)

	By("Capturing BPF state after " + operation)
	after := captureBPFState(nodeName)
	Expect(after.ProgIDs).ToNot(BeEmpty(), "should have BPF programs after %s", operation)
	Expect(after.GlobalMaps).ToNot(BeEmpty(), "should have global maps after %s", operation)
	GinkgoWriter.Printf("After %s: progs=%v perPodMaps=%v globalMaps=%v binaries=%v\n",
		operation, after.ProgIDs, after.MapIDs, after.GlobalMaps, after.Binaries)

	changes, err := diffBinaries(before.Binaries, after.Binaries)
	Expect(err).ToNot(HaveOccurred())
	By(fmt.Sprintf("Validating %s with binary changes: %s", operation, changes))
	validateBPFState(before, after, changes, operation)
}

// nodeState is the BPF state on a node plus the eBPF binaries installed there.
type nodeState struct {
	utils.BPFState
	Binaries map[string]string // .bpf.o file name -> sha256
}

// binaryChanges records which installed eBPF binaries differ between two
// agents, using the grouping the agent itself applies.
type binaryChanges struct {
	ingress, egress, events, shared bool
}

func (c binaryChanges) any() bool { return c.ingress || c.egress || c.events || c.shared }

func (c binaryChanges) String() string {
	if !c.any() {
		return "none"
	}
	var parts []string
	if c.events {
		parts = append(parts, "events")
	}
	if c.shared {
		parts = append(parts, "shared")
	}
	if c.ingress {
		parts = append(parts, "ingress")
	}
	if c.egress {
		parts = append(parts, "egress")
	}
	return strings.Join(parts, ", ")
}

// diffBinaries compares the installed binaries before and after a transition.
// A file present on only one side counts as changed, as it does for the agent,
// which compares against an empty read when its host copy is missing. A changed
// file the test does not know is an error, so a binary added to the agent later
// fails here until the test learns what changing it reloads.
func diffBinaries(before, after map[string]string) (binaryChanges, error) {
	var c binaryChanges
	var unknown []string
	names := map[string]struct{}{}
	for n := range before {
		names[n] = struct{}{}
	}
	for n := range after {
		names[n] = struct{}{}
	}
	for n := range names {
		b, inBefore := before[n]
		a, inAfter := after[n]
		if inBefore && inAfter && a == b {
			continue
		}
		switch {
		case strings.Contains(n, "events"):
			c.events = true
		case strings.Contains(n, "shared"):
			c.shared = true
		case strings.Contains(n, "ingress"):
			c.ingress = true
		case strings.Contains(n, "egress"):
			c.egress = true
		default:
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return c, fmt.Errorf("changed eBPF binaries the test does not classify: %s", strings.Join(unknown, ", "))
	}
	// The TC programs reference the global maps defined in the events binary,
	// and the node-wide maps defined in the shared binary. A change to either
	// recreates those maps, so every TC program is reloaded against them.
	if c.events || c.shared {
		c.ingress, c.egress = true, true
	}
	return c, nil
}

// progDirection returns "ingress" or "egress" for a program pin name such as
// "podid_handle_ingress", or "" if it is neither.
func progDirection(pinName string) string {
	switch {
	case strings.HasSuffix(pinName, "_ingress"):
		return "ingress"
	case strings.HasSuffix(pinName, "_egress"):
		return "egress"
	}
	return ""
}

func validateBPFState(before, after nodeState, changes binaryChanges, operation string) {
	for name, oldID := range before.ProgIDs {
		newID, exists := after.ProgIDs[name]
		Expect(exists).To(BeTrue(), "program %s should still exist after %s", name, operation)

		reloaded := false
		switch progDirection(name) {
		case "ingress":
			reloaded = changes.ingress
		case "egress":
			reloaded = changes.egress
		default:
			Fail(fmt.Sprintf("program pin %s is neither ingress nor egress", name))
		}
		if reloaded {
			Expect(newID).ToNot(Equal(oldID),
				"program %s should be reloaded after %s since its binary changed (old=%d new=%d)", name, operation, oldID, newID)
		} else {
			Expect(newID).To(Equal(oldID),
				"program %s should be kept after %s since its binary is unchanged (old=%d new=%d)", name, operation, oldID, newID)
		}
	}

	for name, oldID := range before.GlobalMaps {
		newID, exists := after.GlobalMaps[name]
		Expect(exists).To(BeTrue(), "global map %s should still exist after %s", name, operation)
		if changes.events {
			Expect(newID).ToNot(Equal(oldID),
				"global map %s should be recreated after %s since the events binary changed (old=%d new=%d)", name, operation, oldID, newID)
		} else {
			Expect(newID).To(Equal(oldID),
				"global map %s should be kept after %s since the events binary is unchanged (old=%d new=%d)", name, operation, oldID, newID)
		}
	}

	// Per-pod maps are only checked when nothing changed: whether a reload
	// keeps them is not part of what this test pins down.
	if !changes.any() {
		for key, oldID := range before.MapIDs {
			newID, exists := after.MapIDs[key]
			Expect(exists).To(BeTrue(), "per-pod map %s should still exist after %s", key, operation)
			Expect(newID).To(Equal(oldID),
				"per-pod map %s should be kept after %s since no binary changed (old=%d new=%d)", key, operation, oldID, newID)
		}
	}
}

// skipIfAgentRejectedSandbox skips the scenario when the workload pod could not
// start because the from agent refused CNI ADD, which happens when that agent
// cannot start against the installed VPC CNI. The image under test has not run
// yet at that point, so this is a limit of the scenario, not a failure.
func skipIfAgentRejectedSandbox(pod *v1.Pod, fromImage string) {
	events := &v1.EventList{}
	err := fw.K8sClient.List(ctx, events, client.InNamespace(pod.Namespace),
		client.MatchingFields{"involvedObject.name": pod.Name})
	if err != nil {
		GinkgoWriter.Printf("listing events for %s: %v\n", pod.Name, err)
		return
	}
	for _, e := range events.Items {
		if e.Reason == "FailedCreatePodSandBox" && strings.Contains(strings.ToLower(e.Message), "network policy") {
			// AfterAll deletes the pod.
			Skip(fmt.Sprintf("from image %s cannot set up pod networking on this cluster, likely incompatible "+
				"with the installed VPC CNI; pass a newer -upgrade-from-image. Sandbox error: %s", fromImage, e.Message))
		}
	}
}

func currentAgentImage() string {
	ds := &appsv1.DaemonSet{}
	err := fw.K8sClient.Get(ctx, client.ObjectKey{
		Name:      agentDaemonSet,
		Namespace: agentNamespace,
	}, ds)
	Expect(err).ToNot(HaveOccurred())

	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == agentContainer {
			return c.Image
		}
	}
	Fail(fmt.Sprintf("container %s not found in DaemonSet %s/%s", agentContainer, agentNamespace, agentDaemonSet))
	return ""
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
			Name:      suffix + "-workload",
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

func captureBPFState(nodeName string) nodeState {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	var err error
	checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)

	output, err := fw.PodManager.ExecInPod(namespace, checkPod.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred())
	GinkgoWriter.Printf("loaded-ebpfdata output:\n%s\n", output)

	bpfState, err := utils.ParseLoadedEBPFData(output)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata output")

	hashes, err := fw.PodManager.ExecInPod(namespace, checkPod.Name,
		[]string{"sh", "-c", "cd " + hostBinaryDir + " && sha256sum *.bpf.o"})
	Expect(err).ToNot(HaveOccurred(), "failed to hash eBPF binaries in %s", hostBinaryDir)
	binaries, err := parseSHA256Sums(hashes)
	Expect(err).ToNot(HaveOccurred(), "failed to parse sha256sum output:\n%s", hashes)

	return nodeState{BPFState: bpfState, Binaries: binaries}
}

// parseSHA256Sums parses sha256sum output ("<hash>  <file>" per line).
func parseSHA256Sums(output string) (map[string]string, error) {
	sums := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return nil, fmt.Errorf("unexpected sha256sum line %q", line)
		}
		sums[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}
	return sums, nil
}
