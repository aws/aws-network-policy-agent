package restart

import (
	"fmt"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	npautils "github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
)

// A same-binary aws-node rollout must REUSE pinned programs/maps, not reload
// them: only the agent restarts, so pods keep their veths and pinned state.
// Verification uses host ground truth cross-checked against itself (see the
// Describe/It text), never an identifier computed in Go and asserted back -
// that would test the agent's naming code against itself.

const (
	recoveryLabelKey   = "recovery"
	recoveryLabelValue = "rollout"
	dottedPodName      = "my.app"
	recoveryDeployName = "recovery-deploy"
	recoveryJobName    = "recovery-job"
	// The CNI host-veth prefix for regular (non-branch-ENI) pods.
	podVethPrefix = "eni"
)

// recoveryCheckPod is the single privileged pod all host commands exec into.
// Package-scoped so the package-level helpers below can reach it, matching how
// the suite exposes fw/ctx/namespace.
var recoveryCheckPod *v1.Pod

// workload couples a running pod with the host veth its TC programs attach to.
type workload struct {
	label    string // human label for messages: "standalone" | "deployment" | "job"
	pod      v1.Pod
	vethName string
}

var _ = Describe("BPF Recovery Across Rollout Restart: reuses pinned progs/maps for standalone (dotted-name), Deployment, and Job pods, cross-checking bpffs pins, the loaded-ebpfdata CLI, and tc-attached prog IDs at each veth before and after the restart", Ordered, func() {
	var (
		networkPolicy *network.NetworkPolicy
		serverPod     *v1.Pod
		clientPod     *v1.Pod
		deployment    *appsv1.Deployment
		job           *batchv1.Job
		nodeName      string
		serverIP      string
		workloads     []workload
	)

	It("keeps each pod's pin path, prog ID, and map IDs identical across the restart, and keeps the CLI-reported prog IDs equal to the tc-attached prog IDs at the veth (the dotted-name pod's identifier must stay 'my_app@ns', not truncate to 'my@ns')", func() {
		By("Deploying the dotted-name standalone pod (nginx server)")
		serverPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: dottedPodName, Namespace: namespace,
				Labels: map[string]string{recoveryLabelKey: recoveryLabelValue, "role": "standalone"},
			},
			Spec: v1.PodSpec{Containers: []v1.Container{{
				Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
			}}},
		}
		var err error
		serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		nodeName = serverPod.Spec.NodeName
		serverIP = serverPod.Status.PodIP
		Expect(nodeName).ToNot(BeEmpty())

		By("Bringing up the single host check pod on the workloads' node")
		recoveryCheckPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildRecoveryCheckPod(nodeName), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("Deploying a Deployment pinned to the same node")
		deployment = buildRecoveryDeployment(nodeName)
		Expect(fw.K8sClient.Create(ctx, deployment)).To(Succeed())
		deployPod, err := fw.PodManager.WaitTillPodWithLabelRunning(ctx, namespace, "role", "deploy", podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		By("Deploying a Job pinned to the same node")
		job = buildRecoveryJob(nodeName)
		Expect(fw.K8sClient.Create(ctx, job)).To(Succeed())
		jobPod, err := fw.PodManager.WaitTillPodWithLabelRunning(ctx, namespace, "role", "job", podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		// Locate each pod's host veth via the CNI's sha1 naming convention. This
		// is ground truth for "where are this pod's TC programs attached", and is
		// independent of the pin-path parser the recovery code uses.
		workloads = []workload{
			{label: "standalone", pod: *serverPod, vethName: utils.HostVethName(namespace, serverPod.Name, podVethPrefix, 0)},
			{label: "deployment", pod: deployPod, vethName: utils.HostVethName(namespace, deployPod.Name, podVethPrefix, 0)},
			{label: "job", pod: jobPod, vethName: utils.HostVethName(namespace, jobPod.Name, podVethPrefix, 0)},
		}
		for _, w := range workloads {
			GinkgoWriter.Printf("Workload %-11s pod=%s veth=%s\n", w.label, w.pod.Name, w.vethName)
		}

		By("Applying a deny-all ingress+egress policy selecting all three workloads")
		networkPolicy = manifest.NewNetworkPolicyBuilder().
			Namespace(namespace).
			Name("rollout-recovery-deny").
			PodSelector(recoveryLabelKey, recoveryLabelValue).
			SetPolicyType(true, true).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
		time.Sleep(bpfSettleInterval)

		By("Deploying an unrestricted client and confirming the server is blocked (enforcement is live)")
		clientPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rollout-client", Namespace: namespace,
				Labels: map[string]string{"role": "client"}, // not selected by the policy
			},
			Spec: v1.PodSpec{
				NodeName:   nodeName,
				Containers: []v1.Container{{Name: "curl", Image: "public.ecr.aws/docker/library/python:3.11-slim", Command: []string{"sleep", "3600"}}},
			},
		}
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))

		// ================= PRE-RESTART: capture host state =================
		By("PRE-RESTART: capturing pin paths, CLI-described IDs, and tc-attached IDs")
		GinkgoWriter.Printf("Pre-restart program pins on node:\n%s\n", strings.Join(listProgramPinBasenames(), "\n"))

		// allBPFStateBeforeRestart: whole-node CLI dump (every pin's prog ID +
		// parsed identifier). podProgramsBeforeRestart: narrowed to just our test
		// pods' programs, keyed by workload label.
		allBPFCLIStateBeforeRestart := dumpAllBPFStateFromCLI()
		podProgramsCLIStateBeforeRestart := map[string]podPrograms{}
		for _, w := range workloads {
			podProgramsCLIStateBeforeRestart[w.label] = selectPodProgramsViaTC(w, allBPFCLIStateBeforeRestart)
		}

		// The identifier the agent parsed out of the pin (CLI "Pod Identifier")
		// must equal the identifier derived from the pod name. Guards the pin-path
		// parser against regressions like truncating "my_app@ns" to "my".
		By("Step 1: the parsed Pod Identifier for each pod matches the name-derived identifier")
		for _, w := range workloads {
			expectedIdentifier := npautils.GetPodIdentifier(w.pod.Name, namespace)
			progs := podProgramsCLIStateBeforeRestart[w.label]
			Expect(allBPFCLIStateBeforeRestart.PodIdentifiers[progs.ingressPin]).To(Equal(expectedIdentifier),
				"%s (pod %s): CLI-parsed identifier for pin %s must match name-derived %q",
				w.label, w.pod.Name, progs.ingressPin, expectedIdentifier)
			Expect(allBPFCLIStateBeforeRestart.PodIdentifiers[progs.egressPin]).To(Equal(expectedIdentifier),
				"%s (pod %s): CLI-parsed identifier for pin %s must match name-derived %q",
				w.label, w.pod.Name, progs.egressPin, expectedIdentifier)
		}

		By("Step 2: each pod's CLI-reported prog IDs match the prog IDs tc has attached at its veth")
		for _, w := range workloads {
			assertCLIAndTCAgree(w, podProgramsCLIStateBeforeRestart[w.label], allBPFCLIStateBeforeRestart)
		}

		// ================= RESTART
		// =================
		By("Rollout-restarting the aws-node DaemonSet (same binary)")
		rolloutRestartDaemonSet()
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		// ================= POST-RESTART: re-capture and compare =================
		By("POST-RESTART: capturing pin paths, CLI-described IDs, and tc-attached IDs")
		GinkgoWriter.Printf("Post-restart program pins on node:\n%s\n", strings.Join(listProgramPinBasenames(), "\n"))

		allBPFStateAfterRestart := dumpAllBPFStateFromCLI()
		podProgramsAfterRestart := map[string]podPrograms{}
		for _, w := range workloads {
			podProgramsAfterRestart[w.label] = selectPodProgramsViaTC(w, allBPFStateAfterRestart)
		}

		By("Step 3: each pod's pin paths are unchanged after restart")
		for _, w := range workloads {
			before, after := podProgramsCLIStateBeforeRestart[w.label], podProgramsAfterRestart[w.label]
			Expect(after.ingressPin).To(Equal(before.ingressPin), "%s: ingress pin path should be unchanged after restart", w.label)
			Expect(after.egressPin).To(Equal(before.egressPin), "%s: egress pin path should be unchanged after restart", w.label)
		}

		// A same-binary rollout reuses programs rather than reloading them, so the
		// prog ID is the same kernel object before and after. Map bindings are
		// frozen into a program at load and cannot change while it lives, so a
		// preserved prog ID already implies preserved map IDs.
		By("Step 4: each pod's prog IDs are preserved (same-binary recovery reuses, not reloads)")
		for _, w := range workloads {
			before, after := podProgramsCLIStateBeforeRestart[w.label], podProgramsAfterRestart[w.label]
			Expect(after.ingressProgID).To(Equal(before.ingressProgID), "%s: ingress prog ID should be preserved", w.label)
			Expect(after.egressProgID).To(Equal(before.egressProgID), "%s: egress prog ID should be preserved", w.label)
		}

		By("Step 5: each pod's CLI-reported prog IDs still match tc-attached prog IDs after restart")
		for _, w := range workloads {
			assertCLIAndTCAgree(w, podProgramsAfterRestart[w.label], allBPFStateAfterRestart)
		}

		By("Enforcement continues after restart")
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		if clientPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		}
		if serverPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
		}
		if deployment != nil {
			_ = fw.K8sClient.Delete(ctx, deployment)
		}
		if job != nil {
			policy := metav1.DeletePropagationForeground
			_ = fw.K8sClient.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &policy})
		}
		if recoveryCheckPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, recoveryCheckPod)
			recoveryCheckPod = nil
		}
	})
})

// podPrograms is one pod's two TC programs, as observed on the host: the pin
// filenames and the prog IDs the CLI reports for them.
type podPrograms struct {
	identifier    string // pod identifier read off the pin basename
	ingressPin    string // "<identifier>_handle_ingress"
	egressPin     string // "<identifier>_handle_egress"
	ingressProgID int    // prog ID the CLI reports for the ingress pin
	egressProgID  int    // prog ID the CLI reports for the egress pin
}

// selectPodProgramsViaTC picks one pod's two programs out of the node-wide CLI
// dump, using tc as the selector: tc reports which prog IDs are attached at the
// pod's veth (kernel ground truth), and we keep only the CLI pins whose prog ID
// is in that set. Those two pins are this pod's; their shared basename is its
// identifier.
//
// Using the tc-attached prog IDs (not a name match) is what keeps this
// independent of the pin-path parser under test. The combined set of both hooks
// is used only to find which two pins belong to the veth; which hook holds which
// direction is asserted separately in assertCLIAndTCAgree.
func selectPodProgramsViaTC(w workload, allBPFState utils.BPFState) podPrograms {
	attachedProgIDs := tcAttachedProgIDSet(w.vethName)
	Expect(attachedProgIDs).ToNot(BeEmpty(), "%s (%s): expected BPF programs attached at the veth's TC hooks", w.label, w.vethName)

	progs := podPrograms{}
	for pin, progID := range allBPFState.ProgIDs {
		if !attachedProgIDs[progID] {
			continue // belongs to a different pod
		}
		switch {
		case strings.HasSuffix(pin, "_handle_ingress"):
			progs.identifier = strings.TrimSuffix(pin, "_handle_ingress")
			progs.ingressPin = pin
			progs.ingressProgID = progID
		case strings.HasSuffix(pin, "_handle_egress"):
			progs.identifier = strings.TrimSuffix(pin, "_handle_egress")
			progs.egressPin = pin
			progs.egressProgID = progID
		}
	}
	Expect(progs.identifier).ToNot(BeEmpty(),
		"%s (%s): no program pin in the CLI dump matched the tc-attached prog IDs %v", w.label, w.vethName, keysOfBool(attachedProgIDs))

	return progs
}

// assertCLIAndTCAgree checks the load-bearing cross-source equality with the
// exact hook<->direction mapping, so it also guards NPA's TC-hook inversion:
// a pod's INGRESS program attaches to the TC EGRESS hook, and its EGRESS
// program attaches to the TC INGRESS hook (attachIngressBPFProbe ->
// TCEgressAttach, attachEgressBPFProbe -> TCIngressAttach). So the prog ID the
// CLI reports for the pod's ingress pin must be the one tc shows on the egress
// hook, and vice versa. Each hook carries exactly one filter (fixed handle), so
// we assert a single ID per hook, not a set.
//
// This intentionally couples the test to the inversion convention: if the
// agent's hook mapping ever changes, this assertion is meant to fail.
func assertCLIAndTCAgree(w workload, progState podPrograms, allBPFCLIState utils.BPFState) {
	// Read the prog IDs straight from the CLI dump keyed by pin name, so the
	// values compared here come purely from the CLI - NOT from progs, whose IDs
	// were already filtered through the tc set during selection. This keeps the
	// comparison a genuine CLI-vs-tc cross-check rather than tc-vs-tc.
	cliIngressProgID := allBPFCLIState.ProgIDs[progState.ingressPin]
	cliEgressProgID := allBPFCLIState.ProgIDs[progState.egressPin]
	Expect(cliIngressProgID).ToNot(BeZero(), "%s: CLI dump has no prog ID for ingress pin %s", w.label, progState.ingressPin)
	Expect(cliEgressProgID).ToNot(BeZero(), "%s: CLI dump has no prog ID for egress pin %s", w.label, progState.egressPin)

	tcIngressHook := tcAttachedProgIDs(w.vethName, "ingress")
	tcEgressHook := tcAttachedProgIDs(w.vethName, "egress")
	Expect(tcIngressHook).To(HaveLen(1), "%s (%s): expected exactly one filter on the TC ingress hook, got %v", w.label, w.vethName, tcIngressHook)
	Expect(tcEgressHook).To(HaveLen(1), "%s (%s): expected exactly one filter on the TC egress hook, got %v", w.label, w.vethName, tcEgressHook)

	// Inversion: ingress program -> egress hook, egress program -> ingress hook.
	Expect(tcEgressHook[0]).To(Equal(cliIngressProgID),
		"%s: pod ingress program (pin %s, CLI prog ID %d) must be attached at the TC EGRESS hook, but tc shows %d there",
		w.label, progState.ingressPin, cliIngressProgID, tcEgressHook[0])
	Expect(tcIngressHook[0]).To(Equal(cliEgressProgID),
		"%s: pod egress program (pin %s, CLI prog ID %d) must be attached at the TC INGRESS hook, but tc shows %d there",
		w.label, progState.egressPin, cliEgressProgID, tcIngressHook[0])
}

// listProgramPinBasenames returns the basenames of every program pin under the
// agent's programs pin directory on the node.
func listProgramPinBasenames() []string {
	out := execInCheckPod([]string{"chroot", "/host", "ls", "-1", "/sys/fs/bpf/globals/aws/programs/"})
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	sort.Strings(names)
	return names
}

// dumpAllBPFStateFromCLI runs `loaded-ebpfdata` in the check pod and parses the
// whole-node dump: every pin's prog ID and the agent's parsed Pod Identifier.
func dumpAllBPFStateFromCLI() utils.BPFState {
	out := execInCheckPod([]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(out).ToNot(BeEmpty(), "empty loaded-ebpfdata output")
	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata output")
	return state
}

// tcAttachedProgIDs returns the BPF prog IDs attached at the given TC hook of a
// host veth, read straight from `tc filter show`.
//
// tc runs from the netshoot image itself (which ships iproute2), NOT via
// chroot /host: the AL2023 node image does not carry tc on the chroot PATH. The
// check pod is hostNetwork, so the pod's own tc sees the host veths and their
// TC filters directly.
func tcAttachedProgIDs(vethName, direction string) []int {
	out := execInCheckPod([]string{"tc", "filter", "show", "dev", vethName, direction})
	return utils.ParseTCFilterProgIDs(out)
}

// tcAttachedProgIDSet returns the union of BPF prog IDs attached at both TC
// hooks (ingress + egress) of a veth, as a set. This is the hook-agnostic view
// used to cross-check against the CLI dump - see selectPodProgramsViaTC.
func tcAttachedProgIDSet(vethName string) map[int]bool {
	set := map[int]bool{}
	for _, dir := range []string{"ingress", "egress"} {
		for _, id := range tcAttachedProgIDs(vethName, dir) {
			set[id] = true
		}
	}
	return set
}

// keysOfBool returns the keys of a set as a slice, for readable failure output.
func keysOfBool(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// fetchAgentMetrics scrapes the aws-node agent's Prometheus endpoint from the
// check pod. The check pod runs with hostNetwork and the netshoot image ships
// curl, so the agent's metrics endpoint is reachable on the node's loopback
// without chroot or a package install. Soft: returns the error instead of
// failing, since step 6 is gathered and logged, not asserted.
func fetchAgentMetrics() (string, error) {
	return execInCheckPodSoft([]string{"curl", "-s", "--max-time", "10", "http://127.0.0.1:8162/metrics"})
}

// execInCheckPod runs a command in the shared check pod and requires success.
func execInCheckPod(command []string) string {
	Expect(recoveryCheckPod).ToNot(BeNil(), "check pod must be created before host exec")
	out, err := fw.PodManager.ExecInPod(namespace, recoveryCheckPod.Name, command)
	Expect(err).ToNot(HaveOccurred(), "exec in check pod failed: %v", command)
	return out
}

// execInCheckPodSoft runs a command in the shared check pod and returns the
// error rather than failing the test.
func execInCheckPodSoft(command []string) (string, error) {
	if recoveryCheckPod == nil {
		return "", fmt.Errorf("check pod not created")
	}
	return fw.PodManager.ExecInPod(namespace, recoveryCheckPod.Name, command)
}

// rolloutRestartDaemonSet triggers a rolling restart of the agent DaemonSet the
// same way `kubectl rollout restart` does: by stamping the pod-template
// restartedAt annotation, which bumps the DaemonSet generation and recreates its
// pods from the unchanged image.
func rolloutRestartDaemonSet() {
	ds := &appsv1.DaemonSet{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Name: agentDaemonSet, Namespace: agentNamespace}, ds)).To(Succeed())
	if ds.Spec.Template.Annotations == nil {
		ds.Spec.Template.Annotations = map[string]string{}
	}
	ds.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = fmt.Sprintf("%d", time.Now().UnixNano())
	Expect(fw.K8sClient.Update(ctx, ds)).To(Succeed())
}

// buildRecoveryCheckPod is the shared BPF check pod, kept alive for the whole
// spec. The netshoot base image already ships curl/tc/bpftool, so this only
// extends the sleep past the base 300s: the pod must outlive the rollout
// restart (up to rolloutTimeout) plus the pre/post capture phases.
func buildRecoveryCheckPod(nodeName string) *v1.Pod {
	p := utils.BuildBPFCheckPod(namespace, nodeName)
	p.Spec.Containers[0].Command = []string{"sleep", "1800"}
	return p
}

func buildRecoveryDeployment(nodeName string) *appsv1.Deployment {
	replicas := int32(1)
	labels := map[string]string{recoveryLabelKey: recoveryLabelValue, "role": "deploy"}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: recoveryDeployName, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "deploy"}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: v1.PodSpec{
					NodeName:   nodeName,
					Containers: []v1.Container{{Name: "app", Image: "public.ecr.aws/nginx/nginx:latest", Command: []string{"sleep", "3600"}}},
				},
			},
		},
	}
}

func buildRecoveryJob(nodeName string) *batchv1.Job {
	backoffLimit := int32(0)
	labels := map[string]string{recoveryLabelKey: recoveryLabelValue, "role": "job"}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: recoveryJobName, Namespace: namespace},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: v1.PodSpec{
					NodeName:      nodeName,
					RestartPolicy: v1.RestartPolicyNever,
					// Long-lived so the pod survives the agent rollout restart.
					Containers: []v1.Container{{Name: "job", Image: "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal", Command: []string{"sleep", "3600"}}},
				},
			},
		},
	}
}
