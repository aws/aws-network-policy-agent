package ebpf

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	fwutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A directory at a pin path the egress program's load needs makes only that
// load fail, after the ingress program and some egress maps are already pinned.
// This relies on the agent loading ingress before egress; otherwise nothing
// would be pinned before the failure and the first spec couldn't catch a leak.
// Job pods have single-use pod identifiers, so any pin a failed attach leaves
// behind is never reclaimed (#621).
var _ = Describe("BPF pins after a failed attach", func() {
	var (
		node       string
		checkPod   *v1.Pod
		faultPath  string
		identifier string
	)

	BeforeEach(func() {
		node = agentNode()

		checkPod = fwutils.BuildBPFCheckPod(namespace, node)
		checkPod.Spec.Containers[0].Command = []string{"sleep", "1200"}
		// sleep runs as PID 1 and ignores SIGTERM.
		checkPodGrace := int64(0)
		checkPod.Spec.TerminationGracePeriodSeconds = &checkPodGrace
		// Registered before the wait, so a pod that never starts is still deleted.
		built := checkPod
		DeferCleanup(func() {
			deleteCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(deleteCtx, built)).To(Succeed())
		})
		var err error
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())

		// Job pods are named <job>-<suffix>, and the identifier drops the last "-" segment.
		identifier = utils.GetPodIdentifier(pinFailJobName+"-x", namespace)
		faultPath, _ = utils.GetBPFMapPinPathFromPodIdentifier(identifier, "egress")
		removeFaultAndPins := fmt.Sprintf("rmdir %s 2>/dev/null; rm -f %s%s_* %s%s_*", faultPath,
			utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, identifier, utils.BPF_MAPS_PIN_PATH_DIRECTORY, identifier)

		By("Removing the fault and pins an earlier failed run may have left for the identifier")
		_, err = hostShell(checkPod.Name, removeFaultAndPins)
		Expect(err).ToNot(HaveOccurred())

		By("Blocking the egress map's pin path for the Job's pod identifier")
		_, err = hostShell(checkPod.Name, fmt.Sprintf("mkdir %s", faultPath))
		Expect(err).ToNot(HaveOccurred())
		// Don't leave the fault or pins from a failed spec to the suites that run next.
		// Registered after the check pod's cleanup, so it runs first.
		DeferCleanup(func() {
			_, err := hostShell(checkPod.Name, removeFaultAndPins)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	It("leaves no pins after a Job pod whose load failed is deleted", func() {
		job := createPinFailJob(node)
		pod := waitForJobPod(job)
		Expect(utils.GetPodIdentifier(pod.Name, namespace)).To(Equal(identifier))

		By("Waiting for the pod's egress load to fail")
		waitForEgressLoadFailure(checkPod.Name, pod.Name, identifier)

		By("Deleting the Job while its pod keeps failing")
		deleteJobAndWait(job)

		// The fault stays in place, so a CNI ADD still running for the deleted pod
		// fails the same way instead of attaching and getting cleaned up by its DEL.
		By("Checking that no pins remain for the identifier")
		expectNoIdentifierPins(checkPod.Name, identifier)
	})

	It("attaches once the load stops failing and leaves no pins after delete", func() {
		job := createPinFailJob(node)
		pod := waitForJobPod(job)
		Expect(utils.GetPodIdentifier(pod.Name, namespace)).To(Equal(identifier))

		By("Waiting for the pod's egress load to fail")
		waitForEgressLoadFailure(checkPod.Name, pod.Name, identifier)

		By("Removing the fault while the pod is retrying")
		_, err := hostShell(checkPod.Name, fmt.Sprintf("rmdir %s", faultPath))
		Expect(err).ToNot(HaveOccurred())

		By("Waiting for the Job to complete")
		Eventually(func() (int32, error) {
			current := &batchv1.Job{}
			err := fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(job), current)
			return current.Status.Succeeded, err
		}, 3*time.Minute, fwutils.ProbeInterval).Should(BeNumerically(">=", 1))

		By("Deleting the Job and checking that no pins remain for the identifier")
		deleteJobAndWait(job)
		expectNoIdentifierPins(checkPod.Name, identifier)
	})
})

// No "-": the pod identifier must be unique to this Job's pods.
const pinFailJobName = "pinfail"

// createPinFailJob creates the Job and registers its deletion as cleanup.
func createPinFailJob(node string) *batchv1.Job {
	job := buildPinFailJob(node)
	Expect(fw.K8sClient.Create(ctx, job)).To(Succeed())
	DeferCleanup(func() { deleteJobAndWait(job) })
	return job
}

func buildPinFailJob(node string) *batchv1.Job {
	backoffLimit := int32(0)
	// Not 0: with a zero grace period the API server removes the pod before the
	// kubelet has torn it down, so the pod being gone wouldn't mean CNI DEL ran.
	grace := int64(1)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: pinFailJobName, Namespace: namespace},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "pinfail"}},
				Spec: v1.PodSpec{
					NodeName:                      node,
					RestartPolicy:                 v1.RestartPolicyNever,
					TerminationGracePeriodSeconds: &grace,
					Containers: []v1.Container{{
						Name: "c", Image: "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
						Command: []string{"sleep", "5"},
					}},
				},
			},
		},
	}
}

func waitForJobPod(job *batchv1.Job) *v1.Pod {
	var pod v1.Pod
	Eventually(func() (int, error) {
		pods := &v1.PodList{}
		err := fw.K8sClient.List(ctx, pods, client.InNamespace(namespace), client.MatchingLabels{"job-name": job.Name})
		if err == nil && len(pods.Items) > 0 {
			pod = pods.Items[0]
		}
		return len(pods.Items), err
	}, time.Minute, fwutils.ProbeInterval).Should(BeNumerically(">", 0))
	return &pod
}

func deleteJobAndWait(job *batchv1.Job) {
	Expect(client.IgnoreNotFound(fw.K8sClient.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationForeground)))).To(Succeed())
	Eventually(func() (int, error) {
		pods := &v1.PodList{}
		err := fw.K8sClient.List(ctx, pods, client.InNamespace(namespace), client.MatchingLabels{"job-name": job.Name})
		return len(pods.Items), err
	}, 3*time.Minute, fwutils.ProbeInterval).Should(BeZero())
	// Foreground deletion removes the Job itself after its pods; both specs reuse its name.
	Eventually(func() bool {
		return apierrors.IsNotFound(fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(job), &batchv1.Job{}))
	}, time.Minute, fwutils.ProbeInterval).Should(BeTrue())
}

// agentNode returns a schedulable node with a ready aws-node pod, so the
// network policy agent runs there.
func agentNode() string {
	pods := &v1.PodList{}
	Expect(fw.K8sClient.List(ctx, pods, client.InNamespace("kube-system"),
		client.MatchingLabels{"k8s-app": "aws-node"})).To(Succeed())
	for _, p := range pods.Items {
		ready := false
		for _, c := range p.Status.Conditions {
			ready = ready || (c.Type == v1.PodReady && c.Status == v1.ConditionTrue)
		}
		if !ready || p.Spec.NodeName == "" {
			continue
		}
		n := &v1.Node{}
		if fw.K8sClient.Get(ctx, client.ObjectKey{Name: p.Spec.NodeName}, n) == nil && !n.Spec.Unschedulable {
			return n.Name
		}
	}
	Fail("no schedulable node with a ready aws-node pod")
	return ""
}

// waitForEgressLoadFailure waits for the agent to log that attaching podName
// failed on the identifier's egress map. The pod's sandbox events only say
// that network policy setup failed, so they can't tell this fault from others.
func waitForEgressLoadFailure(checkPodName, podName, identifier string) {
	attachFailed := fmt.Sprintf("Attaching eBPF probe failed for pod: %s namespace: %s,", podName, namespace)
	egressMap := identifier + "_egress_map"
	Eventually(func() (string, error) {
		// A missing log is an exec error, not output that looks like a match.
		out, err := fw.PodManager.ExecInPod(namespace, checkPodName, []string{"sh", "-c",
			fmt.Sprintf("test -r %[2]s || exit 1; grep -F %[1]s %[2]s | grep -F %[3]s || true",
				shellQuote(attachFailed), npaLog, shellQuote(egressMap))})
		if err == nil && strings.Contains(out, "STDERR:") {
			err = fmt.Errorf("reading the agent log: %s", out)
		}
		return out, err
	}, 2*time.Minute, fwutils.ProbeInterval).ShouldNot(BeEmpty(),
		"the agent never logged the egress load failure for %s", podName)
}

// expectNoIdentifierPins waits for the identifier's pins to go, then checks
// none come back. CNI DEL can still be running after the pod object is gone.
func expectNoIdentifierPins(checkPodName, identifier string) {
	pins := func() ([]string, error) { return identifierPins(checkPodName, identifier) }
	Eventually(pins, time.Minute, fwutils.ProbeInterval).Should(BeEmpty())
	Consistently(pins, 15*time.Second, fwutils.ProbeInterval).Should(BeEmpty())
}

// identifierPins lists the program and map pins named after identifier. It
// skips directories, so the fault itself isn't counted.
func identifierPins(checkPodName, identifier string) ([]string, error) {
	out, err := hostShell(checkPodName, fmt.Sprintf("ls -p %s %s",
		utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, utils.BPF_MAPS_PIN_PATH_DIRECTORY))
	if err != nil {
		return nil, err
	}
	var pins []string
	for _, name := range strings.Fields(out) {
		if strings.HasPrefix(name, identifier+"_") && !strings.HasSuffix(name, "/") {
			pins = append(pins, name)
		}
	}
	return pins, nil
}

// hostShell runs script in the host's root through the check pod.
func hostShell(checkPodName, script string) (string, error) {
	return fw.PodManager.ExecInPod(namespace, checkPodName, []string{"chroot", "/host", "sh", "-c", script})
}
