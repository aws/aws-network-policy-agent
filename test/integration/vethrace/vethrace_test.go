package vethrace

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// The race fires under concurrent CNI ADD. parallelism controls the
	// concurrency of each "wave", completions controls total samples.
	// 50 x 1000 = 20 waves, runtime ~10-13 min, expected ~10 hits on a
	// known-buggy build at the issue's ~1% steady-state failure rate.
	completions  = 1000
	parallelism  = 50
	podSleep     = 5 * time.Second
	churnTimeout = 15 * time.Minute
	pollInterval = 5 * time.Second
	jobName      = "vethrace-churn"

	// Substring of the kubelet FailedCreatePodSandBox event message that
	// only appears when the CNI plugin's call to NPA fails. The full
	// kubelet event surface is:
	//   Failed to create pod sandbox: rpc error: code = Unknown desc =
	//   failed to setup network for sandbox "<id>": plugin type="aws-cni"
	//   name="aws-cni" failed (add): add cmd: failed to setup network policy
	// (see aws/aws-network-policy-agent#569).
	cniNetworkPolicyFailMsg = "failed to setup network policy"
)

var _ = Describe("Veth Race Under Pod Churn", Ordered, func() {
	var (
		networkPolicy     *network.NetworkPolicy
		defaultDenyPolicy *network.NetworkPolicy
		job               *batchv1.Job
		workerNodes       []v1.Node
	)

	// This test reproduces aws/aws-network-policy-agent#569 (NPA returns
	// transient "Link not found" during pod CNI ADD). The network policies
	// force every churn pod through NPA's GetHostVethName path; the Job
	// bursts enough concurrent creates to hit the race window. The fix in
	// this PR retries the netlink lookup inside NPA, so on a fixed build
	// no churn pod should produce a "failed to setup network policy"
	// sandbox event. On an unfixed build the same workload reproduces it.
	It("should not produce CNI network-policy failures during high pod churn", func() {
		By("Getting worker nodes and labeling them for churn scheduling")
		var err error
		workerNodes, err = getWorkerNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(workerNodes)).To(BeNumerically(">=", 1))
		lo.ForEach(workerNodes, func(node v1.Node, _ int) {
			node.Labels["test-node"] = "true"
			err = fw.K8sClient.Update(ctx, &node)
			Expect(err).ToNot(HaveOccurred())
		})

		By("Creating a default deny network policy")
		defaultDenyPolicy = buildDefaultDenyNetworkPolicy()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, defaultDenyPolicy)).ToNot(HaveOccurred())

		By("Creating a network policy targeting churn pods")
		networkPolicy = buildChurnNetworkPolicy()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).ToNot(HaveOccurred())

		By("Recording the event baseline before churn starts")
		startTime := metav1.Now()

		By(fmt.Sprintf("Creating a Job that bursts %d concurrent short-lived pods, %d total",
			parallelism, completions))
		job = buildChurnJob()
		Expect(fw.K8sClient.Create(ctx, job)).ToNot(HaveOccurred())

		By(fmt.Sprintf("Waiting up to %v for the Job to complete %d pods", churnTimeout, completions))
		waitForJobCompletion()

		By("Asserting no churn pod hit the NPA veth race")
		failures := findCniNetworkPolicyFailures(startTime)
		Expect(failures).To(BeEmpty(),
			"detected FailedCreatePodSandBox events with NPA veth race signature; "+
				"this PR's retry path should absorb them")
	})

	AfterAll(func() {
		// Foreground propagation: the API server blocks the Job delete
		// until all dependent pods are gone. Without this the test can
		// exit before the garbage collector drains the (up to completions)
		// finished pods, leaving them in the test namespace.
		if job != nil {
			propagation := metav1.DeletePropagationForeground
			Expect(fw.K8sClient.Delete(ctx, job, &client.DeleteOptions{
				PropagationPolicy: &propagation,
			})).To(Or(Succeed(), MatchError(ContainSubstring("not found"))))
			// Belt-and-suspenders: any pods orphaned by an interrupted
			// delete still get reaped here. List + delete is namespaced
			// and label-scoped, so no risk to anything outside the test.
			pods := &v1.PodList{}
			if err := fw.K8sClient.List(ctx, pods,
				client.InNamespace(namespace),
				client.MatchingLabels{"app": "churn-pod"}); err == nil {
				for i := range pods.Items {
					fw.K8sClient.Delete(ctx, &pods.Items[i])
				}
			}
		}
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		if defaultDenyPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, defaultDenyPolicy)
		}
		lo.ForEach(workerNodes, func(node v1.Node, _ int) {
			delete(node.Labels, "test-node")
			fw.K8sClient.Update(ctx, &node)
		})
	})
})

func buildDefaultDenyNetworkPolicy() *network.NetworkPolicy {
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name("default-deny-all").
		SetPolicyType(true, true).
		Build()
}

func buildChurnNetworkPolicy() *network.NetworkPolicy {
	// Targeted policy on the churn label forces NPA into every CNI ADD
	// path for these pods, which is what makes the race reproducible.
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name("churn-pod-policy").
		PodSelector("app", "churn-pod").
		SetPolicyType(true, true).
		Build()
}

func buildChurnJob() *batchv1.Job {
	par := int32(parallelism)
	comp := int32(completions)
	backoffLimit := int32(0)
	ttl := int32(30)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			Parallelism:             &par,
			Completions:             &comp,
			BackoffLimit:            &backoffLimit,
			TTLSecondsAfterFinished: &ttl,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "churn-pod"},
				},
				Spec: v1.PodSpec{
					NodeSelector: map[string]string{
						"test-node": "true",
					},
					RestartPolicy: v1.RestartPolicyNever,
					Containers: []v1.Container{
						{
							Name:    "churn",
							Image:   "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
							Command: []string{"sleep", fmt.Sprintf("%d", int(podSleep.Seconds()))},
							Resources: v1.ResourceRequirements{
								Requests: v1.ResourceList{
									v1.ResourceCPU:    resource.MustParse("1m"),
									v1.ResourceMemory: resource.MustParse("4Mi"),
								},
							},
						},
					},
				},
			},
		},
	}
}

func getWorkerNodes() ([]v1.Node, error) {
	nodeList := &v1.NodeList{}
	err := fw.K8sClient.List(ctx, nodeList, client.MatchingLabels{
		"kubernetes.io/os": "linux",
	})
	if err != nil {
		return nil, err
	}
	return lo.Filter(nodeList.Items, func(node v1.Node, index int) bool {
		return strings.Contains(node.Status.NodeInfo.OSImage, "Amazon Linux 2023")
	}), nil
}

// findCniNetworkPolicyFailures returns a slice of human-readable lines
// describing each FailedCreatePodSandBox event in the test namespace that
// was emitted at or after startTime and carries the NPA veth race
// signature. Empty slice means the workload completed cleanly.
func findCniNetworkPolicyFailures(startTime metav1.Time) []string {
	events := &v1.EventList{}
	Expect(fw.K8sClient.List(ctx, events, client.InNamespace(namespace))).ToNot(HaveOccurred())

	var hits []string
	for _, e := range events.Items {
		if e.Reason != "FailedCreatePodSandBox" {
			continue
		}
		if e.LastTimestamp.Before(&startTime) {
			continue
		}
		if !strings.Contains(e.Message, cniNetworkPolicyFailMsg) {
			continue
		}
		hits = append(hits, fmt.Sprintf("pod=%s reason=%s msg=%s",
			e.InvolvedObject.Name, e.Reason, e.Message))
	}
	return hits
}

// waitForJobCompletion polls the churn Job until either the desired number
// of completions is reached or the timeout is hit. Polling is sized so the
// race window between batches stays exercised continuously.
func waitForJobCompletion() {
	err := wait.PollUntilContextTimeout(ctx, pollInterval, churnTimeout, true, func(context.Context) (bool, error) {
		j := &batchv1.Job{}
		if err := fw.K8sClient.Get(ctx, client.ObjectKey{Name: jobName, Namespace: namespace}, j); err != nil {
			return false, err
		}
		return j.Status.Succeeded >= int32(completions), nil
	})
	Expect(err).ToNot(HaveOccurred(),
		fmt.Sprintf("churn Job did not reach %d successful pods within %v", completions, churnTimeout))
}
