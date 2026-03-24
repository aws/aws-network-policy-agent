package leak

import (
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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	churnDuration     = 20 * time.Minute
	cronSchedule      = "*/1 * * * *" // every minute
	podsPerJob        = 100
	checkPodNamespace = "kube-system"
)

var _ = Describe("BPF Probe Leak Under Pod Churn", Ordered, func() {
	var (
		networkPolicy     *network.NetworkPolicy
		defaultDenyPolicy *network.NetworkPolicy
		cronJob           *batchv1.CronJob
		workerNodes       []v1.Node
	)

	It("should not leak BPF progs/maps after high pod churn with network policy", func() {
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
		err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, defaultDenyPolicy)
		Expect(err).ToNot(HaveOccurred())

		By("Creating a network policy targeting churn pods")
		networkPolicy = buildChurnNetworkPolicy()
		err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
		Expect(err).ToNot(HaveOccurred())

		By("Creating a CronJob that spawns 100 short-lived pods per minute")
		cronJob = buildChurnCronJob()
		err = fw.K8sClient.Create(ctx, cronJob)
		Expect(err).ToNot(HaveOccurred())

		By(fmt.Sprintf("Waiting %v for pod churn to complete", churnDuration))
		time.Sleep(churnDuration)

		By("Deleting the CronJob and waiting for pods to terminate")
		err = fw.K8sClient.Delete(ctx, cronJob)
		Expect(err).ToNot(HaveOccurred())
		// Wait for all churn pods to terminate
		time.Sleep(2 * time.Minute)

		By("Deploying node-shell check pods on each node to verify no leaked BPF state")
		for _, node := range workerNodes {
			checkPodName := fmt.Sprintf("leak-check-%s", node.Name)
			checkPod := buildNodeCheckPod(checkPodName, node.Name)

			_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
			})

			By(fmt.Sprintf("Checking BPF maps on node %s", node.Name))
			mapsOutput, err := fw.PodManager.ExecInPod(checkPodNamespace, checkPodName,
				[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
			Expect(err).ToNot(HaveOccurred())

			// No churn pod BPF artifacts should remain
			// Only system pods (coredns, aws-node, etc.) should have pinned progs/maps
			assertNoChurnPodLeaks(mapsOutput, node.Name)
		}
	})

	AfterAll(func() {
		if cronJob != nil {
			fw.K8sClient.Delete(ctx, cronJob)
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
	// Deny all ingress and egress for churn pods — forces eBPF probe attachment
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name("churn-pod-policy").
		PodSelector("app", "churn-pod").
		SetPolicyType(true, true).
		Build()
}

func buildChurnCronJob() *batchv1.CronJob {
	parallelism := int32(podsPerJob)
	completions := int32(podsPerJob)
	backoffLimit := int32(0)
	ttl := int32(30) // cleanup finished jobs after 30s
	successfulJobsHistory := int32(0)
	failedJobsHistory := int32(1)

	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "churn-generator",
			Namespace: namespace,
		},
		Spec: batchv1.CronJobSpec{
			Schedule:                   cronSchedule,
			SuccessfulJobsHistoryLimit: &successfulJobsHistory,
			FailedJobsHistoryLimit:     &failedJobsHistory,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Parallelism:             &parallelism,
					Completions:             &completions,
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
									Command: []string{"sleep", "5"},
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
			},
		},
	}
}

func buildNodeCheckPod(name, nodeName string) *v1.Pod {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: checkPodNamespace,
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
					Command: []string{"sleep", "3600"},
					SecurityContext: &v1.SecurityContext{
						Privileged: &privileged,
					},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
							ReadOnly:  true,
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

// assertNoChurnPodLeaks checks that no BPF artifacts from churn pods remain.
// Churn pods have identifier containing "churn-generator" in their BPF pin paths.
func assertNoChurnPodLeaks(output, nodeName string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		Expect(line).ToNot(ContainSubstring("churn"),
			fmt.Sprintf("Leaked BPF artifact found on node %s: %s", nodeName, line))
	}
}
