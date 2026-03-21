package leak

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	churnDuration     = 10 * time.Minute
	cronSchedule      = "*/1 * * * *" // every minute
	podsPerJob        = 100
	checkPodNamespace = "kube-system"
)

var _ = Describe("BPF Probe Leak Under Pod Churn", Ordered, func() {
	var (
		networkPolicy *network.NetworkPolicy
		cronJob       *batchv1.CronJob
	)

	It("should not leak BPF progs/maps after high pod churn with network policy", func() {
		By("Creating a network policy targeting churn pods")
		networkPolicy = buildChurnNetworkPolicy()
		err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)
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
		nodes, err := getWorkerNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodes)).To(BeNumerically(">=", 1))

		for _, node := range nodes {
			checkPodName := fmt.Sprintf("leak-check-%s", node.Name)
			checkPod := buildNodeCheckPod(checkPodName, node.Name)

			_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())

			By(fmt.Sprintf("Checking BPF programs on node %s", node.Name))
			progsOutput, err := fw.PodManager.ExecInPod(checkPodNamespace, checkPodName,
				[]string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--",
					"/opt/cni/bin/aws-eks-na-cli", "ebpf", "progs"})
			Expect(err).ToNot(HaveOccurred())

			By(fmt.Sprintf("Checking BPF maps on node %s", node.Name))
			mapsOutput, err := fw.PodManager.ExecInPod(checkPodNamespace, checkPodName,
				[]string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--",
					"/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
			Expect(err).ToNot(HaveOccurred())

			By(fmt.Sprintf("Checking pinned BPF paths on node %s", node.Name))
			pinnedProgs, err := fw.PodManager.ExecInPod(checkPodNamespace, checkPodName,
				[]string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--",
					"ls", "/sys/fs/bpf/globals/aws/programs/"})
			Expect(err).ToNot(HaveOccurred())

			pinnedMaps, err := fw.PodManager.ExecInPod(checkPodNamespace, checkPodName,
				[]string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--",
					"ls", "/sys/fs/bpf/globals/aws/maps/"})
			Expect(err).ToNot(HaveOccurred())

			// No churn pod BPF artifacts should remain
			// Only system pods (coredns, aws-node, etc.) should have pinned progs/maps
			assertNoChurnPodLeaks(progsOutput, node.Name)
			assertNoChurnPodLeaks(mapsOutput, node.Name)
			assertNoChurnPodLeaks(pinnedProgs, node.Name)
			assertNoChurnPodLeaks(pinnedMaps, node.Name)

			// Cleanup check pod
			err = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
			Expect(err).ToNot(HaveOccurred())
		}
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
	})
})

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
					Name:    "nsenter",
					Image:   "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
					Command: []string{"sleep", "3600"},
					SecurityContext: &v1.SecurityContext{
						Privileged: &privileged,
					},
				},
			},
		},
	}
}

func getWorkerNodes() ([]v1.Node, error) {
	nodeList := &v1.NodeList{}
	err := fw.K8sClient.List(ctx, nodeList)
	if err != nil {
		return nil, err
	}
	var workers []v1.Node
	for _, node := range nodeList.Items {
		// Skip control plane nodes
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			continue
		}
		workers = append(workers, node)
	}
	return workers, nil
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
