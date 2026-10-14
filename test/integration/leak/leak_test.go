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
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	churnDuration = 20 * time.Minute
	cronSchedule  = "*/1 * * * *" // every minute
	podsPerJob    = 100
	pollInterval  = 10 * time.Second
	cronJobName   = "churn-generator"
	agentLogPath  = "/var/log/aws-routed-eni/network-policy-agent.log"
	// Logged once per completed egress probe attach, so a pod appearing twice has
	// been attached twice.
	egressAttachMarker = "Successfully attached Egress TC probe for pod: "
)

var _ = Describe("BPF Probe Leak Under Pod Churn", Ordered, func() {
	var (
		networkPolicy     *network.NetworkPolicy
		defaultDenyPolicy *network.NetworkPolicy
		cronJob           *batchv1.CronJob
		workerNodes       []v1.Node
		// node name -> check pod name / pre-churn state, so the assertions below
		// can compare against the node as it was before this run.
		checkPods      map[string]string
		baselineIdents map[string]map[string]bool
		logOffsets     map[string]int
	)

	It("should not leak BPF progs/maps after high pod churn with network policy", func() {
		By("Getting worker nodes and labeling them for churn scheduling")
		var err error
		workerNodes, err = getWorkerNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(workerNodes)).To(BeNumerically(">=", 1))
		lo.ForEach(workerNodes, func(node v1.Node, _ int) {
			Expect(setNodeTestLabel(node.Name, true)).ToNot(HaveOccurred())
		})

		By("Deploying node-shell check pods and snapshotting pre-churn BPF state")
		// The suite has to tolerate a node that is already dirty. Leaked pins never
		// self-reclaim, so any earlier run's leftovers would otherwise fail this
		// test forever, no matter how correct the agent is. Snapshot first and
		// assert on the delta.
		checkPods = map[string]string{}
		baselineIdents = map[string]map[string]bool{}
		logOffsets = map[string]int{}
		for _, node := range workerNodes {
			checkPodName := fmt.Sprintf("leak-check-%s", node.Name)
			checkPod := buildNodeCheckPod(checkPodName, node.Name)
			_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
			})
			checkPods[node.Name] = checkPodName
			baselineIdents[node.Name] = churnIdentifiersOnNode(checkPodName)
			logOffsets[node.Name] = agentLogLineCount(checkPodName)
		}

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
		// if no successful run of job in 3 minutes we will bail.
		waitForChurnOrBail(3 * time.Minute)

		By("Deleting the CronJob and waiting for pods to terminate")
		err = fw.K8sClient.Delete(ctx, cronJob)
		Expect(err).ToNot(HaveOccurred())
		// Wait for all churn pods to terminate
		time.Sleep(2 * time.Minute)

		for _, node := range workerNodes {
			checkPodName := checkPods[node.Name]

			By(fmt.Sprintf("Checking for newly leaked BPF pins on node %s", node.Name))
			assertNoNewChurnLeaks(baselineIdents[node.Name], churnIdentifiersOnNode(checkPodName), node.Name)

			By(fmt.Sprintf("Checking for ghost re-attaches on node %s", node.Name))
			assertNoGhostReattaches(checkPodName, node.Name, logOffsets[node.Name])
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
			if err := setNodeTestLabel(node.Name, false); err != nil {
				AddReportEntry(fmt.Sprintf("failed to remove test-node label from %s: %v", node.Name, err))
			}
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
			Name:      cronJobName,
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

// setNodeTestLabel adds or removes the churn scheduling label on a node.
//
// It re-reads the node inside a conflict retry rather than updating a copy from
// an earlier List. Node objects are rewritten constantly by their kubelet, so a
// List-then-Update races even seconds later -- and in the cleanup path the copy
// is tens of minutes stale, which silently left the label behind on every node.
func setNodeTestLabel(nodeName string, present bool) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node := &v1.Node{}
		if err := fw.K8sClient.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
			return err
		}
		_, has := node.Labels["test-node"]
		if has == present {
			return nil
		}
		if present {
			if node.Labels == nil {
				node.Labels = map[string]string{}
			}
			node.Labels["test-node"] = "true"
		} else {
			delete(node.Labels, "test-node")
		}
		return fw.K8sClient.Update(ctx, node)
	})
}

// churnIdentifiersOnNode returns the set of podIdentifiers belonging to churn
// pods that currently have pinned BPF programs or maps on the node.
func churnIdentifiersOnNode(checkPodName string) map[string]bool {
	output, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred())

	idents := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, cronJobName) {
			continue
		}
		idents[churnIdentifierFromLine(line)] = true
	}
	return idents
}

// churnIdentifierFromLine pulls the "churn-generator-<generation>" token out of a
// loaded-ebpfdata line so pins for the same identifier collapse to one entry
// regardless of direction or whether it is a program or a map.
func churnIdentifierFromLine(line string) string {
	for _, field := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '/' || r == ':'
	}) {
		if strings.HasPrefix(field, cronJobName) {
			return field
		}
	}
	return line
}

// assertNoNewChurnLeaks fails only on identifiers that were not already pinned
// before this run. Pre-existing leaks are reported, not failed on: they cannot
// self-reclaim, so failing on them would make the suite permanently red on any
// node that ever ran an affected build.
func assertNoNewChurnLeaks(baseline, post map[string]bool, nodeName string) {
	var leaked []string
	for ident := range post {
		if !baseline[ident] {
			leaked = append(leaked, ident)
		}
	}
	if len(baseline) > 0 {
		AddReportEntry(fmt.Sprintf("node %s carried %d pre-existing leaked churn identifier(s) into this run; not counted against it",
			nodeName, len(baseline)))
	}
	Expect(leaked).To(BeEmpty(),
		fmt.Sprintf("node %s leaked %d new churn identifier(s) during this run: %v", nodeName, len(leaked), leaked))
}

// agentLogLineCount records how long the agent log already is, so the ghost
// assertion can ignore everything an earlier run wrote.
func agentLogLineCount(checkPodName string) int {
	output, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/bin/sh", "-c",
			"wc -l < " + agentLogPath + " 2>/dev/null || echo 0"})
	Expect(err).ToNot(HaveOccurred())

	var lines int
	// A missing or empty log is fine; it just means no offset to skip.
	fmt.Sscanf(strings.TrimSpace(output), "%d", &lines)
	return lines
}

// assertNoGhostReattaches checks the invariant that each churn pod completes at
// most one attach. A pod attached twice is the ghost re-add: the second attach
// re-inserts it into the shared progFD -> pods set after its delete already
// removed it, which keeps isProgFdShared true for the last pod of the identifier
// so its programs and maps are never unpinned.
//
// This is independent of pin scanning, so unlike assertNoNewChurnLeaks it is
// unaffected by state left behind on the node.
func assertNoGhostReattaches(checkPodName, nodeName string, logOffset int) {
	// tail -n +N skips lines written before this run, which avoids having to
	// parse the agent's JSON timestamps.
	script := fmt.Sprintf(
		"tail -n +%d %s 2>/dev/null | grep -F %q | grep -F %q "+
			"| sed -e 's/.*for pod: //' -e 's/ in namespace.*//' | sort | uniq -d",
		logOffset+1, agentLogPath, egressAttachMarker, cronJobName)

	output, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/bin/sh", "-c", script})
	Expect(err).ToNot(HaveOccurred())

	ghosts := lo.Filter(strings.Split(strings.TrimSpace(output), "\n"), func(s string, _ int) bool {
		return strings.TrimSpace(s) != ""
	})
	Expect(ghosts).To(BeEmpty(),
		fmt.Sprintf("node %s: %d churn pod(s) completed more than one attach (ghost re-add): %v",
			nodeName, len(ghosts), ghosts))
}

func waitForChurnOrBail(jobStuckTimeout time.Duration) {
	deadline := time.Now().Add(churnDuration)
	start := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		cj := &batchv1.CronJob{}
		Expect(fw.K8sClient.Get(ctx, client.ObjectKey{
			Name:      cronJobName,
			Namespace: namespace,
		}, cj)).ToNot(HaveOccurred())

		if cj.Status.LastSuccessfulTime != nil {
			if time.Since(cj.Status.LastSuccessfulTime.Time) > jobStuckTimeout {
				Fail(fmt.Sprintf("CronJob last succeeded %v ago, stuck for > %v, bailing early",
					time.Since(cj.Status.LastSuccessfulTime.Time), jobStuckTimeout))
			}
			continue
		} else if time.Since(start) > jobStuckTimeout {
			Fail(fmt.Sprintf("CronJob has never succeeded after %v, bailing early", jobStuckTimeout))
		}
	}
}
