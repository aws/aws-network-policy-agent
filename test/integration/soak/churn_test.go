package soak

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// churnLabel is the label selecting churned pods. A NetworkPolicy must select this
// label so NPA programs per-pod BPF for them — without which the leak gate
// compares counts nothing moves and the gate is vacuous.
const churnLabel = "npa-soak-churn"

// churnCronJobName is the per-node CronJob name prefix. One CronJob per node so
// churn distributes across all nodes and every agent's per-pod programming path is
// exercised.
const churnCronJobName = "npa-soak-churn"

// deployChurnCronJobs creates one CronJob per node that spawns short-lived pods
// every minute. The pods carry the churnLabel and are selected by the soak's deny
// policy, so NPA programs per-pod BPF for each. When they terminate, their
// programs and maps must be cleaned up; the leak gate asserts they actually are.
func deployChurnCronJobs(nodes []v1.Node) []*batchv1.CronJob {
	var jobs []*batchv1.CronJob
	for i, node := range nodes {
		job := buildChurnCronJob(fmt.Sprintf("%s-%d", churnCronJobName, i), node.Name)
		if err := fw.K8sClient.Create(ctx, job); err != nil {
			GinkgoWriter.Printf("churn: create cronjob on %s failed: %v\n", node.Name, err)
			continue
		}
		jobs = append(jobs, job)
	}
	return jobs
}

// deleteChurnCronJobs tears down the churn CronJobs and waits briefly for their
// spawned pods to drain. This establishes the quiet window the leak gate needs.
func deleteChurnCronJobs(jobs []*batchv1.CronJob) {
	for _, job := range jobs {
		if err := fw.K8sClient.Delete(ctx, job); err != nil {
			GinkgoWriter.Printf("churn: delete cronjob %s: %v\n", job.Name, err)
		}
	}
	// Give spawned pods time to terminate so the BPF cleanup path runs.
	time.Sleep(90 * time.Second)
}

// assertChurnActive blocks until at least one churn CronJob has run successfully,
// proving the churn driver actually produces pods before the leak gate relies on
// it. Without this, a CronJob that silently fails to schedule (image pull, node
// pressure, selector mismatch) would leave the leak gate comparing an unchurned
// baseline to an unchurned end and passing green. Runs in BeforeAll on the main
// goroutine, so it fails the suite via Expect.
func assertChurnActive(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		jobs := &batchv1.CronJobList{}
		if err := fw.K8sClient.List(ctx, jobs, client.InNamespace(namespace)); err == nil {
			for _, j := range jobs.Items {
				if j.Status.LastSuccessfulTime != nil {
					GinkgoWriter.Printf("churn: confirmed active (last success %s)\n",
						j.Status.LastSuccessfulTime.Time.Format(time.RFC3339))
					return
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
	Fail(fmt.Sprintf("churn driver produced no successful pods within %s; the leak "+
		"gate would be vacuous. Check CronJob scheduling (image pull, node selector, "+
		"resource pressure).", timeout))
}

// buildChurnCronJob creates a CronJob that spawns short-lived pods on the target
// node every minute. Pods carry the churnLabel so the soak's NetworkPolicy selects
// them, causing NPA to program per-pod BPF.
func buildChurnCronJob(name, nodeName string) *batchv1.CronJob {
	parallelism := int32(10)
	completions := int32(10)
	backoffLimit := int32(0)
	ttl := int32(30)
	successfulHistory := int32(0)
	failedHistory := int32(1)

	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: batchv1.CronJobSpec{
			Schedule:                   "*/1 * * * *",
			SuccessfulJobsHistoryLimit: &successfulHistory,
			FailedJobsHistoryLimit:     &failedHistory,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Parallelism:             &parallelism,
					Completions:             &completions,
					BackoffLimit:            &backoffLimit,
					TTLSecondsAfterFinished: &ttl,
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{"app": churnLabel},
						},
						Spec: v1.PodSpec{
							NodeSelector:  map[string]string{"kubernetes.io/hostname": nodeName},
							RestartPolicy: v1.RestartPolicyNever,
							Containers: []v1.Container{{
								Name:    "churn",
								Image:   driverImage,
								Command: []string{"sleep", "5"},
								Resources: v1.ResourceRequirements{
									Requests: v1.ResourceList{
										v1.ResourceCPU:    resource.MustParse("1m"),
										v1.ResourceMemory: resource.MustParse("4Mi"),
									},
								},
							}},
						},
					},
				},
			},
		},
	}
}
