package soak

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// buildNginxPod is the policy target. The resource request keeps it from being the
// first eviction victim under churn; a dead server would make BLOCKED probes pass
// for the wrong reason.
func buildNginxPod(app string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace, Labels: map[string]string{"app": app}},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name: "nginx", Image: nginxImage,
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
				Resources: v1.ResourceRequirements{
					Requests: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("10m"),
						v1.ResourceMemory: resource.MustParse("32Mi"),
					},
				},
			}},
		},
	}
}

// buildClientPod is a long-lived pod the probe execs a python TCP connect from.
func buildClientPod(app, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace, Labels: map[string]string{"app": app}},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name: "client", Image: "public.ecr.aws/docker/library/python:3.11-slim",
				Command: []string{"sleep", "infinity"},
			}},
		},
	}
}

// buildIngressDeny denies all ingress to pods matching app=label, forcing NPA to
// program per-pod BPF and enforce.
func buildIngressDeny(name, label string) *network.NetworkPolicy {
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name(name).
		PodSelector("app", label).
		SetPolicyTypes([]network.PolicyType{network.PolicyTypeIngress}).
		Build()
}

// buildChurnCronJob spawns short-lived, policy-selected pods every minute on the
// target node, so NPA repeatedly programs and tears down per-pod BPF state.
func buildChurnCronJob(nodeName string) *batchv1.CronJob {
	parallelism := int32(10)
	completions := int32(10)
	backoffLimit := int32(0)
	ttl := int32(30)
	successHistory := int32(0)
	failHistory := int32(1)

	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "np-soak-churn", Namespace: namespace},
		Spec: batchv1.CronJobSpec{
			Schedule: "*/1 * * * *",
			// Forbid overlapping runs so an overrunning job can't stack and amplify
			// churn, which would fail drain-to-baseline on outstanding jobs, not a leak.
			ConcurrencyPolicy:          batchv1.ForbidConcurrent,
			SuccessfulJobsHistoryLimit: &successHistory,
			FailedJobsHistoryLimit:     &failHistory,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Parallelism:             &parallelism,
					Completions:             &completions,
					BackoffLimit:            &backoffLimit,
					TTLSecondsAfterFinished: &ttl,
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": churnApp}},
						Spec: v1.PodSpec{
							NodeName:      nodeName,
							RestartPolicy: v1.RestartPolicyNever,
							Containers: []v1.Container{{
								Name:    "churn",
								Image:   "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
								Command: []string{"sleep", "10"},
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

// churnRanSuccessfully reports whether the churn CronJob has had at least one
// successful run, proving pods were actually created (and NPA programmed them).
func churnRanSuccessfully() bool {
	cj := &batchv1.CronJob{}
	if err := fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "np-soak-churn"}, cj); err != nil {
		return false
	}
	return cj.Status.LastSuccessfulTime != nil
}

// execConnect returns "CONNECTED" or "BLOCKED". Only those exact tokens count as a
// verdict; anything else is a broken probe (ExecInPod appends stderr to stdout
// without erroring, so a failed script must not be read as BLOCKED) and is retried,
// then failed rather than returned as a bogus verdict.
func execConnect(podName, ip string, port int) string {
	script := fmt.Sprintf(`import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(3)
try:
 s.connect(('%s',%d));print('CONNECTED')
except Exception:
 print('BLOCKED')
finally:
 s.close()`, ip, port)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		out, err := fw.PodManager.ExecInPod(namespace, podName, []string{"python3", "-c", script})
		if err == nil {
			switch strings.TrimSpace(out) {
			case "CONNECTED":
				return "CONNECTED"
			case "BLOCKED":
				return "BLOCKED"
			default:
				err = fmt.Errorf("unexpected probe output (not a clean verdict): %q", out)
			}
		}
		lastErr = err
		GinkgoWriter.Printf("execConnect: probe error (attempt %d): %v\n", attempt+1, err)
		time.Sleep(2 * time.Second)
	}
	Expect(lastErr).ToNot(HaveOccurred(), "execConnect failed after retries (probe infra, not a verdict)")
	return "BLOCKED" // unreachable; Expect above fails the spec
}

// bpfCounts returns the number of loaded BPF programs and per-pod maps on a node.
func bpfCounts(nodeName string) (progs, maps int) {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, created)

	out, err := fw.PodManager.ExecInPod(namespace, created.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred(), "failed to dump bpf state")

	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata")
	return len(state.ProgIDs), len(state.MapIDs)
}
