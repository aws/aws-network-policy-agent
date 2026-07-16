package soak

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// buildNginxDeployment is the policy target, wrapped in a 1-replica Deployment
// rather than a bare Pod. Two reasons:
//   - Ownership: EKS network policy is documented to apply only to pods with an
//     ownerReference (part of a Deployment/ReplicaSet), so a bare-Pod target rests
//     on undocumented behavior; a Deployment keeps the core assertion inside support.
//   - Distinct pod identifier: NPA derives a pod's identity by stripping the last
//     "-<segment>" of its name (GetPodIdentifier). A bare pod named "np-soak-server"
//     collapses to identifier "np-soak" — colliding with a bare "np-soak-client".
//     A Deployment pod is "np-soak-server-<rs>-<pod>", yielding a distinct
//     "np-soak-server-<rs>" identifier, so enforcement can't be confused with a
//     similarly-named neighbor.
//
// The resource request keeps it from being the first eviction victim under churn;
// a dead server would make BLOCKED probes pass for the wrong reason.
func buildNginxDeployment(app string) *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": app}},
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
			},
		},
	}
}

// buildClientPod is a long-lived pod the probe execs a bash /dev/tcp connect from.
// It reuses the churn image (amazonlinux:2023-minimal) rather than pulling a python
// runtime just to open one socket — bash's /dev/tcp does the same with no extra
// dependency, and it drops one hardcoded public-ECR image. `sleep infinity` (GNU
// coreutils is present) keeps it up for arbitrarily long soaks; the small resource
// request keeps it off the eviction shortlist under sustained same-node churn (an
// evicted client would fail probes for reasons unrelated to enforcement).
func buildClientPod(app, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace, Labels: map[string]string{"app": app}},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name: "client", Image: churnImage,
				Command: []string{"sleep", "infinity"},
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
		ObjectMeta: metav1.ObjectMeta{Name: churnApp, Namespace: namespace},
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
								Image:   churnImage,
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
	if err := fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: churnApp}, cj); err != nil {
		return false
	}
	return cj.Status.LastSuccessfulTime != nil
}

// execConnect returns "CONNECTED" or "BLOCKED". Only those exact tokens count as a
// verdict; anything else is a broken probe (ExecInPod appends stderr to stdout
// without erroring, so a failed probe must not be read as BLOCKED) and is retried,
// then failed rather than returned as a bogus verdict.
//
// The probe is a bash /dev/tcp connect (no python runtime needed, so the client can
// reuse the minimal churn image). The `2>/dev/null` is load-bearing: bash writes
// "connect: Connection refused/timed out" to stderr on a denied connection, and
// ExecInPod folds stderr into stdout — without the redirect a legitimate BLOCKED
// would arrive as "BLOCKED\nSTDERR: bash: connect: ...", miss the exact-token match,
// and be misclassified as a probe error. With it, output is exactly one token.
func execConnect(podName, ip string, port int) string {
	script := fmt.Sprintf(
		`timeout 3 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null && echo CONNECTED || echo BLOCKED`,
		ip, port)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		out, err := fw.PodManager.ExecInPod(namespace, podName, []string{"bash", "-c", script})
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
	// A non-empty check is not enough: ExecInPod folds stderr into the returned
	// string ("STDERR: ..."), so a stderr-only dump would pass an empty check, parse
	// to zero counts, and silently green the drain leak check (0 <= baseline). Assert
	// the dump actually contains program data. The deny policy is active whenever
	// bpfCounts runs, so the server always has at least one program.
	Expect(out).To(ContainSubstring("PinPath:"), "bpf state dump has no program data on "+nodeName)

	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata")
	Expect(state.ProgIDs).ToNot(BeEmpty(), "parsed zero BPF programs on "+nodeName)
	return len(state.ProgIDs), len(state.MapIDs)
}
