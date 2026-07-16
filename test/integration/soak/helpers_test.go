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
	return buildNginxDeploymentOnNode(app, "")
}

// buildNginxDeploymentOnNode is buildNginxDeployment pinned to a node (empty nodeName
// = let the scheduler place it). The negative control pins to the server's node so
// its unselected-traffic guarantee is exercised on the same node under churn.
func buildNginxDeploymentOnNode(app, nodeName string) *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": app}},
				Spec: v1.PodSpec{
					NodeName: nodeName,
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
//
// Churn pods run nginx (a real listener), NOT sleep. This is load-bearing for the
// fail-open probe: a no-listener pod answers a TCP connect with an instant RST, so
// probing it reads BLOCKED whether or not NPA has programmed it — an unprogrammed,
// fail-open pod would look identical to an enforced one and the check would be
// vacuous. With a listener, CONNECTED is unambiguous evidence of fail-open and
// BLOCKED means the deny is enforced (drop → timeout, or RST once the ingress-deny
// program is attached).
//
// Lifetime is bounded to ~45s via activeDeadlineSeconds so the pod lives long
// enough to be probed after churnConvergenceDeadline, while still completing inside
// the 1-minute schedule under Forbid. Parallelism is 5 (down from 10) to keep a run
// finishing within the window now that each pod runs longer.
func buildChurnCronJob(nodeName string) *batchv1.CronJob {
	parallelism := int32(5)
	completions := int32(5)
	backoffLimit := int32(0)
	activeDeadline := int64(45)
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
					Parallelism:  &parallelism,
					Completions:  &completions,
					BackoffLimit: &backoffLimit,
					// nginx never exits on its own, so bound the pod's life here; the Job
					// completes when activeDeadlineSeconds elapses, then TTL cleans it up.
					ActiveDeadlineSeconds:   &activeDeadline,
					TTLSecondsAfterFinished: &ttl,
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": churnApp}},
						Spec: v1.PodSpec{
							NodeName:      nodeName,
							RestartPolicy: v1.RestartPolicyNever,
							Containers: []v1.Container{{
								Name:  "churn",
								Image: nginxImage,
								Ports: []v1.ContainerPort{{ContainerPort: 80}},
								Resources: v1.ResourceRequirements{
									Requests: v1.ResourceList{
										v1.ResourceCPU:    resource.MustParse("5m"),
										v1.ResourceMemory: resource.MustParse("16Mi"),
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

// churnPodsRunning reports whether at least one churn pod is currently Running with
// an IP, proving churn actually landed on the node (and, since the churn deny policy
// is already applied, that NPA has a fresh pod to program right now).
//
// We do NOT use CronJob.Status.LastSuccessfulTime: churn pods run nginx bounded by
// activeDeadlineSeconds, so the Job terminates as Failed (reason DeadlineExceeded),
// never Complete — LastSuccessfulTime would stay nil forever even though churn ran
// perfectly. Observing a Running pod is both correct and the right trigger for the
// forced BPF peak sample (the pod is programmed while Running, not after it exits).
func churnPodsRunning() bool {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", churnApp)
	if err != nil {
		return false
	}
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == v1.PodRunning && p.Status.PodIP != "" && p.DeletionTimestamp == nil {
			return true
		}
	}
	return false
}

// verifyChurnPodsEnforced probes every Running churn pod (nginx listener) that is
// past churnConvergenceDeadline and confirms the churn deny policy is enforced on it.
// It returns the number of past-deadline pods verified BLOCKED this sweep.
//
// A CONNECTED verdict on a pod older than the deadline is fail-open: NPA has not
// converged on a fresh, policy-selected pod (probe-attach race, missed CNI ADD,
// PolicyEndpoint lag). That fails the spec immediately, naming the pod and its age.
// Pods younger than the deadline are skipped — a brief allow window before
// programming completes is expected in standard mode, not a defect.
func verifyChurnPodsEnforced(clientPodName string, now time.Time) int {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", churnApp)
	if err != nil {
		// A transient list blip is not a verdict; skip this sweep rather than aborting
		// a long soak (mirrors execConnect's retry-not-fail stance on probe infra).
		GinkgoWriter.Printf("verifyChurnPodsEnforced: list error, skipping sweep: %v\n", err)
		return 0
	}

	verified := 0
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != v1.PodRunning || p.Status.PodIP == "" || p.DeletionTimestamp != nil {
			continue
		}
		// Age from the pod's start time (fall back to creation) so we only probe pods
		// that have had at least churnConvergenceDeadline to be programmed.
		started := p.CreationTimestamp.Time
		if p.Status.StartTime != nil {
			started = p.Status.StartTime.Time
		}
		age := now.Sub(started)
		if age < churnConvergenceDeadline {
			continue
		}
		// Re-read immediately before probing: the list can be up to ~15s stale by the
		// time we reach a late pod (each enforced probe burns the full 3s timeout), and
		// a pod hitting its activeDeadlineSeconds mid-loop begins terminating — NPA
		// detaches on the delete event while nginx may still serve during grace, which
		// would read CONNECTED and look like a false fail-open. Skip once it's leaving.
		fresh := &v1.Pod{}
		if err := fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: p.Name}, fresh); err != nil {
			continue // gone / unreadable — not a verdict
		}
		if fresh.DeletionTimestamp != nil || fresh.Status.Phase != v1.PodRunning {
			continue
		}
		verdict := execConnect(clientPodName, p.Status.PodIP, serverPort)
		Expect(verdict).To(Equal("BLOCKED"), fmt.Sprintf(
			"fail-open: churn pod %s (age %s) still CONNECTED after churnConvergenceDeadline %s; "+
				"NPA did not converge on a fresh policy-selected pod", p.Name, age.Round(time.Second), churnConvergenceDeadline))
		verified++
	}
	return verified
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

// verifyControlReachable probes the negative-control pod, which NO policy selects,
// so it must stay CONNECTED. A BLOCKED control is the over-enforcement signal: NPA
// is wrongly dropping unselected traffic (conntrack cleanup race, catch-all applied
// to the wrong pod identifier, map corruption) — a false-DENY class the deny-side
// probes are structurally blind to.
//
// One BLOCKED is confirmed with an immediate re-probe before failing: a single lost
// SYN is normally absorbed by the 3s connect timeout's kernel retries, but this
// guards a long run against a one-off node blip. Two consecutive BLOCKED fails.
func verifyControlReachable(clientPodName, controlIP string) {
	if execConnect(clientPodName, controlIP, serverPort) == "CONNECTED" {
		return
	}
	Expect(execConnect(clientPodName, controlIP, serverPort)).To(Equal("CONNECTED"),
		"over-enforcement: control pod (selected by no policy) is BLOCKED twice in a row; "+
			"NPA is dropping traffic it should not — server BLOCKED + control BLOCKED points at a "+
			"node-level or over-enforcement problem, not correct enforcement")
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
