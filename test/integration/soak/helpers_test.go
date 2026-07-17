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

// buildNginxDeployment wraps the policy target in a 1-replica Deployment, not a bare
// Pod: EKS network policy applies only to owner-referenced pods, and NPA's pod
// identifier (name minus the last "-<segment>") would collide between bare pods
// sharing a prefix. The resource request keeps it off the eviction shortlist.
func buildNginxDeployment(app string) *appsv1.Deployment {
	return buildNginxDeploymentOnNode(app, "")
}

// buildNginxDeploymentOnNode pins to a node; empty nodeName lets the scheduler place it.
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

// buildClientPod is the long-lived pod probes exec from. bash /dev/tcp needs no
// extra runtime; the resource request keeps it off the eviction shortlist.
func buildClientPod(app, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: namespace, Labels: map[string]string{"app": app}},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name: "client", Image: clientImage,
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
// Churn pods run nginx (a real listener), NOT sleep — load-bearing for the fail-open
// probe: a no-listener pod answers with an instant RST, so it reads BLOCKED whether
// or not NPA programmed it, making the check vacuous. With a listener, CONNECTED is
// unambiguous fail-open evidence. activeDeadlineSeconds bounds each pod's life so it
// is probeable after churnConvergenceDeadline yet finishes inside the 1-minute
// schedule under Forbid.
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
			// Forbid overlap: stacked runs would fail drain-to-baseline on load, not a leak.
			ConcurrencyPolicy:          batchv1.ForbidConcurrent,
			SuccessfulJobsHistoryLimit: &successHistory,
			FailedJobsHistoryLimit:     &failHistory,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Parallelism:  &parallelism,
					Completions:  &completions,
					BackoffLimit: &backoffLimit,
					// nginx never exits; this bounds the pod's life, then TTL cleans up.
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

// churnPodsRunning reports whether a churn pod is currently Running with an IP.
// Do NOT use CronJob.Status.LastSuccessfulTime instead: churn pods are killed by
// activeDeadlineSeconds, so Jobs always end Failed and it stays nil forever. A
// Running pod is also the right trigger for the forced BPF peak sample (pods are
// programmed while Running, not after exit).
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

// verifyChurnPodsEnforced probes Running churn pods aged between
// churnConvergenceDeadline and churnProbeMaxAge and confirms the churn deny is
// enforced; returns how many were verified BLOCKED this sweep. CONNECTED past the
// deadline is fail-open; a first CONNECTED is confirmed with one re-probe (~3s) so
// a small programming overshoot converges instead of failing the spec.
func verifyChurnPodsEnforced(clientPodName string, now time.Time) int {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", churnApp)
	if err != nil {
		// Transient list blip: skip the sweep, don't abort a long soak.
		GinkgoWriter.Printf("verifyChurnPodsEnforced: list error, skipping sweep: %v\n", err)
		return 0
	}

	verified := 0
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != v1.PodRunning || p.Status.PodIP == "" || p.DeletionTimestamp != nil {
			continue
		}
		started := p.CreationTimestamp.Time
		if p.Status.StartTime != nil {
			started = p.Status.StartTime.Time
		}
		age := now.Sub(started)
		// Below the deadline a brief allow window is expected (standard mode), not a
		// defect. Above churnProbeMaxAge the pod can be deleted mid-probe: NPA detaches
		// while nginx serves through termination grace, reading CONNECTED twice — a
		// false fail-open. The fresh re-read below guards entry, not probe duration.
		if age < churnConvergenceDeadline || age > churnProbeMaxAge {
			continue
		}
		// Re-read before probing: the listing can be ~15s stale and a terminating pod
		// reads CONNECTED for the same detach-during-grace reason.
		fresh := &v1.Pod{}
		if err := fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: p.Name}, fresh); err != nil {
			continue // gone / unreadable — not a verdict
		}
		if fresh.DeletionTimestamp != nil || fresh.Status.Phase != v1.PodRunning {
			continue
		}
		if execConnect(clientPodName, p.Status.PodIP, serverPort) != "BLOCKED" {
			Expect(execConnect(clientPodName, p.Status.PodIP, serverPort)).To(Equal("BLOCKED"), fmt.Sprintf(
				"fail-open: churn pod %s (age %s) still CONNECTED twice after churnConvergenceDeadline %s; "+
					"NPA did not converge on a fresh policy-selected pod", p.Name, age.Round(time.Second), churnConvergenceDeadline))
		}
		verified++
	}
	return verified
}

// execConnect returns "CONNECTED" or "BLOCKED"; anything else is a broken probe and
// is retried, then failed — never returned as a verdict (ExecInPod folds stderr into
// stdout without erroring, so a failed probe must not read as BLOCKED). The
// 2>/dev/null is load-bearing: bash writes connect errors to stderr, which would
// otherwise corrupt a legitimate BLOCKED token.
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

// currentPodIP re-resolves the Running pod IP behind a 1-replica Deployment's app
// label, falling back to lastIP on transient errors. Deployments replace pods on
// eviction, and a probe against the stale IP times out as BLOCKED — turning the
// server sweep vacuous and false-failing the control and unprogram checks.
func currentPodIP(app, lastIP string) string {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", app)
	if err != nil {
		return lastIP
	}
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == v1.PodRunning && p.Status.PodIP != "" && p.DeletionTimestamp == nil {
			if p.Status.PodIP != lastIP {
				GinkgoWriter.Printf("currentPodIP: %s pod replaced, IP %s -> %s\n", app, lastIP, p.Status.PodIP)
			}
			return p.Status.PodIP
		}
	}
	return lastIP
}

// verifyControlReachable probes the negative-control pod (selected by no policy),
// which must stay CONNECTED. BLOCKED is the over-enforcement signal — a false-DENY
// class the deny-side probes can't see. One BLOCKED is confirmed with a re-probe
// before failing to absorb a one-off node blip.
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
	// Non-empty is not enough: ExecInPod folds stderr into the output, so a
	// stderr-only dump would parse to zero counts and silently green the leak check.
	Expect(out).To(ContainSubstring("PinPath:"), "bpf state dump has no program data on "+nodeName)

	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata")
	Expect(state.ProgIDs).ToNot(BeEmpty(), "parsed zero BPF programs on "+nodeName)
	return len(state.ProgIDs), len(state.MapIDs)
}
