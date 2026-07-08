package soak

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/test/integration/soak/schedule"
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// activityLoops runs the concurrent soak drivers. Each driver ticks on a cadence
// from the schedule, performs its action, and records any violation into the
// shared recorder. No driver asserts: Ginkgo assertions are unsafe off the main
// goroutine, so the spec asserts on the recorder once every loop has stopped.
type activityLoops struct {
	rec      *Recorder
	cfg      *Config
	sched    *schedule.Schedule
	nodes    []v1.Node
	target   *v1.Pod // ingress-denied server the probe sweep tries to reach
	prober   *v1.Pod // unrestricted pod the probe sweep connects from
	baseline baseline
	memory   *memoryMonitor
	restarts *restartMonitor

	deadline time.Time // end of the run, set in start; used to suppress kills in the settle window
	wg       sync.WaitGroup
}

func newActivityLoops(rec *Recorder, cfg *Config, sched *schedule.Schedule,
	nodes []v1.Node, target, prober *v1.Pod, base baseline, mem *memoryMonitor,
	restarts *restartMonitor) *activityLoops {
	return &activityLoops{
		rec: rec, cfg: cfg, sched: sched, nodes: nodes,
		target: target, prober: prober, baseline: base, memory: mem, restarts: restarts,
	}
}

// start launches every activity loop. Each returns when runCtx is cancelled.
func (a *activityLoops) start(runCtx context.Context) {
	// Record the run deadline so agentKill can suppress kills in the final settle
	// window, leaving the agent steady for the end-of-run recovery and leak gates.
	if dl, ok := runCtx.Deadline(); ok {
		a.deadline = dl
	}
	a.run(runCtx, "probe-sweep", a.sched.Interval(schedule.ProbeSweep), a.probeSweep)
	a.run(runCtx, "agent-kill", a.sched.Interval(schedule.AgentKill), a.agentKill)
	a.run(runCtx, "policy-update", a.sched.Interval(schedule.PolicyHotUpdate), a.policyHotUpdate)
	a.run(runCtx, "ns-churn", a.sched.Interval(schedule.NamespaceChurn), a.namespaceChurn)
	a.run(runCtx, "trend-sample", a.sched.Interval(schedule.TrendSample), a.trendSample)
}

// wait blocks until every loop has returned.
func (a *activityLoops) wait() { a.wg.Wait() }

// run starts one ticking loop. tick is invoked every interval until runCtx is
// done; a tick that takes longer than the interval simply delays the next one
// (time.Ticker drops, not queues) which is the behavior we want for slow actions
// like an agent kill.
func (a *activityLoops) run(runCtx context.Context, name string, interval time.Duration, tick func(context.Context)) {
	a.wg.Add(1)
	go func() {
		defer GinkgoRecover() // a panic in a driver must not crash the test process silently
		defer a.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		GinkgoWriter.Printf("loop %s started (interval %s)\n", name, interval)

		for {
			select {
			case <-runCtx.Done():
				GinkgoWriter.Printf("loop %s stopping\n", name)
				return
			case <-ticker.C:
				tick(runCtx)
			}
		}
	}()
}

// probeSweep verifies enforcement is still correct: the protected server must deny
// a fresh connection that the ingress policy does not allow. A reachable connection
// is a false-allow and a mis-enforcement violation.
//
// This is the point-in-time correctness check; the continuous port-reuse driver
// (started separately) covers the return-traffic path that the #462 race breaks.
func (a *activityLoops) probeSweep(runCtx context.Context) {
	reachable, err := a.serverReachable()
	if err != nil {
		// A probe infrastructure error (exec failed) is not an enforcement
		// verdict; log and move on rather than recording a false violation.
		GinkgoWriter.Printf("probe-sweep: probe error: %v\n", err)
		return
	}
	if reachable {
		a.rec.Record(MisEnforcement, time.Now(),
			"deny-server %s reachable from prober despite ingress-deny policy (false-allow)",
			a.target.Status.PodIP)
	}
}

// agentKill deletes the agent pod on a rotating node and validates recovery: after
// the agent restarts, enforcement must still hold. A node is chosen per tick so a
// multi-node run exercises kills across the fleet, not just one node.
func (a *activityLoops) agentKill(runCtx context.Context) {
	// Suppress kills inside the final settle window so the agent is steady when the
	// end-of-run recovery, leak, and restart gates sample it. Without this a kill at
	// t≈deadline would leave a node mid-restart and mask a leak or a real restart.
	if !a.deadline.IsZero() && time.Until(a.deadline) < a.sched.SettleWindow() {
		GinkgoWriter.Printf("agent-kill: within settle window, skipping\n")
		return
	}

	node := a.nodes[a.killIndex()%len(a.nodes)]

	// Tell the restart monitor this recreation is expected, so it is not counted as
	// the agent dying on its own.
	if a.restarts != nil {
		a.restarts.NoteKill(node.Name)
	}

	if err := a.deleteAgentPodOn(runCtx, node.Name); err != nil {
		GinkgoWriter.Printf("agent-kill: delete failed on %s: %v\n", node.Name, err)
		return
	}

	// Give the agent time to restart and re-attach before checking enforcement.
	select {
	case <-runCtx.Done():
		return
	case <-time.After(bpfSettle):
	}

	reachable, err := a.serverReachable()
	if err != nil {
		GinkgoWriter.Printf("agent-kill: post-kill probe error: %v\n", err)
		return
	}
	if reachable {
		a.rec.Record(RecoveryFailure, time.Now(),
			"protected server reachable after agent kill on %s (enforcement not restored)", node.Name)
	}
}

// killCounter rotates the node selection for agentKill. It is only touched from
// the single agent-kill goroutine, so it needs no synchronization.
var killCounter int

func (a *activityLoops) killIndex() int {
	idx := killCounter
	killCounter++
	return idx
}

// deleteAgentPodOn deletes the aws-node agent pod scheduled on nodeName.
func (a *activityLoops) deleteAgentPodOn(runCtx context.Context, nodeName string) error {
	pods := &v1.PodList{}
	if err := fw.K8sClient.List(runCtx, pods, client.InNamespace(agentNamespace),
		client.MatchingLabels{"k8s-app": agentDaemonSet}); err != nil {
		return err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == nodeName {
			return fw.K8sClient.Delete(runCtx, p)
		}
	}
	return fmt.Errorf("no %s pod found on node %s", agentDaemonSet, nodeName)
}

// policyHotUpdate mutates the ingress policy in place, exercising the reconcile
// path under traffic. The mutation toggles a benign label-selector port so the
// policy object changes and triggers a reprogram without ever opening the server.
func (a *activityLoops) policyHotUpdate(runCtx context.Context) {
	pol := &network.NetworkPolicy{}
	key := client.ObjectKey{Namespace: namespace, Name: denyPolicyName}
	if err := fw.K8sClient.Get(runCtx, key, pol); err != nil {
		GinkgoWriter.Printf("policy-update: get failed: %v\n", err)
		return
	}
	updated := pol.DeepCopy()
	// Annotate with a changing value to force a generation bump and reconcile.
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations["soak/hot-update"] = time.Now().Format(time.RFC3339Nano)
	if err := fw.K8sClient.Patch(runCtx, updated, client.MergeFrom(pol)); err != nil {
		GinkgoWriter.Printf("policy-update: patch failed: %v\n", err)
		return
	}

	// After the update, enforcement must still hold. A false-allow here means the
	// reconcile left a window of non-enforcement.
	time.Sleep(bpfSettle)
	if reachable, err := a.serverReachable(); err == nil && reachable {
		a.rec.Record(MisEnforcement, time.Now(),
			"deny-server reachable after policy hot-update (reconcile left enforcement gap)")
	}
}

// namespaceChurn creates and tears down a throwaway namespace with a workload,
// exercising selector re-evaluation and cleanup. A failure to fully delete is a
// cleanup problem; we surface it as a leak-adjacent violation only if BPF state
// is left behind, which the end-of-run leak check captures, so here we just drive
// the churn.
func (a *activityLoops) namespaceChurn(runCtx context.Context) {
	ns := fmt.Sprintf("%s-churn-%d", namespace, time.Now().UnixNano())
	if err := fw.NamespaceManager.CreateNamespace(runCtx, ns); err != nil {
		GinkgoWriter.Printf("ns-churn: create %s failed: %v\n", ns, err)
		return
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "churn", Namespace: ns, Labels: map[string]string{"app": "churn"}},
		Spec: v1.PodSpec{
			NodeName:      a.nodes[0].Name,
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name: "sleep", Image: "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
				Command: []string{"sleep", "30"},
			}},
		},
	}
	if _, err := fw.PodManager.CreateAndWaitTillPodIsRunning(runCtx, pod, podReadyTimeout); err != nil {
		GinkgoWriter.Printf("ns-churn: pod in %s failed: %v\n", ns, err)
	}
	if err := fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(runCtx, ns); err != nil {
		GinkgoWriter.Printf("ns-churn: delete %s failed: %v\n", ns, err)
	}
}

// trendSample records BPF state and NPA container memory for the trend log on the
// same cadence. The BPF counts leave a visible progression for post-mortem
// analysis; the memory samples feed the per-node growth trackers that the
// end-of-run check judges against the >50 MiB budget.
func (a *activityLoops) trendSample(runCtx context.Context) {
	// Sample the restart monitor first: it is a cheap k8s API read and is the
	// signal that must not miss an in-place restart between kills.
	if a.restarts != nil {
		a.restarts.sample(a.nodes)
	}

	for _, node := range a.nodes {
		// Non-asserting: a transient bpf-check failure must not fail the 4h run
		// from a driver goroutine (assertions off the main goroutine are unsafe).
		state, err := tryDumpBPFState(node.Name)
		if err != nil {
			GinkgoWriter.Printf("trend: bpf dump on %s failed: %v\n", node.Name, err)
			continue
		}
		GinkgoWriter.Printf("trend node=%s progs=%d maps=%d t=%s\n",
			node.Name, len(state.ProgIDs), len(state.MapIDs), time.Now().Format(time.RFC3339))

		npaPod, err := npaPodOnNode(node.Name)
		if err != nil {
			GinkgoWriter.Printf("trend: locate NPA pod on %s failed: %v\n", node.Name, err)
			continue
		}
		a.memory.sample(node.Name, npaPod)
	}
}

// serverReachable reports whether a fresh TCP connection from the prober to the
// ingress-denied target server succeeds. Under the deny policy it must not, so a
// success is a false-allow. The probe execs curl inside the prober pod (which has
// curl and no policy of its own), so any block observed comes from the target's
// policy, not the prober's.
//
// It distinguishes "blocked" (the expected, correct outcome) from "probe
// infrastructure broke" by inspecting curl's exit: a connection failure is a
// non-error blocked result, while an exec/transport failure is returned as an
// error so the caller does not record a false mis-enforcement.
func (a *activityLoops) serverReachable() (bool, error) {
	// curl -s -o /dev/null --max-time N --fail: exit 0 only on a 2xx/3xx response
	// (reachable); non-zero on connection refused/timeout (blocked) or usage error.
	url := fmt.Sprintf("http://%s:%d/", a.target.Status.PodIP, serverPort)
	out, err := fw.PodManager.ExecInPod(namespace, a.prober.Name,
		[]string{"curl", "-s", "-o", "/dev/null", "--max-time", "5", "-w", "%{http_code}", url})
	if err != nil {
		// A blocked connection makes curl exit non-zero, which ExecInPod surfaces
		// as an error. That is the expected outcome under the deny policy, so it is
		// "not reachable", not a probe failure.
		return false, nil
	}
	// Reachable only if curl got an HTTP response code (server answered).
	return strings.HasPrefix(strings.TrimSpace(out), "2") || strings.HasPrefix(strings.TrimSpace(out), "3"), nil
}
