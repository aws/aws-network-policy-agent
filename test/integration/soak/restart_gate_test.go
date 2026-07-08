package soak

import (
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// npaContainer is defined in memory_test.go as "aws-eks-nodeagent".

// restartMonitor tracks NPA container restarts per node across the whole run,
// robust to the agent-kill loop deleting and recreating the aws-node pod.
//
// A naive start-vs-end diff of containerStatuses.restartCount is wrong: RestartCount
// counts container restarts within one pod, and it resets to 0 when the pod itself
// is recreated. The agent-kill loop deletes pods on purpose, so a real OOM/crash
// restart that happened before that node's next kill would be erased. The monitor
// instead samples on the trend cadence, keyed by pod UID, and accumulates:
//   - in-place container restarts (RestartCount rising while the pod UID is stable),
//   - unexpected pod recreations (UID changing when we did not kill that node).
//
// Kills the harness itself performs are registered via NoteKill so they are not
// counted as unexpected recreations.
type restartMonitor struct {
	mu sync.Mutex

	// per-node last-observed state.
	lastUID      map[string]types.UID
	lastRestarts map[string]int32
	// kills the harness performed on each node since the last sample, so an
	// expected recreation is not flagged.
	pendingKills map[string]int

	// accumulated findings.
	inPlaceRestarts map[string]int32  // node -> total in-place container restarts
	lastReason      map[string]string // node -> last termination reason seen
	unexpectedNew   map[string]int    // node -> unexpected pod recreations
}

func newRestartMonitor(nodes []v1.Node) *restartMonitor {
	m := &restartMonitor{
		lastUID:         map[string]types.UID{},
		lastRestarts:    map[string]int32{},
		pendingKills:    map[string]int{},
		inPlaceRestarts: map[string]int32{},
		lastReason:      map[string]string{},
		unexpectedNew:   map[string]int{},
	}
	// Seed the baseline so the first sample does not count pre-existing state.
	for _, node := range nodes {
		if pod := agentPodOnNode(node.Name); pod != nil {
			m.lastUID[node.Name] = pod.UID
			m.lastRestarts[node.Name] = npaRestartCount(pod)
		}
	}
	return m
}

// NoteKill records that the harness deliberately deleted the aws-node pod on a
// node, so the next observed pod recreation there is expected, not a violation.
func (m *restartMonitor) NoteKill(nodeName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingKills[nodeName]++
}

// sample observes each node once and updates the accumulators. Safe to call from
// the trend-sample loop goroutine.
func (m *restartMonitor) sample(nodes []v1.Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, node := range nodes {
		pod := agentPodOnNode(node.Name)
		if pod == nil {
			continue // transient (mid-recreation); pick it up next sample
		}
		count := npaRestartCount(pod)
		reason := npaLastTerminationReason(pod)

		prevUID, hadPrev := m.lastUID[node.Name]
		switch {
		case !hadPrev:
			// first observation of this node
		case pod.UID == prevUID:
			// same pod: any rise in RestartCount is a real in-place restart.
			if delta := count - m.lastRestarts[node.Name]; delta > 0 {
				m.inPlaceRestarts[node.Name] += delta
				if reason != "" {
					m.lastReason[node.Name] = reason
				}
			}
		default:
			// pod was recreated. Expected if we killed this node; otherwise the
			// agent's pod vanished on its own, which is itself a restart signal.
			if m.pendingKills[node.Name] > 0 {
				m.pendingKills[node.Name]--
			} else {
				m.unexpectedNew[node.Name]++
			}
			// A fresh pod that already shows restarts terminated in-place before we
			// first saw it; count those too.
			if count > 0 {
				m.inPlaceRestarts[node.Name] += count
				if reason != "" {
					m.lastReason[node.Name] = reason
				}
			}
		}

		m.lastUID[node.Name] = pod.UID
		m.lastRestarts[node.Name] = count
	}
}

// finalize takes a last sample and records an AgentRestart violation for any node
// that saw an in-place restart or an unexpected pod recreation. This is Gate 3.
func (m *restartMonitor) finalize(rec *Recorder, nodes []v1.Node) {
	m.sample(nodes)

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, node := range nodes {
		n := node.Name
		if r := m.inPlaceRestarts[n]; r > 0 {
			rec.Record(AgentRestart, time.Now(),
				"node %s: aws-eks-nodeagent restarted in place %d time(s) (reason: %s)",
				n, r, orUnknown(m.lastReason[n]))
		}
		if u := m.unexpectedNew[n]; u > 0 {
			rec.Record(AgentRestart, time.Now(),
				"node %s: aws-node pod was recreated %d time(s) without a harness kill "+
					"(agent process died on its own)", n, u)
		}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// agentPodOnNode returns the aws-node pod scheduled on a node, or nil.
func agentPodOnNode(nodeName string) *v1.Pod {
	pods := &v1.PodList{}
	if err := fw.K8sClient.List(ctx, pods, client.InNamespace(agentNamespace),
		client.MatchingLabels{"k8s-app": agentDaemonSet}); err != nil {
		GinkgoWriter.Printf("restart-monitor: list aws-node pods: %v\n", err)
		return nil
	}
	for i := range pods.Items {
		if pods.Items[i].Spec.NodeName == nodeName {
			return &pods.Items[i]
		}
	}
	return nil
}

func npaRestartCount(pod *v1.Pod) int32 {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == npaContainer {
			return cs.RestartCount
		}
	}
	return 0
}

func npaLastTerminationReason(pod *v1.Pod) string {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == npaContainer && cs.LastTerminationState.Terminated != nil {
			return fmt.Sprintf("%s (exit %d)",
				cs.LastTerminationState.Terminated.Reason,
				cs.LastTerminationState.Terminated.ExitCode)
		}
	}
	return ""
}
