package soak

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	"github.com/aws/aws-network-policy-agent/test/integration/soak/ctrace"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

// agentLogPath is where the node agent writes its policy event logs by default.
// Keep in sync with pkg/config.defaultLogFile.
const agentLogPath = "/var/log/aws-routed-eni/network-policy-agent.log"

// nodeBaseline is the per-node starting state the leak and growth checks compare
// the end-of-run state against.
type nodeBaseline struct {
	progCount int
	mapCount  int
}

// baseline holds the warm-up-excluded starting state for every node under test.
type baseline struct {
	perNode map[string]nodeBaseline
}

// captureBaseline records BPF program and map counts on each node after warm-up.
// It is the reference point for assertNoBPFLeak: a leak is "ended higher than it
// started", which only means anything against a captured start.
func captureBaseline(nodes []v1.Node) baseline {
	b := baseline{perNode: make(map[string]nodeBaseline, len(nodes))}
	for _, node := range nodes {
		state := dumpBPFState(node.Name)
		b.perNode[node.Name] = nodeBaseline{
			progCount: len(state.ProgIDs),
			mapCount:  len(state.MapIDs),
		}
		GinkgoWriter.Printf("baseline node=%s progs=%d maps=%d\n",
			node.Name, len(state.ProgIDs), len(state.MapIDs))
	}
	return b
}

// assertNoBPFLeak records a BPFLeak violation for any node whose program or map
// count ended above baseline after churn drained. The counts should return to
// baseline because every churned pod's programs and maps must be torn down; a
// sustained excess is the leak the 20-minute suite cannot surface.
func assertNoBPFLeak(rec *Recorder, base baseline, nodes []v1.Node) {
	for _, node := range nodes {
		start, ok := base.perNode[node.Name]
		if !ok {
			continue
		}
		state := dumpBPFState(node.Name)
		progs, maps := len(state.ProgIDs), len(state.MapIDs)
		if progs > start.progCount || maps > start.mapCount {
			rec.Record(BPFLeak, time.Now(),
				"node %s: progs %d->%d, maps %d->%d did not return to baseline",
				node.Name, start.progCount, progs, start.mapCount, maps)
		}
	}
}

// dumpBPFState runs the node agent CLI inside a privileged pod and parses the
// loaded-ebpfdata dump. It asserts on success, so it is only safe to call from the
// main goroutine (baseline capture, end-of-run leak check). Concurrent activity
// loops must use tryDumpBPFState, which returns an error instead of asserting.
func dumpBPFState(nodeName string) utils.BPFState {
	state, err := tryDumpBPFState(nodeName)
	Expect(err).ToNot(HaveOccurred(), "failed to dump bpf state on "+nodeName)
	return state
}

// tryDumpBPFState is the non-asserting form. A transient infra error (check pod
// failed to schedule, exec hiccup) is returned rather than failing the whole run,
// so a driver loop can log and move on instead of a flake tanking a 4h soak.
func tryDumpBPFState(nodeName string) (utils.BPFState, error) {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	if err != nil {
		return utils.BPFState{}, fmt.Errorf("start bpf-check pod on %s: %w", nodeName, err)
	}
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, created)

	output, err := fw.PodManager.ExecInPod(namespace, created.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	if err != nil {
		return utils.BPFState{}, fmt.Errorf("dump bpf state on %s: %w", nodeName, err)
	}
	return utils.ParseLoadedEBPFData(output)
}

// scanForConntrackRace reads each node's agent log and records a ConntrackRace
// violation for every confirmed #462 delete->deny pair. This is the log-signature
// half of the #462 detection; the behavioral half is the port-reuse driver's
// dropped connections, recorded live by the activity loops.
func scanForConntrackRace(rec *Recorder, nodes []v1.Node) {
	for _, node := range nodes {
		log := readAgentLog(node.Name)
		matches, err := ctrace.Scan(strings.NewReader(log), cfg.RaceWindow)
		if err != nil {
			// A scan error means the log format drifted from what ctrace matches;
			// that is itself worth surfacing, but as a test-infra problem, not a
			// silent pass. Fail loudly here on the main goroutine.
			Expect(err).ToNot(HaveOccurred(),
				fmt.Sprintf("conntrack-race scan failed on node %s", node.Name))
		}
		for _, m := range matches {
			rec.Record(ConntrackRace, m.DenyAt,
				"node %s: cleanup deleted %s:%d->%s:%d then denied return within %s (#462)",
				node.Name, m.DeletedFlow.SrcIP, m.DeletedFlow.SrcPort,
				m.DeletedFlow.DstIP, m.DeletedFlow.DstPort, m.Gap())
		}
	}
}

// readAgentLog cats the node agent's log file from inside a privileged pod. The
// log is node-local, so reading it requires the same host-chroot pod the BPF dump
// uses.
func readAgentLog(nodeName string) string {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, created)

	output, err := fw.PodManager.ExecInPod(namespace, created.Name,
		[]string{"chroot", "/host", "cat", agentLogPath})
	Expect(err).ToNot(HaveOccurred(), "failed to read agent log")
	return output
}

// contextForDuration returns a context that cancels after d, so every activity
// loop observes one shared deadline and stops together at the end of the soak
// window.
func contextForDuration(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
