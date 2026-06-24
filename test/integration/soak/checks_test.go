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
// loaded-ebpfdata dump, reusing the same primitives as the leak and restart
// suites so the soak observes BPF state exactly as they do.
func dumpBPFState(nodeName string) utils.BPFState {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, created)

	output, err := fw.PodManager.ExecInPod(namespace, created.Name,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred(), "failed to dump bpf state")

	state, err := utils.ParseLoadedEBPFData(output)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata")
	return state
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
