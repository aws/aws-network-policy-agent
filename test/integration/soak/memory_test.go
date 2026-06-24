package soak

import (
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/test/integration/soak/kubestats"
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// npaContainer is the NPA sidecar inside the aws-node DaemonSet pod. The >50 MiB
// growth criterion is about this container alone, not the whole pod (which also
// holds the CNI), which is why we read per-container kubelet stats rather than the
// pod-level memory metric.
const npaContainer = "aws-eks-nodeagent"

// memoryMonitor tracks NPA container working-set growth on each node over the run,
// sampling the kubelet /stats/summary endpoint. It holds one GrowthTracker per
// node and is safe for concurrent Observe/finalize because sampling runs from an
// activity loop while the spec reads the result at the end.
type memoryMonitor struct {
	clientset *kubernetes.Clientset
	limit     uint64

	mu       sync.Mutex
	trackers map[string]*kubestats.GrowthTracker // node name -> tracker
}

func newMemoryMonitor(clientset *kubernetes.Clientset, limitBytes uint64) *memoryMonitor {
	return &memoryMonitor{
		clientset: clientset,
		limit:     limitBytes,
		trackers:  make(map[string]*kubestats.GrowthTracker),
	}
}

// sample reads the NPA container's working set on one node and feeds it to that
// node's tracker. A fetch or lookup error is logged, not recorded as a violation:
// a transient kubelet hiccup is not a memory leak, and the end-of-run check still
// has every successful sample to judge from.
func (m *memoryMonitor) sample(node string, npaPod string) {
	ws, err := m.fetchWorkingSet(node, npaPod)
	if err != nil {
		GinkgoWriter.Printf("memory: sample on %s failed: %v\n", node, err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	tracker, ok := m.trackers[node]
	if !ok {
		tracker = kubestats.NewGrowthTracker(m.limit)
		m.trackers[node] = tracker
	}
	tracker.Observe(ws)
	GinkgoWriter.Printf("memory node=%s npa-ws=%dMiB baseline=%dMiB growth=%dMiB t=%s\n",
		node, ws/mib, tracker.Baseline()/mib, tracker.Growth()/mib, time.Now().Format(time.RFC3339))
}

// fetchWorkingSet pulls the kubelet summary for a node via the API-server proxy
// and extracts the NPA container's working set. It uses only the kubeconfig the
// suite already has — no AWS credentials — which is the whole reason for reading
// kubelet stats instead of CloudWatch.
func (m *memoryMonitor) fetchWorkingSet(node, npaPod string) (uint64, error) {
	raw, err := m.clientset.CoreV1().RESTClient().Get().
		Resource("nodes").
		Name(node).
		SubResource("proxy").
		Suffix("stats/summary").
		DoRaw(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch kubelet summary for %s: %w", node, err)
	}
	summary, err := kubestats.ParseSummary(raw)
	if err != nil {
		return 0, err
	}
	return summary.ContainerWorkingSet(agentNamespace, npaPod, npaContainer)
}

// finalize records a MemoryGrowth violation for every node whose NPA container
// grew past the budget. Called once on the main goroutine after the loops stop.
func (m *memoryMonitor) finalize(rec *Recorder) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for node, tracker := range m.trackers {
		if tracker.Exceeded() {
			rec.Record(MemoryGrowth, time.Now(),
				"node %s: NPA container working-set grew %dMiB (%d->%d bytes), over %dMiB budget",
				node, tracker.Growth()/mib, tracker.Baseline(), tracker.Peak(), m.limit/mib)
		}
	}
}

// npaPodOnNode finds the aws-node DaemonSet pod scheduled on a node, so memory
// sampling can address the NPA container by its actual pod name (which the kubelet
// summary keys on).
func npaPodOnNode(nodeName string) (string, error) {
	pods := &v1.PodList{}
	if err := fw.K8sClient.List(ctx, pods, client.InNamespace(agentNamespace),
		client.MatchingLabels{"k8s-app": agentDaemonSet}); err != nil {
		return "", err
	}
	for i := range pods.Items {
		if pods.Items[i].Spec.NodeName == nodeName {
			return pods.Items[i].Name, nil
		}
	}
	return "", fmt.Errorf("no %s pod found on node %s", agentDaemonSet, nodeName)
}
