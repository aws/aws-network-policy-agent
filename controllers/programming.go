package controllers

import (
	"context"
	"slices"
	"sync"
	"time"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Policy enforcement runs in two stages.
//
// Stage 1 is the (slice, parent) reconcile. It runs on a single worker, recomputes what the
// parent policy selects from its live slices, records that in the reconciler's maps, and queues
// every pod identifier whose eBPF maps that may have changed. It never touches eBPF state.
//
// Stage 2 programs one pod identifier at a time: it attaches probes for the identifier's
// selected pods on this node, then rewrites the identifier's maps from the recorded state and
// the informer cache as they are when the pass runs. The queue never hands one identifier to two
// workers at once, and reprocesses an identifier queued while it was being processed, so the
// last pass for an identifier always reads the newest state. A failed pass is retried with
// backoff until one succeeds.

const (
	policyEndpointProgrammerName        = "policyendpoint-programmer"
	clusterPolicyEndpointProgrammerName = "clusterpolicyendpoint-programmer"

	programmingRetryBaseDelay = 5 * time.Millisecond
	programmingRetryMaxDelay  = 30 * time.Second

	// A stage-1 reconcile tracks up to two changes per identifier it queues: its E2E change and
	// its setup or teardown.
	maxPendingChangesPerIdentifier = 128

	// programmingWorkerCount is the number of stage-2 workers of each controller, and isn't
	// configurable. The queue makes more workers safe for any one identifier. During a rollout
	// the policy controller can remove the last old replica of an identifier from a policy
	// before it lists the new pod, and a pass that runs in between writes the identifier
	// without the policy until the next pass. Whether a pass runs in between depends on timing,
	// with any number of workers. With a backlog, one worker reaches an identifier later than
	// two would, so its pass more often reads both updates. That narrows the window but does
	// not close it.
	programmingWorkerCount = 1

	// stageOneWorkerCount is the number of (slice, parent) workers of each controller. Stage 1
	// must run on one: a reconcile reads and rewrites a policy's recorded state in steps that are
	// not atomic, so two reconciles of one policy at once would each work from the other's half.
	stageOneWorkerCount = 1
)

// newProgrammingQueue returns a stage-2 queue. It exists from construction, so adding to it never
// blocks, even before the manager starts the programming workers.
func newProgrammingQueue(name string) priorityqueue.PriorityQueue[string] {
	return priorityqueue.New[string](name, func(o *priorityqueue.Opts[string]) {
		o.RateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[string](
			programmingRetryBaseDelay, programmingRetryMaxDelay)
	})
}

// setupProgrammer registers the stage-2 controller that runs program on the identifiers in queue.
func setupProgrammer(mgr ctrl.Manager, name string, queue priorityqueue.PriorityQueue[string],
	program func(context.Context, string) error) error {
	_, err := controller.NewTyped[string](name, mgr, controller.TypedOptions[string]{
		Reconciler: reconcile.TypedFunc[string](func(ctx context.Context, podIdentifier string) (reconcile.Result, error) {
			return reconcile.Result{}, program(ctx, podIdentifier)
		}),
		MaxConcurrentReconciles: programmingWorkerCount,
		NewQueue: func(string, workqueue.TypedRateLimiter[string]) workqueue.TypedRateLimitingInterface[string] {
			return queue
		},
	})
	return err
}

// identifiersToProgram returns the identifiers a policy's reconcile must queue: the ones it
// selects pods of on this node, and the ones whose pods here it selected before, so a pod it
// stopped selecting is reprogrammed.
//
// An identifier the policy selects only on other nodes is not queued, even though the policy's
// rules reach this node's replicas through the shared maps. Queueing it when the policy stops
// selecting it would reset a new pod here to the baseline in the interval during a rollout
// when NPC has dropped the last old replica and not yet listed the new one, a pod that CNI ADD
// programmed with the policy's rules. This node's rules for such an identifier change only
// when something else reprograms it.
//
// Every such identifier is queued, whether or not it has programs on this node: a pass that
// finds none writes nothing. Leaving one out because it has no programs yet would race a pass
// whose first attach is creating them, which then writes the rules it read before this
// reconcile, with no later pass to rewrite them.
func identifiersToProgram(localPods, priorLocalPods map[string][]npatypes.Pod) []string {
	podIdentifiers := make([]string, 0, len(localPods)+len(priorLocalPods))
	for podIdentifier := range localPods {
		podIdentifiers = append(podIdentifiers, podIdentifier)
	}
	for podIdentifier := range priorLocalPods {
		if _, ok := localPods[podIdentifier]; !ok {
			podIdentifiers = append(podIdentifiers, podIdentifier)
		}
	}
	slices.Sort(podIdentifiers)
	return podIdentifiers
}

func queueIdentifiers(queue priorityqueue.PriorityQueue[string], podIdentifiers []string) {
	for _, podIdentifier := range podIdentifiers {
		queue.Add(podIdentifier)
	}
}

// localPodsOf returns the pods of podIdentifier on this node that the given policies select,
// from each policy's entry in localPodsByPolicy (map[string][]npatypes.Pod per policy key).
func localPodsOf(localPodsByPolicy *sync.Map, podIdentifier string, policyKeys []string) []npatypes.Pod {
	var pods []npatypes.Pod
	for _, key := range lo.Uniq(policyKeys) {
		if v, ok := localPodsByPolicy.Load(key); ok {
			pods = append(pods, v.(map[string][]npatypes.Pod)[podIdentifier]...)
		}
	}
	return uniquePods(pods)
}

// uniquePods dedupes on identity rather than the whole struct: a StatefulSet pod keeps its name
// across recreation but not its address, so two slices can list it with different IPs.
func uniquePods(pods []npatypes.Pod) []npatypes.Pod {
	return lo.UniqBy(pods, func(pod npatypes.Pod) types.NamespacedName { return pod.NamespacedName })
}

// programmingPass is what one programming pass for an identifier did.
type programmingPass struct {
	// wrote is true when the identifier's maps were written.
	wrote bool
	// skipped is the number of pods whose attach cannot be retried into success.
	skipped int
}

// changeTriggerTime returns the last-change-trigger-time annotation NPC set on a policy endpoint,
// if it is newer than startedAt and was not already consumed for req, and marks it consumed.
// Each value is consumed once, so a resync or relist of an unchanged endpoint never re-observes it.
func changeTriggerTime(annotations map[string]string, startedAt time.Time, req EndpointRequest,
	consumed *sync.Map) (time.Time, bool) {
	triggerTimeStr := annotations[LastChangeTriggerTimeAnnotation]
	if triggerTimeStr == "" {
		return time.Time{}, false
	}
	triggerTime, err := time.Parse(time.RFC3339Nano, triggerTimeStr)
	if err != nil {
		log().Debugf("Failed to parse %s annotation: %v", LastChangeTriggerTimeAnnotation, err)
		return time.Time{}, false
	}
	if !triggerTime.After(startedAt) {
		return time.Time{}, false
	}
	if prev, ok := consumed.Load(req); ok && prev.(string) == triggerTimeStr {
		return time.Time{}, false
	}
	consumed.Store(req, triggerTimeStr)
	return triggerTime, true
}

// programmingLatencyTracker takes one latency sample per change, once every identifier the
// change queued on this node has been programmed, retries included: an E2E sample from a
// policy change's trigger time, or a setup or teardown sample from a PolicyEndpoint's
// reconcile. A change that queued nothing, or whose identifiers all turned out to have nothing
// on this node, produces no sample.
type programmingLatencyTracker struct {
	histogram prometheus.Observer
	now       func() time.Time

	mu      sync.Mutex
	pending map[string][]*pendingChange
}

type pendingChange struct {
	since time.Time
	// observe records the time from since until the change landed
	observe func(time.Duration)
	// identifiers not yet programmed
	remaining int
	// whether some identifier's pass wrote maps
	wrote bool
}

func newProgrammingLatencyTracker(histogram prometheus.Observer) *programmingLatencyTracker {
	return &programmingLatencyTracker{histogram: histogram, now: time.Now, pending: map[string][]*pendingChange{}}
}

// track registers a policy change that queued podIdentifiers, for an E2E sample from
// triggeredAt. It must run before they are queued, so a pass cannot land them before the
// change is waiting on it.
func (t *programmingLatencyTracker) track(triggeredAt time.Time, podIdentifiers []string) {
	t.trackFunc(triggeredAt, podIdentifiers, t.observeE2E)
}

// trackFunc registers a change that queued podIdentifiers, passing observe the time from since
// until the change has landed. Like track, it must run before they are queued.
func (t *programmingLatencyTracker) trackFunc(since time.Time, podIdentifiers []string, observe func(time.Duration)) {
	podIdentifiers = lo.Uniq(podIdentifiers)
	if len(podIdentifiers) == 0 {
		return
	}
	change := &pendingChange{since: since, observe: observe, remaining: len(podIdentifiers)}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, podIdentifier := range podIdentifiers {
		pending := append(t.pending[podIdentifier], change)
		// An identifier whose pods never attach never lands its changes; bound what it holds.
		// Dropping the oldest loses only its sample: no other identifier can land it alone.
		if len(pending) > maxPendingChangesPerIdentifier {
			pending = slices.Delete(pending, 0, len(pending)-maxPendingChangesPerIdentifier)
		}
		t.pending[podIdentifier] = pending
	}
}

// begin returns the changes a pass for podIdentifier starting now will land if it succeeds.
// Changes tracked after this point wait for the next pass, which their queueing guarantees.
func (t *programmingLatencyTracker) begin(podIdentifier string) []*pendingChange {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.pending[podIdentifier])
}

// finish records that a successful pass for podIdentifier landed the changes begin returned.
func (t *programmingLatencyTracker) finish(podIdentifier string, landed []*pendingChange, wrote bool) {
	if len(landed) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	remaining := slices.DeleteFunc(t.pending[podIdentifier], func(c *pendingChange) bool {
		return slices.Contains(landed, c)
	})
	if len(remaining) == 0 {
		delete(t.pending, podIdentifier)
	} else {
		t.pending[podIdentifier] = remaining
	}
	for _, change := range landed {
		change.wrote = change.wrote || wrote
		change.remaining--
		if change.remaining > 0 || !change.wrote {
			continue
		}
		change.observe(t.now().Sub(change.since))
	}
}

func (t *programmingLatencyTracker) observeE2E(latency time.Duration) {
	if latency < 0 {
		// Clock skew between NPC (control plane) and this node
		log().Debugf("Skipping negative E2E policy programming latency %.3fs", latency.Seconds())
		return
	}
	t.histogram.Observe(latency.Seconds())
}

// deleteCleanups keeps the cleanup a slice deletion does. When a policy's slice goes away and
// the policy no longer selects any of an identifier's pods on this node, the deletion writes the
// identifier without that policy's rules, even where the policy still selects the identifier's
// pods on other nodes. Any later write of the identifier includes the policy again. So each
// identifier records the policy whose slice deletion last cleaned it up, until a later reconcile
// queues it or a CNI ADD writes it, and a programming pass leaves that policy out.
type deleteCleanups struct {
	// pod identifier -> name of the policy left out
	byIdentifier sync.Map
}

// record updates the identifiers a reconcile of parent queued. If the reconcile was for a deleted
// slice, the ones parent still selects somewhere but no longer selects any pods of on this node
// leave parent out; every other queued identifier is written with all its policies. One parent
// selects nowhere has no slices left to leave out.
func (d *deleteCleanups) record(parent string, queued []string, sliceDeleted bool,
	localPods map[string][]npatypes.Pod, selected map[string]bool) {
	for _, podIdentifier := range queued {
		if sliceDeleted && len(localPods[podIdentifier]) == 0 && selected[podIdentifier] {
			d.byIdentifier.Store(podIdentifier, parent)
		} else {
			d.byIdentifier.Delete(podIdentifier)
		}
	}
}

// forget drops podIdentifier's record, once it is written with all its policies or has nothing
// left on this node to program.
func (d *deleteCleanups) forget(podIdentifier string) {
	d.byIdentifier.Delete(podIdentifier)
}

// forgetParent drops parent's record for podIdentifier, once parent selects none of its pods.
func (d *deleteCleanups) forgetParent(podIdentifier, parent string) {
	d.byIdentifier.CompareAndDelete(podIdentifier, parent)
}

// without returns refs minus the slices of the policy podIdentifier leaves out, if any.
func (d *deleteCleanups) without(podIdentifier string, refs []utils.PolicyEndpointRef) []utils.PolicyEndpointRef {
	parent, ok := d.byIdentifier.Load(podIdentifier)
	if !ok {
		return refs
	}
	return lo.Filter(refs, func(ref utils.PolicyEndpointRef, _ int) bool { return ref.Parent != parent.(string) })
}

// withIdentifiers returns priorLocalPods with an entry for each of podIdentifiers it lacks: the map
// itself if it lacks none, and otherwise a copy, since the map is shared with the recorded state.
func withIdentifiers(priorLocalPods map[string][]npatypes.Pod, podIdentifiers []string) map[string][]npatypes.Pod {
	if !slices.ContainsFunc(podIdentifiers, func(podIdentifier string) bool {
		_, ok := priorLocalPods[podIdentifier]
		return !ok
	}) {
		return priorLocalPods
	}
	merged := make(map[string][]npatypes.Pod, len(priorLocalPods)+len(podIdentifiers))
	for podIdentifier, pods := range priorLocalPods {
		merged[podIdentifier] = pods
	}
	for _, podIdentifier := range podIdentifiers {
		if _, ok := merged[podIdentifier]; !ok {
			merged[podIdentifier] = nil
		}
	}
	return merged
}
