/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/lo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	networking "k8s.io/api/networking/v1"
)

func log() logger.Logger {
	return logger.Get()
}

const (
	// LastChangeTriggerTimeAnnotation is set by NPC on PolicyEndpoint to track
	// when the resource was last created/updated. NPA reads this to compute
	// E2E policy programming latency.
	LastChangeTriggerTimeAnnotation = "networking.k8s.aws/last-change-trigger-time"

	POLICIES_APPLIED = 0
	DEFAULT_ALLOW    = 1
	DEFAULT_DENY     = 2
)

var (
	policySetupLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "awsnodeagent_policy_setup_latency_ms",
			Help: "policy configuration setup call latency in ms",
		},
		[]string{"name", "namespace"},
	)
	policyTearDownLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "awsnodeagent_policy_teardown_latency_ms",
			Help: "policy configuration teardown call latency in ms",
		},
		[]string{"name", "namespace"},
	)
	// Buckets for latency:
	//   0.25, 0.50s                    (sub-second, 250ms steps)
	//   1s, 2s, 3s, ..., 59s           (1s steps for normal operations)
	//   60s, 65s, 70s, ..., 115s       (5s steps)
	//   120s, 150s, 180s, ..., 300s    (30s steps)
	policyProgrammingLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "awsnodeagent_policy_programming_latency_seconds",
			Help: "E2E latency from NPC PolicyEndpoint change to NPA eBPF map programming, in seconds",
			Buckets: append(append(append(
				prometheus.LinearBuckets(0.25, 0.25, 2), // 0.25, 0.50
				prometheus.LinearBuckets(1, 1, 59)...),  // 1, 2, 3, ..., 59
				prometheus.LinearBuckets(60, 5, 12)...), // 60, 65, 70, ..., 115
				prometheus.LinearBuckets(120, 30, 7)...), // 120, 150, 180, ..., 300
		},
	)
	prometheusRegistered = false
)

// milliseconds returns d in fractional milliseconds.
func milliseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func prometheusRegister() {
	if !prometheusRegistered {
		metrics.Registry.MustRegister(policySetupLatency)
		metrics.Registry.MustRegister(policyTearDownLatency)
		metrics.Registry.MustRegister(policyProgrammingLatency)
		prometheusRegistered = true
	}
}

// NewPolicyEndpointsReconciler constructs new PolicyEndpointReconciler
func NewPolicyEndpointsReconciler(k8sClient client.Client, nodeIP string, ebpfClient ebpf.BpfClient, enableIPv6 bool) *PolicyEndpointsReconciler {
	r := &PolicyEndpointsReconciler{
		k8sClient:          k8sClient,
		nodeIP:             nodeIP,
		ebpfClient:         ebpfClient,
		enableIPv6:         enableIPv6,
		trackerStartTime:   time.Now(),
		programQueue:       newProgrammingQueue(policyEndpointProgrammerName),
		programmingLatency: newProgrammingLatencyTracker(policyProgrammingLatency),
	}

	prometheusRegister()
	return r
}

// PolicyEndpointsReconciler reconciles a PolicyEndpoints object
type PolicyEndpointsReconciler struct {
	// k8sClient reads PolicyEndpoints with client.UnsafeDisableDeepCopy: returned objects are
	// shared with the informer cache and must not be mutated.
	k8sClient client.Client
	scheme    *runtime.Scheme
	//Primary IP of EC2 instance
	nodeIP string
	// trackerStartTime records when this reconciler started. Used to filter
	// stale PolicyEndpoint annotations and avoid emitting artificially high
	// E2E latency on restart
	trackerStartTime time.Time
	// lastObservedTriggerTimes maps a PE's EndpointRequest to the last
	// last-change-trigger-time annotation value consumed, so each trigger
	// time is observed at most once
	lastObservedTriggerTimes sync.Map
	programmingLatency       *programmingLatencyTracker
	deleteCleanups           deleteCleanups
	// sliceLocalIdentifiers holds, per live slice (EndpointRequest), the identifiers it selected
	// pods of on this node at its last reconcile. A slice's deletion reads its own entry, so a
	// sibling reconciled first, which rewrites the policy's local pods, can't hide what it selected.
	sliceLocalIdentifiers sync.Map

	// What each NetworkPolicy selects, as of its last reconcile. Only the PolicyEndpoint
	// reconcile writes these, on a single worker; the programming workers and the CNI RPC path
	// read them concurrently.
	//
	// Maps a pod identifier to the live PolicyEndpoints ([]utils.PolicyEndpointRef) of every
	// NetworkPolicy that selects a pod of that identifier on any node
	podIdentifierToPolicyEndpointMap sync.Map
	// Serializes writes to podIdentifierToPolicyEndpointMap
	podIdentifierToPolicyEndpointMapMutex sync.Mutex
	// Maps a NetworkPolicy to the pod identifiers it selects on any node ([]string)
	networkPolicyToPodIdentifierMap sync.Map
	// Maps a NetworkPolicy to the pods it selects on this node, by pod identifier
	// (map[string][]npatypes.Pod)
	networkPolicyToLocalPodsMap sync.Map

	// Pod identifiers whose eBPF maps need programming
	programQueue priorityqueue.PriorityQueue[string]

	//BPF Client instance
	ebpfClient ebpf.BpfClient
	enableIPv6 bool
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/status,verbs=get

func (r *PolicyEndpointsReconciler) Reconcile(ctx context.Context, req EndpointRequest) (ctrl.Result, error) {
	log().Debugf("Received a new reconcile request %v", req)
	if err := r.reconcile(ctx, req); err != nil {
		log().Errorf("Reconcile error: %v", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// reconcile is stage 1 for one slice event: it recomputes the slice's parent NetworkPolicy and
// queues the identifiers to program. A slice that is gone, being deleted, or now owned by another
// parent simply no longer contributes to req.Parent; its new parent has its own request.
func (r *PolicyEndpointsReconciler) reconcile(ctx context.Context, req EndpointRequest) error {
	start := time.Now()
	policyEndpoint := &policyk8sawsv1.PolicyEndpoint{}
	live := true
	if err := r.k8sClient.Get(ctx, req.Endpoint, policyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if !apierrors.IsNotFound(err) {
			log().Errorf("Unable to get policy endpoint spec for policyendpoint %s: %v", req.Endpoint, err)
			return err
		}
		live = false
	} else if policyEndpoint.Spec.PolicyRef.Name != req.Parent || !policyEndpoint.DeletionTimestamp.IsZero() {
		live = false
	}
	if !live {
		r.lastObservedTriggerTimes.Delete(req)
	}

	queued, err := r.reconcileNetworkPolicy(ctx, req.Endpoint.Namespace, req.Parent, &req, !live)
	if err != nil {
		return err
	}
	if live {
		if triggeredAt, ok := changeTriggerTime(policyEndpoint.Annotations, r.trackerStartTime, req, &r.lastObservedTriggerTimes); ok {
			r.programmingLatency.track(triggeredAt, queued)
		}
	}
	// The PolicyEndpoint is set up or torn down on this node once every identifier it queued is
	// programmed. Only a reconcile that queued work on this node is a measurement. Observing
	// unconditionally would add a label series per PE name per node -- every node reconciles
	// every PE, GenerateName means the names are never reused, and nothing ever removes a series.
	latency := policySetupLatency
	if !live {
		latency = policyTearDownLatency
	}
	r.programmingLatency.trackFunc(start, queued, func(elapsed time.Duration) {
		latency.WithLabelValues(req.Endpoint.Name, req.Endpoint.Namespace).Observe(milliseconds(elapsed))
	})
	queueIdentifiers(r.programQueue, queued)
	log().Debugf("Reconciled NetworkPolicy %s/%s for %s: queued %d identifier(s)",
		req.Endpoint.Namespace, req.Parent, req.Endpoint.Name, len(queued))
	return nil
}

// reconcileNetworkPolicy recomputes what parentNP selects from its live PolicyEndpoints and
// records it. It returns the pod identifiers whose maps on this node may have changed.
// slice is the request being reconciled, if any, and sliceDeleted reports that it is gone.
func (r *PolicyEndpointsReconciler) reconcileNetworkPolicy(ctx context.Context, namespace, parentNP string,
	slice *EndpointRequest, sliceDeleted bool) ([]string, error) {
	policyEndpoints, err := r.derivePolicyEndpointsOfParentNP(ctx, parentNP, namespace)
	if err != nil {
		// This is expected only if the error is due to inability to list the PE from the cache, in which case we should requeue the reconcile request
		return nil, err
	}
	names := lo.Map(policyEndpoints, func(pe policyk8sawsv1.PolicyEndpoint, _ int) string { return pe.Name })
	selected, localPods, localBySlice := r.selectedPods(policyEndpoints)

	for podIdentifier := range selected {
		utils.SetParentPolicyEndpoints(&r.podIdentifierToPolicyEndpointMap, &r.podIdentifierToPolicyEndpointMapMutex,
			podIdentifier, parentNP, names)
	}
	networkPolicyIdentifier := utils.GetNetworkPolicyIdentifier(parentNP, namespace)
	stale := utils.DeriveStalePodIdentifiers(&r.networkPolicyToPodIdentifierMap, networkPolicyIdentifier, selected)
	for _, podIdentifier := range stale {
		utils.DeleteParentFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
			&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parentNP)
		r.deleteCleanups.forgetParent(podIdentifier, parentNP)
	}

	var priorLocalPods map[string][]npatypes.Pod
	if v, ok := r.networkPolicyToLocalPodsMap.Load(networkPolicyIdentifier); ok {
		priorLocalPods = v.(map[string][]npatypes.Pod)
	}
	commitPolicySelection(&r.networkPolicyToPodIdentifierMap, &r.networkPolicyToLocalPodsMap,
		networkPolicyIdentifier, selected, localPods)

	log().Debugf("NetworkPolicy %s/%s: %d PolicyEndpoint(s) select %d identifier(s), %d with pods on this node, %d no longer selected",
		namespace, parentNP, len(policyEndpoints), len(selected), len(localPods), len(stale))
	if slice != nil && sliceDeleted {
		if v, ok := r.sliceLocalIdentifiers.Load(*slice); ok {
			priorLocalPods = withIdentifiers(priorLocalPods, v.([]string))
		}
	}
	queued := identifiersToProgram(r.ebpfClient, localPods, priorLocalPods)
	queued = r.programmingLatency.withPendingMeasurements(queued, priorLocalPods)
	r.deleteCleanups.record(parentNP, queued, sliceDeleted, localPods, selected)
	recordSliceLocalIdentifiers(&r.sliceLocalIdentifiers, slice, sliceDeleted, localBySlice)
	return queued, nil
}

// selectedPods returns every pod identifier the PolicyEndpoints select on any node, their
// selected pods on this node by identifier, and the identifiers each slice selects pods of on
// this node, by slice name. Host-network pods are skipped: they have no veth to
// attach to.
func (r *PolicyEndpointsReconciler) selectedPods(policyEndpoints []policyk8sawsv1.PolicyEndpoint) (map[string]bool,
	map[string][]npatypes.Pod, map[string][]string) {
	selected := make(map[string]bool)
	localPods := make(map[string][]npatypes.Pod)
	localBySlice := make(map[string][]string)
	nodeIP := net.ParseIP(r.nodeIP)
	for i := range policyEndpoints {
		pe := &policyEndpoints[i]
		ignored := 0
		var firstIgnored types.NamespacedName
		for _, pod := range pe.Spec.PodSelectorEndpoints {
			// PolicyEndpoints only select pods in their own namespace.
			if pod.Namespace != pe.Namespace {
				if ignored == 0 {
					firstIgnored = types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
				}
				ignored++
				continue
			}
			if string(pod.PodIP) == string(pod.HostIP) {
				log().Debugf("Skipping hostNetwork pod: name: %s namespace: %s (PodIP == HostIP: %s)",
					pod.Name, pod.Namespace, pod.PodIP)
				continue
			}
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			selected[podIdentifier] = true
			if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
				localPods[podIdentifier] = append(localPods[podIdentifier], npatypes.Pod{
					NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, PodIP: pod.PodIP})
				if !slices.Contains(localBySlice[pe.Name], podIdentifier) {
					localBySlice[pe.Name] = append(localBySlice[pe.Name], podIdentifier)
				}
			}
		}
		if ignored > 0 {
			log().Warnf("Ignored %d podSelectorEndpoints in PolicyEndpoint %s/%s with a different namespace (first: %s)",
				ignored, pe.Namespace, pe.Name, firstIgnored)
		}
	}
	for podIdentifier, pods := range localPods {
		localPods[podIdentifier] = uniquePods(pods)
	}
	return selected, localPods, localBySlice
}

// commitPolicySelection records what a policy selects, or forgets the policy once it selects nothing.
func commitPolicySelection(policyToPodIdentifiers, policyToLocalPods *sync.Map, policyKey string,
	selected map[string]bool, localPods map[string][]npatypes.Pod) {
	if len(selected) == 0 {
		policyToPodIdentifiers.Delete(policyKey)
	} else {
		policyToPodIdentifiers.Store(policyKey, slices.Sorted(maps.Keys(selected)))
	}
	if len(localPods) == 0 {
		policyToLocalPods.Delete(policyKey)
	} else {
		policyToLocalPods.Store(policyKey, localPods)
	}
}

// programIdentifier is stage 2 for one pod identifier. It brings the identifier's eBPF maps in
// line with every NetworkPolicy recorded as selecting it, attaching probes for its selected pods
// on this node first. Any failure, including an attach failure after the maps were written, is
// returned so the identifier is retried.
func (r *PolicyEndpointsReconciler) programIdentifier(ctx context.Context, podIdentifier string) error {
	changes := r.programmingLatency.begin(podIdentifier)
	pass, err := r.programIdentifierMaps(ctx, podIdentifier)
	if err != nil {
		log().Errorf("Programming network policies for podIdentifier %s failed, will retry: %v", podIdentifier, err)
		return err
	}
	// Pods that cannot attach yet are not retried, since retrying cannot help, but they are
	// local and a later pass can still program them; that pass reports the latency.
	if !pass.wrote && pass.skipped > 0 {
		return nil
	}
	r.programmingLatency.finish(podIdentifier, changes, pass.wrote)
	return nil
}

// programIdentifierMaps reports whether it wrote the identifier's maps and how many of its pods
// could not attach.
func (r *PolicyEndpointsReconciler) programIdentifierMaps(ctx context.Context, podIdentifier string) (programmingPass, error) {
	refs := r.deleteCleanups.without(podIdentifier, r.policyEndpointRefs(podIdentifier))
	namespace, ok := utils.GetPodNamespaceFromPodIdentifier(podIdentifier)
	if !ok {
		// Identifiers come from GetPodIdentifier, so this cannot happen; retrying cannot help.
		log().Errorf("Skipping policy programming for podIdentifier %s: it has no namespace", podIdentifier)
		return programmingPass{}, nil
	}

	parents := lo.Map(refs, func(ref utils.PolicyEndpointRef, _ int) string {
		return utils.GetNetworkPolicyIdentifier(ref.Parent, namespace)
	})
	attached, attachErr := attachProbesForIdentifier(r.ebpfClient, podIdentifier,
		localPodsOf(&r.networkPolicyToLocalPodsMap, podIdentifier, parents))

	// The identifier's pods left the node, or none could attach yet: there is nothing to program.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		r.deleteCleanups.forget(podIdentifier)
		return programmingPass{skipped: attached.skipped}, attachErr
	}

	policyEndpoints, err := r.policyEndpointsOf(ctx, namespace, podIdentifier, refs)
	if err != nil {
		return programmingPass{}, errors.Join(attachErr, fmt.Errorf("get policy endpoints for podIdentifier %s: %w", podIdentifier, err))
	}
	ingressRules, egressRules, state := r.firewallRulesFor(policyEndpoints)
	if err := r.updateeBPFMaps(podIdentifier, ingressRules, egressRules, state); err != nil {
		return programmingPass{}, errors.Join(attachErr, err)
	}
	return programmingPass{wrote: true, skipped: attached.skipped}, attachErr
}

func (r *PolicyEndpointsReconciler) policyEndpointRefs(podIdentifier string) []utils.PolicyEndpointRef {
	if refs, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		return refs.([]utils.PolicyEndpointRef)
	}
	return nil
}

// policyEndpointsOf resolves podIdentifier's refs against the informer cache and returns the
// slices that apply to it, dropping slices that are gone, being deleted, or whose name was reused
// under another parent.
//
// A grouped PolicyEndpoint carries the rules of one resolved-port group and applies only to the
// pods its group lists, matched within its own policy. Ungrouped ones apply to every pod of their
// policy, so a controller that does not set the field behaves as before. The pod's groups come
// from the slices that list it on every call, so a group the pod has left contributes nothing.
func (r *PolicyEndpointsReconciler) policyEndpointsOf(ctx context.Context, namespace, podIdentifier string,
	refs []utils.PolicyEndpointRef) ([]*policyk8sawsv1.PolicyEndpoint, error) {
	policyEndpoints := make([]*policyk8sawsv1.PolicyEndpoint, 0, len(refs))
	groups := map[string]bool{}
	for _, ref := range refs {
		pe := &policyk8sawsv1.PolicyEndpoint{}
		if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, pe, client.UnsafeDisableDeepCopy); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		if pe.Spec.PolicyRef.Name != ref.Parent || !pe.DeletionTimestamp.IsZero() {
			continue
		}
		if pe.Spec.TargetGroup != "" && slices.ContainsFunc(pe.Spec.PodSelectorEndpoints, func(pod policyk8sawsv1.PodEndpoint) bool {
			return utils.GetPodIdentifier(pod.Name, pod.Namespace) == podIdentifier
		}) {
			groups[targetGroupKey(pe.Spec.PolicyRef.Name, pe.Spec.TargetGroup)] = true
		}
		policyEndpoints = append(policyEndpoints, pe)
	}
	return slices.DeleteFunc(policyEndpoints, func(pe *policyk8sawsv1.PolicyEndpoint) bool {
		return pe.Spec.TargetGroup != "" && !groups[targetGroupKey(pe.Spec.PolicyRef.Name, pe.Spec.TargetGroup)]
	}), nil
}

// targetGroupKey scopes a group to the policy that produced it. A group key is a content hash of
// the resolved ports, so two policies selecting the same pods can produce the same key for
// different pods, and a set keyed by the group alone would let one policy's group admit the other's.
func targetGroupKey(parentNP, targetGroup string) string {
	return parentNP + "/" + targetGroup
}

// firewallRulesFor returns the rule sets and pod state to program for the given policies. With
// no live PolicyEndpoint that is the baseline state; otherwise a direction with neither rules
// nor isolation allows everything.
func (r *PolicyEndpointsReconciler) firewallRulesFor(policyEndpoints []*policyk8sawsv1.PolicyEndpoint) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, int) {
	if len(policyEndpoints) == 0 {
		return nil, nil, r.baselinePodState()
	}
	ingressRules, egressRules, isIngressIsolated, isEgressIsolated := r.deriveFirewallRules(policyEndpoints)
	if len(ingressRules) == 0 && !isIngressIsolated {
		r.addCatchAllEntry(&ingressRules)
	}
	if len(egressRules) == 0 && !isEgressIsolated {
		r.addCatchAllEntry(&egressRules)
	}
	return ingressRules, egressRules, ebpf.POLICIES_APPLIED
}

// baselinePodState is the pod state of a pod no policy applies to.
func (r *PolicyEndpointsReconciler) baselinePodState() int {
	if utils.IsStrictMode(r.ebpfClient.GetNetworkPolicyMode()) {
		return DEFAULT_DENY
	}
	return DEFAULT_ALLOW
}

func (r *PolicyEndpointsReconciler) deriveFirewallRules(policyEndpoints []*policyk8sawsv1.PolicyEndpoint) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, bool, bool) {
	var ingressRules, egressRules []fwrp.EbpfFirewallRules
	isIngressIsolated, isEgressIsolated := false, false

	for _, currentPE := range policyEndpoints {
		// currentPE is shared with the informer cache (UnsafeDisableDeepCopy). slices.Clip
		// makes appends to Except/L4Info reallocate, but their existing elements, and the
		// Protocol/Port/EndPort pointers inside each Port, still belong to the cache: rule
		// processing must treat them as read-only. Guarded by
		// TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged.
		for _, endPointInfo := range currentPE.Spec.Ingress {
			ingressRules = append(ingressRules,
				fwrp.EbpfFirewallRules{
					IPCidr: endPointInfo.CIDR,
					Except: slices.Clip(endPointInfo.Except),
					L4Info: slices.Clip(endPointInfo.Ports),
				})
		}

		for _, endPointInfo := range currentPE.Spec.Egress {
			if endPointInfo.CIDR == "" && endPointInfo.DomainName == "" {
				log().Warnf("both CIDR and DomainName are empty in PE name %s, NS: %s", currentPE.Name, currentPE.Namespace)
				continue
			}
			if endPointInfo.CIDR == "" {
				log().Infof("CIDR is empty, skipping the egress rule %s, NS: %s", currentPE.Name, currentPE.Namespace)
				continue
			}

			egressRules = append(egressRules,
				fwrp.EbpfFirewallRules{
					IPCidr: endPointInfo.CIDR,
					Except: slices.Clip(endPointInfo.Except),
					L4Info: slices.Clip(endPointInfo.Ports),
				})
		}
		ingressIsolated, egressIsolated := r.deriveDefaultPodIsolation(currentPE, len(ingressRules), len(egressRules))
		isIngressIsolated = isIngressIsolated || ingressIsolated
		isEgressIsolated = isEgressIsolated || egressIsolated
	}
	log().Infof("Total no.of - ingressRules %d egressRules %d", len(ingressRules), len(egressRules))
	if len(ingressRules) > 0 {
		isIngressIsolated = false
	}
	if len(egressRules) > 0 {
		isEgressIsolated = false
	}
	return ingressRules, egressRules, isIngressIsolated, isEgressIsolated
}

func (r *PolicyEndpointsReconciler) deriveDefaultPodIsolation(policyEndpoint *policyk8sawsv1.PolicyEndpoint,
	ingressRulesCount, egressRulesCount int) (bool, bool) {
	isIngressIsolated, isEgressIsolated := false, false

	for _, value := range policyEndpoint.Spec.PodIsolation {
		if value == networking.PolicyTypeIngress && ingressRulesCount == 0 {
			log().Info("Default Deny enabled on Ingress")
			isIngressIsolated = true
		}
		if value == networking.PolicyTypeEgress && egressRulesCount == 0 {
			log().Info("Default Deny enabled on Egress")
			isEgressIsolated = true
		}
	}
	return isIngressIsolated, isEgressIsolated
}

func (r *PolicyEndpointsReconciler) updateeBPFMaps(podIdentifier string,
	ingressRules, egressRules []fwrp.EbpfFirewallRules, state int) error {

	// Map Update should only happen once for those that share the same Map
	if err := r.ebpfClient.UpdateEbpfMaps(podIdentifier, ingressRules, egressRules); err != nil {
		return fmt.Errorf("update ingress/egress maps for podIdentifier %s: %w", podIdentifier, err)
	}

	if err := r.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.POD_STATE_MAP_KEY, state, true, true); err != nil {
		return fmt.Errorf("update pod_state map for podIdentifier %s: %w", podIdentifier, err)
	}

	if err := r.ebpfClient.CreatePodStateEbpfEntryIfNotExists(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, ebpf.DEFAULT_ALLOW); err != nil {
		return fmt.Errorf("seed cluster-policy pod_state for podIdentifier %s: %w", podIdentifier, err)
	}
	return nil
}

func (r *PolicyEndpointsReconciler) addCatchAllEntry(firewallRules *[]fwrp.EbpfFirewallRules) {
	//Add allow-all entry to firewall rule set
	var catchAllCIDR string
	if r.enableIPv6 {
		catchAllCIDR = "::/0"
	} else {
		catchAllCIDR = "0.0.0.0/0"
	}
	*firewallRules = append(*firewallRules,
		fwrp.EbpfFirewallRules{
			IPCidr: policyk8sawsv1.NetworkAddress(catchAllCIDR),
		})
}

// SetupWithManager sets up both stages with the Manager: the PolicyEndpoint controller on a
// single worker, and the programming controller on programmingWorkers.
func (r *PolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, programmingWorkers int) error {
	if err := setupEndpointController(mgr, "policyendpoint", &policyk8sawsv1.PolicyEndpoint{},
		policyEndpointParent, r, controller.TypedOptions[EndpointRequest]{}); err != nil {
		return err
	}
	return setupProgrammer(mgr, policyEndpointProgrammerName, r.programQueue, programmingWorkers, r.programIdentifier)
}

func policyEndpointParent(pe *policyk8sawsv1.PolicyEndpoint) string { return pe.Spec.PolicyRef.Name }

// derivePolicyEndpointsOfParentNP returns the parent NetworkPolicy's live slices as objects,
// mirroring getClusterPolicyEndpointsOfParentCNP. A slice being deleted is left out, so it stops
// contributing as soon as its deletion starts.
func (r *PolicyEndpointsReconciler) derivePolicyEndpointsOfParentNP(ctx context.Context, parentNP, resourceNamespace string) ([]policyk8sawsv1.PolicyEndpoint, error) {
	policyEndpointList := &policyk8sawsv1.PolicyEndpointList{}
	if err := r.k8sClient.List(ctx, policyEndpointList, &client.ListOptions{
		Namespace: resourceNamespace,
	}, client.UnsafeDisableDeepCopy); err != nil {
		// A List failure is propagated, never reported as an empty list. An empty parent PE list
		// reads as "this NetworkPolicy is fully deleted" and tears down enforcement, so
		// collapsing a transient API/cache error into that case would open traffic.
		return nil, fmt.Errorf(
			"list PolicyEndpoints in namespace %q: %w",
			resourceNamespace,
			err,
		)
	}

	var parentPolicyEndpoints []policyk8sawsv1.PolicyEndpoint
	for _, policyEndpoint := range policyEndpointList.Items {
		if policyEndpoint.Spec.PolicyRef.Name == parentNP && policyEndpoint.DeletionTimestamp.IsZero() {
			parentPolicyEndpoints = append(parentPolicyEndpoints, policyEndpoint)
		}
	}
	return parentPolicyEndpoints, nil
}

func (r *PolicyEndpointsReconciler) GeteBPFClient() ebpf.BpfClient {
	return r.ebpfClient
}

func (r *PolicyEndpointsReconciler) DeriveFireWallRulesPerPodIdentifier(podIdentifier string, podNamespace string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, error) {

	// The CNI ADD writes these rules, with every policy that selects the identifier.
	r.deleteCleanups.forget(podIdentifier)
	policyEndpoints, err := r.policyEndpointsOf(context.Background(), podNamespace, podIdentifier, r.policyEndpointRefs(podIdentifier))
	if err != nil {
		log().Errorf("Error deriving firewall rules: %v", err)
		return nil, nil, nil
	}
	ingressRules, egressRules, isIngressIsolated, isEgressIsolated := r.deriveFirewallRules(policyEndpoints)

	if len(ingressRules) == 0 && !isIngressIsolated {
		// No active ingress rules for this pod, but we only should land here
		// if there are active egress rules. So, we need to add an allow-all entry to ingress rule set
		log().Info("No Ingress rules and no ingress isolation - Appending catch all entry")
		r.addCatchAllEntry(&ingressRules)
	}

	if len(egressRules) == 0 && !isEgressIsolated {
		// No active egress rules for this pod but we only should land here
		// if there are active ingress rules. So, we need to add an allow-all entry to egress rule set
		log().Info("No Egress rules and no egress isolation - Appending catch all entry")
		r.addCatchAllEntry(&egressRules)
	}

	return ingressRules, egressRules, nil
}

func (r *PolicyEndpointsReconciler) ArePoliciesAvailableInLocalCache(podIdentifier string) bool {
	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		if len(policyEndpointList.([]utils.PolicyEndpointRef)) > 0 {
			log().Infof("Active policies available against podIdentifier %s", podIdentifier)
			return true
		}
	}
	return false
}
