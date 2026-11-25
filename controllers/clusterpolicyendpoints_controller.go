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
	"net"
	"slices"
	"sync"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
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
)

var (
	// Buckets for latency
	clusterPolicyProgrammingLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "awsnodeagent_cluster_policy_programming_latency_seconds",
			Help: "E2E latency from NPC ClusterPolicyEndpoint change to NPA eBPF map programming, in seconds",
			Buckets: append(append(append(
				prometheus.LinearBuckets(0.25, 0.25, 2), // 0.25, 0.50
				prometheus.LinearBuckets(1, 1, 59)...),  // 1, 2, 3, ..., 59
				prometheus.LinearBuckets(60, 5, 12)...), // 60, 65, 70, ..., 115
				prometheus.LinearBuckets(120, 30, 7)...), // 120, 150, 180, ..., 300
		},
	)
	clusterPolicyPrometheusRegistered = false
)

func clusterPolicyPrometheusRegister() {
	if !clusterPolicyPrometheusRegistered {
		metrics.Registry.MustRegister(clusterPolicyProgrammingLatency)
		clusterPolicyPrometheusRegistered = true
	}
}

// NewClusterPolicyEndpointsReconciler constructs new ClusterPolicyEndpointReconciler
func NewClusterPolicyEndpointsReconciler(k8sClient client.Client, nodeIP string, ebpfClient ebpf.BpfClient) *ClusterPolicyEndpointsReconciler {
	r := &ClusterPolicyEndpointsReconciler{
		k8sClient:          k8sClient,
		nodeIP:             nodeIP,
		ebpfClient:         ebpfClient,
		trackerStartTime:   time.Now(),
		programQueue:       newProgrammingQueue(clusterPolicyEndpointProgrammerName),
		programmingLatency: newProgrammingLatencyTracker(clusterPolicyProgrammingLatency),
	}
	clusterPolicyPrometheusRegister()
	return r
}

// ClusterPolicyEndpointsReconciler reconciles an ClusterPolicyEndpoint object
type ClusterPolicyEndpointsReconciler struct {
	// k8sClient reads ClusterPolicyEndpoints with client.UnsafeDisableDeepCopy: returned objects
	// are shared with the informer cache and must not be mutated.
	k8sClient client.Client
	scheme    *runtime.Scheme
	nodeIP    string
	// trackerStartTime records when this reconciler started. Used to filter
	// stale ClusterPolicyEndpoint annotations and avoid emitting artificially high
	// E2E latency on restart
	trackerStartTime time.Time
	// lastObservedTriggerTimes maps a CPE's EndpointRequest to the last
	// last-change-trigger-time annotation value consumed, so each trigger
	// time is observed at most once
	lastObservedTriggerTimes sync.Map
	programmingLatency       *programmingLatencyTracker

	// What each ClusterNetworkPolicy selects, as of its last reconcile. Only the
	// ClusterPolicyEndpoint reconcile writes these, on a single worker; the programming workers
	// and the CNI RPC path read them concurrently.
	//
	// Maps a pod identifier to the live ClusterPolicyEndpoints ([]utils.PolicyEndpointRef) of
	// every ClusterNetworkPolicy that selects a pod of that identifier on any node
	podIdentifierToClusterPolicyEndpointMap sync.Map
	// Serializes writes to podIdentifierToClusterPolicyEndpointMap
	podIdentifierToClusterPolicyEndpointMapMutex sync.Mutex
	// Maps a ClusterNetworkPolicy to the pod identifiers it selects on any node ([]string)
	clusterNetworkPolicyToPodIdentifierMap sync.Map
	// Maps a ClusterNetworkPolicy to the pods it selects on this node, by pod identifier
	// (map[string][]npatypes.Pod)
	clusterNetworkPolicyToLocalPodsMap sync.Map

	// Pod identifiers whose cluster-policy eBPF maps need programming
	programQueue priorityqueue.PriorityQueue[string]
	// queuePeer queues an identifier on the PolicyEndpoint programmer (LinkProgrammers). Nil when
	// this reconciler runs alone.
	queuePeer func(podIdentifier string)

	ebpfClient ebpf.BpfClient
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints/status,verbs=get

func (r *ClusterPolicyEndpointsReconciler) Reconcile(ctx context.Context, req EndpointRequest) (ctrl.Result, error) {
	log().Infof("Received a new reconcile request for ClusterPolicyEndpoint %v", req)
	if err := r.reconcile(ctx, req); err != nil {
		log().Errorf("ClusterPolicyEndpoint reconcile error: %v", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// reconcile is stage 1 for one slice event: it recomputes the slice's parent
// ClusterNetworkPolicy and queues the identifiers to program. A slice that is gone, being
// deleted, or now owned by another parent simply no longer contributes to req.Parent; its new
// parent has its own request.
func (r *ClusterPolicyEndpointsReconciler) reconcile(ctx context.Context, req EndpointRequest) error {
	clusterPolicyEndpoint := &policyk8sawsv1.ClusterPolicyEndpoint{}
	live := true
	// Cluster-scoped: use only name, no namespace
	if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: req.Endpoint.Name}, clusterPolicyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if !apierrors.IsNotFound(err) {
			log().Errorf("Unable to get cluster policy endpoint spec for ClusterPolicyendpoint %s: %v", req.Endpoint.Name, err)
			return err
		}
		live = false
	} else if clusterPolicyEndpoint.Spec.PolicyRef.Name != req.Parent || !clusterPolicyEndpoint.DeletionTimestamp.IsZero() {
		live = false
	}
	if !live {
		r.lastObservedTriggerTimes.Delete(req)
	}

	queued, err := r.reconcileClusterNetworkPolicy(ctx, req.Parent)
	if err != nil {
		return err
	}
	if live {
		if triggeredAt, ok := changeTriggerTime(clusterPolicyEndpoint.Annotations, r.trackerStartTime, req, &r.lastObservedTriggerTimes); ok {
			r.programmingLatency.track(triggeredAt, queued)
		}
	}
	queueIdentifiers(r.programQueue, queued)
	log().Debugf("Reconciled ClusterNetworkPolicy %s for %s: queued %d identifier(s)",
		req.Parent, req.Endpoint.Name, len(queued))
	return nil
}

// reconcileClusterNetworkPolicy recomputes what parentCNPName selects from its live
// ClusterPolicyEndpoints and records it. It returns the pod identifiers whose maps on this node
// may have changed.
func (r *ClusterPolicyEndpointsReconciler) reconcileClusterNetworkPolicy(ctx context.Context, parentCNPName string) ([]string, error) {
	clusterPolicyEndpoints, err := r.getClusterPolicyEndpointsOfParentCNP(ctx, parentCNPName)
	if err != nil {
		return nil, err
	}
	names := lo.Map(clusterPolicyEndpoints, func(cpe policyk8sawsv1.ClusterPolicyEndpoint, _ int) string { return cpe.Name })
	selected, localPods := r.selectedPods(clusterPolicyEndpoints)

	for podIdentifier := range selected {
		utils.SetParentPolicyEndpoints(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex,
			podIdentifier, parentCNPName, names)
	}
	stale := utils.DeriveStalePodIdentifiers(&r.clusterNetworkPolicyToPodIdentifierMap, parentCNPName, selected)
	for _, podIdentifier := range stale {
		utils.DeleteParentFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap,
			&r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCNPName)
	}

	var priorLocalPods map[string][]npatypes.Pod
	if v, ok := r.clusterNetworkPolicyToLocalPodsMap.Load(parentCNPName); ok {
		priorLocalPods = v.(map[string][]npatypes.Pod)
	}
	commitPolicySelection(&r.clusterNetworkPolicyToPodIdentifierMap, &r.clusterNetworkPolicyToLocalPodsMap,
		parentCNPName, selected, localPods)

	log().Infof("ClusterNetworkPolicy %s: %d ClusterPolicyEndpoint(s) select %d identifier(s), %d with pods on this node, %d no longer selected",
		parentCNPName, len(clusterPolicyEndpoints), len(selected), len(localPods), len(stale))
	return identifiersToProgram(localPods, priorLocalPods, stale, len(clusterPolicyEndpoints) == 0), nil
}

// selectedPods returns every pod identifier the ClusterPolicyEndpoints select on any node, and
// their selected pods on this node by identifier.
func (r *ClusterPolicyEndpointsReconciler) selectedPods(clusterPolicyEndpoints []policyk8sawsv1.ClusterPolicyEndpoint) (map[string]bool,
	map[string][]npatypes.Pod) {
	selected := make(map[string]bool)
	localPods := make(map[string][]npatypes.Pod)
	nodeIP := net.ParseIP(r.nodeIP)
	for i := range clusterPolicyEndpoints {
		cpe := &clusterPolicyEndpoints[i]
		for _, pod := range cpe.Spec.PodSelectorEndpoints {
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			selected[podIdentifier] = true
			if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
				localPods[podIdentifier] = append(localPods[podIdentifier], npatypes.Pod{
					NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, PodIP: pod.PodIP})
			}
		}
	}
	for podIdentifier, pods := range localPods {
		localPods[podIdentifier] = uniquePods(pods)
	}
	return selected, localPods
}

// programIdentifier is stage 2 for one pod identifier. It brings the identifier's cluster-policy
// eBPF maps in line with every ClusterNetworkPolicy recorded as selecting it, attaching probes
// for its selected pods on this node first. Any failure, including an attach failure after the
// maps were written, is returned so the identifier is retried: on this path a missed write can
// leave a required Deny rule unapplied.
func (r *ClusterPolicyEndpointsReconciler) programIdentifier(ctx context.Context, podIdentifier string) error {
	changes := r.programmingLatency.begin(podIdentifier)
	pass, err := r.programIdentifierMaps(ctx, podIdentifier)
	if err != nil {
		log().Errorf("Programming cluster policies for podIdentifier %s failed, will retry: %v", podIdentifier, err)
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
func (r *ClusterPolicyEndpointsReconciler) programIdentifierMaps(ctx context.Context, podIdentifier string) (programmingPass, error) {
	refs := r.clusterPolicyEndpointRefs(podIdentifier)
	parents := lo.Map(refs, func(ref utils.PolicyEndpointRef, _ int) string { return ref.Parent })
	attached, attachErr := attachProbesForIdentifier(r.ebpfClient, podIdentifier,
		localPodsOf(&r.clusterNetworkPolicyToLocalPodsMap, podIdentifier, parents))
	// Programs this attach created have empty maps for both policy types. Queue the other
	// programmer before writing, so that it writes its policies even if this pass then fails.
	if attached.createdContext && r.queuePeer != nil {
		r.queuePeer(podIdentifier)
	}

	// The identifier's pods left the node, or none could attach yet: there is nothing to program.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		return programmingPass{skipped: attached.skipped}, attachErr
	}

	clusterPolicyEndpoints, err := r.clusterPolicyEndpointsOf(ctx, refs)
	if err != nil {
		return programmingPass{}, errors.Join(attachErr, fmt.Errorf("get cluster policy endpoints for podIdentifier %s: %w", podIdentifier, err))
	}
	ingressRules, egressRules := r.deriveClusterPolicyFirewallRules(clusterPolicyEndpoints)
	if err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules); err != nil {
		return programmingPass{}, errors.Join(attachErr, err)
	}
	return programmingPass{wrote: true, skipped: attached.skipped}, attachErr
}

func (r *ClusterPolicyEndpointsReconciler) clusterPolicyEndpointRefs(podIdentifier string) []utils.PolicyEndpointRef {
	if refs, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		return refs.([]utils.PolicyEndpointRef)
	}
	return nil
}

// clusterPolicyEndpointsOf resolves refs against the informer cache, dropping slices that are
// gone, being deleted, or whose name was reused under another parent.
func (r *ClusterPolicyEndpointsReconciler) clusterPolicyEndpointsOf(ctx context.Context,
	refs []utils.PolicyEndpointRef) ([]*policyk8sawsv1.ClusterPolicyEndpoint, error) {
	clusterPolicyEndpoints := make([]*policyk8sawsv1.ClusterPolicyEndpoint, 0, len(refs))
	for _, ref := range refs {
		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{}
		// Cluster-scoped: no namespace
		if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: ref.Name}, cpe, client.UnsafeDisableDeepCopy); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		if cpe.Spec.PolicyRef.Name != ref.Parent || !cpe.DeletionTimestamp.IsZero() {
			continue
		}
		clusterPolicyEndpoints = append(clusterPolicyEndpoints, cpe)
	}
	return clusterPolicyEndpoints, nil
}

func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyBPFMaps(podIdentifier string, ingressRules, egressRules []fwrp.EbpfFirewallRules) error {

	state := ebpf.POLICIES_APPLIED

	err := r.ebpfClient.UpdateClusterPolicyEbpfMaps(podIdentifier, ingressRules, egressRules)
	if err != nil {
		return fmt.Errorf("update cluster policy maps for podIdentifier %s: %w", podIdentifier, err)
	}

	if len(ingressRules) == 0 && len(egressRules) == 0 {
		// Default state for cluster network policies when no rules are applied
		state = ebpf.DEFAULT_ALLOW
	}

	err = r.ebpfClient.UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, state, true, true)
	if err != nil {
		return fmt.Errorf("update cluster-policy pod_state for podIdentifier %s: %w", podIdentifier, err)
	}

	defaultState := ebpf.DEFAULT_ALLOW
	if utils.IsStrictMode(r.ebpfClient.GetNetworkPolicyMode()) {
		defaultState = ebpf.DEFAULT_DENY
	}

	// TODO: Can be optimized to avoid redundant createIfNotExists calls
	if err := r.ebpfClient.CreatePodStateEbpfEntryIfNotExists(podIdentifier, ebpf.POD_STATE_MAP_KEY, defaultState); err != nil {
		return fmt.Errorf("seed pod_state for podIdentifier %s: %w", podIdentifier, err)
	}
	return nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyFirewallRules(clusterPolicyEndpoints []*policyk8sawsv1.ClusterPolicyEndpoint) ([]fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules) {
	var clusterPolicyIngressRules, clusterPolicyEgressRules []fwrp.EbpfFirewallRules

	for _, currentCPE := range clusterPolicyEndpoints {
		// currentCPE is shared with the informer cache (UnsafeDisableDeepCopy). slices.Clip
		// makes appends to L4Info reallocate, but its existing elements, and the
		// Protocol/Port/EndPort pointers inside each Port, still belong to the cache: rule
		// processing must treat them as read-only. Guarded by
		// TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged.
		for _, endPointInfo := range currentCPE.Spec.Ingress {
			priority := int(currentCPE.Spec.Priority)
			if currentCPE.Spec.Tier == policyk8sawsv1.BaselineTier {
				priority += fwrp.BASELINE_TIER_PRIORITY_OFFSET
			}
			clusterPolicyIngressRules = append(clusterPolicyIngressRules, fwrp.EbpfFirewallRules{
				Priority: priority,
				Action:   endPointInfo.Action,
				IPCidr:   endPointInfo.CIDR,
				L4Info:   slices.Clip(endPointInfo.Ports),
			})
		}

		for _, endPointInfo := range currentCPE.Spec.Egress {

			if endPointInfo.CIDR == "" && endPointInfo.DomainName == "" {
				log().Warnf("both CIDR and DomainName are empty in PE name %s", currentCPE.Name)
				continue
			}

			if endPointInfo.CIDR == "" {
				log().Infof("CIDR is empty, skipping the egress rule %s", currentCPE.Name)
				continue
			}

			priority := int(currentCPE.Spec.Priority)
			if currentCPE.Spec.Tier == policyk8sawsv1.BaselineTier {
				priority += fwrp.BASELINE_TIER_PRIORITY_OFFSET
			}
			clusterPolicyEgressRules = append(clusterPolicyEgressRules, fwrp.EbpfFirewallRules{
				Priority:   priority,
				Action:     endPointInfo.Action,
				DomainName: string(endPointInfo.DomainName),
				IPCidr:     endPointInfo.CIDR,
				L4Info:     slices.Clip(endPointInfo.Ports),
			})
		}
		log().Infof("Total no.of clusterPolicy ingressRules %d egressRules %d", len(clusterPolicyIngressRules), len(clusterPolicyEgressRules))
	}
	return clusterPolicyIngressRules, clusterPolicyEgressRules
}

// getClusterPolicyEndpointsOfParentCNP returns the parent CNP's live CPEs. A CPE being deleted
// is left out, so it stops contributing as soon as its deletion starts. Callers must distinguish
// an empty result from a List failure: reading a transient API error as "no CPEs left" would
// clear eBPF Deny rules and open traffic.
func (r *ClusterPolicyEndpointsReconciler) getClusterPolicyEndpointsOfParentCNP(ctx context.Context, parentCNP string) ([]policyk8sawsv1.ClusterPolicyEndpoint, error) {
	ClusterPolicyEndpointList := &policyk8sawsv1.ClusterPolicyEndpointList{}
	// Cluster-scoped: no namespace filter
	if err := r.k8sClient.List(ctx, ClusterPolicyEndpointList, &client.ListOptions{}, client.UnsafeDisableDeepCopy); err != nil {
		log().Errorf("Unable to list ClusterPolicyEndpoints err: %v", err)
		return nil, err
	}

	var parentClusterPolicyEndpoints []policyk8sawsv1.ClusterPolicyEndpoint
	for _, ClusterPolicyEndpoint := range ClusterPolicyEndpointList.Items {
		if ClusterPolicyEndpoint.Spec.PolicyRef.Name == parentCNP && ClusterPolicyEndpoint.DeletionTimestamp.IsZero() {
			parentClusterPolicyEndpoints = append(parentClusterPolicyEndpoints, ClusterPolicyEndpoint)
		}
	}
	return parentClusterPolicyEndpoints, nil
}

func (r *ClusterPolicyEndpointsReconciler) DeriveClusterPolicyFireWallRulesPerPodIdentifier(ctx context.Context, podIdentifier string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, error) {

	clusterPolicyEndpoints, err := r.clusterPolicyEndpointsOf(ctx, r.clusterPolicyEndpointRefs(podIdentifier))
	if err != nil {
		log().Errorf("Error deriving cluster firewall rules: %v", err)
		return nil, nil, err
	}
	clusterPolicyIngressRules, clusterPolicyEgressRules := r.deriveClusterPolicyFirewallRules(clusterPolicyEndpoints)
	return clusterPolicyIngressRules, clusterPolicyEgressRules, nil
}

func (r *ClusterPolicyEndpointsReconciler) ArePoliciesAvailableInLocalCache(podIdentifier string) bool {
	if policyEndpointList, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		if len(policyEndpointList.([]utils.PolicyEndpointRef)) > 0 {
			log().Infof("Active cluster policies available against podIdentifier %s", podIdentifier)
			return true
		}
	}
	return false
}

func (r *ClusterPolicyEndpointsReconciler) GeteBPFClient() ebpf.BpfClient {
	return r.ebpfClient
}

// SetupWithManager sets up both stages with the Manager: the ClusterPolicyEndpoint controller on
// stageOneWorkerCount workers, and the programming controller on programmingWorkerCount.
func (r *ClusterPolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupEndpointController(mgr, "clusterpolicyendpoint", &policyk8sawsv1.ClusterPolicyEndpoint{},
		clusterPolicyEndpointParent, r, controller.TypedOptions[EndpointRequest]{MaxConcurrentReconciles: stageOneWorkerCount}); err != nil {
		return err
	}
	return setupProgrammer(mgr, clusterPolicyEndpointProgrammerName, r.programQueue, r.programIdentifier)
}

func clusterPolicyEndpointParent(cpe *policyk8sawsv1.ClusterPolicyEndpoint) string {
	return cpe.Spec.PolicyRef.Name
}
