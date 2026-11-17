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
		k8sClient:        k8sClient,
		nodeIP:           nodeIP,
		ebpfClient:       ebpfClient,
		trackerStartTime: time.Now(),
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

	// Maps pod Identifier to list of ClusterPolicyEndpoint resources ([]utils.PolicyEndpointRef)
	podIdentifierToClusterPolicyEndpointMap      sync.Map
	podIdentifierToClusterPolicyEndpointMapMutex sync.Mutex
	// Maps a ClusterPolicyEndpoint's EndpointRequest to a list of local pods
	ClusterPolicyEndpointSelectorMap sync.Map
	// Maps ClusterNetworkPolicy to list of selected pod Identifiers
	clusterNetworkPolicyToPodIdentifierMap sync.Map

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

func (r *ClusterPolicyEndpointsReconciler) reconcile(ctx context.Context, req EndpointRequest) error {
	ClusterPolicyEndpoint := &policyk8sawsv1.ClusterPolicyEndpoint{}
	// Cluster-scoped: use only name, no namespace
	if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: req.Endpoint.Name}, ClusterPolicyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanUpClusterPolicyEndpoint(ctx, req)
		}
		log().Errorf("Unable to get cluster policy endpoint spec for ClusterPolicyendpoint %s: %v", req.Endpoint.Name, err)
		return err
	}
	// A slice now owned by another parent is gone from req.Parent; its new parent has its own request
	if ClusterPolicyEndpoint.Spec.PolicyRef.Name != req.Parent || !ClusterPolicyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpClusterPolicyEndpoint(ctx, req)
	}
	return r.reconcileClusterPolicyEndpoint(ctx, ClusterPolicyEndpoint)
}

// cleanUpClusterPolicyEndpoint removes the slice's contribution under req.Parent and reprograms
// the parent's remaining slices. It touches only state recorded under req.Parent, so it is safe
// to repeat and to run before or after the slice's reconcile under a new parent.
func (r *ClusterPolicyEndpointsReconciler) cleanUpClusterPolicyEndpoint(ctx context.Context, req EndpointRequest) error {
	log().Infof("Clean Up ClusterPolicyEndpoint resources for %s under %s", req.Endpoint.Name, req.Parent)

	r.lastObservedTriggerTimes.Delete(req)

	parentCNPName := req.Parent
	resourceName := req.Endpoint.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, err :=
		r.deriveTargetPodsForParentCNP(ctx, parentCNPName, resourceName)
	if err != nil {
		return err
	}

	// Remove the deleted CPE's entry from the identifiers whose local pods it tracked under this
	// parent. Derive prunes entries only for identifiers that went stale, i.e. ones the parent no
	// longer selects anywhere, so an identifier still selected via a sibling CPE keeps this entry.
	// Later reconciles read these entries, so the departing one has to be scrubbed here.
	//
	// A retry may see a smaller set than the first pass did. If the object no longer exists, it will have the pods that failed cleanup
	// and if the object still exists, it will have all the target pods.
	// and DeletePolicyEndpointFromPodIdentifierMap is idempotent either way.
	if existingPods, ok := r.ClusterPolicyEndpointSelectorMap.Load(req); ok {
		for _, pod := range existingPods.([]npatypes.Pod) {
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier,
				utils.PolicyEndpointRef{Name: resourceName, Parent: parentCNPName})
		}
	}

	log().Infof("cleanUpClusterPolicyEndpoint: Pods to cleanup - %d and Pods to be updated - %d", len(podsToBeCleanedUp), len(targetPods))

	_, _, updateErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, parentCNPName, targetPods, targetPodIdentifiers, false)
	if updateErr != nil {
		log().Errorf("failed to update cluster policy bpf probes for policy endpoint %s : %v", resourceName, updateErr)
	}
	failedCleanups, _, cleanupErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, parentCNPName, podsToBeCleanedUp, targetPodIdentifiers, true)
	if cleanupErr != nil {
		log().Errorf("failed to clean up cluster policy bpf probes for policy endpoint %s : %v", resourceName, cleanupErr)
	}

	// Same tracking as reconcileClusterPolicyEndpoint.
	trackedPods, trackedPodIdentifiers := trackFailedCleanups(targetPods, failedCleanups, clusterWidePodIdentifiers)
	r.commitClusterPolicyEndpointState(parentCNPName, trackedPods, trackedPodIdentifiers, parentCPEList)

	// Until every cleanup succeeds, the deleted CPE's entry holds the ones that failed, so the
	// retry repeats only those. If the CPE is in parentCPEList (its deletion is in progress,
	// or it is the parent's last CPE), the commit above has already written its entry.
	err = errors.Join(updateErr, cleanupErr)
	if !slices.Contains(parentCPEList, resourceName) {
		// Gate on the failures themselves, not on err: updateErr can be set with nothing owed
		// a cleanup, and storing an empty set would leave an entry keyed by a deleted CPE.
		if len(failedCleanups) > 0 {
			r.ClusterPolicyEndpointSelectorMap.Store(req, failedCleanups)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(req)
		}
	}
	return err
}

func (r *ClusterPolicyEndpointsReconciler) reconcileClusterPolicyEndpoint(ctx context.Context, ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint) error {
	log().Infof("Processing Cluster Policy Endpoint Name: %s", ClusterPolicyEndpoint.Name)

	parentCNPName := ClusterPolicyEndpoint.Spec.PolicyRef.Name
	resourceName := ClusterPolicyEndpoint.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, err :=
		r.deriveTargetPodsForParentCNP(ctx, parentCNPName, resourceName)
	if err != nil {
		return err
	}

	// Programming runs whether or not cleanup succeeded, so a failing cleanup does not hold
	// back the other pods this CPE selects.
	failedCleanups, cleaned, cleanupErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, parentCNPName, podsToBeCleanedUp, targetPodIdentifiers, false)
	if cleanupErr != nil {
		log().Errorf("failed to update cluster policy enforcement status for existing pods: %v", cleanupErr)
	}

	// Track the pods programmed below, so they can be cleaned up later, and the pods whose
	// cleanup failed, so the retry and the CPE delete flow still find them.
	trackedPods, trackedPodIdentifiers := trackFailedCleanups(targetPods, failedCleanups, clusterWidePodIdentifiers)
	r.commitClusterPolicyEndpointState(parentCNPName, trackedPods, trackedPodIdentifiers, parentCPEList)

	programmed := 0
	skipped := 0
	var programmingErr error
	for podIdentifier := range targetPodIdentifiers {
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, parentCNPName, false)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resource %s for podIdentifier %s: %v", ClusterPolicyEndpoint.Name, podIdentifier, err)
			programmingErr = errors.Join(programmingErr, err)
			continue
		}
		result, err := r.configureClusterPolicyBPFProbes(podIdentifier, targetPods, ingressRules, egressRules)
		switch {
		case err != nil:
			// Checked before the skip case: a skip travels in result, not in err, so a real
			// failure is never mistaken for one. On this path a masked failure can leave a
			// required Deny rule unapplied, so it must reach the requeue.
			log().Errorf("Error configuring Cluster Policy eBPF Probes for podIdentifier %s: %v", podIdentifier, err)
			programmingErr = errors.Join(programmingErr, err)
		case result.programmed:
			programmed++
		case result.skipped > 0:
			// Retrying cannot resolve this, so do not report it as a failure.
			skipped += result.skipped
			log().Warnf("Skipped cluster policy eBPF programming for podIdentifier %s: %d pod(s) cannot attach yet",
				podIdentifier, result.skipped)
		default:
			log().Debugf("No cluster policy eBPF programming needed for podIdentifier %s on this node", podIdentifier)
		}
	}

	// See the PolicyEndpoint path for why this is three-way rather than a bool. A failing
	// pass defers, a pass that wrote something records, and a pass with nothing to do on this
	// node consumes the trigger without a sample so a later resync cannot report the age of
	// the annotation as programming latency. Cleanup writes count as work.
	outcome := programmingNoWork
	switch {
	case cleanupErr != nil || programmingErr != nil:
		outcome = programmingDeferred
	case programmed > 0 || cleaned > 0:
		outcome = programmingLanded
	case skipped > 0:
		// Deferred rather than consumed: see the PolicyEndpoint path. These pods are local
		// and a later pass can still program them.
		outcome = programmingDeferred
	}
	r.observeClusterPolicyProgrammingLatency(ClusterPolicyEndpoint, outcome)

	return errors.Join(cleanupErr, programmingErr)
}

// observeClusterPolicyProgrammingLatency emits the E2E latency histogram from
// the last-change-trigger-time annotation. Each annotation value is observed at
// most once per CPE: it is consumed once the change has landed, so stale
// rewrites/resyncs/relists never re-observe it.
//
// A pass that has not landed the change leaves the annotation unconsumed, so the
// later pass that does land it reports the full time including any retry delay.
func (r *ClusterPolicyEndpointsReconciler) observeClusterPolicyProgrammingLatency(cpe *policyk8sawsv1.ClusterPolicyEndpoint, outcome policyProgrammingOutcome) {
	if cpe.Annotations == nil {
		return
	}
	triggerTimeStr, ok := cpe.Annotations[LastChangeTriggerTimeAnnotation]
	if !ok || triggerTimeStr == "" {
		return
	}
	triggerTime, err := time.Parse(time.RFC3339Nano, triggerTimeStr)
	if err != nil {
		log().Debugf("Failed to parse %s annotation: %v", LastChangeTriggerTimeAnnotation, err)
		return
	}
	if !triggerTime.After(r.trackerStartTime) {
		return
	}
	cpeKey := EndpointRequest{Endpoint: types.NamespacedName{Name: cpe.Name}, Parent: cpe.Spec.PolicyRef.Name}
	if prev, ok := r.lastObservedTriggerTimes.Load(cpeKey); ok && prev.(string) == triggerTimeStr {
		return
	}
	if outcome == programmingDeferred {
		// Left unconsumed on purpose: the pass that lands the change observes it.
		log().Debugf("Deferring E2E cluster policy programming latency for CPE %s: change has not landed yet", cpe.Name)
		return
	}
	// Consume before the suppression check below: the change has landed, so a
	// clock-skew-suppressed observation must not be re-emitted (inflated) by a
	// later resync of the same annotation.
	r.lastObservedTriggerTimes.Store(cpeKey, triggerTimeStr)
	if outcome == programmingNoWork {
		// Consumed without measuring: nothing on this node implements this change, so any
		// elapsed time here is the age of the annotation, not programming latency.
		log().Debugf("No local work for CPE %s: consuming trigger without a latency sample", cpe.Name)
		return
	}
	latency := time.Since(triggerTime).Seconds()
	if latency < 0 {
		// Clock skew between NPC (control plane) and this node
		log().Debugf("Skipping negative E2E cluster policy programming latency %.3fs for CPE %s", latency, cpe.Name)
		return
	}
	clusterPolicyProgrammingLatency.Observe(latency)
	log().Debugf("E2E cluster policy programming latency: %.3fs for CPE %s", latency, cpe.Name)
}

func (r *ClusterPolicyEndpointsReconciler) configureClusterPolicyBPFProbes(podIdentifier string, targetPods []npatypes.Pod, ingressRules, egressRules []fwrp.EbpfFirewallRules) (probeConfigResult, error) {
	attached, configureProbesErr := attachProbesForIdentifier(r.ebpfClient, podIdentifier, targetPods)
	result := probeConfigResult{skipped: attached.skipped}

	// AttacheBPFProbes skips pods already deleted from the node, so the CPE can still list a
	// pod that has no programs here. There is nothing to program until a new pod attaches, so
	// this returns without programmed set rather than claiming work it did not do.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		return result, configureProbesErr
	}

	// Program whatever did attach. updateClusterPolicyBPFMaps logs its own failure, and the
	// returned error is logged again by the caller, so it is not logged a third time here.
	if err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules); err != nil {
		return result, errors.Join(configureProbesErr, fmt.Errorf("cluster policy map updates failed for podIdentifier %s: %w", podIdentifier, err))
	}
	result.programmed = true
	return result, configureProbesErr
}

func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyBPFMaps(podIdentifier string, ingressRules, egressRules []fwrp.EbpfFirewallRules) error {

	state := ebpf.POLICIES_APPLIED

	err := r.ebpfClient.UpdateClusterPolicyEbpfMaps(podIdentifier, ingressRules, egressRules)
	if err != nil {
		log().Errorf("Cluster Policy Map update(s) failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}

	if len(ingressRules) == 0 && len(egressRules) == 0 {
		// Default state for cluster network policies when no rules are applied
		state = ebpf.DEFAULT_ALLOW
	}

	err = r.ebpfClient.UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, state, true, true)
	if err != nil {
		log().Errorf("Cluster Policy pod state maps update(s) failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}

	defaultState := ebpf.DEFAULT_ALLOW
	if utils.IsStrictMode(r.ebpfClient.GetNetworkPolicyMode()) {
		defaultState = ebpf.DEFAULT_DENY
	}

	// TODO: Can be optimized to avoid redundant createIfNotExists calls
	if err := r.ebpfClient.CreatePodStateEbpfEntryIfNotExists(podIdentifier, ebpf.POD_STATE_MAP_KEY, defaultState); err != nil {
		log().Errorf("Pod-state seed failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}
	return nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyIngressAndEgressFirewallRules(ctx context.Context, podIdentifier string, parentCNPName string, isDeleteFlow bool) ([]fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules, error) {

	var clusterPolicyIngressRules, clusterPolicyEgressRules []fwrp.EbpfFirewallRules
	currentCPE := &policyk8sawsv1.ClusterPolicyEndpoint{}

	if ClusterPolicyEndpointList, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		log().Infof("Total number of ClusterPolicyEndpoint resources for podIdentifier %s are %d", podIdentifier, len(ClusterPolicyEndpointList.([]utils.PolicyEndpointRef)))
		for _, ref := range ClusterPolicyEndpointList.([]utils.PolicyEndpointRef) {
			// Cluster-scoped: no namespace
			cpeNamespacedName := types.NamespacedName{Name: ref.Name}

			if err := r.k8sClient.Get(ctx, cpeNamespacedName, currentCPE, client.UnsafeDisableDeepCopy); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, err
			}

			// The name was reused under another parent; this entry's cleanup is still pending
			if currentCPE.Spec.PolicyRef.Name != ref.Parent {
				continue
			}

			if isDeleteFlow && ref.Parent == parentCNPName {
				log().Debugf("CPE belongs to same CNP. Ignore and move on since it's a delete flow parentCNP %s currentCPE %s", parentCNPName, ref.Name)
				continue
			}

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
	}
	return clusterPolicyIngressRules, clusterPolicyEgressRules, nil
}

// deriveTargetPodsForParentCNP scrubs the parent's entries out of every stale identifier's
// podIdentifierToClusterPolicyEndpointMap entry so cleanupClusterPolicyPod's presence check
// only sees sibling CPEs from OTHER parents. Leaves ClusterPolicyEndpointSelectorMap and
// clusterNetworkPolicyToPodIdentifierMap untouched for the caller to commit via
// commitClusterPolicyEndpointState once cleanup has run.
func (r *ClusterPolicyEndpointsReconciler) deriveTargetPodsForParentCNP(ctx context.Context, parentCNPName, resourceName string) ([]npatypes.Pod, map[string]bool, []npatypes.Pod, []string, map[string]bool, error) {
	var newTargetPods []npatypes.Pod
	var podsToBeCleanedUp []npatypes.Pod
	var parentCPEList []string
	var currentPods []npatypes.Pod
	var clusterWidePodIdentifiers = make(map[string]bool)
	var stalePodIdentifiers []string
	podIdentifiers := make(map[string]bool)

	parentCPEObjects, err := r.getClusterPolicyEndpointsOfParentCNP(ctx, parentCNPName)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	log().Infof("Parent Cluster Network Policy resource Name: %s Total Cluster Policy Endpoints for Parent CNP: Count: %d", parentCNPName, len(parentCPEObjects))

	if len(parentCPEObjects) == 0 {
		parentCPEList = []string{resourceName}
	} else {
		parentCPEList = lo.Map(parentCPEObjects, func(cpe policyk8sawsv1.ClusterPolicyEndpoint, _ int) string {
			return cpe.Name
		})
		for _, currentCPE := range parentCPEObjects {
			currentTargetPods, currentPodIdentifiers, currentClusterwidePodIdentifiers := r.deriveClusterPolicyTargetPods(&currentCPE, parentCNPName, parentCPEList)
			newTargetPods = append(newTargetPods, currentTargetPods...)
			for pid := range currentPodIdentifiers {
				podIdentifiers[pid] = true
			}
			for podIdentifier := range currentClusterwidePodIdentifiers {
				clusterWidePodIdentifiers[podIdentifier] = true
			}
		}
	}

	stalePodIdentifiers = utils.DeriveStalePodIdentifiers(&r.clusterNetworkPolicyToPodIdentifierMap, parentCNPName, clusterWidePodIdentifiers)

	// Commit records the parent's pods under every one of its CPEs, so a CPE reconciled before
	// it has an entry of its own, such as a new slice, finds them under a sibling.
	for _, cpeName := range lo.Uniq(append([]string{resourceName}, parentCPEList...)) {
		key := EndpointRequest{Endpoint: types.NamespacedName{Name: cpeName}, Parent: parentCNPName}
		if existingPods, ok := r.ClusterPolicyEndpointSelectorMap.Load(key); ok {
			currentPods = append(currentPods, existingPods.([]npatypes.Pod)...)
		}
	}
	// Dedupe on identity, not on the whole struct: the same pod can be recorded under two
	// slices with different PodIPs (a StatefulSet pod keeps its name across recreation but
	// not its address), and GetPodListToBeCleanedUp matches on NamespacedName, so both copies
	// would land in podsToBeCleanedUp and the pod would be cleaned up twice.
	currentPods = lo.UniqBy(currentPods, func(pod npatypes.Pod) types.NamespacedName {
		return pod.NamespacedName
	})

	// A stale identifier still holds the slices from the reconcile that last selected it,
	// including deleted ones and ones whose names moved to another parent, so drop every entry
	// of this parent rather than only its live slices
	for _, podIdentifier := range stalePodIdentifiers {
		utils.DeleteParentFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCNPName)
	}

	if len(currentPods) > 0 {
		podsToBeCleanedUp = utils.GetPodListToBeCleanedUp(currentPods, newTargetPods, podIdentifiers)
	}
	return newTargetPods, podIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyTargetPods(ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint, parentCNPName string, parentCPEList []string) ([]npatypes.Pod, map[string]bool, map[string]bool) {
	var targetPods []npatypes.Pod
	podIdentifiers := make(map[string]bool)
	clusterwidePodIdentifiers := make(map[string]bool)

	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range ClusterPolicyEndpoint.Spec.PodSelectorEndpoints {
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		clusterwidePodIdentifiers[podIdentifier] = true
		if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			targetPods = append(targetPods, npatypes.Pod{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, PodIP: pod.PodIP})
			podIdentifiers[podIdentifier] = true
		}
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCNPName, parentCPEList)
	}
	return targetPods, podIdentifiers, clusterwidePodIdentifiers
}

// updateClusterPolicyEnforcementStatusForPods returns the pods whose cleanup failed.
//
// Despite the name, this is not cleanup-only: cleanUpClusterPolicyEndpoint also calls it on
// targetPods, the pods the parent policy still selects. For those, cleanupClusterPolicyPod
// re-derives the surviving rules and reprograms them, which is what drops the departing
// slice's contribution while leaving the rest of the parent's policy in place.
func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyEnforcementStatusForPods(ctx context.Context, parentCNPName string, cleanupPods []npatypes.Pod, podIdentifiers map[string]bool, isDeleteFlow bool) ([]npatypes.Pod, int, error) {
	var failed []npatypes.Pod
	var err error
	cleaned := 0
	for _, cleanupPod := range cleanupPods {
		wrote, cleanupErr := r.cleanupClusterPolicyPod(ctx, cleanupPod, parentCNPName, isDeleteFlow)
		if cleanupErr != nil {
			log().Errorf("Cluster Policy Cleanup/Update unsuccessful for Pod Name: %s Namespace: %s ", cleanupPod.Name, cleanupPod.Namespace)
			failed = append(failed, cleanupPod)
			err = errors.Join(err, cleanupErr)
			continue
		}
		if wrote {
			cleaned++
		}
	}
	return failed, cleaned, err
}

// cleanupClusterPolicyPod reports whether it wrote any map, so a cleanup that did real work
// is told apart from one that found nothing on this node.
func (r *ClusterPolicyEndpointsReconciler) cleanupClusterPolicyPod(ctx context.Context, targetPod npatypes.Pod, parentCNPName string, isDeleteFlow bool) (bool, error) {
	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)

	// The map consulted below is populated for pods on every node, so it cannot tell us
	// whether this node still holds programs for the identifier. Only the eBPF context can,
	// and every write below needs it, so when it is gone there is nothing here to clean up.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy cleanup for podIdentifier %s: no eBPF context registered", podIdentifier)
		return false, nil
	}

	if _, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		// A sibling CPE (from this or another parent CNP) still targets the identifier —
		// recompute rules from what remains.
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, parentCNPName, isDeleteFlow)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resources for podIdentifier %s: %v", podIdentifier, err)
			return false, err
		}
		if err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules); err != nil {
			log().Errorf("cluster policy map update(s) failed for podIdentifier %s: %v", podIdentifier, err)
			return false, err
		}
		return true, nil
	}

	// Nothing selects this identifier; clear its eBPF maps.
	log().Debugf("No cluster policies left for podIdentifier %s, clearing cluster policy maps", podIdentifier)
	if err := r.updateClusterPolicyBPFMaps(podIdentifier, nil, nil); err != nil {
		log().Errorf("cluster policy map clear failed for podIdentifier %s: %v", podIdentifier, err)
		return false, err
	}
	return true, nil
}

// commitClusterPolicyEndpointState updates the two maps derive left untouched. Runs after
// cleanup. Callers also pass the pods whose cleanup failed, so the retry derives them as
// stale again. Keys clusterNetworkPolicyToPodIdentifierMap by the exact parent CNP name.
func (r *ClusterPolicyEndpointsReconciler) commitClusterPolicyEndpointState(
	parentCNPName string,
	newTargetPods []npatypes.Pod,
	clusterWidePodIdentifiers map[string]bool,
	parentCPEList []string,
) {
	for _, cpeName := range parentCPEList {
		key := EndpointRequest{Endpoint: types.NamespacedName{Name: cpeName}, Parent: parentCNPName}
		if len(newTargetPods) > 0 {
			r.ClusterPolicyEndpointSelectorMap.Store(key, newTargetPods)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(key)
		}
	}

	if len(clusterWidePodIdentifiers) == 0 {
		r.clusterNetworkPolicyToPodIdentifierMap.Delete(parentCNPName)
		return
	}
	clusterWidePodIdentifiersList := make([]string, 0, len(clusterWidePodIdentifiers))
	for pid := range clusterWidePodIdentifiers {
		clusterWidePodIdentifiersList = append(clusterWidePodIdentifiersList, pid)
	}
	r.clusterNetworkPolicyToPodIdentifierMap.Store(parentCNPName, clusterWidePodIdentifiersList)
}

// getClusterPolicyEndpointsOfParentCNP returns the CPEs whose PolicyRef.Name matches
// parentCNP. Callers must distinguish an empty result from a List failure — passing a
// nil slice to the "no CPEs left" branch would incorrectly clear eBPF Deny rules on a
// transient API error and open traffic.
func (r *ClusterPolicyEndpointsReconciler) getClusterPolicyEndpointsOfParentCNP(ctx context.Context, parentCNP string) ([]policyk8sawsv1.ClusterPolicyEndpoint, error) {
	ClusterPolicyEndpointList := &policyk8sawsv1.ClusterPolicyEndpointList{}
	// Cluster-scoped: no namespace filter
	if err := r.k8sClient.List(ctx, ClusterPolicyEndpointList, &client.ListOptions{}, client.UnsafeDisableDeepCopy); err != nil {
		log().Errorf("Unable to list ClusterPolicyEndpoints err: %v", err)
		return nil, err
	}

	var parentClusterPolicyEndpoints []policyk8sawsv1.ClusterPolicyEndpoint
	for _, ClusterPolicyEndpoint := range ClusterPolicyEndpointList.Items {
		if ClusterPolicyEndpoint.Spec.PolicyRef.Name == parentCNP {
			parentClusterPolicyEndpoints = append(parentClusterPolicyEndpoints, ClusterPolicyEndpoint)
		}
	}
	return parentClusterPolicyEndpoints, nil
}

func (r *ClusterPolicyEndpointsReconciler) DeriveClusterPolicyFireWallRulesPerPodIdentifier(ctx context.Context, podIdentifier string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, error) {

	clusterPolicyIngressRules, clusterPolicyEgressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, "", false)
	if err != nil {
		log().Errorf("Error deriving cluster firewall rules: %v", err)
		return clusterPolicyIngressRules, clusterPolicyEgressRules, err
	}

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

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterPolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return setupEndpointController(mgr, "clusterpolicyendpoint", &policyk8sawsv1.ClusterPolicyEndpoint{},
		clusterPolicyEndpointParent, r, controller.TypedOptions[EndpointRequest]{})
}

func clusterPolicyEndpointParent(cpe *policyk8sawsv1.ClusterPolicyEndpoint) string {
	return cpe.Spec.PolicyRef.Name
}
