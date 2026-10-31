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
	"maps"
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
	// lastObservedTriggerTimes maps CPE name (cluster-scoped, so name alone is
	// unique) to the last last-change-trigger-time annotation value consumed,
	// so each trigger time is observed at most once
	lastObservedTriggerTimes sync.Map

	// Maps pod Identifier to list of ClusterPolicyEndpoint resources
	podIdentifierToClusterPolicyEndpointMap      sync.Map
	podIdentifierToClusterPolicyEndpointMapMutex sync.Mutex
	// Maps ClusterPolicyEndpoint resource with a list of local pods (cluster-scoped)
	ClusterPolicyEndpointSelectorMap sync.Map
	// Maps ClusterNetworkPolicy to list of selected pod Identifiers
	clusterNetworkPolicyToPodIdentifierMap sync.Map
	// Maps a ClusterPolicyEndpoint to its parent ClusterNetworkPolicy (Spec.PolicyRef.Name) for
	// the delete path, where the object is gone
	clusterPolicyEndpointToParentCNPMap sync.Map
	// Reused ClusterPolicyEndpoint names whose cleanup under a previous parent is still to run
	parentTransitions      map[string][]parentTransition
	parentTransitionsMutex sync.Mutex

	ebpfClient ebpf.BpfClient
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints/status,verbs=get

func (r *ClusterPolicyEndpointsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log().Infof("Received a new reconcile request for ClusterPolicyEndpoint %v", req)
	if err := r.reconcile(ctx, req); err != nil {
		log().Errorf("ClusterPolicyEndpoint reconcile error: %v", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ClusterPolicyEndpointsReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	if err := r.reconcileRequest(ctx, req); err != nil {
		return err
	}
	// Lists in this reconcile can note parent transitions for other names
	return r.settleParentTransitions(ctx)
}

func (r *ClusterPolicyEndpointsReconciler) reconcileRequest(ctx context.Context, req ctrl.Request) error {
	if err := r.settleParentTransitions(ctx); err != nil {
		return err
	}
	ClusterPolicyEndpoint := &policyk8sawsv1.ClusterPolicyEndpoint{}
	// Cluster-scoped: use only name, no namespace
	if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: req.Name}, ClusterPolicyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if apierrors.IsNotFound(err) {
			parentCNPName, seen := r.clusterPolicyEndpointToParentCNPMap.Load(req.Name)
			if !seen {
				// Never written into this agent's state (see noteParentCNP), so nothing to clean up
				log().Debugf("ClusterPolicyEndpoint %s was never reconciled by this agent, nothing to clean up", req.Name)
				return nil
			}
			if err := r.cleanUpClusterPolicyEndpoint(ctx, req, parentCNPName.(string)); err != nil {
				// Keep the record so the retry finds the parent
				return err
			}
			r.clusterPolicyEndpointToParentCNPMap.Delete(req.Name)
			return nil
		}
		log().Errorf("Unable to get cluster policy endpoint spec for ClusterPolicyendpoint %s: %v", req.Name, err)
		return err
	}
	r.noteParentCNP(req.Name, ClusterPolicyEndpoint.Spec.PolicyRef.Name)
	// Clean up under a previous parent before writing state under the new one
	if err := r.settleParentTransitions(ctx); err != nil {
		return err
	}
	if !ClusterPolicyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpClusterPolicyEndpoint(ctx, req, ClusterPolicyEndpoint.Spec.PolicyRef.Name)
	}
	return r.reconcileClusterPolicyEndpoint(ctx, ClusterPolicyEndpoint)
}

func (r *ClusterPolicyEndpointsReconciler) cleanUpClusterPolicyEndpoint(ctx context.Context, req ctrl.Request, parentCNPName string) error {
	return r.cleanUpClusterPolicyEndpointWithPriorPods(ctx, req, parentCNPName, r.selectorPods(req.Name))
}

// cleanUpClusterPolicyEndpointWithPriorPods cleans up a ClusterPolicyEndpoint under
// parentCNPName, given the local pods it was programmed for there.
func (r *ClusterPolicyEndpointsReconciler) cleanUpClusterPolicyEndpointWithPriorPods(ctx context.Context, req ctrl.Request,
	parentCNPName string, priorPods []npatypes.Pod) error {
	log().Infof("Clean Up ClusterPolicyEndpoint resources for name: %s", req.Name)

	r.lastObservedTriggerTimes.Delete(req.Name)

	resourceName := req.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, err :=
		r.deriveTargetPodsForParentCNPWithPriorPods(ctx, parentCNPName, resourceName, priorPods)
	if err != nil {
		return err
	}

	// Remove the deleted CPE's name from the identifiers whose local pods it tracked. Derive
	// prunes names only for identifiers that went stale, i.e. ones the parent no longer
	// selects anywhere, so an identifier still selected via a sibling CPE keeps this name.
	// Later reconciles read these entries, so the departing name has to be scrubbed here.
	for _, pod := range priorPods {
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, resourceName)
	}

	log().Infof("cleanUpClusterPolicyEndpoint: Pods to cleanup - %d and Pods to be updated - %d", len(podsToBeCleanedUp), len(targetPods))

	_, updateErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, parentCNPName, targetPods, targetPodIdentifiers, false)
	if updateErr != nil {
		log().Errorf("failed to update cluster policy bpf probes for policy endpoint %s : %v", req.Name, updateErr)
	}
	failedCleanups, cleanupErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, parentCNPName, podsToBeCleanedUp, targetPodIdentifiers, true)
	if cleanupErr != nil {
		log().Errorf("failed to clean up cluster policy bpf probes for policy endpoint %s : %v", req.Name, cleanupErr)
	}

	// Same tracking as reconcileClusterPolicyEndpoint.
	trackedPods := append(slices.Clone(targetPods), failedCleanups...)
	trackedPodIdentifiers := maps.Clone(clusterWidePodIdentifiers)
	for _, pod := range failedCleanups {
		trackedPodIdentifiers[utils.GetPodIdentifier(pod.Name, pod.Namespace)] = true
	}
	r.commitClusterPolicyEndpointState(parentCNPName, trackedPods, trackedPodIdentifiers, parentCPEList)

	// Until every cleanup succeeds, the deleted CPE's entry holds the ones that failed, so the
	// retry repeats only those. If the CPE is in parentCPEList (its deletion is in progress,
	// or it is the parent's last CPE), the commit above has already written its entry.
	err = errors.Join(updateErr, cleanupErr)
	if !slices.Contains(parentCPEList, resourceName) {
		if err != nil {
			r.ClusterPolicyEndpointSelectorMap.Store(resourceName, failedCleanups)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(resourceName)
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
	failedCleanups, cleanupErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, parentCNPName, podsToBeCleanedUp, targetPodIdentifiers, false)
	if cleanupErr != nil {
		log().Errorf("failed to update cluster policy enforcement status for existing pods: %v", cleanupErr)
	}

	// Track the pods programmed below, so they can be cleaned up later, and the pods whose
	// cleanup failed, so the retry and the CPE delete flow still find them.
	trackedPods := append(slices.Clone(targetPods), failedCleanups...)
	trackedPodIdentifiers := maps.Clone(clusterWidePodIdentifiers)
	for _, pod := range failedCleanups {
		trackedPodIdentifiers[utils.GetPodIdentifier(pod.Name, pod.Namespace)] = true
	}
	r.commitClusterPolicyEndpointState(parentCNPName, trackedPods, trackedPodIdentifiers, parentCPEList)

	var programmingErr error
	for podIdentifier := range targetPodIdentifiers {
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, parentCNPName, false)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resource %s for podIdentifier %s: %v", ClusterPolicyEndpoint.Name, podIdentifier, err)
			programmingErr = errors.Join(programmingErr, err)
			continue
		}
		if err := r.configureClusterPolicyBPFProbes(podIdentifier, targetPods, ingressRules, egressRules); err != nil {
			log().Errorf("Error configuring Cluster Policy eBPF Probes for podIdentifier %s: %v", podIdentifier, err)
			programmingErr = errors.Join(programmingErr, err)
		}
	}

	// Latency is recorded only for a pass whose cleanup succeeded, so the retry after a failed
	// cleanup measures the change. A programming error consumes the annotation without
	// recording a sample.
	if cleanupErr == nil {
		r.observeClusterPolicyProgrammingLatency(ClusterPolicyEndpoint, programmingErr == nil)
	}

	return errors.Join(cleanupErr, programmingErr)
}

// observeClusterPolicyProgrammingLatency emits the E2E latency histogram from
// the last-change-trigger-time annotation. Each annotation value is consumed
// at most once per CPE, even when the observation is suppressed (programming
// failure, clock skew), so stale rewrites/resyncs/relists never re-observe it.
func (r *ClusterPolicyEndpointsReconciler) observeClusterPolicyProgrammingLatency(cpe *policyk8sawsv1.ClusterPolicyEndpoint, programmingSucceeded bool) {
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
	if prev, ok := r.lastObservedTriggerTimes.Load(cpe.Name); ok && prev.(string) == triggerTimeStr {
		return
	}
	// Consume before the suppression checks below: a suppressed observation
	// must never be re-emitted (inflated) by a later resync of the same annotation.
	r.lastObservedTriggerTimes.Store(cpe.Name, triggerTimeStr)
	if !programmingSucceeded {
		log().Debugf("Skipping E2E cluster policy programming latency for CPE %s: programming failed", cpe.Name)
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

func (r *ClusterPolicyEndpointsReconciler) configureClusterPolicyBPFProbes(podIdentifier string, targetPods []npatypes.Pod, ingressRules, egressRules []fwrp.EbpfFirewallRules) error {

	for _, pod := range targetPods {
		currentPodIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if currentPodIdentifier != podIdentifier {
			continue
		}

		// podConfirmedLive=false: PolicyEndpoints can still list pods already deleted from this node.
		_, err := r.ebpfClient.AttacheBPFProbes(pod.NamespacedName, podIdentifier, ebpf.INTERFACE_COUNT_UNKNOWN, false)
		if err != nil {
			log().Errorf("Failed to attach eBPF probes for pod %s namespace %s : %v", pod.Name, pod.Namespace, err)
			return err
		}
		log().Infof("Successfully attached required eBPF probes for pod: %s in namespace %s", pod.Name, pod.Namespace)
	}

	// AttacheBPFProbes skips pods already deleted from the node, so the CPE can still list a
	// pod that has no programs here. There is nothing to program until a new pod attaches.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		return nil
	}

	err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules)
	if err != nil {
		log().Errorf("cluster policy Map updates failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}

	return nil
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
		log().Infof("Total number of ClusterPolicyEndpoint resources for podIdentifier %s are %d", podIdentifier, len(ClusterPolicyEndpointList.([]string)))
		for _, ClusterPolicyEndpointResource := range ClusterPolicyEndpointList.([]string) {
			// Cluster-scoped: no namespace
			cpeNamespacedName := types.NamespacedName{Name: ClusterPolicyEndpointResource}

			if err := r.k8sClient.Get(ctx, cpeNamespacedName, currentCPE, client.UnsafeDisableDeepCopy); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, err
			}

			if isDeleteFlow && currentCPE.Spec.PolicyRef.Name == parentCNPName {
				log().Debugf("CPE belongs to same CNP. Ignore and move on since it's a delete flow parentCNP %s currentCPE %s", parentCNPName, ClusterPolicyEndpointResource)
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

// deriveTargetPodsForParentCNP scrubs the parent's CPEs out of every stale identifier's
// podIdentifierToClusterPolicyEndpointMap entry so cleanupClusterPolicyPod's presence check
// only sees sibling CPEs from OTHER parents. Leaves ClusterPolicyEndpointSelectorMap and
// clusterNetworkPolicyToPodIdentifierMap untouched for the caller to commit via
// commitClusterPolicyEndpointState once cleanup has run.
func (r *ClusterPolicyEndpointsReconciler) deriveTargetPodsForParentCNP(ctx context.Context, parentCNPName, resourceName string) ([]npatypes.Pod, map[string]bool, []npatypes.Pod, []string, map[string]bool, error) {
	return r.deriveTargetPodsForParentCNPWithPriorPods(ctx, parentCNPName, resourceName, r.selectorPods(resourceName))
}

// deriveTargetPodsForParentCNPWithPriorPods is deriveTargetPodsForParentCNP given the local pods
// resourceName was programmed for under parentCNPName.
func (r *ClusterPolicyEndpointsReconciler) deriveTargetPodsForParentCNPWithPriorPods(ctx context.Context,
	parentCNPName, resourceName string, priorPods []npatypes.Pod) ([]npatypes.Pod, map[string]bool, []npatypes.Pod, []string, map[string]bool, error) {
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
			currentTargetPods, currentPodIdentifiers, currentClusterwidePodIdentifiers := r.deriveClusterPolicyTargetPods(&currentCPE, parentCPEList)
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
	currentPods = append(currentPods, priorPods...)
	for _, cpeName := range parentCPEList {
		if cpeName == resourceName {
			continue
		}
		if existingPods, ok := r.ClusterPolicyEndpointSelectorMap.Load(cpeName); ok {
			currentPods = append(currentPods, existingPods.([]npatypes.Pod)...)
		}
	}
	currentPods = lo.Uniq(currentPods)

	// The live list alone is not sufficient: a stale identifier still holds the slice names
	// from the reconcile that last selected it, and the CPE being deleted is by definition no
	// longer in the live list. Prune against the live slices PLUS resourceName, which on the
	// delete path is the departing CPE's own name (and is already a member of parentCPEList
	// on the reconcile path, making it a no-op).
	pruneNames := parentCPEList
	if !slices.Contains(pruneNames, resourceName) {
		pruneNames = append(slices.Clone(parentCPEList), resourceName)
	}
	for _, podIdentifier := range stalePodIdentifiers {
		for _, cpeName := range pruneNames {
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, cpeName)
		}
	}

	if len(currentPods) > 0 {
		podsToBeCleanedUp = utils.GetPodListToBeCleanedUp(currentPods, newTargetPods, podIdentifiers)
	}
	return newTargetPods, podIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyTargetPods(ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint, parentCPEList []string) ([]npatypes.Pod, map[string]bool, map[string]bool) {
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
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCPEList)
	}
	return targetPods, podIdentifiers, clusterwidePodIdentifiers
}

// updateClusterPolicyEnforcementStatusForPods returns the pods whose cleanup failed.
func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyEnforcementStatusForPods(ctx context.Context, parentCNPName string, cleanupPods []npatypes.Pod, podIdentifiers map[string]bool, isDeleteFlow bool) ([]npatypes.Pod, error) {
	var failed []npatypes.Pod
	var err error
	for _, cleanupPod := range cleanupPods {
		if cleanupErr := r.cleanupClusterPolicyPod(ctx, cleanupPod, parentCNPName, isDeleteFlow); cleanupErr != nil {
			log().Errorf("Cluster Policy Cleanup/Update unsuccessful for Pod Name: %s Namespace: %s ", cleanupPod.Name, cleanupPod.Namespace)
			failed = append(failed, cleanupPod)
			err = errors.Join(err, cleanupErr)
		}
	}
	return failed, err
}

func (r *ClusterPolicyEndpointsReconciler) cleanupClusterPolicyPod(ctx context.Context, targetPod npatypes.Pod, parentCNPName string, isDeleteFlow bool) error {
	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)

	// The map consulted below is populated for pods on every node, so it cannot tell us
	// whether this node still holds programs for the identifier. Only the eBPF context can,
	// and every write below needs it, so when it is gone there is nothing here to clean up.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy cleanup for podIdentifier %s: no eBPF context registered", podIdentifier)
		return nil
	}

	if _, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		// A sibling CPE (from this or another parent CNP) still targets the identifier —
		// recompute rules from what remains.
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, parentCNPName, isDeleteFlow)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resources for podIdentifier %s: %v", podIdentifier, err)
			return err
		}
		if err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules); err != nil {
			log().Errorf("cluster policy map update(s) failed for podIdentifier %s: %v", podIdentifier, err)
			return err
		}
		return nil
	}

	// Nothing selects this identifier; clear its eBPF maps.
	log().Debugf("No cluster policies left for podIdentifier %s, clearing cluster policy maps", podIdentifier)
	if err := r.updateClusterPolicyBPFMaps(podIdentifier, nil, nil); err != nil {
		log().Errorf("cluster policy map clear failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}
	return nil
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
		if len(newTargetPods) > 0 {
			r.ClusterPolicyEndpointSelectorMap.Store(cpeName, newTargetPods)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(cpeName)
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

// selectorPods returns the local pods a ClusterPolicyEndpoint was last programmed for.
func (r *ClusterPolicyEndpointsReconciler) selectorPods(clusterPolicyEndpoint string) []npatypes.Pod {
	if p, ok := r.ClusterPolicyEndpointSelectorMap.Load(clusterPolicyEndpoint); ok {
		return p.([]npatypes.Pod)
	}
	return nil
}

// noteParentCNP records a ClusterPolicyEndpoint's parent before any state is written under its
// name. A different recorded parent means the name was reused under another ClusterNetworkPolicy
// before the old delete was processed; that delete's cleanup is queued for settleParentTransitions.
func (r *ClusterPolicyEndpointsReconciler) noteParentCNP(clusterPolicyEndpoint, parentCNPName string) {
	prev, ok := r.clusterPolicyEndpointToParentCNPMap.Load(clusterPolicyEndpoint)
	if ok && prev.(string) == parentCNPName {
		return
	}
	if ok {
		log().Infof("ClusterPolicyEndpoint %s now belongs to ClusterNetworkPolicy %s instead of %s, queueing cleanup under %s",
			clusterPolicyEndpoint, parentCNPName, prev, prev)
		r.parentTransitionsMutex.Lock()
		if r.parentTransitions == nil {
			r.parentTransitions = map[string][]parentTransition{}
		}
		r.parentTransitions[clusterPolicyEndpoint] = append(r.parentTransitions[clusterPolicyEndpoint],
			parentTransition{oldParent: prev.(string), oldPods: r.selectorPods(clusterPolicyEndpoint)})
		r.parentTransitionsMutex.Unlock()
	}
	r.clusterPolicyEndpointToParentCNPMap.Store(clusterPolicyEndpoint, parentCNPName)
}

// settleParentTransitions runs queued cleanups under previous parents, oldest first per name.
// Cleanups only queue the transitions they find, so this never nests. A failed transition stays
// queued, with its saved pods, for the next reconcile.
func (r *ClusterPolicyEndpointsReconciler) settleParentTransitions(ctx context.Context) error {
	for {
		r.parentTransitionsMutex.Lock()
		var clusterPolicyEndpoint string
		var transition parentTransition
		found := false
		for cpe, pending := range r.parentTransitions {
			if !found || cpe < clusterPolicyEndpoint {
				clusterPolicyEndpoint, transition, found = cpe, pending[0], true
			}
		}
		r.parentTransitionsMutex.Unlock()
		if !found {
			return nil
		}

		if err := r.cleanUpClusterPolicyEndpointWithPriorPods(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: clusterPolicyEndpoint}},
			transition.oldParent, transition.oldPods); err != nil {
			return err
		}

		r.parentTransitionsMutex.Lock()
		if pending := r.parentTransitions[clusterPolicyEndpoint][1:]; len(pending) > 0 {
			r.parentTransitions[clusterPolicyEndpoint] = pending
		} else {
			delete(r.parentTransitions, clusterPolicyEndpoint)
		}
		r.parentTransitionsMutex.Unlock()
	}
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
			// This reconcile writes sibling names into state, so record their parents first
			r.noteParentCNP(ClusterPolicyEndpoint.Name, parentCNP)
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
		if len(policyEndpointList.([]string)) > 0 {
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyk8sawsv1.ClusterPolicyEndpoint{}).
		Complete(r)
}
