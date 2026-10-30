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
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func msSince(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
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
		k8sClient:        k8sClient,
		nodeIP:           nodeIP,
		ebpfClient:       ebpfClient,
		enableIPv6:       enableIPv6,
		trackerStartTime: time.Now(),
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
	// lastObservedTriggerTimes maps a PE's types.NamespacedName to the last
	// last-change-trigger-time annotation value consumed, so each trigger
	// time is observed at most once
	lastObservedTriggerTimes sync.Map
	// Maps pod Identifier to list of PolicyEndpoint resources
	podIdentifierToPolicyEndpointMap sync.Map
	// Mutex for operations on PodIdentifierToPolicyEndpointMap
	podIdentifierToPolicyEndpointMapMutex sync.Mutex
	// Maps PolicyEndpoint resource with a list of local pods
	policyEndpointSelectorMap sync.Map
	// Maps a Network Policy to list of selected pod Identifiers
	networkPolicyToPodIdentifierMap sync.Map
	//BPF Client instance
	ebpfClient ebpf.BpfClient
	enableIPv6 bool
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/status,verbs=get

func (r *PolicyEndpointsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log().Infof("Received a new reconcile request %v", req)
	if err := r.reconcile(ctx, req); err != nil {
		log().Errorf("Reconcile error: %v", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *PolicyEndpointsReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	policyEndpoint := &policyk8sawsv1.PolicyEndpoint{}
	if err := r.k8sClient.Get(ctx, req.NamespacedName, policyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanUpPolicyEndpoint(ctx, req)
		}
		log().Errorf("Unable to get policy endpoint spec for policyendpoint %s: %v", req.NamespacedName, err)
		return err
	}
	if !policyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpPolicyEndpoint(ctx, req)
	}
	return r.reconcilePolicyEndpoint(ctx, policyEndpoint)
}

func (r *PolicyEndpointsReconciler) cleanUpPolicyEndpoint(ctx context.Context, req ctrl.Request) error {
	log().Infof("Clean Up PolicyEndpoint resources for name: %s", req.NamespacedName.Name)
	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(req.NamespacedName.Name,
		req.NamespacedName.Namespace)

	r.lastObservedTriggerTimes.Delete(req.NamespacedName)

	start := time.Now()

	// Get all podIdentifiers since we need to decide if pinpath has to be deleted on local node
	parentNP := utils.GetParentNPNameFromPEName(req.NamespacedName.Name)
	resourceName := req.NamespacedName.Name
	resourceNamespace := req.NamespacedName.Namespace
	targetPods, podIdentifiers, podsToBeCleanedUp, parentPEList, clusterWidePodIdentifiers, err :=
		r.deriveTargetPodsForParentNP(ctx, parentNP, resourceNamespace, resourceName)
	if err != nil {
		// This is expected only if the error is due to inability to list the PE from the cache, in which case we should requeue the reconcile request
		return err
	}

	// Remove the deleted PE's own name from every identifier that recorded it. Derive prunes
	// only identifiers that went stale, so one still selected via a sibling slice keeps this
	// name, and inserts are append-only. resourceName is an exact match off the delete event,
	// so this can only ever remove the departing slice. Uses the selector map's full prior set,
	// not podsToBeCleanedUp, which omits pods a sibling still selects.
	if priorPods, ok := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier); ok {
		for _, pod := range priorPods.([]npatypes.Pod) {
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
				&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, resourceName)
		}
	}

	log().Infof("cleanUpPolicyEndpoint: Pods to cleanup - %d and Pods to be updated - %d", len(podsToBeCleanedUp), len(targetPods))

	// targetPods are pods which would need map update
	if len(targetPods) > 0 {
		log().Debug("Updating active pods...")
		err := r.updatePolicyEnforcementStatusForPods(ctx, req.NamespacedName.Name, targetPods, podIdentifiers, false)
		if err != nil {
			return fmt.Errorf("update active pods for policyendpoint %s: %w", req.NamespacedName.Name, err)
		}
		duration := msSince(start)
		policyTearDownLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	}

	r.commitPolicyEndpointState(resourceName, resourceNamespace, targetPods, clusterWidePodIdentifiers, parentPEList)

	// podsToBeCleanedUp - pods which are no longer selected by this policy
	if len(podsToBeCleanedUp) > 0 {
		log().Debug("Cleaning up current policy against below pods..")
		err := r.updatePolicyEnforcementStatusForPods(ctx, req.NamespacedName.Name, podsToBeCleanedUp, podIdentifiers, true)
		if err != nil {
			return fmt.Errorf("clean up deselected pods for policyendpoint %s: %w", req.NamespacedName.Name, err)
		}
		duration := msSince(start)
		policyTearDownLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	}

	r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
	return nil
}

func (r *PolicyEndpointsReconciler) updatePolicyEnforcementStatusForPods(ctx context.Context, policyEndpointName string,
	targetPods []npatypes.Pod, podIdentifiers map[string]bool, isDeleteFlow bool) error {
	var err error
	// 1. If the pods are already deleted, we move on.
	// 2. If the pods have another policy or policies active against them, we update the maps to purge the entries
	//    introduced by the current policy.
	// 3. If there are no more active policies against this pod, we update pod_state to default deny/allow
	for _, targetPod := range targetPods {
		podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)
		log().Infof("Updating Pod: Name: %s Namespace: %s PodIdentifier: %s", targetPod.Name, targetPod.Namespace, podIdentifier)

		cleanupErr := r.cleanupPod(ctx, targetPod, policyEndpointName, isDeleteFlow)
		if cleanupErr != nil {
			log().Errorf("Cleanup/Update unsuccessful for pod %s/%s: %v",
				targetPod.Namespace, targetPod.Name, cleanupErr)
			err = errors.Join(err, cleanupErr)
			// we don't want to return an error right away but instead attempt to clean up all the pods
			// in the list before returning
		}
	}
	return err
}

func (r *PolicyEndpointsReconciler) reconcilePolicyEndpoint(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint) error {
	log().Infof("Processing Policy Endpoint  Name: %s Namespace %s", policyEndpoint.Name, policyEndpoint.Namespace)
	start := time.Now()

	// Identify pods local to the node. PolicyEndpoint resource will include `HostIP` field and
	// network policy agent relies on it to filter local pods
	parentNP := policyEndpoint.Spec.PolicyRef.Name
	resourceNamespace := policyEndpoint.Namespace
	resourceName := policyEndpoint.Name

	targetPods, podIdentifiers, podsToBeCleanedUp, parentPEList, clusterWidePodIdentifiers, err :=
		r.deriveTargetPodsForParentNP(ctx, parentNP, resourceNamespace, resourceName)
	if err != nil {
		// This is expected only if the error is due to inability to list the PE from the cache, in which case we should requeue the reconcile request
		return err
	}

	// Check if we need to remove this policy against any existing pods against which this policy
	// is currently active. podIdentifiers will have the pod identifiers of the targetPods from the derived PEs
	err = r.updatePolicyEnforcementStatusForPods(ctx, policyEndpoint.Name, podsToBeCleanedUp, podIdentifiers, false)
	if err != nil {
		return fmt.Errorf("update policy enforcement status for deselected pods: %w", err)
	}

	programmed := 0
	var programmingErrs []error
	r.commitPolicyEndpointState(resourceName, resourceNamespace, targetPods, clusterWidePodIdentifiers, parentPEList)

	// Program the podIdentifiers local to the node.
	for podIdentifier := range podIdentifiers {
		// Derive Ingress IPs from the PolicyEndpoint
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier,
			policyEndpoint.Namespace, policyEndpoint.Name, false)
		if err != nil {
			log().Errorf("Error Parsing policy Endpoint resource %s: %v", policyEndpoint.Name, err)
			// Join, so failures already collected in this pass are not dropped.
			return errors.Join(append(programmingErrs, err)...)
		}

		if len(ingressRules) == 0 && !isIngressIsolated {
			//Add allow-all entry to Ingress rule set
			log().Info("No Ingress rules and no ingress isolation - Appending catch all entry")
			r.addCatchAllEntry(&ingressRules)
		}

		if len(egressRules) == 0 && !isEgressIsolated {
			//Add allow-all entry to Egress rule set
			log().Info("No Egress rules and no egress isolation - Appending catch all entry")
			r.addCatchAllEntry(&egressRules)
		}

		// Setup/configure eBPF probes/maps for local pods
		err = r.configureeBPFProbes(ctx, podIdentifier, targetPods, ingressRules, egressRules)
		switch {
		case err == nil:
			programmed++
		case errors.Is(err, ebpf.ErrProbeAttachSkipped):
			// Retrying cannot resolve this, so do not report it as a failure.
			log().Warnf("Skipped eBPF programming for podIdentifier %s: %v", podIdentifier, err)
		default:
			log().Errorf("Error configuring eBPF Probes %v", err)
			// Collect rather than return, so one failing podIdentifier does not
			// stop the others from being programmed.
			programmingErrs = append(programmingErrs, fmt.Errorf("podIdentifier %s: %w", podIdentifier, err))
		}
		duration := msSince(start)
		policySetupLatency.WithLabelValues(policyEndpoint.Name, policyEndpoint.Namespace).Observe(duration)
	}

	// Observe E2E policy programming latency (NPC change → NPA eBPF programmed).
	// Skips count as neither: programming nothing records no sample, but
	// programming some identifiers still reports the latency that was real.
	r.observePolicyProgrammingLatency(policyEndpoint, programmed > 0 && len(programmingErrs) == 0)

	return errors.Join(programmingErrs...)
}

func (r *PolicyEndpointsReconciler) commitPolicyEndpointState(
	resourceName string,
	resourceNamespace string,
	newTargetPods []npatypes.Pod,
	clusterWidePodIdentifiers map[string]bool,
	parentPEList []string,
) {
	for _, peName := range parentPEList {
		policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(peName, resourceNamespace)
		if len(newTargetPods) > 0 {
			r.policyEndpointSelectorMap.Store(policyEndpointIdentifier, newTargetPods)
		} else {
			r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
		}
	}

	// Store the cluster wide pod identifiers associated with this network policy
	// since this map helps track stale identifiers and cleanup from PodIdentifier to PolicyEndpoint mappings
	parentNP := utils.GetParentNPNameFromPEName(resourceName)
	networkPolicyIdentifier := utils.GetNetworkPolicyIdentifier(parentNP, resourceNamespace)
	if len(clusterWidePodIdentifiers) == 0 {
		r.networkPolicyToPodIdentifierMap.Delete(networkPolicyIdentifier)
		return
	}
	clusterWidePodIdentifiersList := make([]string, 0, len(clusterWidePodIdentifiers))
	for pid := range clusterWidePodIdentifiers {
		clusterWidePodIdentifiersList = append(clusterWidePodIdentifiersList, pid)
	}
	r.networkPolicyToPodIdentifierMap.Store(networkPolicyIdentifier, clusterWidePodIdentifiersList)
}

// observePolicyProgrammingLatency emits the E2E latency histogram from the
// last-change-trigger-time annotation. Each annotation value is consumed at
// most once per PE, so stale rewrites/resyncs/relists never re-observe it.
func (r *PolicyEndpointsReconciler) observePolicyProgrammingLatency(pe *policyk8sawsv1.PolicyEndpoint, programmingSucceeded bool) {
	if pe.Annotations == nil {
		return
	}
	triggerTimeStr, ok := pe.Annotations[LastChangeTriggerTimeAnnotation]
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
	peKey := types.NamespacedName{Namespace: pe.Namespace, Name: pe.Name}
	if prev, ok := r.lastObservedTriggerTimes.Load(peKey); ok && prev.(string) == triggerTimeStr {
		return
	}
	if !programmingSucceeded {
		// Leave the trigger time unconsumed: the reconcile is retried, and the
		// retry that succeeds must still be able to observe this latency.
		log().Debugf("Skipping E2E policy programming latency for PE %s/%s: programming failed", pe.Namespace, pe.Name)
		return
	}
	// Consume before the suppression check below: a suppressed observation must
	// never be re-emitted (inflated) by a later resync of the same annotation.
	r.lastObservedTriggerTimes.Store(peKey, triggerTimeStr)
	latency := time.Since(triggerTime).Seconds()
	if latency < 0 {
		// Clock skew between NPC (control plane) and this node
		log().Debugf("Skipping negative E2E policy programming latency %.3fs for PE %s/%s", latency, pe.Namespace, pe.Name)
		return
	}
	policyProgrammingLatency.Observe(latency)
	log().Debugf("E2E policy programming latency: %.3fs for PE %s/%s", latency, pe.Namespace, pe.Name)
}

func (r *PolicyEndpointsReconciler) configureeBPFProbes(ctx context.Context, podIdentifier string,
	targetPods []npatypes.Pod, ingressRules, egressRules []fwrp.EbpfFirewallRules) error {
	var err error

	//Loop over target pods and setup/configure/update eBPF probes/maps
	for _, pod := range targetPods {
		currentPodIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if currentPodIdentifier != podIdentifier {
			log().Debugf("Target Pod doesn't belong to the current pod Identifier: Name: %s Pod ID: %s", pod.Name, podIdentifier)
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

	// AttacheBPFProbes skips pods already deleted from the node, so the PolicyEndpoint can
	// still list a pod that has no programs here. There is nothing to program until a new
	// pod attaches.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		return nil
	}

	err = r.updateeBPFMaps(podIdentifier, ingressRules, egressRules, ebpf.POLICIES_APPLIED)
	if err != nil {
		log().Errorf("Map updates failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}
	return nil
}

func (r *PolicyEndpointsReconciler) cleanupPod(ctx context.Context, targetPod npatypes.Pod,
	policyEndpoint string, isDeleteFlow bool) error {

	var err error
	var ingressRules, egressRules []fwrp.EbpfFirewallRules
	var isIngressIsolated, isEgressIsolated bool
	noActiveIngressPolicies, noActiveEgressPolicies := false, false

	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)

	// The map consulted below is populated for pods on every node, so it cannot tell us
	// whether this node still holds programs for the identifier. Only the eBPF context can,
	// and every write below needs it, so when it is gone there is nothing here to clean up.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping policy cleanup for podIdentifier %s: no eBPF context registered", podIdentifier)
		return nil
	}

	// If the pod identifier is not in the PI→PE map, no policy tracks this pod anymore.
	// Restore baseline state directly — this handles the case where stale pruning already
	// removed the entry before cleanupPod runs.
	if _, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); !ok {

		state := DEFAULT_ALLOW
		if utils.IsStrictMode(r.GeteBPFClient().GetNetworkPolicyMode()) {
			state = DEFAULT_DENY
		}
		log().Infof("No entry in podIdentifierToPolicyEndpointMap for podIdentifier: %s. Restoring pod_state to baseline, networkPolicyMode: %s",
			podIdentifier, r.GeteBPFClient().GetNetworkPolicyMode())

		if err := r.updateeBPFMaps(podIdentifier, nil, nil, state); err != nil {
			// No policy tracks this pod anymore, but the baseline pod_state write failed.
			// Returning the error propagates it up to Reconcile, so controller-runtime
			// requeues and retries the baseline restore. This matters because a pod with no
			// active policies must land on its baseline state (DEFAULT_ALLOW, or DEFAULT_DENY
			// in strict mode); leaving it unwritten could keep stale enforcement in place.
			return fmt.Errorf("baseline restore failed for podIdentifier %s, requeueing for retry: %w", podIdentifier, err)
		}
		return nil
	}

	// Detach eBPF probes attached to the local pods (if required). We should detach eBPF probes if this
	// is the only PolicyEndpoint resource that applies to this pod. If not, just update the Ingress/Egress Map contents
	ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err = r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, targetPod.Namespace,
		policyEndpoint, isDeleteFlow)
	if err != nil {
		return fmt.Errorf("derive firewall rules for podIdentifier %s: %w", podIdentifier, err)
	}

	if len(ingressRules) == 0 && !isIngressIsolated {
		noActiveIngressPolicies = true
	}
	if len(egressRules) == 0 && !isEgressIsolated {
		noActiveEgressPolicies = true
	}

	// We update pod_state to default allow/deny if there are no other policies applied
	if noActiveIngressPolicies && noActiveEgressPolicies {
		state := DEFAULT_ALLOW
		if utils.IsStrictMode(r.GeteBPFClient().GetNetworkPolicyMode()) {
			state = DEFAULT_DENY
		}

		log().Infof("No active policies. Updating pod_state map for podIdentifier: %s networkPolicyMode: %s", podIdentifier, r.GeteBPFClient().GetNetworkPolicyMode())
		if err = r.updateeBPFMaps(podIdentifier, ingressRules, egressRules, state); err != nil {
			return fmt.Errorf("apply baseline state for podIdentifier %s: %w", podIdentifier, err)
		}
	} else {
		// We've additional PolicyEndpoint resources configured against this pod
		// Update the Maps and move on
		log().Infof("Active policies against this pod. Skip Detaching probes and Update Maps... ")
		if noActiveIngressPolicies {
			// Add an allow-all entry to ingress rule set so ingress traffic
			// isn't dropped by the eBPF dataplane.
			log().Info("No Ingress rules and no ingress isolation - Appending catch all entry")
			r.addCatchAllEntry(&ingressRules)
		}
		if noActiveEgressPolicies {
			// Add an allow-all entry to egress rule set so egress traffic
			// isn't dropped by the eBPF dataplane. Without this, egress_map
			// ends up not having the catch all rule while pod_state_map stays
			// at POLICIES_APPLIED and the eBPF dataplane drops all egress traffic.
			log().Info("No Egress rules and no egress isolation - Appending catch all entry")
			r.addCatchAllEntry(&egressRules)
		}

		if err = r.updateeBPFMaps(podIdentifier, ingressRules, egressRules, ebpf.POLICIES_APPLIED); err != nil {
			return fmt.Errorf("apply remaining policies for podIdentifier %s: %w", podIdentifier, err)
		}
	}

	return nil
}

func (r *PolicyEndpointsReconciler) deriveIngressAndEgressFirewallRules(ctx context.Context,
	podIdentifier string, resourceNamespace string, resourceName string, isDeleteFlow bool) ([]fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules, bool, bool, error) {
	var ingressRules, egressRules []fwrp.EbpfFirewallRules
	isIngressIsolated, isEgressIsolated := false, false
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		log().Infof("Total number of PolicyEndpoint resources for podIdentifier %s are %d", podIdentifier, len(policyEndpointList.([]string)))
		for _, policyEndpointResource := range policyEndpointList.([]string) {
			peNamespacedName := types.NamespacedName{
				Name:      policyEndpointResource,
				Namespace: resourceNamespace,
			}

			if isDeleteFlow {
				deletedPEParentNPName := utils.GetParentNPNameFromPEName(resourceName)
				currentPEParentNPName := utils.GetParentNPNameFromPEName(policyEndpointResource)
				if deletedPEParentNPName == currentPEParentNPName {
					log().Debugf("PE belongs to same NP. Ignore and move on since it's a delete flow deletedPE %s currentPE %s", resourceName, policyEndpointResource)
					continue
				}
			}

			if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE, client.UnsafeDisableDeepCopy); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, isIngressIsolated, isEgressIsolated, err
			}

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
			log().Infof("Total no.of - ingressRules %d egressRules %d", len(ingressRules), len(egressRules))
			ingressIsolated, egressIsolated := r.deriveDefaultPodIsolation(currentPE, len(ingressRules), len(egressRules))
			isIngressIsolated = isIngressIsolated || ingressIsolated
			isEgressIsolated = isEgressIsolated || egressIsolated
		}
	}
	if len(ingressRules) > 0 {
		isIngressIsolated = false
	}
	if len(egressRules) > 0 {
		isEgressIsolated = false
	}
	return ingressRules, egressRules, isIngressIsolated, isEgressIsolated, nil
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

func (r *PolicyEndpointsReconciler) deriveTargetPodsForParentNP(ctx context.Context,
	parentNP, resourceNamespace, resourceName string) ([]npatypes.Pod, map[string]bool, []npatypes.Pod, []string, map[string]bool, error) {
	var targetPods, podsToBeCleanedUp, priorTargetPods []npatypes.Pod
	podIdentifiers := make(map[string]bool)            // node-local only
	clusterWidePodIdentifiers := make(map[string]bool) // all identifiers this NP selects (any node) - dedupe across PEs

	parentPEList, err := r.derivePolicyEndpointsOfParentNP(ctx, parentNP, resourceNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	log().Infof("Parent NP resource: Name: %s Total PEs for Parent NP: Count: %d", parentNP, len(parentPEList))

	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(resourceName, resourceNamespace)

	// Gather the set of pods (local to the node) that are configured with this policy's rules from previous reconciliations.
	if p, exists := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier); exists {
		priorTargetPods = append(priorTargetPods, p.([]npatypes.Pod)...)
	}

	if len(parentPEList) == 0 {
		podsToBeCleanedUp = append(podsToBeCleanedUp, priorTargetPods...)
		parentPEList = []string{resourceName}
		log().Infof("No PEs left: number of pods to cleanup - %d", len(podsToBeCleanedUp))
	} else {
		for _, policyEndpointResourceName := range parentPEList {
			currentPE := &policyk8sawsv1.PolicyEndpoint{}
			peNamespacedName := types.NamespacedName{
				Name:      policyEndpointResourceName,
				Namespace: resourceNamespace,
			}
			if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE, client.UnsafeDisableDeepCopy); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				// A transient Get failure must not be treated as "PE has no pods":
				// falling through would derive an empty selection, flag this NP's
				// identifiers as stale, and prune live enforcement
				return nil, nil, nil, nil, nil, err
			}

			log().Infof("Processing PE Name %s", policyEndpointResourceName)
			localTargetPods, localTargetPodIdentifiers, clusterWideTargetPodIdentifiers := r.deriveTargetPods(ctx, currentPE, parentPEList)
			log().Infof("Adding to current targetPods Total pods: %d", len(localTargetPods))
			targetPods = append(targetPods, localTargetPods...)
			for podIdentifier := range localTargetPodIdentifiers {
				podIdentifiers[podIdentifier] = true
			}

			for podIdentifier := range clusterWideTargetPodIdentifiers {
				clusterWidePodIdentifiers[podIdentifier] = true
			}
		}
	}

	// parentNP is re-derived from the resource name to maintain consistency with the read and write operations on maps.
	parentNP = utils.GetParentNPNameFromPEName(resourceName)

	// Diff the previous selected-identifier set (from networkPolicyToPodIdentifierMap)
	// against the current one. Both sides cover every identifier this NP selects on any
	// node, so non-local identifiers that are no longer selected are flagged stale and
	// pruned from podIdentifierToPolicyEndpointMap which maintains this mapping cluster-wide
	// for optimization purposes
	networkPolicyIdentifier := utils.GetNetworkPolicyIdentifier(parentNP, resourceNamespace)
	stalePodIdentifiers := utils.DeriveStalePodIdentifiers(&r.networkPolicyToPodIdentifierMap,
		networkPolicyIdentifier, clusterWidePodIdentifiers)

	// Prune by exact PolicyEndpoint name rather than by derived parent NP name.
	// GetParentNPNameFromPEName is lossy -- GenerateName truncates the base at 58 chars, so
	// two policies whose names agree up to the last hyphen inside that prefix derive the same
	// string, and a parent-wide match would drop the other policy's slices. Exact names can
	// only ever under-delete.
	//
	// The live list alone is not sufficient: a stale identifier still holds the slice names
	// from the reconcile that last selected it, and the PE being deleted is by definition no
	// longer in the live list. So prune against the live slices PLUS resourceName, which on
	// the delete path is the departing PE's own name (and on the reconcile path is already a
	// member of parentPEList, making it a no-op).
	pruneNames := parentPEList
	if !slices.Contains(pruneNames, resourceName) {
		pruneNames = append(slices.Clone(parentPEList), resourceName)
	}
	for _, podIdentifier := range stalePodIdentifiers {
		for _, policyEndpointName := range pruneNames {
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
				&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, policyEndpointName)
		}
	}

	if len(priorTargetPods) > 0 {
		podsToBeCleanedUp = r.getPodListToBeCleanedUp(priorTargetPods, targetPods, podIdentifiers)
	}
	return targetPods, podIdentifiers, podsToBeCleanedUp, parentPEList, clusterWidePodIdentifiers, nil
}

// Derives list of local pods the policy endpoint resource selects.
// Function returns:
//   - targetPods: node-local pods selected by this PE (drives eBPF programming)
//   - podIdentifiers: identifiers of the local targetPods
//   - clusterwidePodIdentifiers: every identifier this PE selects, on any node
func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint, parentPEList []string) ([]npatypes.Pod, map[string]bool, map[string]bool) {
	var targetPods []npatypes.Pod
	podIdentifiers := make(map[string]bool)            // node-local only - drives eBPF programming
	clusterwidePodIdentifiers := make(map[string]bool) // every identifier this NetworkPolicy selects (any node) - mirrors podIdentifierToPolicyEndpointMap inserts

	// Pods are grouped by Host IP. Individual node agents will filter (local) pods
	// by the Host IP value.
	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range policyEndpoint.Spec.PodSelectorEndpoints {
		if string(pod.PodIP) == string(pod.HostIP) {
			log().Infof("Skipping hostNetwork pod: name: %s namespace: %s (PodIP == HostIP: %s)",
				pod.Name, pod.Namespace, pod.PodIP)
			continue
		}
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		clusterwidePodIdentifiers[podIdentifier] = true
		if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			targetPods = append(targetPods, npatypes.Pod{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, PodIP: pod.PodIP})
			podIdentifiers[podIdentifier] = true
			log().Infof("Found a matching Pod: name: %s namespace: %s podIdentifier: %s", pod.Name, pod.Namespace, podIdentifier)
		}
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToPolicyEndpointMap, &r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parentPEList)
	}
	return targetPods, podIdentifiers, clusterwidePodIdentifiers
}

func (r *PolicyEndpointsReconciler) getPodListToBeCleanedUp(oldPodSet []npatypes.Pod,
	newPodSet []npatypes.Pod, podIdentifiers map[string]bool) []npatypes.Pod {
	var podsToBeCleanedUp []npatypes.Pod

	for _, oldPod := range oldPodSet {
		activePod := false
		oldPodIdentifier := utils.GetPodIdentifier(oldPod.Name, oldPod.Namespace)
		for _, newPod := range newPodSet {
			if oldPod.NamespacedName == newPod.NamespacedName {
				activePod = true
				break
			}
		}
		// We want to clean up the pod when pod is still running but pod is not an active pod against policy endpoint
		// This implies policy endpoint is no longer applied to the podIdentifier
		if !activePod && !podIdentifiers[oldPodIdentifier] {
			log().Infof("Pod to cleanup: name: %s namespace: %s", oldPod.Name, oldPod.Namespace)
			podsToBeCleanedUp = append(podsToBeCleanedUp, oldPod)
		}
	}

	return podsToBeCleanedUp
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

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyk8sawsv1.PolicyEndpoint{}).
		Complete(r)
}

func (r *PolicyEndpointsReconciler) derivePolicyEndpointsOfParentNP(ctx context.Context, parentNP, resourceNamespace string) ([]string, error) {
	var parentPolicyEndpointList []string

	policyEndpointList := &policyk8sawsv1.PolicyEndpointList{}
	if err := r.k8sClient.List(ctx, policyEndpointList, &client.ListOptions{
		Namespace: resourceNamespace,
	}, client.UnsafeDisableDeepCopy); err != nil {
		// A List failure is propagated, never reported as an empty list. Callers read an empty
		// parent PE list as "this NetworkPolicy is fully deleted" and tear down enforcement, so
		// collapsing a transient API/cache error into that case would open traffic.
		return nil, fmt.Errorf(
			"list PolicyEndpoints in namespace %q: %w",
			resourceNamespace,
			err,
		)
	}

	for _, policyEndpoint := range policyEndpointList.Items {
		if policyEndpoint.Spec.PolicyRef.Name == parentNP {
			parentPolicyEndpointList = append(parentPolicyEndpointList, policyEndpoint.Name)
			log().Debugf("Found another PE resource for the parent NP name %s", policyEndpoint.Name)
		}
	}
	return parentPolicyEndpointList, nil
}

func (r *PolicyEndpointsReconciler) GeteBPFClient() ebpf.BpfClient {
	return r.ebpfClient
}

func (r *PolicyEndpointsReconciler) DeriveFireWallRulesPerPodIdentifier(podIdentifier string, podNamespace string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, error) {

	ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(), podIdentifier,
		podNamespace, "", false)
	if err != nil {
		log().Errorf("Error deriving firewall rules: %v", err)
		return ingressRules, egressRules, nil
	}

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
		if len(policyEndpointList.([]string)) > 0 {
			log().Infof("Active policies available against podIdentifier %s", podIdentifier)
			return true
		}
	}
	return false
}
