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
	"github.com/samber/lo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
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
	// lastObservedTriggerTimes maps a PE's EndpointRequest to the last
	// last-change-trigger-time annotation value consumed, so each trigger
	// time is observed at most once
	lastObservedTriggerTimes sync.Map
	// Maps pod Identifier to list of PolicyEndpoint resources ([]utils.PolicyEndpointRef)
	podIdentifierToPolicyEndpointMap sync.Map
	// Mutex for operations on PodIdentifierToPolicyEndpointMap
	podIdentifierToPolicyEndpointMapMutex sync.Mutex
	// Maps a PolicyEndpoint's EndpointRequest to a list of local pods
	policyEndpointSelectorMap sync.Map
	// Maps a Network Policy to list of selected pod Identifiers
	networkPolicyToPodIdentifierMap sync.Map
	//BPF Client instance
	ebpfClient ebpf.BpfClient
	enableIPv6 bool
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/status,verbs=get

func (r *PolicyEndpointsReconciler) Reconcile(ctx context.Context, req EndpointRequest) (ctrl.Result, error) {
	log().Infof("Received a new reconcile request %v", req)
	if err := r.reconcile(ctx, req); err != nil {
		log().Errorf("Reconcile error: %v", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *PolicyEndpointsReconciler) reconcile(ctx context.Context, req EndpointRequest) error {
	policyEndpoint := &policyk8sawsv1.PolicyEndpoint{}
	if err := r.k8sClient.Get(ctx, req.Endpoint, policyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanUpPolicyEndpoint(ctx, req)
		}
		log().Errorf("Unable to get policy endpoint spec for policyendpoint %s: %v", req.Endpoint, err)
		return err
	}
	// A slice now owned by another parent is gone from req.Parent; its new parent has its own request
	if policyEndpoint.Spec.PolicyRef.Name != req.Parent || !policyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpPolicyEndpoint(ctx, req)
	}
	return r.reconcilePolicyEndpoint(ctx, policyEndpoint)
}

// cleanUpPolicyEndpoint removes the slice's contribution under req.Parent and reprograms the
// parent's remaining slices. It touches only state recorded under req.Parent, so it is safe to
// repeat and to run before or after the slice's reconcile under a new parent.
func (r *PolicyEndpointsReconciler) cleanUpPolicyEndpoint(ctx context.Context, req EndpointRequest) error {
	log().Infof("Clean Up PolicyEndpoint resources for %s under %s", req.Endpoint, req.Parent)

	r.lastObservedTriggerTimes.Delete(req)

	start := time.Now()

	// Get all podIdentifiers since we need to decide if pinpath has to be deleted on local node
	parentNP := req.Parent
	resourceName := req.Endpoint.Name
	resourceNamespace := req.Endpoint.Namespace
	targetPods, podIdentifiers, podsToBeCleanedUp, parentPEList, clusterWidePodIdentifiers, err :=
		r.deriveTargetPodsForParentNP(ctx, parentNP, resourceNamespace, resourceName)
	if err != nil {
		// This is expected only if the error is due to inability to list the PE from the cache, in which case we should requeue the reconcile request
		return err
	}

	// Remove the deleted PE from every identifier that recorded it under this parent. Derive
	// prunes only identifiers that went stale, so one still selected via a sibling slice keeps
	// this entry, and inserts are append-only. Uses the selector map's full prior set, not
	// podsToBeCleanedUp, which omits pods a sibling still selects.
	//
	// A retry may see a smaller set than the first pass did, depending on what the entry
	// holds by then, and DeletePolicyEndpointFromPodIdentifierMap is idempotent either way.
	if priorPods, ok := r.policyEndpointSelectorMap.Load(req); ok {
		for _, pod := range priorPods.([]npatypes.Pod) {
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
				&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier,
				utils.PolicyEndpointRef{Name: resourceName, Parent: parentNP})
		}
	}

	log().Infof("cleanUpPolicyEndpoint: Pods to cleanup - %d and Pods to be updated - %d", len(podsToBeCleanedUp), len(targetPods))

	// Program the pods this PE still selects and clean up the deselected ones, regardless of
	// whether either step fails, so a failing cleanup does not strand the pods programmed in
	// the same pass. The cleanup failures are tracked below so the retry repeats only them.
	//
	// Failures from the first call are a subset of targetPods, which trackedPods already
	// carries, so they are deliberately not added to failedCleanups -- that set feeds the
	// departing PE's selector entry, and a pod that failed to PROGRAM must not be recorded
	// there as one of its prior pods or the retry would treat it as needing cleanup.
	_, _, updateErr := r.updatePolicyEnforcementStatusForPods(ctx, parentNP, targetPods, podIdentifiers, false)
	if updateErr != nil {
		updateErr = fmt.Errorf("update active pods for policyendpoint %s: %w", resourceName, updateErr)
	}
	failedCleanups, _, cleanupErr := r.updatePolicyEnforcementStatusForPods(ctx, parentNP, podsToBeCleanedUp, podIdentifiers, true)
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("clean up deselected pods for policyendpoint %s: %w", resourceName, cleanupErr)
	}
	// Only a pass that actually tore something down, and succeeded at it, is a teardown
	// measurement. Observing unconditionally would also add a label series per PE name per
	// node -- every node reconciles every PE, GenerateName means the names are never reused,
	// and nothing ever removes a series -- so empty and failed passes would grow cardinality
	// without recording anything meaningful.
	if updateErr == nil && cleanupErr == nil && (len(targetPods) > 0 || len(podsToBeCleanedUp) > 0) {
		policyTearDownLatency.WithLabelValues(resourceName, resourceNamespace).Observe(msSince(start))
	}

	// Commit the pods this PE still programs plus the pods whose cleanup failed, with their
	// identifiers, so the retry derives the failed ones as stale again and repeats only those.
	trackedPods, trackedPodIdentifiers := trackFailedCleanups(targetPods, failedCleanups, clusterWidePodIdentifiers)
	r.commitPolicyEndpointState(parentNP, resourceNamespace, trackedPods, trackedPodIdentifiers, parentPEList)

	// Until every cleanup succeeds, keep this PE's selector entry holding the pods that failed
	// so the retry finds them. commitPolicyEndpointState already stored/deleted the entries for
	// the PEs in parentPEList; only touch this request's entry when the PE is not one of them,
	// or we would clobber what commit just wrote.
	err = errors.Join(updateErr, cleanupErr)
	if !slices.Contains(parentPEList, resourceName) {
		if len(failedCleanups) > 0 {
			r.policyEndpointSelectorMap.Store(req, failedCleanups)
		} else {
			r.policyEndpointSelectorMap.Delete(req)
		}
	}

	return err
}

// updatePolicyEnforcementStatusForPods runs cleanupPod over each pod and returns the pods
// it failed on, so the caller can keep tracking them and retry only those on the next
// reconcile.
//
// Despite the name, this is not cleanup-only: cleanUpPolicyEndpoint also calls it on
// targetPods, the pods the parent policy still selects. For those, cleanupPod re-derives
// the surviving rules and reprograms them, which is what drops the departing slice's
// contribution while leaving the rest of the parent's policy in place.
func (r *PolicyEndpointsReconciler) updatePolicyEnforcementStatusForPods(ctx context.Context, parentNP string,
	targetPods []npatypes.Pod, podIdentifiers map[string]bool, isDeleteFlow bool) ([]npatypes.Pod, int, error) {
	var failed []npatypes.Pod
	var err error
	cleaned := 0
	// 1. If the pods are already deleted, we move on.
	// 2. If the pods have another policy or policies active against them, we update the maps to purge the entries
	//    introduced by the current policy.
	// 3. If there are no more active policies against this pod, we update pod_state to default deny/allow
	for _, targetPod := range targetPods {
		podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)
		log().Infof("Updating Pod: Name: %s Namespace: %s PodIdentifier: %s", targetPod.Name, targetPod.Namespace, podIdentifier)

		wrote, cleanupErr := r.cleanupPod(ctx, targetPod, parentNP, isDeleteFlow)
		if cleanupErr != nil {
			failed = append(failed, targetPod)
			err = errors.Join(err, fmt.Errorf("pod %s/%s: %w",
				targetPod.Namespace, targetPod.Name, cleanupErr))
			// we don't want to return an error right away but instead attempt to clean up all the pods
			// in the list before returning
			continue
		}
		if wrote {
			cleaned++
		}
	}
	return failed, cleaned, err
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

	// Programming runs whether or not cleanup succeeded, so a failing cleanup does not hold
	// back the other pods this policy selects. podIdentifiers has the pod identifiers of the
	// targetPods from the derived PEs.
	failedCleanups, cleaned, cleanupErr := r.updatePolicyEnforcementStatusForPods(ctx, parentNP, podsToBeCleanedUp, podIdentifiers, false)
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("clean up deselected pods for policyendpoint %s: %w", policyEndpoint.Name, cleanupErr)
	}

	// Track the pods programmed below, so they can be cleaned up later, and the pods whose
	// cleanup failed, so the retry still finds them and repeats only those.
	trackedPods, trackedPodIdentifiers := trackFailedCleanups(targetPods, failedCleanups, clusterWidePodIdentifiers)
	r.commitPolicyEndpointState(parentNP, resourceNamespace, trackedPods, trackedPodIdentifiers, parentPEList)

	// Program the podIdentifiers local to the node.
	programmed := 0
	skipped := 0
	var programmingErr error
	for podIdentifier := range podIdentifiers {
		// Derive Ingress IPs from the PolicyEndpoint
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier,
			policyEndpoint.Namespace, parentNP, false)
		if err != nil {
			// Record and continue: a derive failure for one identifier must not abort the
			// loop for every identifier after it. The returned error requeues the request.
			programmingErr = errors.Join(programmingErr, fmt.Errorf(
				"parse policyendpoint %s for podIdentifier %s: %w", policyEndpoint.Name, podIdentifier, err))
			continue
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
		result, err := r.configureeBPFProbes(podIdentifier, targetPods, ingressRules, egressRules)
		switch {
		case err != nil:
			// Checked before the skip case: a skip travels in result, not in err, so a real
			// failure here is never mistaken for one. Record and continue so every other
			// identifier is still programmed. The returned error requeues the request, so this
			// pod is retried instead of left unprogrammed until the PE next changes.
			programmingErr = errors.Join(programmingErr, fmt.Errorf(
				"configure eBPF probes for podIdentifier %s: %w", podIdentifier, err))
		case result.programmed:
			programmed++
		case result.skipped > 0:
			// Retrying cannot resolve this, so do not report it as a failure.
			skipped += result.skipped
			log().Warnf("Skipped eBPF programming for podIdentifier %s: %d pod(s) cannot attach yet",
				podIdentifier, result.skipped)
		default:
			// No context on this node and nothing skipped, so this identifier had nothing to do.
			log().Debugf("No eBPF programming needed for podIdentifier %s on this node", podIdentifier)
		}
		duration := msSince(start)
		policySetupLatency.WithLabelValues(policyEndpoint.Name, policyEndpoint.Namespace).Observe(duration)
	}

	// Three outcomes, because the trigger annotation has to be handled differently in each.
	// A failing pass leaves it unconsumed so the retry that finally lands the change records
	// it, retry delay included -- otherwise the histogram would drop exactly the slow
	// recover-after-failure cases it most needs to show. A pass that wrote something records
	// the sample. A pass with nothing to do on this node consumes the trigger without a
	// sample: leaving it would let a later resync of the unchanged PE, or a sibling slice
	// gaining a local pod, measure from the original change and report that staleness as
	// programming latency. Cleanup writes count as work, so a cleanup-only pass that finally
	// succeeds is still measured.
	outcome := programmingNoWork
	switch {
	case cleanupErr != nil || programmingErr != nil:
		outcome = programmingDeferred
	case programmed > 0 || cleaned > 0:
		outcome = programmingLanded
	case skipped > 0:
		// Deferred rather than consumed: these pods are local and a later pass can still
		// attach and program them, and that latency is real. Consuming here would drop it.
		outcome = programmingDeferred
	}
	r.observePolicyProgrammingLatency(policyEndpoint, outcome)

	return errors.Join(cleanupErr, programmingErr)
}

func (r *PolicyEndpointsReconciler) commitPolicyEndpointState(
	parentNP string,
	resourceNamespace string,
	newTargetPods []npatypes.Pod,
	clusterWidePodIdentifiers map[string]bool,
	parentPEList []string,
) {
	for _, peName := range parentPEList {
		key := EndpointRequest{Endpoint: types.NamespacedName{Name: peName, Namespace: resourceNamespace}, Parent: parentNP}
		if len(newTargetPods) > 0 {
			r.policyEndpointSelectorMap.Store(key, newTargetPods)
		} else {
			r.policyEndpointSelectorMap.Delete(key)
		}
	}

	// Store the cluster wide pod identifiers associated with this network policy
	// since this map helps track stale identifiers and cleanup from PodIdentifier to PolicyEndpoint mappings
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
// last-change-trigger-time annotation. Each annotation value is observed at most
// once per PE: it is consumed once the change has landed, so stale
// rewrites/resyncs/relists never re-observe it.
//
// A pass that has not landed the change leaves the annotation unconsumed, so the
// later pass that does land it reports the full time including any retry delay.
// policyProgrammingOutcome says what a reconcile pass did with the change its trigger
// annotation refers to. A bool cannot express it, because consuming the trigger and recording
// a sample are separate decisions: a pass with nothing to do on this node must consume without
// measuring, or a later resync measures from a change that landed long ago.
type policyProgrammingOutcome int

const (
	// programmingNoWork: the change does not apply to this node. Consume, no sample.
	programmingNoWork policyProgrammingOutcome = iota
	// programmingLanded: maps were written here. Consume and record the sample.
	programmingLanded
	// programmingDeferred: the pass failed. Neither, so the retry that lands it measures.
	programmingDeferred
)

func (r *PolicyEndpointsReconciler) observePolicyProgrammingLatency(pe *policyk8sawsv1.PolicyEndpoint, outcome policyProgrammingOutcome) {
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
	peKey := EndpointRequest{Endpoint: types.NamespacedName{Namespace: pe.Namespace, Name: pe.Name}, Parent: pe.Spec.PolicyRef.Name}
	if prev, ok := r.lastObservedTriggerTimes.Load(peKey); ok && prev.(string) == triggerTimeStr {
		return
	}
	if outcome == programmingDeferred {
		// Left unconsumed on purpose: the pass that lands the change observes it.
		log().Debugf("Deferring E2E policy programming latency for PE %s/%s: change has not landed yet", pe.Namespace, pe.Name)
		return
	}
	// Consume before the suppression check below: the change has landed, so a
	// clock-skew-suppressed observation must not be re-emitted (inflated) by a
	// later resync of the same annotation.
	r.lastObservedTriggerTimes.Store(peKey, triggerTimeStr)
	if outcome == programmingNoWork {
		// Consumed without measuring: nothing on this node implements this change, so any
		// elapsed time here is the age of the annotation, not programming latency.
		log().Debugf("No local work for PE %s/%s: consuming trigger without a latency sample", pe.Namespace, pe.Name)
		return
	}
	latency := time.Since(triggerTime).Seconds()
	if latency < 0 {
		// Clock skew between NPC (control plane) and this node
		log().Debugf("Skipping negative E2E policy programming latency %.3fs for PE %s/%s", latency, pe.Namespace, pe.Name)
		return
	}
	policyProgrammingLatency.Observe(latency)
	log().Debugf("E2E policy programming latency: %.3fs for PE %s/%s", latency, pe.Namespace, pe.Name)
}

// probeConfigResult reports what configureeBPFProbes actually did. The caller needs the three
// cases apart: maps written, nothing on this node to write, and pods that can never attach.
// Returning only an error cannot express them, and treating "no error" as "programmed" counts
// a pass that wrote nothing.
type probeConfigResult struct {
	// programmed is true when the identifier's maps were written on this pass.
	programmed bool
	// skipped is the number of pods whose probe attach cannot be retried into success.
	skipped int
}

func (r *PolicyEndpointsReconciler) configureeBPFProbes(podIdentifier string,
	targetPods []npatypes.Pod, ingressRules, egressRules []fwrp.EbpfFirewallRules) (probeConfigResult, error) {
	attached, configureProbesErr := attachProbesForIdentifier(r.ebpfClient, podIdentifier, targetPods)
	result := probeConfigResult{skipped: attached.skipped}

	// AttacheBPFProbes skips pods already deleted from the node, so the PolicyEndpoint can
	// still list a pod that has no programs here. There is nothing to program until a new
	// pod attaches, so this returns without programmed set: counting it would consume the
	// change's trigger time for work that never happened.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		return result, configureProbesErr
	}

	if err := r.updateeBPFMaps(podIdentifier, ingressRules, egressRules, ebpf.POLICIES_APPLIED); err != nil {
		return result, errors.Join(configureProbesErr, fmt.Errorf("map updates failed for podIdentifier %s: %w", podIdentifier, err))
	}
	result.programmed = true
	return result, configureProbesErr
}

// cleanupPod reconciles one pod's programming after its policy stopped selecting it. It
// reports whether it wrote any map, so the caller can tell a cleanup that did real work from
// one that found nothing on this node and count the former as programming.
func (r *PolicyEndpointsReconciler) cleanupPod(ctx context.Context, targetPod npatypes.Pod,
	parentNP string, isDeleteFlow bool) (bool, error) {

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
		return false, nil
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
			return false, fmt.Errorf("baseline restore failed for podIdentifier %s, requeueing for retry: %w", podIdentifier, err)
		}
		return true, nil
	}

	// Detach eBPF probes attached to the local pods (if required). We should detach eBPF probes if this
	// is the only PolicyEndpoint resource that applies to this pod. If not, just update the Ingress/Egress Map contents
	ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err = r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, targetPod.Namespace,
		parentNP, isDeleteFlow)
	if err != nil {
		return false, fmt.Errorf("derive firewall rules for podIdentifier %s: %w", podIdentifier, err)
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
			return false, fmt.Errorf("apply baseline state for podIdentifier %s: %w", podIdentifier, err)
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
			return false, fmt.Errorf("apply remaining policies for podIdentifier %s: %w", podIdentifier, err)
		}
	}

	// Both arms above write a map, so reaching here means cleanup did real work.
	return true, nil
}

func (r *PolicyEndpointsReconciler) deriveIngressAndEgressFirewallRules(ctx context.Context,
	podIdentifier string, resourceNamespace string, parentNP string, isDeleteFlow bool) ([]fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules, bool, bool, error) {
	var ingressRules, egressRules []fwrp.EbpfFirewallRules
	isIngressIsolated, isEgressIsolated := false, false
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		log().Infof("Total number of PolicyEndpoint resources for podIdentifier %s are %d", podIdentifier, len(policyEndpointList.([]utils.PolicyEndpointRef)))
		for _, ref := range policyEndpointList.([]utils.PolicyEndpointRef) {
			peNamespacedName := types.NamespacedName{
				Name:      ref.Name,
				Namespace: resourceNamespace,
			}

			if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE, client.UnsafeDisableDeepCopy); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, isIngressIsolated, isEgressIsolated, err
			}

			// The name was reused under another parent; this entry's cleanup is still pending
			if currentPE.Spec.PolicyRef.Name != ref.Parent {
				continue
			}

			if isDeleteFlow && ref.Parent == parentNP {
				log().Debugf("PE belongs to same NP. Ignore and move on since it's a delete flow parentNP %s currentPE %s", parentNP, ref.Name)
				continue
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

	parentPEObjects, err := r.derivePolicyEndpointsOfParentNP(ctx, parentNP, resourceNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	parentPEList := lo.Map(parentPEObjects, func(pe policyk8sawsv1.PolicyEndpoint, _ int) string {
		return pe.Name
	})

	log().Infof("Parent NP resource: Name: %s Total PEs for Parent NP: Count: %d", parentNP, len(parentPEList))

	// Gather the pods (local to the node) this policy's rules were applied to in previous
	// reconciles, from every one of the parent's slices -- not just the reconciled one -- so a
	// slice reconciled before it has an entry of its own (a new slice created in the same
	// update that deselects a pod) still finds that pod under a sibling and cleans it up. The
	// selector map is keyed by name, namespace and parent, so a same-named slice in another
	// namespace, or one recorded under another parent, is not read.
	for _, peName := range lo.Uniq(append([]string{resourceName}, parentPEList...)) {
		key := EndpointRequest{Endpoint: types.NamespacedName{Name: peName, Namespace: resourceNamespace}, Parent: parentNP}
		if existingPods, ok := r.policyEndpointSelectorMap.Load(key); ok {
			priorTargetPods = append(priorTargetPods, existingPods.([]npatypes.Pod)...)
		}
	}
	// Dedupe on identity, not on the whole struct: the same pod can be recorded under two
	// slices with different PodIPs (a StatefulSet pod keeps its name across recreation but
	// not its address), and GetPodListToBeCleanedUp matches on NamespacedName, so both copies
	// would land in podsToBeCleanedUp and the pod would be cleaned up twice.
	priorTargetPods = lo.UniqBy(priorTargetPods, func(pod npatypes.Pod) types.NamespacedName {
		return pod.NamespacedName
	})

	if len(parentPEList) == 0 {
		podsToBeCleanedUp = append(podsToBeCleanedUp, priorTargetPods...)
		parentPEList = []string{resourceName}
		log().Infof("No PEs left: number of pods to cleanup - %d", len(podsToBeCleanedUp))
	} else {
		for _, currentPE := range parentPEObjects {
			log().Infof("Processing PE Name %s", currentPE.Name)
			localTargetPods, localTargetPodIdentifiers, clusterWideTargetPodIdentifiers := r.deriveTargetPods(ctx, &currentPE, parentNP, parentPEList)
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

	// Diff the previous selected-identifier set (from networkPolicyToPodIdentifierMap)
	// against the current one. Both sides cover every identifier this NP selects on any
	// node, so non-local identifiers that are no longer selected are flagged stale and
	// pruned from podIdentifierToPolicyEndpointMap which maintains this mapping cluster-wide
	// for optimization purposes
	networkPolicyIdentifier := utils.GetNetworkPolicyIdentifier(parentNP, resourceNamespace)
	stalePodIdentifiers := utils.DeriveStalePodIdentifiers(&r.networkPolicyToPodIdentifierMap,
		networkPolicyIdentifier, clusterWidePodIdentifiers)

	// A stale identifier still holds the slices from the reconcile that last selected it,
	// including deleted ones and ones whose names moved to another parent, so drop every entry
	// of this parent rather than only its live slices
	for _, podIdentifier := range stalePodIdentifiers {
		utils.DeleteParentFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
			&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parentNP)
	}

	if len(priorTargetPods) > 0 {
		podsToBeCleanedUp = utils.GetPodListToBeCleanedUp(priorTargetPods, targetPods, podIdentifiers)
	}
	return targetPods, podIdentifiers, podsToBeCleanedUp, parentPEList, clusterWidePodIdentifiers, nil
}

// Derives list of local pods the policy endpoint resource selects.
// Function returns:
//   - targetPods: node-local pods selected by this PE (drives eBPF programming)
//   - podIdentifiers: identifiers of the local targetPods
//   - clusterwidePodIdentifiers: every identifier this PE selects, on any node
func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint, parentNP string, parentPEList []string) ([]npatypes.Pod, map[string]bool, map[string]bool) {
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
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToPolicyEndpointMap, &r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parentNP, parentPEList)
	}
	return targetPods, podIdentifiers, clusterwidePodIdentifiers
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
	return setupEndpointController(mgr, "policyendpoint", &policyk8sawsv1.PolicyEndpoint{},
		policyEndpointParent, r, controller.TypedOptions[EndpointRequest]{})
}

func policyEndpointParent(pe *policyk8sawsv1.PolicyEndpoint) string { return pe.Spec.PolicyRef.Name }

// derivePolicyEndpointsOfParentNP returns the parent NetworkPolicy's slices as objects, not
// just names, mirroring getClusterPolicyEndpointsOfParentCNP. The List already carries every
// slice's full spec, so returning the objects saves the caller a per-name Get -- and, more
// importantly, leaves it with no call inside its loop that can fail partway. A mid-loop
// failure there would be observed after podIdentifierToPolicyEndpointMap had already been
// written for the slices processed before it, while networkPolicyToPodIdentifierMap is only
// written on the commit path the failure skips. The two maps would then disagree, and since
// staleness is computed as "previously selected minus currently selected", the names left in
// podIdentifierToPolicyEndpointMap could never be pruned again.
func (r *PolicyEndpointsReconciler) derivePolicyEndpointsOfParentNP(ctx context.Context, parentNP, resourceNamespace string) ([]policyk8sawsv1.PolicyEndpoint, error) {
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

	var parentPolicyEndpoints []policyk8sawsv1.PolicyEndpoint
	for _, policyEndpoint := range policyEndpointList.Items {
		if policyEndpoint.Spec.PolicyRef.Name == parentNP {
			parentPolicyEndpoints = append(parentPolicyEndpoints, policyEndpoint)
			log().Debugf("Found another PE resource for the parent NP name %s", policyEndpoint.Name)
		}
	}
	return parentPolicyEndpoints, nil
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
		if len(policyEndpointList.([]utils.PolicyEndpointRef)) > 0 {
			log().Infof("Active policies available against podIdentifier %s", podIdentifier)
			return true
		}
	}
	return false
}
