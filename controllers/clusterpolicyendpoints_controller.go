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
	"net"
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
	k8sClient client.Client
	scheme    *runtime.Scheme
	nodeIP    string
	// trackerStartTime records when this reconciler started. Used to filter
	// stale ClusterPolicyEndpoint annotations and avoid emitting artificially high
	// E2E latency on restart
	trackerStartTime time.Time

	// Maps pod Identifier to list of ClusterPolicyEndpoint resources
	podIdentifierToClusterPolicyEndpointMap      sync.Map
	podIdentifierToClusterPolicyEndpointMapMutex sync.Mutex
	// Maps ClusterPolicyEndpoint resource with a list of local pods (cluster-scoped)
	ClusterPolicyEndpointSelectorMap sync.Map
	// Maps ClusterNetworkPolicy to list of selected pod Identifiers
	clusterNetworkPolicyToPodIdentifierMap sync.Map

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
	ClusterPolicyEndpoint := &policyk8sawsv1.ClusterPolicyEndpoint{}
	// Cluster-scoped: use only name, no namespace
	if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: req.Name}, ClusterPolicyEndpoint); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanUpClusterPolicyEndpoint(ctx, req)
		}
		log().Errorf("Unable to get cluster policy endpoint spec for ClusterPolicyendpoint %s: %v", req.Name, err)
		return err
	}
	if !ClusterPolicyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpClusterPolicyEndpoint(ctx, req)
	}
	return r.reconcileClusterPolicyEndpoint(ctx, ClusterPolicyEndpoint)
}

func (r *ClusterPolicyEndpointsReconciler) cleanUpClusterPolicyEndpoint(ctx context.Context, req ctrl.Request) error {
	log().Infof("Clean Up ClusterPolicyEndpoint resources for name: %s", req.Name)

	parentCNP := utils.GetParentNPNameFromPEName(req.Name)
	resourceName := req.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp := r.deriveTargetPodsForParentCNP(ctx, parentCNP, resourceName)

	r.ClusterPolicyEndpointSelectorMap.Delete(resourceName)

	log().Infof("cleanUpClusterPolicyEndpoint: Pods to cleanup - %d and Pods to be updated - %d", len(podsToBeCleanedUp), len(targetPods))

	if len(targetPods) > 0 {
		err := r.updateClusterPolicyEnforcementStatusForPods(ctx, req.Name, targetPods, targetPodIdentifiers, false)
		if err != nil {
			log().Errorf("failed to update cluster policy bpf probes for policy endpoint %s : %v", req.Name, err)
			return err
		}
	}

	if len(podsToBeCleanedUp) > 0 {
		err := r.updateClusterPolicyEnforcementStatusForPods(ctx, req.Name, podsToBeCleanedUp, targetPodIdentifiers, true)
		if err != nil {
			log().Errorf("failed to clean up cluster policy bpf probes for policy endpoint %s : %v", req.Name, err)
			return err
		}
	}

	for _, podToBeCleanedUp := range podsToBeCleanedUp {
		podIdentifier := utils.GetPodIdentifier(podToBeCleanedUp.Name, podToBeCleanedUp.Namespace)
		utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, req.Name)
	}

	return nil
}

func (r *ClusterPolicyEndpointsReconciler) reconcileClusterPolicyEndpoint(ctx context.Context, ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint) error {
	log().Infof("Processing Cluster Policy Endpoint Name: %s", ClusterPolicyEndpoint.Name)

	parentCNP := ClusterPolicyEndpoint.Spec.PolicyRef.Name
	resourceName := ClusterPolicyEndpoint.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp := r.deriveTargetPodsForParentCNP(ctx, parentCNP, resourceName)

	// Handle cleanup of pods
	err := r.updateClusterPolicyEnforcementStatusForPods(ctx, ClusterPolicyEndpoint.Name, podsToBeCleanedUp, targetPodIdentifiers, false)
	if err != nil {
		log().Errorf("failed to update cluster policy enforcement status for existing pods: %v", err)
		return err
	}

	for podIdentifier := range targetPodIdentifiers {
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, ClusterPolicyEndpoint.Name, false)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resource %s: %v", ClusterPolicyEndpoint.Name, err)
			return err
		}

		err = r.configureClusterPolicyBPFProbes(podIdentifier, targetPods, ingressRules, egressRules)
		if err != nil {
			log().Errorf("Error configuring Cluster Policy eBPF Probes %v", err)
		}
	}

	r.observeClusterPolicyProgrammingLatency(ClusterPolicyEndpoint)

	return nil
}

// observeClusterPolicyProgrammingLatency reads the last-change-trigger-time annotation
// from the ClusterPolicyEndpoint and emits the E2E latency histogram if the timestamp
// is newer than this agent's start time.
func (r *ClusterPolicyEndpointsReconciler) observeClusterPolicyProgrammingLatency(cpe *policyk8sawsv1.ClusterPolicyEndpoint) {
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
	latency := time.Since(triggerTime).Seconds()
	clusterPolicyProgrammingLatency.Observe(latency)
	log().Debugf("E2E cluster policy programming latency: %.3fs for CPE %s", latency, cpe.Name)
}

func (r *ClusterPolicyEndpointsReconciler) configureClusterPolicyBPFProbes(podIdentifier string, targetPods []npatypes.Pod, ingressRules, egressRules []fwrp.EbpfFirewallRules) error {

	for _, pod := range targetPods {
		currentPodIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if currentPodIdentifier != podIdentifier {
			continue
		}

		err := r.ebpfClient.AttacheBPFProbes(pod.NamespacedName, podIdentifier, ebpf.INTERFACE_COUNT_UNKNOWN)
		if err != nil {
			log().Errorf("Failed to attach eBPF probes for pod %s namespace %s : %v", pod.Name, pod.Namespace, err)
			return err
		}
		log().Infof("Successfully attached required eBPF probes for pod: %s in namespace %s", pod.Name, pod.Namespace)
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
	r.ebpfClient.CreatePodStateEbpfEntryIfNotExists(podIdentifier, ebpf.POD_STATE_MAP_KEY, defaultState)
	return nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyIngressAndEgressFirewallRules(ctx context.Context, podIdentifier string, resourceName string, isDeleteFlow bool) ([]fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules, error) {

	var clusterPolicyIngressRules, clusterPolicyEgressRules []fwrp.EbpfFirewallRules
	currentCPE := &policyk8sawsv1.ClusterPolicyEndpoint{}

	if ClusterPolicyEndpointList, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		log().Infof("Total number of ClusterPolicyEndpoint resources for podIdentifier %s are %d", podIdentifier, len(ClusterPolicyEndpointList.([]string)))
		for _, ClusterPolicyEndpointResource := range ClusterPolicyEndpointList.([]string) {
			// Cluster-scoped: no namespace
			cpeNamespacedName := types.NamespacedName{Name: ClusterPolicyEndpointResource}

			if isDeleteFlow {
				deletedCPEParentCNPName := utils.GetParentNPNameFromPEName(resourceName)
				currentCPEParentCNPName := utils.GetParentNPNameFromPEName(ClusterPolicyEndpointResource)
				if deletedCPEParentCNPName == currentCPEParentCNPName {
					log().Debugf("CPE belongs to same CNP. Ignore and move on since it's a delete flow deletedCPE %s currentCPE %s", resourceName, ClusterPolicyEndpointResource)
					continue
				}
			}

			if err := r.k8sClient.Get(ctx, cpeNamespacedName, currentCPE); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, err
			}

			for _, endPointInfo := range currentCPE.Spec.Ingress {
				priority := int(currentCPE.Spec.Priority)
				if currentCPE.Spec.Tier == policyk8sawsv1.BaselineTier {
					priority += fwrp.BASELINE_TIER_PRIORITY_OFFSET
				}
				clusterPolicyIngressRules = append(clusterPolicyIngressRules, fwrp.EbpfFirewallRules{
					Priority: priority,
					Action:   endPointInfo.Action,
					IPCidr:   endPointInfo.CIDR,
					L4Info:   endPointInfo.Ports,
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
					L4Info:     endPointInfo.Ports,
				})
			}
			log().Infof("Total no.of clusterPolicy ingressRules %d egressRules %d", len(clusterPolicyIngressRules), len(clusterPolicyEgressRules))
		}
	}
	return clusterPolicyIngressRules, clusterPolicyEgressRules, nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveTargetPodsForParentCNP(ctx context.Context, parentCNP, resourceName string) ([]npatypes.Pod, map[string]bool, []npatypes.Pod) {
	var newTargetPods, podsToBeCleanedUp, currentPods []npatypes.Pod
	var targetPodIdentifiers []string
	podIdentifiers := make(map[string]bool)

	// Get current pods selected by the PE objects for this CNP
	existingPods, podsPresent := r.ClusterPolicyEndpointSelectorMap.Load(resourceName)
	if podsPresent {
		existingPodsSlice := existingPods.([]npatypes.Pod)
		currentPods = append(currentPods, existingPodsSlice...)
	}

	// Get all ClusterPolicyEndpoints for this ClusterNetworkPolicy in one call
	parentCPEObjects := r.getClusterPolicyEndpointsOfParentCNP(ctx, parentCNP)
	log().Infof("Parent Cluster Network Policy resource Name: %s Total Cluster Policy Endpoints for Parent CNP: Count: %d", parentCNP, len(parentCPEObjects))

	if len(parentCPEObjects) == 0 {
		podsToBeCleanedUp = append(podsToBeCleanedUp, currentPods...)
		r.ClusterPolicyEndpointSelectorMap.Delete(resourceName)
		log().Infof("No CPEs left: number of pods to cleanup - %d", len(podsToBeCleanedUp))
		return newTargetPods, podIdentifiers, podsToBeCleanedUp
	}

	// Extract names for later use
	parentCPEList := lo.Map(parentCPEObjects, func(cpe policyk8sawsv1.ClusterPolicyEndpoint, _ int) string {
		return cpe.Name
	})

	// Process each ClusterPolicyEndpoint object on this node.
	// Collect all the newTargetPods and PodIdentifiers targeted by this CNP
	for _, currentCPE := range parentCPEObjects {
		currentTargetPods, currentPodIdentifiers := r.deriveClusterPolicyTargetPods(&currentCPE, parentCPEList)
		newTargetPods = append(newTargetPods, currentTargetPods...)
		for podIdentifier := range currentPodIdentifiers {
			podIdentifiers[podIdentifier] = true
			targetPodIdentifiers = append(targetPodIdentifiers, podIdentifier)
		}
	}
	// Derive Pod Identifiers that are no longer selected by this policy
	stalePodIdentifiers := utils.DeriveStalePodIdentifiers(&r.clusterNetworkPolicyToPodIdentifierMap, resourceName, targetPodIdentifiers)

	for _, ClusterPolicyEndpointResource := range parentCPEList {
		if len(newTargetPods) > 0 {
			r.ClusterPolicyEndpointSelectorMap.Store(ClusterPolicyEndpointResource, newTargetPods)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(ClusterPolicyEndpointResource)
		}

		for _, podIdentifier := range stalePodIdentifiers {
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, ClusterPolicyEndpointResource)
		}
	}

	if len(targetPodIdentifiers) == 0 {
		r.clusterNetworkPolicyToPodIdentifierMap.Delete(utils.GetParentNPNameFromPEName(resourceName))
	} else {
		r.clusterNetworkPolicyToPodIdentifierMap.Store(utils.GetParentNPNameFromPEName(resourceName), targetPodIdentifiers)
	}
	// Verify which pods needs to be cleaned up
	if len(currentPods) > 0 {
		podsToBeCleanedUp = utils.GetPodListToBeCleanedUp(currentPods, newTargetPods, podIdentifiers)
	}
	return newTargetPods, podIdentifiers, podsToBeCleanedUp
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyTargetPods(ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint, parentCPEList []string) ([]npatypes.Pod, map[string]bool) {
	var targetPods []npatypes.Pod
	podIdentifiers := make(map[string]bool)

	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range ClusterPolicyEndpoint.Spec.PodSelectorEndpoints {
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			targetPods = append(targetPods, npatypes.Pod{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, PodIP: pod.PodIP})
			podIdentifiers[podIdentifier] = true
		}
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCPEList)
	}
	return targetPods, podIdentifiers
}

func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyEnforcementStatusForPods(ctx context.Context, ClusterPolicyEndpointName string, cleanupPods []npatypes.Pod, podIdentifiers map[string]bool, isDeleteFlow bool) error {
	var err error
	for _, cleanupPod := range cleanupPods {
		cleanupErr := r.cleanupClusterPolicyPod(ctx, cleanupPod, ClusterPolicyEndpointName, isDeleteFlow)
		if cleanupErr != nil {
			log().Errorf("Cluster Policy Cleanup/Update unsuccessful for Pod Name: %s Namespace: %s ", cleanupPod.Name, cleanupPod.Namespace)
			err = errors.Join(err, cleanupErr)
		}
	}
	return err
}

func (r *ClusterPolicyEndpointsReconciler) cleanupClusterPolicyPod(ctx context.Context, targetPod npatypes.Pod, clusterPolicyEndpoint string, isDeleteFlow bool) error {
	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)

	if _, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		clusterPolicyIngressRules, clusterPolicyEgressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, clusterPolicyEndpoint, isDeleteFlow)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resource %s: %v", clusterPolicyEndpoint, err)
			return err
		}

		// No catch-all rules for cluster policies - just update with remaining rules
		err = r.updateClusterPolicyBPFMaps(podIdentifier, clusterPolicyIngressRules, clusterPolicyEgressRules)
		if err != nil {
			log().Errorf("cluster policy map update(s) failed for podIdentifier %s: %v", podIdentifier, err)
			return err
		}
	}
	return nil
}

func (r *ClusterPolicyEndpointsReconciler) getClusterPolicyEndpointsOfParentCNP(ctx context.Context, parentCNP string) []policyk8sawsv1.ClusterPolicyEndpoint {
	var parentClusterPolicyEndpoints []policyk8sawsv1.ClusterPolicyEndpoint

	ClusterPolicyEndpointList := &policyk8sawsv1.ClusterPolicyEndpointList{}
	// Cluster-scoped: no namespace filter
	if err := r.k8sClient.List(ctx, ClusterPolicyEndpointList, &client.ListOptions{}); err != nil {
		log().Errorf("Unable to list ClusterPolicyEndpoints err: %v", err)
		return nil
	}

	for _, ClusterPolicyEndpoint := range ClusterPolicyEndpointList.Items {
		if ClusterPolicyEndpoint.Spec.PolicyRef.Name == parentCNP {
			parentClusterPolicyEndpoints = append(parentClusterPolicyEndpoints, ClusterPolicyEndpoint)
		}
	}
	return parentClusterPolicyEndpoints
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
