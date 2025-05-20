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
	"sync"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
	networking "k8s.io/api/networking/v1"
)

const (
	defaultLocalConntrackCacheCleanupPeriodInSeconds = 300
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
	prometheusRegistered = false
)

const (
	POLICIES_APPLIED = 0
	DEFAULT_ALLOW    = 1
	DEFAULT_DENY     = 2
)

func msSince(start time.Time) float64 {
	return float64(time.Since(start) / time.Millisecond)
}

func prometheusRegister() {
	if !prometheusRegistered {
		prometheus.MustRegister(policySetupLatency)
		prometheus.MustRegister(policyTearDownLatency)
		prometheusRegistered = true
	}
}

// NewPolicyEndpointsReconciler constructs new PolicyEndpointReconciler
func NewPolicyEndpointsReconciler(k8sClient client.Client, log logr.Logger, nodeIP string, ebpfClient ebpf.BpfClient) *PolicyEndpointsReconciler {
	r := &PolicyEndpointsReconciler{
		k8sClient:  k8sClient,
		log:        log,
		nodeIP:     nodeIP,
		ebpfClient: ebpfClient,
	}

	prometheusRegister()
	return r
}

// PolicyEndpointsReconciler reconciles a PolicyEndpoints object
type PolicyEndpointsReconciler struct {
	k8sClient client.Client
	scheme    *runtime.Scheme
	//Primary IP of EC2 instance
	nodeIP string
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
	// NetworkPolicy mode standard/strict
	networkPolicyMode string
	//Logger
	log logr.Logger
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/status,verbs=get

func (r *PolicyEndpointsReconciler) SetNetworkPolicyMode(mode string) {
	r.networkPolicyMode = mode
}

func (r *PolicyEndpointsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.log.Info("Received a new reconcile request", "req", req)
	if err := r.reconcile(ctx, req); err != nil {
		r.log.Error(err, "Reconcile error")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *PolicyEndpointsReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	policyEndpoint := &policyk8sawsv1.PolicyEndpoint{}
	if err := r.k8sClient.Get(ctx, req.NamespacedName, policyEndpoint); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanUpPolicyEndpoint(ctx, req)
		}
		r.log.Error(err, "Unable to get policy endpoint spec", "policyendpoint", req.NamespacedName)
		return err
	}
	if !policyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpPolicyEndpoint(ctx, req)
	}
	return r.reconcilePolicyEndpoint(ctx, policyEndpoint)
}

func (r *PolicyEndpointsReconciler) cleanUpPolicyEndpoint(ctx context.Context, req ctrl.Request) error {
	r.log.Info("Clean Up PolicyEndpoint resources for", "name:", req.NamespacedName.Name)
	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(req.NamespacedName.Name,
		req.NamespacedName.Namespace)

	start := time.Now()

	// Get all podIdentifiers since we need to decide if pinpath has to be deleted on local node
	parentNP := utils.GetParentNPNameFromPEName(req.NamespacedName.Name)
	resourceName := req.NamespacedName.Name
	resourceNamespace := req.NamespacedName.Namespace
	targetPods, podIdentifiers, podsToBeCleanedUp := r.deriveTargetPodsForParentNP(ctx, parentNP, resourceNamespace, resourceName)

	r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)

	// targetPods are pods which would need map update
	if len(targetPods) > 0 {
		r.log.Info("Updating active pods...")
		err := r.updatePolicyEnforcementStatusForPods(ctx, req.NamespacedName.Name, targetPods, podIdentifiers, false)
		if err != nil {
			r.log.Info("failed to update bpf probes for ", "policy endpoint ", req.NamespacedName.Name)
			return err
		}
		duration := msSince(start)
		policyTearDownLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	}

	// podsToBeCleanedUp - pods which are no longer selected by this policy
	if len(podsToBeCleanedUp) > 0 {
		r.log.Info("Cleaning up current policy against below pods..")
		err := r.updatePolicyEnforcementStatusForPods(ctx, req.NamespacedName.Name, podsToBeCleanedUp, podIdentifiers, true)
		if err != nil {
			r.log.Info("failed to clean up bpf probes for ", "policy endpoint ", req.NamespacedName.Name)
			return err
		}
		duration := msSince(start)
		policyTearDownLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	}

	for _, podToBeCleanedUp := range podsToBeCleanedUp {
		podIdentifier := utils.GetPodIdentifier(podToBeCleanedUp.Name, podToBeCleanedUp.Namespace, r.log)
		//Delete this policyendpoint resource against the current PodIdentifier
		r.deletePolicyEndpointFromPodIdentifierMap(ctx, podIdentifier, req.NamespacedName.Name)
	}

	return nil
}

func (r *PolicyEndpointsReconciler) IsProgFdShared(targetPodName string,
	targetPodNamespace string) (bool, error) {
	targetpodNamespacedName := utils.GetPodNamespacedName(targetPodName, targetPodNamespace)
	// check ingress caches
	if targetProgFD, ok := r.ebpfClient.GetIngressPodToProgMap().Load(targetpodNamespacedName); ok {
		if currentList, ok := r.ebpfClient.GetIngressProgToPodsMap().Load(targetProgFD); ok {
			podsList, ok := currentList.(map[string]struct{})
			if ok {
				if len(podsList) > 1 {
					r.log.Info("isProgFdShared", "Found shared ingress progFD for target: ", targetPodName, "progFD: ", targetProgFD)
					return true, nil
				}
				return false, nil // Not shared (only one pod)
			}
		}
	}

	// Check Egress Maps if not found in Ingress
	if targetProgFD, ok := r.ebpfClient.GetEgressPodToProgMap().Load(targetpodNamespacedName); ok {
		if currentList, ok := r.ebpfClient.GetEgressProgToPodsMap().Load(targetProgFD); ok {
			podsList, ok := currentList.(map[string]struct{})
			if ok {
				if len(podsList) > 1 {
					r.log.Info("IsProgFdShared", "Found shared egress progFD for target:", targetPodName, "progFD:", targetProgFD)
					return true, nil
				}
				return false, nil // Not shared (only one pod)
			}
		}
	}

	// If not found in both maps, return an error
	r.log.Info("IsProgFdShared", "Pod not found in either IngressPodToProgMap or EgressPodToProgMap:", targetpodNamespacedName)
	return false, fmt.Errorf("pod not found in either IngressPodToProgMap or EgressPodToProgMap: %s", targetpodNamespacedName)
}

func (r *PolicyEndpointsReconciler) updatePolicyEnforcementStatusForPods(ctx context.Context, policyEndpointName string,
	targetPods []types.NamespacedName, podIdentifiers map[string]bool, isDeleteFlow bool) error {
	var err error
	// 1. If the pods are already deleted, we move on.
	// 2. If the pods have another policy or policies active against them, we update the maps to purge the entries
	//    introduced by the current policy.
	// 3. If there are no more active policies against this pod, we update pod_state to default deny/allow
	for _, targetPod := range targetPods {
		r.log.Info("Updating Pod: ", "Name: ", targetPod.Name, "Namespace: ", targetPod.Namespace)

		podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace, r.log)
		r.log.Info("Derived ", "Pod identifier to check if update is needed : ", podIdentifier)

		cleanupErr := r.cleanupPod(ctx, targetPod, policyEndpointName, isDeleteFlow)
		if cleanupErr != nil {
			r.log.Info("Cleanup/Update unsuccessful for Pod ", "Name: ", targetPod.Name, "Namespace: ", targetPod.Namespace)
			err = errors.Join(err, cleanupErr)
			// we don't want to return an error right away but instead attempt to clean up all the pods
			// in the list before returning
		}
	}
	return err
}

func (r *PolicyEndpointsReconciler) reconcilePolicyEndpoint(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint) error {
	r.log.Info("Processing Policy Endpoint  ", "Name: ", policyEndpoint.Name, "Namespace ", policyEndpoint.Namespace)
	start := time.Now()

	// Identify pods local to the node. PolicyEndpoint resource will include `HostIP` field and
	// network policy agent relies on it to filter local pods
	parentNP := policyEndpoint.Spec.PolicyRef.Name
	policyEndpointNamespace := policyEndpoint.Namespace
	policyEndpointName := policyEndpoint.Name
	targetPods, podIdentifiers, podsToBeCleanedUp := r.deriveTargetPodsForParentNP(ctx, parentNP, policyEndpointNamespace, policyEndpointName)

	// Check if we need to remove this policy against any existing pods against which this policy
	// is currently active. podIdentifiers will have the pod identifiers of the targetPods from the derived PEs
	err := r.updatePolicyEnforcementStatusForPods(ctx, policyEndpoint.Name, podsToBeCleanedUp, podIdentifiers, false)
	if err != nil {
		r.log.Error(err, "failed to update policy enforcement status for existing pods")
		return err
	}

	for podIdentifier, _ := range podIdentifiers {
		// Derive Ingress IPs from the PolicyEndpoint
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier,
			policyEndpoint.Namespace, policyEndpoint.Name, false)
		if err != nil {
			r.log.Error(err, "Error Parsing policy Endpoint resource", "name:", policyEndpoint.Name)
			return err
		}

		if len(ingressRules) == 0 && !isIngressIsolated {
			//Add allow-all entry to Ingress rule set
			r.log.Info("No Ingress rules and no ingress isolation - Appending catch all entry")
			r.addCatchAllEntry(ctx, &ingressRules)
		}

		if len(egressRules) == 0 && !isEgressIsolated {
			//Add allow-all entry to Egress rule set
			r.log.Info("No Egress rules and no egress isolation - Appending catch all entry")
			r.addCatchAllEntry(ctx, &egressRules)
		}

		// Setup/configure eBPF probes/maps for local pods
		err = r.configureeBPFProbes(ctx, podIdentifier, targetPods, ingressRules, egressRules)
		if err != nil {
			r.log.Info("Error configuring eBPF Probes ", "error: ", err)
		}
		duration := msSince(start)
		policySetupLatency.WithLabelValues(policyEndpoint.Name, policyEndpoint.Namespace).Observe(duration)
	}
	return nil
}

func (r *PolicyEndpointsReconciler) configureeBPFProbes(ctx context.Context, podIdentifier string,
	targetPods []types.NamespacedName, ingressRules, egressRules []ebpf.EbpfFirewallRules) error {
	var err error

	//Loop over target pods and setup/configure/update eBPF probes/maps
	for _, pod := range targetPods {
		r.log.Info("Processing Pod: ", "name:", pod.Name, "namespace:", pod.Namespace, "podIdentifier: ", podIdentifier)

		currentPodIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace, r.log)
		if currentPodIdentifier != podIdentifier {
			r.log.Info("Target Pod doesn't belong to the current pod Identifier: ", "Name: ", pod.Name, "Pod ID: ", podIdentifier)
			continue
		}

		err = r.ebpfClient.AttacheBPFProbes(pod, podIdentifier)
		if err != nil {
			r.log.Info("Attaching eBPF probe failed for", "pod", pod.Name, "namespace", pod.Namespace)
			return err
		}
		r.log.Info("Successfully attached required eBPF probes for", "pod:", pod.Name, "in namespace", pod.Namespace)
	}

	err = r.updateeBPFMaps(ctx, podIdentifier, ingressRules, egressRules)
	if err != nil {
		r.log.Error(err, "failed to update map ", "podIdentifier ", podIdentifier)
		return err
	}
	return nil
}

func (r *PolicyEndpointsReconciler) cleanupPod(ctx context.Context, targetPod types.NamespacedName,
	policyEndpoint string, isDeleteFlow bool) error {

	var err error
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	var isIngressIsolated, isEgressIsolated bool
	noActiveIngressPolicies, noActiveEgressPolicies := false, false

	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace, r.log)

	// Detach eBPF probes attached to the local pods (if required). We should detach eBPF probes if this
	// is the only PolicyEndpoint resource that applies to this pod. If not, just update the Ingress/Egress Map contents
	if _, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err = r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, targetPod.Namespace,
			policyEndpoint, isDeleteFlow)
		if err != nil {
			r.log.Error(err, "Error Parsing policy Endpoint resource", "name ", policyEndpoint)
			return err
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
			if utils.IsStrictMode(r.networkPolicyMode) {
				state = DEFAULT_DENY
			}
			r.log.Info("No active policies. Updating pod_state map for ", "podIdentifier: ", podIdentifier, "networkPolicyMode: ", r.networkPolicyMode)
			err = r.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, state, true, true)
			if err != nil {
				r.log.Error(err, "Map update(s) failed for, ", "podIdentifier ", podIdentifier)
				return err
			}
		} else {
			// We've additional PolicyEndpoint resources configured against this pod
			// Update the Maps and move on
			r.log.Info("Active policies against this pod. Skip Detaching probes and Update Maps... ")
			if noActiveIngressPolicies {
				// No active ingress rules for this pod, but we only should land here
				// if there are active egress rules. So, we need to add an allow-all entry to ingress rule set
				r.log.Info("No Ingress rules and no ingress isolation - Appending catch all entry")
				r.addCatchAllEntry(ctx, &ingressRules)
			}

			if noActiveEgressPolicies {
				// No active egress rules for this pod but we only should land here
				// if there are active ingress rules. So, we need to add an allow-all entry to egress rule set
				r.log.Info("No Egress rules and no egress isolation - Appending catch all entry")
				r.addCatchAllEntry(ctx, &egressRules)
			}

			err = r.updateeBPFMaps(ctx, podIdentifier, ingressRules, egressRules)
			if err != nil {
				r.log.Info("Map Update failed for ", "policyEndpoint: ")
				return err
			}
		}
	}
	return nil
}

func (r *PolicyEndpointsReconciler) deriveIngressAndEgressFirewallRules(ctx context.Context,
	podIdentifier string, resourceNamespace string, resourceName string, isDeleteFlow bool) ([]ebpf.EbpfFirewallRules, []ebpf.EbpfFirewallRules, bool, bool, error) {
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	isIngressIsolated, isEgressIsolated := false, false
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		r.log.Info("Total number of PolicyEndpoint resources for", "podIdentifier ", podIdentifier, " are ", len(policyEndpointList.([]string)))
		for _, policyEndpointResource := range policyEndpointList.([]string) {
			peNamespacedName := types.NamespacedName{
				Name:      policyEndpointResource,
				Namespace: resourceNamespace,
			}

			if isDeleteFlow {
				deletedPEParentNPName := utils.GetParentNPNameFromPEName(resourceName)
				currentPEParentNPName := utils.GetParentNPNameFromPEName(policyEndpointResource)
				if deletedPEParentNPName == currentPEParentNPName {
					r.log.Info("PE belongs to same NP. Ignore and move on since it's a delete flow",
						"deletedPE", resourceName, "currentPE", policyEndpointResource)
					continue
				}
			}

			if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, isIngressIsolated, isEgressIsolated, err
			}
			r.log.Info("Deriving Firewall rules for PolicyEndpoint:", "Name: ", currentPE.Name)

			for _, endPointInfo := range currentPE.Spec.Ingress {
				ingressRules = append(ingressRules,
					ebpf.EbpfFirewallRules{
						IPCidr: endPointInfo.CIDR,
						Except: endPointInfo.Except,
						L4Info: endPointInfo.Ports,
					})
			}

			for _, endPointInfo := range currentPE.Spec.Egress {
				egressRules = append(egressRules,
					ebpf.EbpfFirewallRules{
						IPCidr: endPointInfo.CIDR,
						Except: endPointInfo.Except,
						L4Info: endPointInfo.Ports,
					})
			}
			r.log.Info("Total no.of - ", "ingressRules", len(ingressRules), "egressRules", len(egressRules))
			ingressIsolated, egressIsolated := r.deriveDefaultPodIsolation(ctx, currentPE, len(ingressRules), len(egressRules))
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

func (r *PolicyEndpointsReconciler) deriveDefaultPodIsolation(ctx context.Context, policyEndpoint *policyk8sawsv1.PolicyEndpoint,
	ingressRulesCount, egressRulesCount int) (bool, bool) {
	isIngressIsolated, isEgressIsolated := false, false

	for _, value := range policyEndpoint.Spec.PodIsolation {
		if value == networking.PolicyTypeIngress && ingressRulesCount == 0 {
			r.log.Info("Default Deny enabled on Ingress")
			isIngressIsolated = true
		}
		if value == networking.PolicyTypeEgress && egressRulesCount == 0 {
			r.log.Info("Default Deny enabled on Egress")
			isEgressIsolated = true
		}
	}
	return isIngressIsolated, isEgressIsolated
}

func (r *PolicyEndpointsReconciler) updateeBPFMaps(ctx context.Context, podIdentifier string,
	ingressRules, egressRules []ebpf.EbpfFirewallRules) error {

	// Map Update should only happen once for those that share the same Map
	err := r.ebpfClient.UpdateEbpfMaps(podIdentifier, ingressRules, egressRules)
	if err != nil {
		r.log.Error(err, "Map update(s) failed for, ", "podIdentifier ", podIdentifier)
		return err
	}
	return nil
}

func (r *PolicyEndpointsReconciler) deriveTargetPodsForParentNP(ctx context.Context,
	parentNP, policyEndpointNamespace, policyEndpointName string) ([]types.NamespacedName, map[string]bool, []types.NamespacedName) {
	var targetPods, podsToBeCleanedUp, currentPods []types.NamespacedName
	var targetPodIdentifiers []string
	var allPodIdentifiers []string
	podIdentifiers := make(map[string]bool)
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	r.log.Info("Parent NP resource:", "Name: ", parentNP)
	parentPEList := r.derivePolicyEndpointsOfParentNP(ctx, parentNP, policyEndpointNamespace)
	r.log.Info("Total PEs for Parent NP:", "Count: ", len(parentPEList))

	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(policyEndpointName, policyEndpointNamespace)
	// Gather the current set of pods (local to the node) that are configured with this policy rules.
	existingPods, podsPresent := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier)
	if podsPresent {
		existingPodsSlice := existingPods.([]types.NamespacedName)
		for _, pods := range existingPodsSlice {
			currentPods = append(currentPods, pods)
			r.log.Info("Current pods for this slice : ", "Pod name", pods.Name, "Pod namespace", pods.Namespace)
		}
	}

	for _, policyEndpointResource := range parentPEList {
		r.log.Info("Derive PE Object ", "Name ", policyEndpointResource)
		peNamespacedName := types.NamespacedName{
			Name:      policyEndpointResource,
			Namespace: policyEndpointNamespace,
		}
		if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
		}
		r.log.Info("Processing PE ", "Name ", policyEndpointResource)
		currentTargetPods, currentPodIdentifiers, nonLocalPodIdentifiers := r.deriveTargetPods(ctx, currentPE, parentPEList)
		r.log.Info("Adding to current targetPods", "Total pods: ", len(currentTargetPods))
		targetPods = append(targetPods, currentTargetPods...)
		for podIdentifier, _ := range currentPodIdentifiers {
			podIdentifiers[podIdentifier] = true
			targetPodIdentifiers = append(targetPodIdentifiers, podIdentifier)
		}
		for podIdentifier, _ := range nonLocalPodIdentifiers {
			allPodIdentifiers = append(allPodIdentifiers, podIdentifier)
		}
	}

	//Update active podIdentifiers selected by the current Network Policy
	stalePodIdentifiers := r.deriveStalePodIdentifiers(ctx, policyEndpointName, targetPodIdentifiers)

	if len(parentPEList) == 0 {
		podsToBeCleanedUp = append(podsToBeCleanedUp, currentPods...)
		r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
		r.log.Info("No PEs left: ", "number of pods to cleanup - ", len(podsToBeCleanedUp))
		for _, podIdentifier := range stalePodIdentifiers {
			r.deletePolicyEndpointFromPodIdentifierMap(ctx, podIdentifier, policyEndpointName)
		}
	}

	for _, policyEndpointResource := range parentPEList {
		policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(policyEndpointResource, policyEndpointNamespace)
		if len(targetPods) > 0 {
			r.log.Info("Update target pods for PE Object ", "Name ", policyEndpointResource, " with Total pods: ", len(targetPods))
			r.policyEndpointSelectorMap.Store(policyEndpointIdentifier, targetPods)
		} else {
			r.log.Info("No more target pods so deleting the entry in PE selector map for ", "Name ", policyEndpointResource)
			r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
		}
		for _, podIdentifier := range stalePodIdentifiers {
			r.deletePolicyEndpointFromPodIdentifierMap(ctx, podIdentifier, policyEndpointResource)
		}
	}

	// Update active podIdentifiers selected by the current Network Policy
	allPodIdentifiers = append(allPodIdentifiers, targetPodIdentifiers...)
	if len(allPodIdentifiers) == 0 {
		r.networkPolicyToPodIdentifierMap.Delete(utils.GetParentNPNameFromPEName(policyEndpointName))
	} else {
		r.networkPolicyToPodIdentifierMap.Store(utils.GetParentNPNameFromPEName(policyEndpointName), allPodIdentifiers)
	}

	if len(currentPods) > 0 {
		podsToBeCleanedUp = r.getPodListToBeCleanedUp(currentPods, targetPods, podIdentifiers)
	}
	return targetPods, podIdentifiers, podsToBeCleanedUp
}

// Derives list of local pods the policy endpoint resource selects.
// Function returns list of target pods along with their unique identifiers. It also
// captures list of (any) existing pods against which this policy is no longer active.
func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint, parentPEList []string) ([]types.NamespacedName, map[string]bool, map[string]bool) {
	var targetPods []types.NamespacedName
	localPodIdentifiers := make(map[string]bool)
	nonLocalPodIdentifiers := make(map[string]bool)

	// Pods are grouped by Host IP. Individual node agents will filter (local) pods
	// by the Host IP value.
	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range policyEndpoint.Spec.PodSelectorEndpoints {
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace, r.log)
		if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			r.log.Info("Found a matching Pod: ", "name: ", pod.Name, "namespace: ", pod.Namespace)
			targetPods = append(targetPods, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace})
			localPodIdentifiers[podIdentifier] = true
			r.log.Info("Derived ", "Pod identifier: ", podIdentifier)
		} else {
			nonLocalPodIdentifiers[podIdentifier] = true
		}
		r.updatePodIdentifierToPEMap(ctx, podIdentifier, parentPEList)
	}
	return targetPods, localPodIdentifiers, nonLocalPodIdentifiers
}

func (r *PolicyEndpointsReconciler) getPodListToBeCleanedUp(oldPodSet []types.NamespacedName,
	newPodSet []types.NamespacedName, podIdentifiers map[string]bool) []types.NamespacedName {
	var podsToBeCleanedUp []types.NamespacedName

	for _, oldPod := range oldPodSet {
		activePod := false
		oldPodIdentifier := utils.GetPodIdentifier(oldPod.Name, oldPod.Namespace, r.log)
		for _, newPod := range newPodSet {
			if oldPod == newPod {
				activePod = true
				break
			}
		}
		// We want to clean up the pod when pod is still running but pod is not an active pod against policy endpoint
		// This implies policy endpoint is no longer applied to the podIdentifier
		if !activePod && !podIdentifiers[oldPodIdentifier] {
			r.log.Info("Pod to cleanup: ", "name: ", oldPod.Name, "namespace: ", oldPod.Namespace)
			podsToBeCleanedUp = append(podsToBeCleanedUp, oldPod)
		}
	}

	return podsToBeCleanedUp
}

func (r *PolicyEndpointsReconciler) updatePodIdentifierToPEMap(ctx context.Context, podIdentifier string,
	parentPEList []string) {
	r.podIdentifierToPolicyEndpointMapMutex.Lock()
	defer r.podIdentifierToPolicyEndpointMapMutex.Unlock()
	var policyEndpoints []string

	r.log.Info("Current PE Count for Parent NP:", "Count: ", len(parentPEList))
	if currentPESet, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		policyEndpoints = currentPESet.([]string)
		for _, policyEndpointResourceName := range parentPEList {
			r.log.Info("PE for parent NP", "name", policyEndpointResourceName)
			addPEResource := true
			for _, pe := range currentPESet.([]string) {
				if pe == policyEndpointResourceName {
					//Nothing to do if this PE is already tracked against this podIdentifier
					addPEResource = false
					break
				}
			}
			if addPEResource {
				r.log.Info("Adding PE", "name", policyEndpointResourceName, "for podIdentifier", podIdentifier)
				policyEndpoints = append(policyEndpoints, policyEndpointResourceName)
			}
		}
	} else {
		policyEndpoints = append(policyEndpoints, parentPEList...)
	}
	r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, policyEndpoints)
	return
}

func (r *PolicyEndpointsReconciler) deriveStalePodIdentifiers(ctx context.Context, resourceName string,
	targetPodIdentifiers []string) []string {
	var stalePodIdentifiers []string
	if currentPodIdentifiers, ok := r.networkPolicyToPodIdentifierMap.Load(utils.GetParentNPNameFromPEName(resourceName)); ok {
		for _, podIdentifier := range currentPodIdentifiers.([]string) {
			r.log.Info("podIdentifier", "name", podIdentifier)
			stalePodIdentifier := true
			for _, pe := range targetPodIdentifiers {
				if pe == podIdentifier {
					//Nothing to do if this PE is already tracked against this podIdentifier
					stalePodIdentifier = false
					break
				}
			}
			if stalePodIdentifier {
				stalePodIdentifiers = append(stalePodIdentifiers, podIdentifier)
			}
		}
	}
	return stalePodIdentifiers
}

func (r *PolicyEndpointsReconciler) deletePolicyEndpointFromPodIdentifierMap(ctx context.Context, podIdentifier string,
	policyEndpoint string) {
	r.podIdentifierToPolicyEndpointMapMutex.Lock()
	defer r.podIdentifierToPolicyEndpointMapMutex.Unlock()
	var currentPEList []string
	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		for _, policyEndpointName := range policyEndpointList.([]string) {
			if policyEndpointName == policyEndpoint {
				continue
			}
			currentPEList = append(currentPEList, policyEndpointName)
		}
		if len(currentPEList) == 0 {
			r.podIdentifierToPolicyEndpointMap.Delete(podIdentifier)
		} else {
			r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, currentPEList)
		}
	}
}

func (r *PolicyEndpointsReconciler) addCatchAllEntry(ctx context.Context, firewallRules *[]ebpf.EbpfFirewallRules) {
	//Add allow-all entry to firewall rule set
	catchAllRule := policyk8sawsv1.EndpointInfo{
		CIDR: "0.0.0.0/0",
	}
	*firewallRules = append(*firewallRules,
		ebpf.EbpfFirewallRules{
			IPCidr: catchAllRule.CIDR,
			L4Info: catchAllRule.Ports,
		})

	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyk8sawsv1.PolicyEndpoint{}).
		Complete(r)
}

func (r *PolicyEndpointsReconciler) derivePolicyEndpointsOfParentNP(ctx context.Context, parentNP, resourceNamespace string) []string {
	var parentPolicyEndpointList []string

	policyEndpointList := &policyk8sawsv1.PolicyEndpointList{}
	if err := r.k8sClient.List(ctx, policyEndpointList, &client.ListOptions{
		Namespace: resourceNamespace,
	}); err != nil {
		r.log.Info("Unable to list PolicyEndpoints", "err", err)
		return nil
	}

	for _, policyEndpoint := range policyEndpointList.Items {
		if policyEndpoint.Spec.PolicyRef.Name == parentNP {
			parentPolicyEndpointList = append(parentPolicyEndpointList, policyEndpoint.Name)
			r.log.Info("Found another PE resource for the parent NP", "name", policyEndpoint.Name)
		}
	}
	return parentPolicyEndpointList
}

func (r *PolicyEndpointsReconciler) GeteBPFClient() ebpf.BpfClient {
	return r.ebpfClient
}

func (r *PolicyEndpointsReconciler) DeriveFireWallRulesPerPodIdentifier(podIdentifier string, podNamespace string) ([]ebpf.EbpfFirewallRules,
	[]ebpf.EbpfFirewallRules, error) {

	ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(), podIdentifier,
		podNamespace, "", false)
	if err != nil {
		r.log.Error(err, "Error deriving firewall rules")
		return ingressRules, egressRules, nil
	}

	if len(ingressRules) == 0 && !isIngressIsolated {
		// No active ingress rules for this pod, but we only should land here
		// if there are active egress rules. So, we need to add an allow-all entry to ingress rule set
		r.log.Info("No Ingress rules and no ingress isolation - Appending catch all entry")
		r.addCatchAllEntry(context.Background(), &ingressRules)
	}

	if len(egressRules) == 0 && !isEgressIsolated {
		// No active egress rules for this pod but we only should land here
		// if there are active ingress rules. So, we need to add an allow-all entry to egress rule set
		r.log.Info("No Egress rules and no egress isolation - Appending catch all entry")
		r.addCatchAllEntry(context.Background(), &egressRules)
	}

	return ingressRules, egressRules, nil
}

func (r *PolicyEndpointsReconciler) ArePoliciesAvailableInLocalCache(podIdentifier string) bool {
	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		if len(policyEndpointList.([]string)) > 0 {
			r.log.Info("Active policies available against", "podIdentifier", podIdentifier)
			return true
		}
	}
	return false
}
