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
	"os"
	"strconv"
	"sync"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils/imds"
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
	envLocalConntrackCacheCleanupPeriod              = "CONNTRACK_CACHE_CLEANUP_PERIOD"
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
func NewPolicyEndpointsReconciler(k8sClient client.Client, log logr.Logger,
	enableCloudWatchLogs bool, enableIPv6 bool, enableNetworkPolicy bool) (*PolicyEndpointsReconciler, error) {
	r := &PolicyEndpointsReconciler{
		k8sClient: k8sClient,
		log:       log,
	}

	if !enableIPv6 {
		r.nodeIP, _ = imds.GetMetaData("local-ipv4")
	} else {
		r.nodeIP, _ = imds.GetMetaData("ipv6")
	}
	conntrackTTL := r.getLocalConntrackCacheCleanupPeriod()
	var err error
	if enableNetworkPolicy {
		r.ebpfClient, err = ebpf.NewBpfClient(&r.policyEndpointeBPFContext, r.nodeIP,
			enableCloudWatchLogs, enableIPv6, conntrackTTL)

		// Start prometheus
		prometheusRegister()
	}

	return r, err
}

// PolicyEndpointsReconciler reconciles a PolicyEndpoints object
type PolicyEndpointsReconciler struct {
	k8sClient client.Client
	scheme    *runtime.Scheme
	//Primary IP of EC2 instance
	nodeIP string
	// Maps PolicyEndpoint resource to it's eBPF context
	policyEndpointeBPFContext sync.Map
	// Maps pod Identifier to list of PolicyEndpoint resources
	podIdentifierToPolicyEndpointMap sync.Map
	// Mutex for operations on PodIdentifierToPolicyEndpointMap
	podIdentifierToPolicyEndpointMapMutex sync.Mutex
	// Maps PolicyEndpoint resource with a list of local pods
	policyEndpointSelectorMap sync.Map
	//BPF Client instance
	ebpfClient ebpf.BpfClient

	//Logger
	log logr.Logger
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=policyendpoints/status,verbs=get

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

	if targetPods, ok := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier); ok {
		err := r.updatePolicyEnforcementStatusForPods(ctx, req.NamespacedName.Name, targetPods.([]types.NamespacedName))
		if err != nil {
			r.log.Info("failed to clean up bpf probes for ", "policy endpoint ", req.NamespacedName.Name)
			return err
		}
		r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
		duration := msSince(start)
		policyTearDownLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	}
	return nil
}

func (r *PolicyEndpointsReconciler) updatePolicyEnforcementStatusForPods(ctx context.Context, policyEndpointName string,
	targetPods []types.NamespacedName) error {
	var err error
	// 1. If the pods are already deleted, we move on.
	// 2. If the pods have another policy or policies active against them, we update the maps to purge the entries
	//    introduced by the current policy.
	// 3. If there are no more active policies against this pod. Detach and delete the probes and
	//    corresponding BPF maps. We will also clean up eBPF pin paths under BPF FS.
	for _, targetPod := range targetPods {
		r.log.Info("Updating Pod: ", "Name: ", targetPod.Name, "Namespace: ", targetPod.Namespace)
		cleanupErr := r.cleanupeBPFProbes(ctx, targetPod, policyEndpointName)
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
	targetPods, podIdentifiers, podsToBeCleanedUp := r.deriveTargetPods(ctx, policyEndpoint)

	// Check if we need to remove this policy against any existing pods against which this policy
	// is currently active
	err := r.updatePolicyEnforcementStatusForPods(ctx, policyEndpoint.Name, podsToBeCleanedUp)
	if err != nil {
		r.log.Error(err, "failed to update policy enforcement status for existing pods")
		return err
	}

	for podIdentifier, _ := range podIdentifiers {
		// Derive Ingress IPs from the PolicyEndpoint
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier,
			policyEndpoint.Namespace)
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

		currentPodIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if currentPodIdentifier != podIdentifier {
			r.log.Info("Target Pod doesn't belong to the current pod Identifier: ", "Name: ", pod.Name, "Pod ID: ", podIdentifier)
			continue
		}

		// Check if an eBPF probe is already attached on both ingress and egress direction(s) for this pod.
		// If yes, then skip probe attach flow for this pod and update the relevant map entries.
		isIngressProbeAttached, isEgressProbeAttached := r.ebpfClient.IsEBPFProbeAttached(pod.Name, pod.Namespace)
		err = r.ebpfClient.AttacheBPFProbes(pod, podIdentifier, !isIngressProbeAttached, !isEgressProbeAttached)
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

func (r *PolicyEndpointsReconciler) cleanupeBPFProbes(ctx context.Context, targetPod types.NamespacedName,
	policyEndpoint string) error {

	var err error
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	var isIngressIsolated, isEgressIsolated bool
	noActiveIngressPolicies, noActiveEgressPolicies := false, false

	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)
	// Delete this policyendpoint resource against the current PodIdentifier
	r.deletePolicyEndpointFromPodIdentifierMap(ctx, podIdentifier, policyEndpoint)

	// Detach eBPF probes attached to the local pods (if required). We should detach eBPF probes if this
	// is the only PolicyEndpoint resource that applies to this pod. If not, just update the Ingress/Egress Map contents
	if _, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err = r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, targetPod.Namespace)
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

		// We only detach probes if there are no policyendpoint resources on both the
		// directions
		if noActiveIngressPolicies && noActiveEgressPolicies {
			err = r.ebpfClient.DetacheBPFProbes(targetPod, noActiveIngressPolicies, noActiveEgressPolicies)
			if err != nil {
				r.log.Info("PolicyEndpoint cleanup unsuccessful", "Name: ", policyEndpoint)
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
	podIdentifier string, resourceNamespace string) ([]ebpf.EbpfFirewallRules, []ebpf.EbpfFirewallRules, bool, bool, error) {
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

// Derives list of local pods the policy endpoint resource selects.
// Function returns list of target pods along with their unique identifiers. It also
// captures list of (any) existing pods against which this policy is no longer active.
func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint) ([]types.NamespacedName, map[string]bool, []types.NamespacedName) {
	var targetPods, podsToBeCleanedUp []types.NamespacedName
	podIdentifiers := make(map[string]bool)

	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(policyEndpoint.Name,
		policyEndpoint.Namespace)
	// Gather the current set of pods (local to the node) that are configured with this policy rules.
	currentPods, podsPresent := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier)
	// Pods are grouped by Host IP. Individual node agents will filter (local) pods
	// by the Host IP value.
	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range policyEndpoint.Spec.PodSelectorEndpoints {
		if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			r.log.Info("Found a matching Pod: ", "name: ", pod.Name, "namespace: ", pod.Namespace)
			targetPods = append(targetPods, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace})
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			podIdentifiers[podIdentifier] = true
			r.log.Info("Derived ", "Pod identifier: ", podIdentifier)
			r.updatePodIdentifierToPEMap(ctx, podIdentifier, policyEndpoint.ObjectMeta.Name)
		}
	}
	if podsPresent && len(currentPods.([]types.NamespacedName)) > 0 {
		podsToBeCleanedUp = r.getPodListToBeCleanedUp(currentPods.([]types.NamespacedName), targetPods)
	}

	if len(targetPods) > 0 {
		r.policyEndpointSelectorMap.Store(policyEndpointIdentifier, targetPods)
	} else {
		r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
	}
	return targetPods, podIdentifiers, podsToBeCleanedUp
}

func (r *PolicyEndpointsReconciler) getPodListToBeCleanedUp(oldPodSet []types.NamespacedName,
	newPodSet []types.NamespacedName) []types.NamespacedName {
	var podsToBeCleanedUp []types.NamespacedName

	for _, oldPod := range oldPodSet {
		activePod := false
		for _, newPod := range newPodSet {
			if oldPod == newPod {
				activePod = true
				break
			}
		}
		if !activePod {
			podsToBeCleanedUp = append(podsToBeCleanedUp, oldPod)
		}
	}
	return podsToBeCleanedUp
}

func (r *PolicyEndpointsReconciler) updatePodIdentifierToPEMap(ctx context.Context, podIdentifier string,
	policyEndpointName string) {
	r.podIdentifierToPolicyEndpointMapMutex.Lock()
	defer r.podIdentifierToPolicyEndpointMapMutex.Unlock()

	var policyEndpoints []string
	if currentPESet, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		policyEndpoints = currentPESet.([]string)
		for _, pe := range currentPESet.([]string) {
			if pe == policyEndpointName {
				//Nothing to do if this PE is already tracked against this podIdentifier
				return
			}
		}
	}
	policyEndpoints = append(policyEndpoints, policyEndpointName)
	r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, policyEndpoints)
	return
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
		r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, currentPEList)
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

func (r *PolicyEndpointsReconciler) getLocalConntrackCacheCleanupPeriod() time.Duration {
	periodStr, found := os.LookupEnv(envLocalConntrackCacheCleanupPeriod)
	if !found {
		return defaultLocalConntrackCacheCleanupPeriodInSeconds
	}
	if cleanupPeriod, err := strconv.Atoi(periodStr); err == nil {
		if cleanupPeriod < 1 {
			r.log.Info("conntrack cache cleanup is set to less than 1s. Reverting to default value")
			return defaultLocalConntrackCacheCleanupPeriodInSeconds
		}
		r.log.Info("Setting CONNTRACK_CACHE_CLEANUP_PERIOD %v", cleanupPeriod)
		return time.Duration(cleanupPeriod) * time.Second
	}
	return defaultLocalConntrackCacheCleanupPeriodInSeconds
}
