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
	"os"
	"strconv"
	"sync"
	"time"

	policyk8sawsv1 "github.com/achevuru/aws-network-policy-agent/api/v1alpha1"
	"github.com/achevuru/aws-network-policy-agent/pkg/ebpf"
	"github.com/achevuru/aws-network-policy-agent/pkg/utils"
	"github.com/achevuru/aws-network-policy-agent/pkg/utils/imds"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
)

const (
	envLocalConntrackCacheCleanupPeriod     = "CONNTRACK_CACHE_CLEANUP_PERIOD"
	defaultLocalConntrackCacheCleanupPeriod = 300
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
	enableCloudWatchLogs bool, enableIPv6 bool) (*PolicyEndpointsReconciler, error) {
	var err error
	r := &PolicyEndpointsReconciler{
		K8sClient: k8sClient,
		Log:       log,
	}

	r.nodeIP, err = imds.GetNodeAddress(enableIPv6)
	if err != nil {
		log.Error(err, "Unable to derive Node IP. Abort....")
	}

	conntrackTTL := r.getLocalConntrackCacheCleanupPeriod()
	r.ebpfClient, err = ebpf.NewBpfClient(&r.policyEndpointeBPFContext, &r.IngressProgPodMap,
		&r.EgressProgPodMap, r.nodeIP, enableCloudWatchLogs, enableIPv6, conntrackTTL)

	// Initialize prometheus metrics/server
	prometheusRegister()
	return r, err
}

// PolicyEndpointsReconciler reconciles a PolicyEndpoints object
type PolicyEndpointsReconciler struct {
	K8sClient client.Client
	Scheme    *runtime.Scheme
	nodeIP    string
	// Maps PolicyEndpoint resource to it's eBPF context
	policyEndpointeBPFContext sync.Map
	// Maps pod Identifier to list of PolicyEndpoint resources
	podIdentifierToPolicyEndpointMap sync.Map
	// Maps PolicyEndpoint resource with a list of local pods
	policyEndpointSelectorMap sync.Map
	//Maps a Pod by name to it's Ingress eBPF hooks
	IngressProgPodMap sync.Map
	//Maps a Pod by name to it's Egress eBPF hooks
	EgressProgPodMap sync.Map

	ebpfClient ebpf.BpfClient

	Log logr.Logger
}

//+kubebuilder:rbac:groups=policy.k8s.aws.nodeagent,resources=policyendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy.k8s.aws.nodeagent,resources=policyendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policy.k8s.aws.nodeagent,resources=policyendpoints/finalizers,verbs=update

func (r *PolicyEndpointsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.Info("Received a new reconcile request", "req", req)
	if err := r.reconcile(ctx, req); err != nil {
		r.Log.Info("Reconcile error - requeue the request", "err", err)
		return ctrl.Result{Requeue: true}, err
	}
	return ctrl.Result{}, nil
}

func (r *PolicyEndpointsReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	policyEndpoint := &policyk8sawsv1.PolicyEndpoint{}
	if err := r.K8sClient.Get(ctx, req.NamespacedName, policyEndpoint); err != nil {
		if err = client.IgnoreNotFound(err); err == nil {
			return r.cleanUpPolicyEndpoint(ctx, req)
		}
		r.Log.Info("Unable to get policy endpoint spec", "policyendpoint", req.NamespacedName, "error", err)
		return client.IgnoreNotFound(err)
	}
	if !policyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpPolicyEndpoint(ctx, req)
	}
	return r.reconcilePolicyEndpoint(ctx, policyEndpoint, req)
}

func (r *PolicyEndpointsReconciler) cleanUpPolicyEndpoint(ctx context.Context, req ctrl.Request) error {
	r.Log.Info("Clean Up PolicyEndpoint resources for", "name:", req.NamespacedName.Name)
	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(req.NamespacedName.Name,
		req.NamespacedName.Namespace)

	start := time.Now()
	duration := msSince(start)

	if targetPods, ok := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier); ok {
		err := r.updatePods(ctx, req, targetPods.([]types.NamespacedName))
		if err != nil {
			r.Log.Info("Pod clean up failed for ", "policy endpoint: ", req.NamespacedName.Name)
			return err
		}
		r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
		policyTearDownLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	}
	return nil
}

func (r *PolicyEndpointsReconciler) updatePods(ctx context.Context, req ctrl.Request,
	targetPods []types.NamespacedName) error {
	var err error
	// 1. If the pods are already deleted, we move on.
	// 2. If the pods have another policy or policies active against them, we update the maps to purge the entries
	//    introduced by the current policy.
	// 3. If there are no more active policies against this pod. Detach and delete the probes and
	//    corresponding BPF maps. We will also clean up eBPF pin paths under BPF FS.
	for _, targetPod := range targetPods {
		r.Log.Info("Updating Pod: ", "Name: ", targetPod.Name, "Namespace: ", targetPod.Namespace)
		podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace)
		err = r.cleanupeBPFProbes(ctx, targetPod, podIdentifier, req.NamespacedName.Name)
		if err != nil {
			r.Log.Info("Cleanup/Update unsuccessful for Pod ", "Name: ", targetPod.Name, "Namespace: ", targetPod.Namespace)
			// we don't want to return an error right away but instead attempt to clean up all the pods
			// in the list before returning
		}
	}
	return err
}
func (r *PolicyEndpointsReconciler) reconcilePolicyEndpoint(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint, req ctrl.Request) error {

	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(req.NamespacedName.Name,
		req.NamespacedName.Namespace)
	r.Log.Info("Processing: ", "Policy Endpoint Identifer: ", policyEndpointIdentifier)

	start := time.Now()
	duration := msSince(start)

	// Identify pods local to the node. PolicyEndpoint resource will include `HostIP` field and
	// network policy agent relies on it to filter local pods
	targetPods, podIdentifiers, podsToBeCleanedUp := r.deriveTargetPods(ctx, policyEndpoint, policyEndpointIdentifier)

	// Check if we need to remove this policy against any existing pods against which this policy
	// is currently active
	err := r.updatePods(ctx, req, podsToBeCleanedUp)
	if err != nil {
		r.Log.Info("Error updating the older pods") //TODO - we need to continue and not bail out.retry?
	}

	for podIdentifier, _ := range podIdentifiers {
		// Derive Ingress IPs from the PolicyEndpoint
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(ctx, policyEndpoint, podIdentifier,
			policyEndpoint.ObjectMeta.Namespace)
		if err != nil {
			r.Log.Error(err, "Error Parsing policy Endpoint resource")
			return err
		}

		if len(ingressRules) == 0 && !isIngressIsolated {
			//Add allow-all entry to Ingress rule set
			r.Log.Info("No Ingress rules and no ingress isolation - Appending catch all entry")
			r.addCatchAllFirewallEntry(ctx, &ingressRules)
		}

		if len(egressRules) == 0 && !isEgressIsolated {
			//Add allow-all entry to Egress rule set
			r.Log.Info("No Egress rules and no egress isolation - Appending catch all entry")
			r.addCatchAllFirewallEntry(ctx, &egressRules)
		}

		// Setup/configure eBPF probes/maps for local pods
		err = r.configureeBPFProbes(ctx, podIdentifier, targetPods, ingressRules, egressRules, isIngressIsolated, isEgressIsolated)
		if err != nil {
			r.Log.Info("Error configuring eBPF Probes ", "error: ", err)
			return err
		}
	}
	policySetupLatency.WithLabelValues(req.NamespacedName.Name, req.NamespacedName.Namespace).Observe(duration)
	return nil
}

func (r *PolicyEndpointsReconciler) configureeBPFProbes(ctx context.Context, podIdentifier string,
	targetPods []types.NamespacedName, ingressRules, egressRules []ebpf.EbpfFirewallRules,
	isIngressIsolated, isEgressIsolated bool) error {
	var err error
	var ingress, egress bool

	//Loop over target pods and setup/configure/update eBPF probes/maps
	for _, pod := range targetPods {
		r.Log.Info("Processing Pod: ", "name:", pod.Name, "namespace:", pod.Namespace, "podIdentifier: ", podIdentifier)
		ingress, egress = false, false

		currentPodIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		if currentPodIdentifier != podIdentifier {
			r.Log.Info("Target Pod doesn't belong to the current pod Identifier: ", "Name: ", pod.Name, "Pod ID: ", podIdentifier)
			continue
		}

		// Check if an eBPF probe is already attached on both ingress and egress direction(s) for this pod.
		// If yes, then skip probe attach flow for this pod and update the relevant map entries.
		ingressProbeAttached, egressProbeAttached := r.iseBPFProbeAttached(ctx, pod.Name, pod.Namespace)
		if !ingressProbeAttached {
			ingress = true
		}
		if !egressProbeAttached {
			egress = true
		}

		err = r.ebpfClient.AttacheBPFProbes(pod, podIdentifier, ingress, egress)
		if err != nil {
			r.Log.Info("Attaching eBPF probe failed for", "pod:", pod.Name, "in namespace", pod.Namespace)
			return err
		}
		r.Log.Info("Successfully attached required eBPF probes for", "pod:", pod.Name, "in namespace", pod.Namespace)
	}

	err = r.updateBPFMaps(ctx, podIdentifier, ingressRules, egressRules, isIngressIsolated, isEgressIsolated)
	if err != nil {
		r.Log.Info("Map Update failed for ", "polciyEndpoint: ")
		return err
	}
	return nil
}

func (r *PolicyEndpointsReconciler) cleanupeBPFProbes(ctx context.Context, targetPod types.NamespacedName, podIdentifier string,
	policyEndpoint string) error {

	var err error
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	var isIngressIsolated, isEgressIsolated bool
	ingress, egress := false, false
	// Delete this policyendpoint resource against the current PodIdentifier
	err = r.deletePolicyEndpointFromPodIdentifierMap(ctx, podIdentifier, policyEndpoint)
	if err != nil {
		r.Log.Info("Internal cache delete unsuccessful..")
	}

	// Detach eBPF probes attached to the local pods (if required). We should detach eBPF probes if this
	// is the only PolicyEndpoint resource that applies to this pod. If not, just update the Ingress/Egress Map contents
	if _, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		ingressRules, egressRules, isIngressIsolated, isEgressIsolated, err = r.deriveIngressAndEgressFirewallRules(ctx, nil, podIdentifier, targetPod.Namespace)
		if err != nil {
			r.Log.Info("Error Parsing policy Endpoint resource", "name:", policyEndpoint)
		}

		if len(ingressRules) == 0 && !isIngressIsolated {
			ingress = true
		}
		if len(egressRules) == 0 && !isEgressIsolated {
			egress = true
		}

		if ingress && egress {
			err = r.ebpfClient.DetacheBPFProbes(targetPod, ingress, egress)
			if err != nil {
				r.Log.Info("PolicyEndpoint cleanup unsuccessful", "Name: ", policyEndpoint)
				return err
			}
			r.IngressProgPodMap.Delete(utils.GetPodNamespacedName(targetPod.Name, targetPod.Namespace))
			r.EgressProgPodMap.Delete(utils.GetPodNamespacedName(targetPod.Name, targetPod.Namespace))
		} else {
			// If we land here, then we've additional PolicyEndpoint resources configured against this pod.
			// Update the Maps and move on
			r.Log.Info("Active policies against this pod. Skip Detaching probes and Update Maps... ")
			if len(ingressRules) == 0 && !isIngressIsolated {
				//Add allow-all entry to Ingress rule set
				r.Log.Info("No Ingress rules and no ingress isolation - Appending catch all entry")
				r.addCatchAllFirewallEntry(ctx, &ingressRules)
			}

			if len(egressRules) == 0 && !isEgressIsolated {
				//Add allow-all entry to Egress rule set
				r.Log.Info("No Egress rules and no egress isolation - Appending catch all entry")
				r.addCatchAllFirewallEntry(ctx, &egressRules)
			}
			err = r.updateBPFMaps(ctx, podIdentifier, ingressRules, egressRules, isIngressIsolated, isEgressIsolated)
			if err != nil {
				r.Log.Info("Map Update failed for ", "policyEndpoint: ")
				return err
			}
		}
	}
	return nil
}

func (r *PolicyEndpointsReconciler) deriveIngressAndEgressFirewallRules(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint, podIdentifier string, resourceNamespace string) ([]ebpf.EbpfFirewallRules, []ebpf.EbpfFirewallRules, bool, bool, error) {
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	isIngressIsolated, isEgressIsolated := false, false
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		r.Log.Info("Total number of PolicyEndpoint resources for", "podIdentifier: ", podIdentifier, " are: ", len(policyEndpointList.([]string)))
		for _, policyEndpointResource := range policyEndpointList.([]string) {
			if policyEndpoint != nil && policyEndpointResource == policyEndpoint.ObjectMeta.Name {
				currentPE = policyEndpoint
				r.Log.Info("Deriving Firewall rules for PolicyEndpoint:", "Name: ", currentPE.ObjectMeta.Name)
			} else {
				peNamespacedName := types.NamespacedName{
					Name:      policyEndpointResource,
					Namespace: resourceNamespace,
				}
				if err := r.K8sClient.Get(ctx, peNamespacedName, currentPE); err != nil {
					if err = client.IgnoreNotFound(err); err == nil {
						continue
					}
				}
				r.Log.Info("Deriving Firewall rules for PolicyEndpoint:", "Name: ", currentPE.ObjectMeta.Name)
			}

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
			r.Log.Info("Total no.of - ", "ingressRules", len(ingressRules), "egressRules", len(egressRules))
			ingressIsolated, egressIsolated := r.deriveDefaultPodIsolation(ctx, currentPE, len(ingressRules), len(egressRules))
			isIngressIsolated = isIngressIsolated || ingressIsolated
			isEgressIsolated = isEgressIsolated || egressIsolated
		}
	}
	if len(ingressRules) > 0 && isIngressIsolated {
		isIngressIsolated = false
	}
	if len(egressRules) > 0 && isEgressIsolated {
		isEgressIsolated = false
	}
	return ingressRules, egressRules, isIngressIsolated, isEgressIsolated, nil
}

func (r *PolicyEndpointsReconciler) deriveDefaultPodIsolation(ctx context.Context, policyEndpoint *policyk8sawsv1.PolicyEndpoint,
	ingressRulesCount, egressRulesCount int) (bool, bool) {
	isIngressIsolated, isEgressIsolated := false, false

	if policyEndpoint == nil {
		return false, false
	}

	for _, value := range policyEndpoint.Spec.PodIsolation {
		if value == policyk8sawsv1.TrafficDirectionIngress && ingressRulesCount == 0 {
			r.Log.Info("Default Deny enabled on Ingress")
			isIngressIsolated = true
		}
		if value == policyk8sawsv1.TrafficDirectionEgress && egressRulesCount == 0 {
			r.Log.Info("Default Deny enabled on Egress")
			isEgressIsolated = true
		}
	}
	return isIngressIsolated, isEgressIsolated
}

func (r *PolicyEndpointsReconciler) updateBPFMaps(ctx context.Context, podIdentifier string,
	ingressRules, egressRules []ebpf.EbpfFirewallRules, isIngressIsolated,
	isEgressIsolated bool) error {

	// Map Update should only happen once for those that share the same Map
	err := r.ebpfClient.UpdateEbpfMaps(podIdentifier, ingressRules, egressRules, isIngressIsolated, isEgressIsolated)
	if err != nil {
		r.Log.Info("Map update(s) failed for, ", "podIdentifier: ", podIdentifier, "error: ", err)
	}
	return nil
}

func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint,
	policyEndpointIdentifier string) ([]types.NamespacedName, map[string]bool, []types.NamespacedName) {
	var targetPods, podsToBeCleanedUp []types.NamespacedName
	podIdentifiers := make(map[string]bool)

	// Gather the current set of pods (local to the node) that are configured with this policy rules.
	currentPods, podsPresent := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier)
	// Pods are grouped by Host IP. Individual node agents will filter (local) pods
	// by the Host IP value.
	for _, pod := range policyEndpoint.Spec.PodSelectorEndpoints {
		if r.nodeIP == string(pod.HostIP) {
			r.Log.Info("Found a matching Pod: ", "name: ", pod.Name, "namespace: ", pod.Namespace)
			targetPods = append(targetPods, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace})
			podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
			podIdentifiers[podIdentifier] = true
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

func (r *PolicyEndpointsReconciler) iseBPFProbeAttached(ctx context.Context, podName string,
	podNamespace string) (bool, bool) {
	ingress, egress := false, false
	if _, ok := r.IngressProgPodMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		r.Log.Info("Pod already has Ingress Probe attached - ", "Name: ", podName, "Namespace: ", podNamespace)
		ingress = true
	}
	if _, ok := r.EgressProgPodMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		r.Log.Info("Pod already has Egress Probe attached - ", "Name: ", podName, "Namespace: ", podNamespace)
		egress = true
	}
	return ingress, egress
}

func (r *PolicyEndpointsReconciler) updatePodIdentifierToPEMap(ctx context.Context, podIdentifier string,
	policyEndpointName string) {
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
	policyEndpoint string) error {
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
	return nil
}

func (r *PolicyEndpointsReconciler) addCatchAllFirewallEntry(ctx context.Context, firewallRules *[]ebpf.EbpfFirewallRules) {
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

func (r *PolicyEndpointsReconciler) getLocalConntrackCacheCleanupPeriod() time.Duration {
	periodStr, found := os.LookupEnv(envLocalConntrackCacheCleanupPeriod)
	if !found {
		return defaultLocalConntrackCacheCleanupPeriod
	}
	if cleanupPeriod, err := strconv.Atoi(periodStr); err == nil {
		if cleanupPeriod < 1 {
			return defaultLocalConntrackCacheCleanupPeriod
		}
		r.Log.Info("Setting CONNTRACK_CACHE_CLEANUP_PERIOD %v", cleanupPeriod)
		return time.Duration(cleanupPeriod) * time.Second
	}
	return defaultLocalConntrackCacheCleanupPeriod
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyk8sawsv1.PolicyEndpoint{}).
		Complete(r)
}
