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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	merge "github.com/aws/aws-network-policy-agent/pkg/utils/mergerules"

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
	v1 "k8s.io/api/core/v1"
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
	enablePolicyEventLogs, enableCloudWatchLogs bool, enableIPv6 bool, enableNetworkPolicy bool, conntrackTTL int, conntrackTableSize int) (*PolicyEndpointsReconciler, error) {
	r := &PolicyEndpointsReconciler{
		k8sClient: k8sClient,
		log:       log,
	}

	if !enableIPv6 {
		r.nodeIP, _ = imds.GetMetaData("local-ipv4")
	} else {
		r.nodeIP, _ = imds.GetMetaData("ipv6")
	}
	r.log.Info("ConntrackTTL", "cleanupPeriod", conntrackTTL)
	var err error
	if enableNetworkPolicy {
		r.ebpfClient, err = ebpf.NewBpfClient(&r.policyEndpointeBPFContext, r.nodeIP,
			enablePolicyEventLogs, enableCloudWatchLogs, enableIPv6, conntrackTTL, conntrackTableSize)

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
	// Maps pod Identifier to list of global PolicyEndpoint resources
	podIdentifierToGlobalPolicyEndpointMap sync.Map
	// Mutex for operations on PodIdentifierToPolicyEndpointMap and PodIdentifierToGlobalPolicyEndpointMap
	podIdentifierToPolicyEndpointMapMutex sync.Mutex
	// Maps PolicyEndpoint resource with a list of local pods
	policyEndpointSelectorMap sync.Map
	// Maps a Network Policy to list of selected pod Identifiers
	networkPolicyToPodIdentifierMap sync.Map
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

	// Get all podIdentifiers since we need to decide if pinpath has to be deleted on local node
	parentNP := utils.GetParentNPNameFromPEName(req.NamespacedName.Name)
	resourceName := req.NamespacedName.Name
	resourceNamespace := req.NamespacedName.Namespace
	targetPods, podIdentifiers, podsToBeCleanedUp := r.deriveTargetPodsForParentNP(ctx, parentNP, resourceNamespace, resourceName)

	r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)

	r.log.Info("cleanUpPolicyEndpoint: ", "Pods to cleanup - ", len(podsToBeCleanedUp), "and Pods to be updated - ", len(targetPods))

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

func (r *PolicyEndpointsReconciler) updatePolicyEnforcementStatusForPods(ctx context.Context, policyEndpointName string,
	targetPods []types.NamespacedName, podIdentifiers map[string]bool, isDeleteFlow bool) error {
	var err error
	// 1. If the pods are already deleted, we move on.
	// 2. If the pods have another policy or policies active against them, we update the maps to purge the entries
	//    introduced by the current policy.
	// 3. If there are no more active policies against this pod. Detach and delete the probes and
	//    corresponding BPF maps. We will also clean up eBPF pin paths under BPF FS.
	for _, targetPod := range targetPods {
		r.log.Info("Updating Pod: ", "Name: ", targetPod.Name, "Namespace: ", targetPod.Namespace)

		deletePinPath := true
		podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace, r.log)
		r.log.Info("Derived ", "Pod identifier to check if update is needed : ", podIdentifier)
		//Derive the podIdentifier and check if there is another pod in the same replicaset using the pinpath
		if found, ok := podIdentifiers[podIdentifier]; ok {
			//podIdentifiers will always have true in the value if found..
			r.log.Info("PodIdentifier pinpath ", "shared: ", found)
			deletePinPath = !found
		}

		cleanupErr := r.cleanupeBPFProbes(ctx, targetPod, policyEndpointName, deletePinPath, isDeleteFlow)
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
	resourceNamespace := policyEndpoint.Namespace
	resourceName := policyEndpoint.Name
	targetPods, podIdentifiers, podsToBeCleanedUp := r.deriveTargetPodsForParentNP(ctx, parentNP, resourceNamespace, resourceName)

	// Check if we need to remove this policy against any existing pods against which this policy
	// is currently active. podIdentifiers will have the pod identifiers of the targetPods from the derived PEs
	err := r.updatePolicyEnforcementStatusForPods(ctx, policyEndpoint.Name, podsToBeCleanedUp, podIdentifiers, false)
	if err != nil {
		r.log.Error(err, "failed to update policy enforcement status for existing pods")
		return err
	}

	for podIdentifier := range podIdentifiers {
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
	policyEndpoint string, deletePinPath, isDeleteFlow bool) error {

	var err error
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	var isIngressIsolated, isEgressIsolated bool
	noActiveIngressPolicies, noActiveEgressPolicies := false, false

	podIdentifier := utils.GetPodIdentifier(targetPod.Name, targetPod.Namespace, r.log)

	// Detach eBPF probes attached to the local pods (if required). We should detach eBPF probes if this
	// is the only PolicyEndpoint resource that applies to this pod. If not, just update the Ingress/Egress Map contents
	_, foundPE := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier)
	_, foundGlobalPE := r.podIdentifierToGlobalPolicyEndpointMap.Load(podIdentifier)
	ok := foundPE || foundGlobalPE
	if ok {
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

		// We only detach probes if there are no policyendpoint resources on both the
		// directions
		if noActiveIngressPolicies && noActiveEgressPolicies {
			err = r.ebpfClient.DetacheBPFProbes(targetPod, noActiveIngressPolicies, noActiveEgressPolicies, deletePinPath)
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

func mergeGlobalRulesHelper(rules []policyk8sawsv1.EndpointInfo, ipPorts map[string][]string, logger logr.Logger) map[string][]string {
	allProtocol := "ALL"
	for _, rule := range rules {
		action := rule.Action
		if rule.Ports == nil {
			rule.Ports = append(rule.Ports, policyk8sawsv1.Port{
				Protocol: (*v1.Protocol)(&allProtocol),
				Port:     nil,
				EndPort:  nil,
			})
		}
		if val, ok := ipPorts[string(rule.CIDR)]; ok {
			for _, prt := range rule.Ports {
				modified := false
				for i, port := range val {
					split := strings.Split(port, "-")
					action2 := split[0]
					protocol := split[1]
					portInt, _ := strconv.Atoi(split[2])
					port := int32(portInt)
					portFin := &port
					if portInt == 0 {
						portFin = nil
					}
					endportInt, _ := strconv.Atoi(split[3])
					endport := int32(endportInt)
					endPortFin := &endport
					if endportInt == 0 {
						endPortFin = nil
					}
					tempPort := policyk8sawsv1.Port{
						Protocol: (*v1.Protocol)(&protocol),
						Port:     portFin,
						EndPort:  endPortFin,
					}
					if protocol == "ALL" || string(*prt.Protocol) == "ALL" || checkPortOverlap(prt, tempPort) {
						modified = true
						mergedPort := merge.MergePorts(tempPort, prt, action2, action, logger)
						val[i] = mergedPort[0]
						if len(mergedPort) > 1 {
							val = append(val, mergedPort[1])
						}
						ipPorts[string(rule.CIDR)] = val
					} else {
						continue
					}
				}
				if !modified {
					zero := int32(0)
					if prt.Port == nil {
						prt.Port = &zero
					}
					if prt.EndPort == nil {
						prt.EndPort = &zero
					}
					ipPorts[string(rule.CIDR)] = append(val, fmt.Sprintf("%s-%s-%d-%d", rule.Action, *prt.Protocol, *prt.Port, *prt.EndPort))
				}
			}
		} else {
			arr := []string{}
			if rule.Ports == nil {
				arr = append(arr, fmt.Sprintf("%s-%s-%d-%d", rule.Action, "ALL", 0, 0))
			} else {
				for _, port := range rule.Ports {
					if port.EndPort == nil {
						temp := int32(0)
						port.EndPort = &temp
					}
					arr = append(arr, fmt.Sprintf("%s-%s-%d-%d", rule.Action, *port.Protocol, *port.Port, *port.EndPort))
				}
			}
			ipPorts[string(rule.CIDR)] = arr
		}
	}
	return ipPorts
}

func (r *PolicyEndpointsReconciler) mergeGlobalRules(currentPE *policyk8sawsv1.PolicyEndpoint, ipIngressPorts map[string][]string, ipEgressPorts map[string][]string) (map[string][]string, map[string][]string) {
	ipIngressPorts = mergeGlobalRulesHelper(currentPE.Spec.Ingress, ipIngressPorts, r.log)
	ipEgressPorts = mergeGlobalRulesHelper(currentPE.Spec.Egress, ipEgressPorts, r.log)
	return ipIngressPorts, ipEgressPorts
}

func mergeLocalRulesHelper(rules []policyk8sawsv1.EndpointInfo, ipPorts map[string][]string) map[string][]string {
	tempAll := "ALL"
	portZero := int32(0)
	for _, rule := range rules {
		if rule.Ports == nil {
			rule.Ports = append(rule.Ports, policyk8sawsv1.Port{
				Protocol: (*v1.Protocol)(&tempAll),
				Port:     &portZero,
				EndPort:  &portZero,
			})
		}
		for _, port := range rule.Ports {
			endport := port.EndPort
			if endport == nil {
				endport = &portZero
			}
			if val, ok := ipPorts[string(rule.CIDR)]; ok {
				val = append(val, fmt.Sprintf("%s-%s-%d-%d", "Allow", *port.Protocol, *port.Port, *endport))
				ipPorts[string(rule.CIDR)] = val
			} else {
				val := []string{}
				val = append(val, fmt.Sprintf("%s-%s-%d-%d", "Allow", *port.Protocol, *port.Port, *endport))
				ipPorts[string(rule.CIDR)] = val
			}
		}
		for _, except := range rule.Except {
			if val, ok := ipPorts[string(except)]; ok {
				val = append(val, fmt.Sprintf("%s-%s-%d-%d", "Deny", "ALL", 0, 0))
				ipPorts[string(except)] = val
			} else {
				val := []string{}
				val = append(val, fmt.Sprintf("%s-%s-%d-%d", "Deny", "ALL", 0, 0))
				ipPorts[string(except)] = val
			}
		}
	}
	return ipPorts
}

func (r *PolicyEndpointsReconciler) mergeLocalRules(currentPE *policyk8sawsv1.PolicyEndpoint, ipIngressPorts map[string][]string, ipEgressPorts map[string][]string) (map[string][]string, map[string][]string) {
	ipIngressPorts = mergeLocalRulesHelper(currentPE.Spec.Ingress, ipIngressPorts)
	ipEgressPorts = mergeLocalRulesHelper(currentPE.Spec.Egress, ipEgressPorts)
	return ipIngressPorts, ipEgressPorts
}

// If an IP or CIDR matches a NP but not an ANP, we will validate the packet using NP
func (r *PolicyEndpointsReconciler) mergeGlobalLocalRules(ingress map[string][]string, egress map[string][]string, ingressLocal map[string][]string, egressLocal map[string][]string) (map[string][]string, map[string][]string) {
	tempIngress := make(map[string][]string)
	tempEgress := make(map[string][]string)
	for localIP, localVal := range ingressLocal {
		merged := false
		for ip, val := range ingress {
			if ip == localIP {
				merged = true
				val = merge.MergeGlobalLocalPorts(val, localVal)
				ingress[ip] = val
			} else {
				continue
			}
		}
		if !merged {
			tempIngress[localIP] = localVal
		}
	}
	for localIP, localVal := range egressLocal {
		merged := false
		for ip, val := range egress {
			if ip == localIP {
				merged = true
				val = merge.MergeGlobalLocalPorts(val, localVal)
				ingress[ip] = val
			} else {
				continue
			}
		}
		if !merged {
			tempEgress[localIP] = localVal
		}
	}
	for ip, val := range tempIngress {
		ingress[ip] = val
	}

	for ip, val := range tempEgress {
		egress[ip] = val
	}
	return ingress, egress
}

func checkPortOverlap(ports, ports2 policyk8sawsv1.Port) bool {
	if *ports.Protocol != *ports2.Protocol {
		return false
	}
	if ports.EndPort != nil && ports2.EndPort != nil {
		if *ports.EndPort < *ports2.Port || *ports.Port > *ports2.EndPort {
			return false
		}
		return true
	} else if ports.EndPort != nil {
		if *ports2.Port >= *ports.Port && *ports2.Port <= *ports.EndPort {
			return true
		}
		return false
	} else if ports2.EndPort != nil {
		if *ports.Port >= *ports2.Port && *ports.Port <= *ports2.EndPort {
			return true
		}
		return false
	}
	return ports.Port == ports2.Port
}

func (r *PolicyEndpointsReconciler) deriveIngressAndEgressFirewallRules(ctx context.Context,
	podIdentifier string, resourceNamespace string, resourceName string, isDeleteFlow bool) ([]ebpf.EbpfFirewallRules, []ebpf.EbpfFirewallRules, bool, bool, error) {
	var ingressRules, egressRules []ebpf.EbpfFirewallRules
	isIngressIsolated, isEgressIsolated := false, false
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	globalRules, localRules := []policyk8sawsv1.PolicyEndpoint{}, []policyk8sawsv1.PolicyEndpoint{}
	found := false

	if policyEndpointList, ok := r.podIdentifierToGlobalPolicyEndpointMap.Load(podIdentifier); ok {
		found = true
		for _, policyEndpointResource := range policyEndpointList.([]string) {
			peNamespacedName := types.NamespacedName{
				Name:      policyEndpointResource,
				Namespace: "kube-system",
			}
			if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, isIngressIsolated, isEgressIsolated, err
			}
			globalRules = append(globalRules, *currentPE)
		}

		// Sort globalRules by priority for ease in merging
		sort.SliceStable(globalRules, func(i, j int) bool {
			return globalRules[i].Spec.Priority < globalRules[j].Spec.Priority
		})
	}

	// Pod has global rules that apply to it, which means we must replace resourceNamespace since it might not be in kube-system
	if len(globalRules) > 0 {
		namespaces := globalRules[0].Spec.Namespaces
		// Longest Prefix Match
		sort.Sort(sort.Reverse(sort.StringSlice(namespaces)))
		for _, ns := range namespaces {
			if strings.HasSuffix(podIdentifier, ns) {
				r.log.Info("Found correct namespace", "namespace", ns)
				resourceNamespace = ns
				break
			}
		}
	}

	if policyEndpointList, ok := r.podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		found = true
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
			localRules = append(localRules, *currentPE)
		}
	}

	ipIngressPorts := make(map[string][]string)
	ipEgressPorts := make(map[string][]string)
	ipLocalIngressPorts := make(map[string][]string)
	ipLocalEgressPorts := make(map[string][]string)

	if found {
		r.log.Info("Total number of global PolicyEndpoint resources for", "podIdentifier ", podIdentifier, " are ", len(globalRules))
		for _, policyEndpointResource := range globalRules {
			if isDeleteFlow {
				deletedPEParentNPName := utils.GetParentNPNameFromPEName(resourceName)
				currentPEParentNPName := utils.GetParentNPNameFromPEName(policyEndpointResource.Name)
				if deletedPEParentNPName == currentPEParentNPName {
					r.log.Info("PE belongs to same NP. Ignore and move on since it's a delete flow",
						"deletedPE", resourceName, "currentPE", policyEndpointResource)
					continue
				}
			}

			r.log.Info("Deriving Firewall rules for global PolicyEndpoint:", "Name: ", policyEndpointResource.Name)

			ipIngressPorts, ipEgressPorts = r.mergeGlobalRules(&policyEndpointResource, ipIngressPorts, ipEgressPorts)
		}

		// Once global rules are processed, "Pass" rules are no longer needed
		ipIngressPorts = removePassRules(ipIngressPorts)
		ipEgressPorts = removePassRules(ipEgressPorts)
		r.log.Info("Merged global ingress rules", "ipIngressPorts", ipIngressPorts)
		r.log.Info("Merged global egress rules", "ipEgressPorts", ipEgressPorts)

		r.log.Info("Total number of PolicyEndpoint resources for", "podIdentifier ", podIdentifier, " are ", len(localRules))

		for _, policyEndpointResource := range localRules {
			if isDeleteFlow {
				deletedPEParentNPName := utils.GetParentNPNameFromPEName(resourceName)
				currentPEParentNPName := utils.GetParentNPNameFromPEName(policyEndpointResource.Name)
				if deletedPEParentNPName == currentPEParentNPName {
					r.log.Info("PE belongs to same NP. Ignore and move on since it's a delete flow",
						"deletedPE", resourceName, "currentPE", policyEndpointResource)
					continue
				}
			}
			r.log.Info("Deriving Firewall rules for PolicyEndpoint:", "Name: ", currentPE.Name)

			ipLocalIngressPorts, ipLocalEgressPorts = r.mergeLocalRules(&policyEndpointResource, ipLocalIngressPorts, ipLocalEgressPorts)

			ingressIsolated, egressIsolated := r.deriveDefaultPodIsolation(ctx, &policyEndpointResource, len(ipLocalIngressPorts), len(ipLocalEgressPorts))
			isIngressIsolated = isIngressIsolated || ingressIsolated
			isEgressIsolated = isEgressIsolated || egressIsolated
		}
	}
	r.log.Info("Merged local ingress rules", "ipLocalIngressPorts", ipLocalIngressPorts)
	r.log.Info("Merged local egress rules", "ipLocalEgressPorts", ipLocalEgressPorts)

	ipIngressPorts, ipEgressPorts = r.mergeGlobalLocalRules(ipIngressPorts, ipEgressPorts, ipLocalIngressPorts, ipLocalEgressPorts)
	r.log.Info("Merged total ingress rules", "ipIngressPorts", ipIngressPorts)
	r.log.Info("Merged total egress rules", "ipEgressPortss", ipEgressPorts)

	ingressAll := ebpf.EbpfFirewallRules{
		IPCidr: "0.0.0.0/0",
		Except: nil,
		L4Info: nil,
	}

	egressAll := ebpf.EbpfFirewallRules{
		IPCidr: "0.0.0.0/0",
		Except: nil,
		L4Info: nil,
	}

	for ip, ports := range ipIngressPorts {
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		exceptDeny := false
		portList := []policyk8sawsv1.Port{}
		denyList := []policyk8sawsv1.Port{}
		ports = dedupPorts(ports)
		for _, port := range ports {
			split := strings.Split(port, "-")
			action := split[0]
			protocol := split[1]
			portInt, _ := strconv.Atoi(split[2])
			port := int32(portInt)
			endportInt, _ := strconv.Atoi(split[3])
			endport := int32(endportInt)

			if protocol == "ALL" {
				if action == "Deny" {
					exceptDeny = true
					break
				}
				continue
			}
			if action == "Deny" {
				denyList = append(denyList, policyk8sawsv1.Port{
					Protocol: (*v1.Protocol)(&protocol),
					Port:     &port,
					EndPort:  &endport,
				})
			} else if action == "Allow" {
				portList = append(portList, policyk8sawsv1.Port{
					Protocol: (*v1.Protocol)(&protocol),
					Port:     &port,
					EndPort:  &endport,
				})
			}

		}
		if exceptDeny {
			ingressRules = append(ingressRules,
				ebpf.EbpfFirewallRules{
					IPCidr: policyk8sawsv1.NetworkAddress(ip),
					Except: []policyk8sawsv1.NetworkAddress{policyk8sawsv1.NetworkAddress(ip)},
					L4Info: []policyk8sawsv1.Port{},
					L4Deny: []policyk8sawsv1.Port{},
				})
		} else {
			ingressRules = append(ingressRules,
				ebpf.EbpfFirewallRules{
					IPCidr: policyk8sawsv1.NetworkAddress(ip),
					Except: []policyk8sawsv1.NetworkAddress{},
					L4Info: portList,
					L4Deny: denyList,
				})
		}
	}

	// Only append "all" traffic rule if global rules exist but local rules don't
	if len(globalRules) != 0 && len(localRules) == 0 {
		ingressRules = append(ingressRules, ingressAll)
		egressRules = append(egressRules, egressAll)
	}

	r.log.Info("Total no.of - ", "ingressRules", len(ingressRules), "egressRules", len(egressRules))
	if len(ingressRules) > 0 {
		isIngressIsolated = false
	}
	if len(egressRules) > 0 {
		isEgressIsolated = false
	}
	return ingressRules, egressRules, isIngressIsolated, isEgressIsolated, nil
}

func removePassRules(ipPorts map[string][]string) map[string][]string {
	for ip, ports := range ipPorts {
		tempPorts := []string{}
		for _, port := range ports {
			portSplit := strings.Split(port, "-")
			if portSplit[0] != "Pass" {
				tempPorts = append(tempPorts, port)
			}
		}
		if len(tempPorts) == 0 {
			delete(ipPorts, ip)
		} else {
			ipPorts[ip] = tempPorts
		}
	}
	return ipPorts
}

func dedupPorts(ports []string) []string {
	dedup := make(map[string]bool)
	for _, port := range ports {
		if _, ok := dedup[port]; ok {
			continue
		}
		dedup[port] = true
	}

	dedupedPorts := []string{}
	for port := range dedup {
		dedupedPorts = append(dedupedPorts, port)
	}
	return dedupedPorts
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
	parentNP, resourceNamespace, resourceName string) ([]types.NamespacedName, map[string]bool, []types.NamespacedName) {
	var targetPods, podsToBeCleanedUp, currentPods []types.NamespacedName
	var targetPodIdentifiers []string
	podIdentifiers := make(map[string]bool)
	currentPE := &policyk8sawsv1.PolicyEndpoint{}

	r.log.Info("Parent NP resource:", "Name: ", parentNP)
	parentPEList := r.derivePolicyEndpointsOfParentNP(ctx, parentNP, resourceNamespace)
	r.log.Info("Total PEs for Parent NP:", "Count: ", len(parentPEList))

	policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(resourceName,
		resourceNamespace)
	// Gather the current set of pods (local to the node) that are configured with this policy rules.
	existingPods, podsPresent := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier)
	if podsPresent {
		existingPodsSlice := existingPods.([]types.NamespacedName)
		for _, pods := range existingPodsSlice {
			currentPods = append(currentPods, pods)
			r.log.Info("Current pods for this slice : ", "Pod name", pods.Name, "Pod namespace", pods.Namespace)
		}
	}

	if len(parentPEList) == 0 {
		podsToBeCleanedUp = append(podsToBeCleanedUp, currentPods...)
		r.policyEndpointSelectorMap.Delete(policyEndpointIdentifier)
		r.log.Info("No PEs left: ", "number of pods to cleanup - ", len(podsToBeCleanedUp))
	}

	for _, policyEndpointResource := range parentPEList {
		r.log.Info("Derive PE Object ", "Name ", policyEndpointResource)
		peNamespacedName := types.NamespacedName{
			Name:      policyEndpointResource,
			Namespace: resourceNamespace,
		}
		if err := r.k8sClient.Get(ctx, peNamespacedName, currentPE); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
		}
		r.log.Info("Processing PE ", "Name ", policyEndpointResource)
		currentTargetPods, currentPodIdentifiers := r.deriveTargetPods(ctx, currentPE, parentPEList)
		r.log.Info("Adding to current targetPods", "Total pods: ", len(currentTargetPods))
		targetPods = append(targetPods, currentTargetPods...)
		for podIdentifier := range currentPodIdentifiers {
			podIdentifiers[podIdentifier] = true
			targetPodIdentifiers = append(targetPodIdentifiers, podIdentifier)
		}
	}

	//Update active podIdentifiers selected by the current Network Policy
	stalePodIdentifiers := r.deriveStalePodIdentifiers(ctx, resourceName, targetPodIdentifiers)

	for _, policyEndpointResource := range parentPEList {
		policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(policyEndpointResource,
			resourceNamespace)
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

	//Update active podIdentifiers selected by the current Network Policy
	r.networkPolicyToPodIdentifierMap.Store(utils.GetParentNPNameFromPEName(resourceName), targetPodIdentifiers)

	if len(currentPods) > 0 {
		podsToBeCleanedUp = r.getPodListToBeCleanedUp(currentPods, targetPods, podIdentifiers)
	}
	return targetPods, podIdentifiers, podsToBeCleanedUp
}

// Derives list of local pods the policy endpoint resource selects.
// Function returns list of target pods along with their unique identifiers. It also
// captures list of (any) existing pods against which this policy is no longer active.
func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoint, parentPEList []string) ([]types.NamespacedName, map[string]bool) {
	var targetPods []types.NamespacedName
	podIdentifiers := make(map[string]bool)

	// Pods are grouped by Host IP. Individual node agents will filter (local) pods
	// by the Host IP value.
	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range policyEndpoint.Spec.PodSelectorEndpoints {
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace, r.log)
		if nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			r.log.Info("Found a matching Pod: ", "name: ", pod.Name, "namespace: ", pod.Namespace)
			targetPods = append(targetPods, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace})
			podIdentifiers[podIdentifier] = true
			r.log.Info("Derived ", "Pod identifier: ", podIdentifier)
		}
		r.updatePodIdentifierToPEMap(ctx, podIdentifier, parentPEList, policyEndpoint.Spec.IsGlobal)
	}
	return targetPods, podIdentifiers
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
		if !activePod && !podIdentifiers[oldPodIdentifier] {
			r.log.Info("Pod to cleanup: ", "name: ", oldPod.Name, "namespace: ", oldPod.Namespace)
			podsToBeCleanedUp = append(podsToBeCleanedUp, oldPod)
		}
	}

	return podsToBeCleanedUp
}

func (r *PolicyEndpointsReconciler) updatePodIdentifierToPEMap(ctx context.Context, podIdentifier string,
	parentPEList []string, isGlobal bool) {
	r.podIdentifierToPolicyEndpointMapMutex.Lock()
	defer r.podIdentifierToPolicyEndpointMapMutex.Unlock()
	var policyEndpoints []string

	if isGlobal {
		r.log.Info("Current Global PE Count for Parent NP:", "Count: ", len(parentPEList))
		if currentPESet, ok := r.podIdentifierToGlobalPolicyEndpointMap.Load(podIdentifier); ok {
			policyEndpoints = currentPESet.([]string)
			for _, policyEndpointResourceName := range parentPEList {
				r.log.Info("Global PE for parent NP", "name", policyEndpointResourceName)
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
		r.podIdentifierToGlobalPolicyEndpointMap.Store(podIdentifier, policyEndpoints)
		return
	}

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
		r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, currentPEList)
	}

	var currentGlobalPEList []string
	if policyEndpointList, ok := r.podIdentifierToGlobalPolicyEndpointMap.Load(podIdentifier); ok {
		for _, policyEndpointName := range policyEndpointList.([]string) {
			if policyEndpointName == policyEndpoint {
				continue
			}
			currentGlobalPEList = append(currentGlobalPEList, policyEndpointName)
		}
		r.podIdentifierToGlobalPolicyEndpointMap.Store(podIdentifier, currentGlobalPEList)
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
	if policyEndpointList, ok := r.podIdentifierToGlobalPolicyEndpointMap.Load(podIdentifier); ok {
		if len(policyEndpointList.([]string)) > 0 {
			r.log.Info("Active policies available against", "podIdentifier", podIdentifier)
			return true
		}
	}
	return false
}
