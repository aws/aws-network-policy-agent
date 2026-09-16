package utils

import (
	"slices"
	"sync"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// GetPodListToBeCleanedUp compares old and new pod sets to determine which pods need cleanup
func GetPodListToBeCleanedUp(oldPodSet []npatypes.Pod, newPodSet []npatypes.Pod, podIdentifiers map[string]bool) []npatypes.Pod {
	var podsToBeCleanedUp []npatypes.Pod

	for _, oldPod := range oldPodSet {
		oldPodIdentifier := GetPodIdentifier(oldPod.Name, oldPod.Namespace)

		if !slices.Contains(newPodSet, oldPod) && !podIdentifiers[oldPodIdentifier] {
			podsToBeCleanedUp = append(podsToBeCleanedUp, oldPod)
		}
	}
	return podsToBeCleanedUp
}

// GetNetworkPolicyIdentifier returns an injective in-memory key for a namespaced
// NetworkPolicy. "/" cannot appear in either Kubernetes name component.
func GetNetworkPolicyIdentifier(policyName, policyNamespace string) string {
	return policyName + "/" + policyNamespace
}

// DeriveStalePodIdentifiers finds pod identifiers that are no longer selected by the policy.
// targetPodIdentifiers covers every identifier the policy selects cluster-wide, so it can be
// large under churn.
func DeriveStalePodIdentifiers(networkPolicyToPodIdentifierMap *sync.Map, policyIdentifier string, targetPodIdentifiers []string) []string {
	var stalePodIdentifiers []string
	if currentPodIdentifiers, ok := networkPolicyToPodIdentifierMap.Load(policyIdentifier); ok {
		targetSet := make(map[string]struct{}, len(targetPodIdentifiers))
		for _, podIdentifier := range targetPodIdentifiers {
			targetSet[podIdentifier] = struct{}{}
		}
		for _, podIdentifier := range currentPodIdentifiers.([]string) {
			if _, selected := targetSet[podIdentifier]; !selected {
				stalePodIdentifiers = append(stalePodIdentifiers, podIdentifier)
			}
		}
	}
	return stalePodIdentifiers
}

// DeletePolicyEndpointFromPodIdentifierMap removes a policy endpoint from a pod's identifier map
func DeletePolicyEndpointFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, policyEndpoint string) {
	mutex.Lock()
	defer mutex.Unlock()

	var currentList []string
	if policyEndpointList, ok := podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		for _, policyEndpointName := range policyEndpointList.([]string) {
			if policyEndpointName == policyEndpoint {
				continue
			}
			currentList = append(currentList, policyEndpointName)
		}
		if len(currentList) == 0 {
			podIdentifierToPolicyEndpointMap.Delete(podIdentifier)
		} else {
			podIdentifierToPolicyEndpointMap.Store(podIdentifier, currentList)
		}
	}
}

// DeleteParentNPFromPodIdentifierMap removes every policy endpoint belonging to the given
// parent network policy from a pod identifier's tracked PE list, deleting the map entry once
// the list is empty. Unlike DeletePolicyEndpointFromPodIdentifierMap (which matches one exact
// PE name), this matches by parent NP name, so it cleans up entries even when the PE slices
// are gone (full NP delete -> empty parent list) or were renamed/re-sliced.
func DeleteParentNPFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, parentNP string) {
	mutex.Lock()
	defer mutex.Unlock()

	var currentList []string
	if policyEndpointList, ok := podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		for _, policyEndpointName := range policyEndpointList.([]string) {
			if GetParentNPNameFromPEName(policyEndpointName) == parentNP {
				continue
			}
			currentList = append(currentList, policyEndpointName)
		}
		if len(currentList) == 0 {
			podIdentifierToPolicyEndpointMap.Delete(podIdentifier)
		} else {
			podIdentifierToPolicyEndpointMap.Store(podIdentifier, currentList)
		}
	}
}

// UpdatePodIdentifierToPolicyEndpointMap adds policy endpoints to a pod's identifier map
func UpdatePodIdentifierToPolicyEndpointMap(podIdentifierMap *sync.Map, mutex *sync.Mutex, podIdentifier string, policyEndpointList []string) {
	mutex.Lock()
	defer mutex.Unlock()

	var policyEndpoints []string
	if currentSet, ok := podIdentifierMap.Load(podIdentifier); ok {
		policyEndpoints = currentSet.([]string)
		for _, policyEndpointResourceName := range policyEndpointList {
			if !slices.Contains(policyEndpoints, policyEndpointResourceName) {
				policyEndpoints = append(policyEndpoints, policyEndpointResourceName)
			}
		}
	} else {
		policyEndpoints = append(policyEndpoints, policyEndpointList...)
	}
	podIdentifierMap.Store(podIdentifier, policyEndpoints)
}
