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

// DeriveStalePodIdentifiers finds pod identifiers that are no longer selected by the policy
func DeriveStalePodIdentifiers(networkPolicyToPodIdentifierMap *sync.Map, resourceName string, targetPodIdentifiers []string) []string {
	var stalePodIdentifiers []string
	if currentPodIdentifiers, ok := networkPolicyToPodIdentifierMap.Load(GetParentNPNameFromPEName(resourceName)); ok {
		for _, podIdentifier := range currentPodIdentifiers.([]string) {
			if !slices.Contains(targetPodIdentifiers, podIdentifier) {
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
