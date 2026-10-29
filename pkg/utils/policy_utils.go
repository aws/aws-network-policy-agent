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
func DeriveStalePodIdentifiers(networkPolicyToPodIdentifierMap *sync.Map, networkPolicyIdentifier string, targetPodIdentifiers map[string]bool) []string {
	var stalePodIdentifiers []string
	if currentPodIdentifiers, ok := networkPolicyToPodIdentifierMap.Load(networkPolicyIdentifier); ok {
		for _, podIdentifier := range currentPodIdentifiers.([]string) {
			if !targetPodIdentifiers[podIdentifier] {
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

// UpdatePodIdentifierToPolicyEndpointMap adds the supplied policy endpoints to the ones
// already tracked for this pod identifier, skipping duplicates. It never removes a name.
//
// Append-only is deliberate. Replacing a parent's names would reclaim the names of
// re-sliced PolicyEndpoints, but deciding which stored names belong to this parent means
// deriving it with GetParentNPNameFromPEName, which is lossy above 58 chars -- so it can
// evict another policy's names and stop its rules being assembled, dropping a Deny on the
// cluster path. Mis-tracking costs enforcement; under-tracking costs memory.
//
// The cost: a name that leaves the live slice set while the identifier is still selected is
// never pruned, so the key survives. Bounded by resharding, not pod churn. See the skipped
// subtests in controllers/{cluster,}policyendpoints_slice_test.go.
//
// Fix: store the parent per entry (podIdentifier -> []struct{ParentNP, Name string}) so both
// eviction and pruning compare a recorded Spec.PolicyRef.Name. Needs the parent on the
// delete path too, where the object is gone.
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
