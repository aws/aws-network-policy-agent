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

// DeletePolicyEndpointFromPodIdentifierMap removes a policy endpoint from a pod's identifier map.
// The stored list must stay sorted (see UpdatePodIdentifierToPolicyEndpointMap), so this
// filters in order into a new slice; readers load the list without the mutex.
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
// The stored list is kept sorted so membership is a binary search. This function and
// DeletePolicyEndpointFromPodIdentifierMap are its only writers and must both preserve the
// order. The list is replaced rather than modified in place because readers (e.g. the CNI
// RPC path) load it without the mutex.
//
// Append-only is deliberate. Replacing a parent's names would reclaim the names of
// re-sliced PolicyEndpoints, but the stored names carry no parent, so it could evict another
// policy's names and stop its rules being assembled, dropping a Deny on the cluster path.
// Mis-tracking costs enforcement; under-tracking costs memory.
//
// The cost: a name that leaves the live slice set while the identifier is still selected is
// never pruned, so the key survives. Bounded by resharding, not pod churn. See the skipped
// subtests in controllers/{cluster,}policyendpoints_slice_test.go.
//
// Fix: store the parent per entry (podIdentifier -> []struct{ParentNP, Name string}) so both
// eviction and pruning compare a recorded Spec.PolicyRef.Name.
func UpdatePodIdentifierToPolicyEndpointMap(podIdentifierMap *sync.Map, mutex *sync.Mutex, podIdentifier string, policyEndpointList []string) {
	mutex.Lock()
	defer mutex.Unlock()

	var current []string
	if currentSet, ok := podIdentifierMap.Load(podIdentifier); ok {
		current = currentSet.([]string)
	}
	var missing []string
	for _, policyEndpointResourceName := range policyEndpointList {
		if _, tracked := slices.BinarySearch(current, policyEndpointResourceName); !tracked {
			log().Debugf("Adding policy endpoint %s for podIdentifier %s", policyEndpointResourceName, podIdentifier)
			missing = append(missing, policyEndpointResourceName)
		}
	}
	if len(missing) == 0 {
		return
	}
	slices.Sort(missing)
	missing = slices.Compact(missing)
	policyEndpoints := make([]string, 0, len(current)+len(missing))
	i, j := 0, 0
	for i < len(current) && j < len(missing) {
		if current[i] < missing[j] {
			policyEndpoints = append(policyEndpoints, current[i])
			i++
		} else {
			policyEndpoints = append(policyEndpoints, missing[j])
			j++
		}
	}
	policyEndpoints = append(policyEndpoints, current[i:]...)
	policyEndpoints = append(policyEndpoints, missing[j:]...)
	podIdentifierMap.Store(podIdentifier, policyEndpoints)
}
