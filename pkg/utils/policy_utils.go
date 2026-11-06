package utils

import (
	"cmp"
	"slices"
	"strings"
	"sync"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// GetPodListToBeCleanedUp compares old and new pod sets to determine which pods need cleanup.
//
// A pod is matched on NamespacedName, not on the whole struct: identity is the name, and
// npatypes.Pod also carries PodIP, which the same pod can legitimately change (a StatefulSet
// pod keeps its name across recreation but not its address). Comparing the whole struct would
// treat a re-addressed pod as absent from the new set, which reads as "no longer selected"
// when it still is. The podIdentifiers guard below happens to mask that today -- a pod in the
// new set always has its identifier there too -- so this is a clarification rather than a
// behaviour change, and it keeps the comparison from depending on that coincidence.
func GetPodListToBeCleanedUp(oldPodSet []npatypes.Pod, newPodSet []npatypes.Pod, podIdentifiers map[string]bool) []npatypes.Pod {
	var podsToBeCleanedUp []npatypes.Pod

	for _, oldPod := range oldPodSet {
		oldPodIdentifier := GetPodIdentifier(oldPod.Name, oldPod.Namespace)

		stillSelected := slices.ContainsFunc(newPodSet, func(newPod npatypes.Pod) bool {
			return newPod.NamespacedName == oldPod.NamespacedName
		})
		if !stillSelected && !podIdentifiers[oldPodIdentifier] {
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

// PolicyEndpointRef is a policy endpoint tracked for a pod, with the parent policy it was
// tracked under. A slice name can be reused under another parent, so the name alone does not
// identify whose rules it contributed.
type PolicyEndpointRef struct {
	Name   string
	Parent string
}

func comparePolicyEndpointRefs(a, b PolicyEndpointRef) int {
	return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Parent, b.Parent))
}

// DeletePolicyEndpointFromPodIdentifierMap removes a policy endpoint from a pod's identifier map.
func DeletePolicyEndpointFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, policyEndpoint PolicyEndpointRef) {
	deleteFromPodIdentifierMap(podIdentifierToPolicyEndpointMap, mutex, podIdentifier, func(ref PolicyEndpointRef) bool { return ref == policyEndpoint })
}

// DeleteParentFromPodIdentifierMap removes every policy endpoint of parent from a pod's identifier
// map, for an identifier the parent no longer selects. This includes slices whose names have since
// moved to another parent, so a name that later moves back cannot revive the entry.
func DeleteParentFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier, parent string) {
	deleteFromPodIdentifierMap(podIdentifierToPolicyEndpointMap, mutex, podIdentifier, func(ref PolicyEndpointRef) bool { return ref.Parent == parent })
}

// The stored list must stay sorted (see UpdatePodIdentifierToPolicyEndpointMap), so this filters
// in order into a new slice; readers load the list without the mutex.
func deleteFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, remove func(PolicyEndpointRef) bool) {
	mutex.Lock()
	defer mutex.Unlock()

	var currentList []PolicyEndpointRef
	if policyEndpointList, ok := podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		for _, ref := range policyEndpointList.([]PolicyEndpointRef) {
			if remove(ref) {
				continue
			}
			currentList = append(currentList, ref)
		}
		if len(currentList) == 0 {
			podIdentifierToPolicyEndpointMap.Delete(podIdentifier)
		} else {
			podIdentifierToPolicyEndpointMap.Store(podIdentifier, currentList)
		}
	}
}

// UpdatePodIdentifierToPolicyEndpointMap adds the supplied policy endpoints of parent to the ones
// already tracked for this pod identifier, skipping duplicates. It never removes an entry.
//
// The stored list is kept sorted so membership is a binary search. This function and
// deleteFromPodIdentifierMap are its only writers and must both preserve the
// order. The list is replaced rather than modified in place because readers (e.g. the CNI
// RPC path) load it without the mutex.
//
// The cost of append-only: a name that leaves the live slice set while the identifier is still
// selected is never pruned, so the key survives. Bounded by resharding, not pod churn. See the
// skipped subtests in controllers/{cluster,}policyendpoints_slice_test.go.
func UpdatePodIdentifierToPolicyEndpointMap(podIdentifierMap *sync.Map, mutex *sync.Mutex, podIdentifier, parent string, policyEndpointList []string) {
	mutex.Lock()
	defer mutex.Unlock()

	var current []PolicyEndpointRef
	if currentSet, ok := podIdentifierMap.Load(podIdentifier); ok {
		current = currentSet.([]PolicyEndpointRef)
	}
	var missing []PolicyEndpointRef
	for _, policyEndpointResourceName := range policyEndpointList {
		ref := PolicyEndpointRef{Name: policyEndpointResourceName, Parent: parent}
		if _, tracked := slices.BinarySearchFunc(current, ref, comparePolicyEndpointRefs); !tracked {
			log().Debugf("Adding policy endpoint %s of %s for podIdentifier %s", ref.Name, ref.Parent, podIdentifier)
			missing = append(missing, ref)
		}
	}
	if len(missing) == 0 {
		return
	}
	slices.SortFunc(missing, comparePolicyEndpointRefs)
	missing = slices.Compact(missing)
	policyEndpoints := make([]PolicyEndpointRef, 0, len(current)+len(missing))
	i, j := 0, 0
	for i < len(current) && j < len(missing) {
		if comparePolicyEndpointRefs(current[i], missing[j]) < 0 {
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
