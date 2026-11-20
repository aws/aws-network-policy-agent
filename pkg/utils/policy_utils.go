package utils

import (
	"cmp"
	"slices"
	"strings"
	"sync"
)

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

// DeleteParentFromPodIdentifierMap removes every policy endpoint of parent from a pod's identifier
// map, for an identifier the parent no longer selects. This includes slices whose names have since
// moved to another parent, so a name that later moves back cannot revive the entry.
func DeleteParentFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier, parent string) {
	deleteFromPodIdentifierMap(podIdentifierToPolicyEndpointMap, mutex, podIdentifier, func(ref PolicyEndpointRef) bool { return ref.Parent == parent })
}

// The stored list must stay sorted (see SetParentPolicyEndpoints), so this filters in order into
// a new slice; readers load the list without the mutex.
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

// SetParentPolicyEndpoints makes parent's entries for podIdentifier exactly the given policy
// endpoint names, leaving every other parent's entries alone. An empty list removes the parent's
// entries, and the identifier's key once no parent has any.
//
// The stored list is kept sorted, and this function and deleteFromPodIdentifierMap are its only
// writers. It is replaced rather than modified in place because readers (the programming workers
// and the CNI RPC path) load it without the mutex.
func SetParentPolicyEndpoints(podIdentifierMap *sync.Map, mutex *sync.Mutex, podIdentifier, parent string, policyEndpointNames []string) {
	mutex.Lock()
	defer mutex.Unlock()

	want := make([]PolicyEndpointRef, 0, len(policyEndpointNames))
	for _, name := range policyEndpointNames {
		want = append(want, PolicyEndpointRef{Name: name, Parent: parent})
	}
	slices.SortFunc(want, comparePolicyEndpointRefs)
	want = slices.Compact(want)

	var current []PolicyEndpointRef
	if currentSet, ok := podIdentifierMap.Load(podIdentifier); ok {
		current = currentSet.([]PolicyEndpointRef)
	}
	var others, have []PolicyEndpointRef
	for _, ref := range current {
		if ref.Parent == parent {
			have = append(have, ref)
		} else {
			others = append(others, ref)
		}
	}
	if slices.Equal(have, want) {
		return
	}

	merged := make([]PolicyEndpointRef, 0, len(others)+len(want))
	i, j := 0, 0
	for i < len(others) && j < len(want) {
		if comparePolicyEndpointRefs(others[i], want[j]) < 0 {
			merged = append(merged, others[i])
			i++
		} else {
			merged = append(merged, want[j])
			j++
		}
	}
	merged = append(merged, others[i:]...)
	merged = append(merged, want[j:]...)
	if len(merged) == 0 {
		podIdentifierMap.Delete(podIdentifier)
		return
	}
	podIdentifierMap.Store(podIdentifier, merged)
}
