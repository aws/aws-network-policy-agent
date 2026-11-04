package utils

import (
	"sync"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
)

func TestGetNetworkPolicyIdentifier(t *testing.T) {
	first := GetNetworkPolicyIdentifier("policy-with-hyphen", "namespace")
	second := GetNetworkPolicyIdentifier("policy", "with-hyphen-namespace")

	assert.Equal(t, "policy-with-hyphen/namespace", first)
	assert.Equal(t, "policy/with-hyphen-namespace", second)
	assert.NotEqual(t, first, second)
}

func TestDeriveStalePodIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		// stored is the previous snapshot in networkPolicyToPodIdentifierMap, keyed by policy identifier.
		stored               map[string][]string
		policyIdentifier     string
		targetPodIdentifiers map[string]bool
		want                 []string
	}{
		{
			name:                 "no previous snapshot for this NP",
			stored:               map[string][]string{},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: map[string]bool{"rs1@ns": true},
			want:                 nil,
		},
		{
			name:                 "all previously selected identifiers still selected",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "rs2@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: map[string]bool{"rs1@ns": true, "rs2@ns": true},
			want:                 nil,
		},
		{
			name:                 "identifier no longer selected is stale",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "churned@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: map[string]bool{"rs1@ns": true},
			want:                 []string{"churned@ns"},
		},
		{
			name:                 "empty current set makes every previous identifier stale (full NP delete)",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "rs2@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: nil,
			want:                 []string{"rs1@ns", "rs2@ns"},
		},
		{
			name:                 "only this NP's snapshot is consulted",
			stored:               map[string][]string{"np/ns": {"rs1@ns"}, "other-np/ns": {"rs9@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: nil,
			want:                 []string{"rs1@ns"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			for k, v := range tt.stored {
				m.Store(k, v)
			}
			got := DeriveStalePodIdentifiers(&m, tt.policyIdentifier, tt.targetPodIdentifiers)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestUpdatePodIdentifierToPolicyEndpointMap(t *testing.T) {
	const podIdentifier = "rs1@ns"

	tests := []struct {
		name     string
		tracked  []string
		incoming []string
		want     []string
	}{
		{
			name:     "first insert for a new identifier",
			tracked:  nil,
			incoming: []string{"np-abcd"},
			want:     []string{"np-abcd"},
		},
		{
			name:     "already-tracked slice is not duplicated",
			tracked:  []string{"np-abcd"},
			incoming: []string{"np-abcd"},
			want:     []string{"np-abcd"},
		},
		{
			name:     "new sibling slice is appended alongside the existing one",
			tracked:  []string{"np-abcd"},
			incoming: []string{"np-abcd", "np-efgh"},
			want:     []string{"np-abcd", "np-efgh"},
		},
		{
			name:     "another NP's slice is preserved",
			tracked:  []string{"other-np-xyz"},
			incoming: []string{"np-abcd"},
			want:     []string{"other-np-xyz", "np-abcd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			var mu sync.Mutex
			if tt.tracked != nil {
				m.Store(podIdentifier, tt.tracked)
			}

			UpdatePodIdentifierToPolicyEndpointMap(&m, &mu, podIdentifier, tt.incoming)

			got, ok := m.Load(podIdentifier)
			assert.True(t, ok)
			assert.ElementsMatch(t, tt.want, got.([]string))
		})
	}
}

// TestGetPodListToBeCleanedUp covers pod matching being on identity rather than on the whole
// npatypes.Pod struct. A pod's PodIP can change while the pod keeps its name (a StatefulSet
// pod recreated in place), and a pod the policy still selects must never be queued for
// cleanup -- that would strip enforcement from a pod still covered by the policy.
func TestGetPodListToBeCleanedUp(t *testing.T) {
	pod := func(name, ip string) npatypes.Pod {
		return npatypes.Pod{
			NamespacedName: types.NamespacedName{Name: name, Namespace: "ns"},
			PodIP:          v1alpha1.NetworkAddress(ip),
		}
	}
	idOf := func(name string) string { return GetPodIdentifier(name, "ns") }

	tests := []struct {
		name       string
		oldPodSet  []npatypes.Pod
		newPodSet  []npatypes.Pod
		identifier map[string]bool
		want       []string
	}{
		{
			name:      "a pod still selected under a new address is not cleaned up",
			oldPodSet: []npatypes.Pod{pod("web-aaa", "10.1.1.1")},
			newPodSet: []npatypes.Pod{pod("web-aaa", "10.1.1.9")},
			want:      nil,
		},
		{
			name:      "a pod absent from the new set is cleaned up",
			oldPodSet: []npatypes.Pod{pod("web-aaa", "10.1.1.1")},
			newPodSet: []npatypes.Pod{pod("api-aaa", "10.1.1.2")},
			want:      []string{"web-aaa"},
		},
		{
			name:       "a pod whose identifier is still selected is left alone",
			oldPodSet:  []npatypes.Pod{pod("web-aaa", "10.1.1.1")},
			newPodSet:  []npatypes.Pod{pod("web-bbb", "10.1.1.2")},
			identifier: map[string]bool{idOf("web-aaa"): true},
			want:       nil,
		},
		{
			name:      "an unchanged pod is left alone",
			oldPodSet: []npatypes.Pod{pod("web-aaa", "10.1.1.1")},
			newPodSet: []npatypes.Pod{pod("web-aaa", "10.1.1.1")},
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPodListToBeCleanedUp(tt.oldPodSet, tt.newPodSet, tt.identifier)
			names := make([]string, 0, len(got))
			for _, p := range got {
				names = append(names, p.Name)
			}
			assert.ElementsMatch(t, tt.want, names)
		})
	}
}
