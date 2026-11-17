package utils

import (
	"sync"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	ref := func(name, parent string) PolicyEndpointRef { return PolicyEndpointRef{Name: name, Parent: parent} }

	tests := []struct {
		name     string
		tracked  []PolicyEndpointRef
		parent   string
		incoming []string
		want     []PolicyEndpointRef
	}{
		{
			name:     "first insert for a new identifier",
			parent:   "np",
			incoming: []string{"np-abcd"},
			want:     []PolicyEndpointRef{ref("np-abcd", "np")},
		},
		{
			name:     "already-tracked slice is not duplicated",
			tracked:  []PolicyEndpointRef{ref("np-abcd", "np")},
			parent:   "np",
			incoming: []string{"np-abcd", "np-abcd"},
			want:     []PolicyEndpointRef{ref("np-abcd", "np")},
		},
		{
			name:     "new sibling slice is added alongside the existing one",
			tracked:  []PolicyEndpointRef{ref("np-abcd", "np")},
			parent:   "np",
			incoming: []string{"np-efgh", "np-abcd"},
			want:     []PolicyEndpointRef{ref("np-abcd", "np"), ref("np-efgh", "np")},
		},
		{
			name:     "another NP's slice is preserved",
			tracked:  []PolicyEndpointRef{ref("other-np-xyz", "other-np")},
			parent:   "np",
			incoming: []string{"np-abcd"},
			want:     []PolicyEndpointRef{ref("np-abcd", "np"), ref("other-np-xyz", "other-np")},
		},
		{
			name:     "a name reused under another parent is tracked separately",
			tracked:  []PolicyEndpointRef{ref("np-abcd", "np-a")},
			parent:   "np-b",
			incoming: []string{"np-abcd"},
			want:     []PolicyEndpointRef{ref("np-abcd", "np-a"), ref("np-abcd", "np-b")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			var mu sync.Mutex
			if tt.tracked != nil {
				m.Store(podIdentifier, tt.tracked)
			}

			UpdatePodIdentifierToPolicyEndpointMap(&m, &mu, podIdentifier, tt.parent, tt.incoming)

			got, ok := m.Load(podIdentifier)
			require.True(t, ok)
			assert.Equal(t, tt.want, got.([]PolicyEndpointRef), "stored sorted by name, then parent")
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

func TestDeletePolicyEndpointFromPodIdentifierMap(t *testing.T) {
	const podIdentifier = "rs1@ns"
	a := PolicyEndpointRef{Name: "np-abcd", Parent: "np-a"}
	b := PolicyEndpointRef{Name: "np-abcd", Parent: "np-b"}
	other := PolicyEndpointRef{Name: "np-efgh", Parent: "np-a"}

	t.Run("removes only the entry with the same parent", func(t *testing.T) {
		var m sync.Map
		var mu sync.Mutex
		m.Store(podIdentifier, []PolicyEndpointRef{a, b, other})

		DeletePolicyEndpointFromPodIdentifierMap(&m, &mu, podIdentifier, a)

		got, ok := m.Load(podIdentifier)
		require.True(t, ok)
		assert.Equal(t, []PolicyEndpointRef{b, other}, got.([]PolicyEndpointRef))
	})

	t.Run("drops the identifier once nothing is left", func(t *testing.T) {
		var m sync.Map
		var mu sync.Mutex
		m.Store(podIdentifier, []PolicyEndpointRef{a})

		DeletePolicyEndpointFromPodIdentifierMap(&m, &mu, podIdentifier, a)

		_, ok := m.Load(podIdentifier)
		assert.False(t, ok)
	})

	t.Run("an untracked entry or identifier is a no-op", func(t *testing.T) {
		var m sync.Map
		var mu sync.Mutex
		m.Store(podIdentifier, []PolicyEndpointRef{b})

		DeletePolicyEndpointFromPodIdentifierMap(&m, &mu, podIdentifier, a)
		DeletePolicyEndpointFromPodIdentifierMap(&m, &mu, "absent@ns", a)

		got, _ := m.Load(podIdentifier)
		assert.Equal(t, []PolicyEndpointRef{b}, got.([]PolicyEndpointRef))
		_, ok := m.Load("absent@ns")
		assert.False(t, ok)
	})
}

func TestDeleteParentFromPodIdentifierMap(t *testing.T) {
	const podIdentifier = "rs1@ns"
	a1 := PolicyEndpointRef{Name: "np-abcd", Parent: "np-a"}
	a2 := PolicyEndpointRef{Name: "np-efgh", Parent: "np-a"}
	b := PolicyEndpointRef{Name: "np-abcd", Parent: "np-b"}

	var m sync.Map
	var mu sync.Mutex
	m.Store(podIdentifier, []PolicyEndpointRef{a1, b, a2})

	DeleteParentFromPodIdentifierMap(&m, &mu, podIdentifier, "np-a")
	got, ok := m.Load(podIdentifier)
	require.True(t, ok)
	assert.Equal(t, []PolicyEndpointRef{b}, got.([]PolicyEndpointRef), "a reused name under another parent is kept")

	DeleteParentFromPodIdentifierMap(&m, &mu, podIdentifier, "np-b")
	_, ok = m.Load(podIdentifier)
	assert.False(t, ok)
}
