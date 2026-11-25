package utils

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSetParentPolicyEndpoints(t *testing.T) {
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
			name:     "a repeated name is stored once",
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
			name:     "a slice no longer listed is dropped",
			tracked:  []PolicyEndpointRef{ref("np-abcd", "np"), ref("np-efgh", "np")},
			parent:   "np",
			incoming: []string{"np-efgh"},
			want:     []PolicyEndpointRef{ref("np-efgh", "np")},
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
		{
			name:     "an empty list removes only this parent's entries",
			tracked:  []PolicyEndpointRef{ref("np-abcd", "np-a"), ref("np-abcd", "np-b")},
			parent:   "np-a",
			incoming: nil,
			want:     []PolicyEndpointRef{ref("np-abcd", "np-b")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			var mu sync.Mutex
			if tt.tracked != nil {
				m.Store(podIdentifier, tt.tracked)
			}

			SetParentPolicyEndpoints(&m, &mu, podIdentifier, tt.parent, tt.incoming)

			got, ok := m.Load(podIdentifier)
			require.True(t, ok)
			assert.Equal(t, tt.want, got.([]PolicyEndpointRef), "stored sorted by name, then parent")
		})
	}

	t.Run("the key is dropped once no parent has entries", func(t *testing.T) {
		var m sync.Map
		var mu sync.Mutex
		m.Store(podIdentifier, []PolicyEndpointRef{ref("np-abcd", "np")})

		SetParentPolicyEndpoints(&m, &mu, podIdentifier, "np", nil)

		_, ok := m.Load(podIdentifier)
		assert.False(t, ok)
	})

	t.Run("an unchanged set leaves the stored list in place", func(t *testing.T) {
		var m sync.Map
		var mu sync.Mutex
		tracked := []PolicyEndpointRef{ref("np-abcd", "np"), ref("other-np-xyz", "other-np")}
		m.Store(podIdentifier, tracked)

		SetParentPolicyEndpoints(&m, &mu, podIdentifier, "np", []string{"np-abcd"})

		got, _ := m.Load(podIdentifier)
		assert.Same(t, &tracked[0], &got.([]PolicyEndpointRef)[0], "no new list is stored")
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
