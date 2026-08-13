package utils

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
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
		// stored is the previous snapshot in networkPolicyToPodIdentifierMap, keyed by policy identifier
		stored               map[string][]string
		policyIdentifier     string
		targetPodIdentifiers []string
		want                 []string
	}{
		{
			name:                 "no previous snapshot for this NP",
			stored:               map[string][]string{},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: []string{"rs1@ns"},
			want:                 nil,
		},
		{
			name:                 "all previously selected identifiers still selected",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "rs2@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: []string{"rs1@ns", "rs2@ns"},
			want:                 nil,
		},
		{
			name:                 "identifier no longer selected is stale",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "churned@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: []string{"rs1@ns"},
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

func TestDeleteParentNPFromPodIdentifierMap(t *testing.T) {
	const podIdentifier = "rs1@ns"

	tests := []struct {
		name string
		// tracked is the identifier's PE list before the purge; nil means no entry at all
		tracked   []string
		parentNP  string
		wantEntry bool
		wantList  []string
	}{
		{
			name:      "single slice of the target NP - entry deleted",
			tracked:   []string{"np-abcd"},
			parentNP:  "np",
			wantEntry: false,
		},
		{
			name:      "all slices of the target NP dropped in one pass - entry deleted",
			tracked:   []string{"np-abcd", "np-efgh"},
			parentNP:  "np",
			wantEntry: false,
		},
		{
			name:      "another NP still references the identifier - entry survives",
			tracked:   []string{"np-abcd", "other-np-xyz"},
			parentNP:  "np",
			wantEntry: true,
			wantList:  []string{"other-np-xyz"},
		},
		{
			name:      "no slice belongs to the target NP - list unchanged",
			tracked:   []string{"other-np-xyz"},
			parentNP:  "np",
			wantEntry: true,
			wantList:  []string{"other-np-xyz"},
		},
		{
			name:      "absent identifier is a no-op",
			tracked:   nil,
			parentNP:  "np",
			wantEntry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			var mu sync.Mutex
			if tt.tracked != nil {
				m.Store(podIdentifier, tt.tracked)
			}

			DeleteParentNPFromPodIdentifierMap(&m, &mu, podIdentifier, tt.parentNP)

			got, ok := m.Load(podIdentifier)
			assert.Equal(t, tt.wantEntry, ok)
			if tt.wantEntry {
				assert.ElementsMatch(t, tt.wantList, got.([]string))
			}
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
