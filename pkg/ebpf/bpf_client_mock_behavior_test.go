package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMockBpfClientHasBPFContextBehavior(t *testing.T) {
	t.Run("defaults to true when no overrides are set", func(t *testing.T) {
		m := &MockBpfClient{}
		assert.True(t, m.HasBPFContext("foo@default"))
	})

	t.Run("returns false only for listed pod identifiers", func(t *testing.T) {
		m := &MockBpfClient{
			PodIdentifiersWithoutBPFContext: map[string]bool{
				"gone@default": true,
			},
		}
		assert.False(t, m.HasBPFContext("gone@default"))
		assert.True(t, m.HasBPFContext("present@default"))
	})
}

func TestMockBpfClientGetNetworkPolicyModeBehavior(t *testing.T) {
	t.Run("falls back to standard when unset", func(t *testing.T) {
		m := &MockBpfClient{}
		assert.Equal(t, "standard", m.GetNetworkPolicyMode())
	})

	t.Run("returns the configured mode", func(t *testing.T) {
		m := &MockBpfClient{NetworkPolicyMode: "strict"}
		assert.Equal(t, "strict", m.GetNetworkPolicyMode())
	})
}

func TestMockBpfClientRecordsLastPodState(t *testing.T) {
	m := &MockBpfClient{}

	err := m.UpdatePodStateEbpfMaps("foo@default", POD_STATE_MAP_KEY, DEFAULT_ALLOW, true, true)
	assert.NoError(t, err)
	assert.Equal(t, POD_STATE_MAP_KEY, m.LastPodStateKey)
	assert.Equal(t, DEFAULT_ALLOW, m.LastPodState)

	err = m.UpdatePodStateEbpfMaps("foo@default", CLUSTER_POLICY_POD_STATE_MAP_KEY, DEFAULT_DENY, true, true)
	assert.NoError(t, err)
	assert.Equal(t, CLUSTER_POLICY_POD_STATE_MAP_KEY, m.LastPodStateKey)
	assert.Equal(t, DEFAULT_DENY, m.LastPodState)
}
