package kubestats

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A trimmed but realistic kubelet /stats/summary payload: the aws-node pod with
// the CNI and NPA containers, plus an unrelated pod. The NPA container's
// working-set is what the soak's >50 MiB gate measures.
const sampleSummary = `{
  "node": {"nodeName": "ip-10-0-1-23.us-west-2.compute.internal"},
  "pods": [
    {
      "podRef": {"name": "aws-node-abcde", "namespace": "kube-system"},
      "containers": [
        {"name": "aws-vpc-cni-init", "memory": {"workingSetBytes": 12000000}},
        {"name": "aws-node", "memory": {"workingSetBytes": 60000000}},
        {"name": "aws-eks-nodeagent", "memory": {"workingSetBytes": 41000000}}
      ]
    },
    {
      "podRef": {"name": "coredns-xyz", "namespace": "kube-system"},
      "containers": [
        {"name": "coredns", "memory": {"workingSetBytes": 15000000}}
      ]
    }
  ]
}`

func TestContainerWorkingSet_FindsNPAContainer(t *testing.T) {
	s, err := ParseSummary([]byte(sampleSummary))
	require.NoError(t, err)

	ws, err := s.ContainerWorkingSet("kube-system", "aws-node-abcde", "aws-eks-nodeagent")
	require.NoError(t, err)
	// Must isolate the NPA container, not fold in the co-located CNI container.
	assert.Equal(t, uint64(41000000), ws)
}

func TestContainerWorkingSet_Errors(t *testing.T) {
	s, err := ParseSummary([]byte(sampleSummary))
	require.NoError(t, err)

	tests := []struct {
		name              string
		ns, pod, ctr      string
		wantErrContaining string
	}{
		{"missing pod", "kube-system", "nope", "aws-eks-nodeagent", "not found in kubelet summary"},
		{"missing container", "kube-system", "aws-node-abcde", "nope", "not found in pod"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.ContainerWorkingSet(tt.ns, tt.pod, tt.ctr)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrContaining)
		})
	}
}

func TestContainerWorkingSet_MissingMemoryIsNotZero(t *testing.T) {
	// A container that has not reported memory yet must error, not read as 0,
	// otherwise the growth baseline would anchor on a false zero.
	payload := `{"node":{"nodeName":"n"},"pods":[
		{"podRef":{"name":"aws-node-x","namespace":"kube-system"},
		 "containers":[{"name":"aws-eks-nodeagent","memory":{}}]}]}`
	s, err := ParseSummary([]byte(payload))
	require.NoError(t, err)

	_, err = s.ContainerWorkingSet("kube-system", "aws-node-x", "aws-eks-nodeagent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has not reported working-set")
}

func TestParseSummary_RejectsGarbage(t *testing.T) {
	_, err := ParseSummary([]byte("not json"))
	require.Error(t, err)
}

func TestGrowthTracker_BaselineToPeak(t *testing.T) {
	const limit = 50 * 1024 * 1024 // 50 MiB
	g := NewGrowthTracker(limit)

	// No samples yet: nothing to flag.
	assert.False(t, g.Exceeded())
	assert.Equal(t, uint64(0), g.Growth())

	g.Observe(40 * 1024 * 1024) // baseline 40 MiB
	g.Observe(60 * 1024 * 1024) // +20 MiB
	g.Observe(50 * 1024 * 1024) // settles, but peak stays at 60

	assert.Equal(t, uint64(40*1024*1024), g.Baseline())
	assert.Equal(t, uint64(60*1024*1024), g.Peak())
	assert.Equal(t, uint64(20*1024*1024), g.Growth())
	assert.False(t, g.Exceeded(), "20 MiB growth is under the 50 MiB budget")
}

func TestGrowthTracker_FlagsExcessGrowth(t *testing.T) {
	const limit = 50 * 1024 * 1024
	g := NewGrowthTracker(limit)
	g.Observe(30 * 1024 * 1024)  // baseline
	g.Observe(100 * 1024 * 1024) // +70 MiB, over budget
	g.Observe(40 * 1024 * 1024)  // later settles, but the peak already breached

	assert.True(t, g.Exceeded(), "a transient peak over budget is still a leak signal")
	assert.Equal(t, uint64(70*1024*1024), g.Growth())
}

func TestGrowthTracker_AtLimitIsNotExceeded(t *testing.T) {
	// The criterion is strictly greater than the budget; exactly at the budget
	// passes, matching the ">50 MiB" wording.
	const limit = 50 * 1024 * 1024
	g := NewGrowthTracker(limit)
	g.Observe(10 * 1024 * 1024)
	g.Observe(60 * 1024 * 1024) // exactly +50 MiB
	assert.Equal(t, uint64(limit), g.Growth())
	assert.False(t, g.Exceeded())
}

func TestGrowthTracker_MonotonicBaseline(t *testing.T) {
	// A dip below baseline must not lower the baseline or produce negative growth.
	g := NewGrowthTracker(50 * 1024 * 1024)
	g.Observe(40 * 1024 * 1024)
	g.Observe(20 * 1024 * 1024) // dip
	assert.Equal(t, uint64(40*1024*1024), g.Baseline())
	assert.Equal(t, uint64(0), g.Growth())
}
