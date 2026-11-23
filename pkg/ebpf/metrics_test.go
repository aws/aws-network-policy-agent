package ebpf

import (
	"errors"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The load and attach latency integration test (test/integration/bpflatency)
// reads probeLatency per op and direction, and holds it to ceilings that must
// be bucket bounds for its quantile check to be exact.
func TestProbeLatencyHistogram(t *testing.T) {
	direction := t.Name()
	t.Cleanup(func() {
		probeLatency.DeleteLabelValues("load", direction, "false")
		probeLatency.DeleteLabelValues("load", direction, "true")
	})
	observeProbeLatency("load", direction, 300, nil)
	observeProbeLatency("load", direction, 1200, nil)
	observeProbeLatency("load", direction, 5, errors.New("verifier"))

	read := func(errLabel string) *dto.Histogram {
		m := &dto.Metric{}
		obs, err := probeLatency.GetMetricWithLabelValues("load", direction, errLabel)
		require.NoError(t, err)
		require.NoError(t, obs.(prometheus.Metric).Write(m))
		return m.GetHistogram()
	}
	ok := read("false")
	assert.Equal(t, uint64(2), ok.GetSampleCount())
	assert.Equal(t, 1500.0, ok.GetSampleSum())
	assert.Equal(t, uint64(1), read("true").GetSampleCount(), "a failed load is its own series")

	for _, ceiling := range []float64{10, 50, 1000, 2000} {
		assert.True(t, slices.Contains(probeLatencyBucketsMs, ceiling), "default ceiling %v ms is a bucket bound", ceiling)
	}
}
