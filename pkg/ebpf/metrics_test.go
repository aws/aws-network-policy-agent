package ebpf

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The load-time integration test (test/integration/bpflatency) reads p50 and
// p99 of these series from /metrics, which a summary only exports if it has
// objectives.
func TestSDKAPILatencyExportsQuantiles(t *testing.T) {
	labels := []string{t.Name(), "false"}
	t.Cleanup(func() { sdkAPILatency.DeleteLabelValues(labels...) })
	obs := sdkAPILatency.WithLabelValues(labels...)
	obs.Observe(1)

	m := &dto.Metric{}
	require.NoError(t, obs.(prometheus.Metric).Write(m))
	var quantiles []float64
	for _, q := range m.GetSummary().GetQuantile() {
		quantiles = append(quantiles, q.GetQuantile())
	}
	assert.Equal(t, []float64{0.5, 0.99}, quantiles)
}
