package utils

import (
	"fmt"
	"math"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// AgentMetricsPort is the port of the agent's default --metrics-bind-addr.
// The agent runs in the host network, so a hostNetwork pod on the node reaches
// it on 127.0.0.1.
const AgentMetricsPort = 8162

// SDKLatencyMetric is the agent's summary of eBPF SDK call latency in ms,
// labeled by api and error.
const SDKLatencyMetric = "awsnodeagent_aws_ebpf_sdk_latency_ms"

// LatencyKey identifies one series of SDKLatencyMetric.
type LatencyKey struct {
	API   string
	Error bool
}

// LatencySeries is one series of SDKLatencyMetric. Count and SumMs are
// cumulative since the agent started. Quantiles maps each objective (0.5,
// 0.99) to its value in ms over the summary's rolling window; a value is NaN
// when the window holds no observations.
type LatencySeries struct {
	Count     uint64
	SumMs     float64
	Quantiles map[float64]float64
}

// MeanMsSince returns the number of observations between before and s, and
// their mean in ms. The mean is NaN when there were none.
func (s LatencySeries) MeanMsSince(before LatencySeries) (uint64, float64) {
	if s.Count < before.Count {
		// The counter went backwards: the agent restarted in between, so
		// s alone covers the interval.
		before = LatencySeries{}
	}
	n := s.Count - before.Count
	if n == 0 {
		return 0, math.NaN()
	}
	return n, (s.SumMs - before.SumMs) / float64(n)
}

// ParseSDKLatency parses the agent's /metrics output and returns every series
// of SDKLatencyMetric.
func ParseSDKLatency(text string) (map[LatencyKey]LatencySeries, error) {
	// The text format ends every line with a newline, and the parser rejects
	// input that doesn't.
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		return nil, fmt.Errorf("parse metrics: %w", err)
	}
	family, ok := families[SDKLatencyMetric]
	if !ok {
		if len(families) == 0 {
			return nil, fmt.Errorf("metrics are empty")
		}
		// The agent has not observed a call since it started.
		return map[LatencyKey]LatencySeries{}, nil
	}
	if family.GetType() != dto.MetricType_SUMMARY {
		return nil, fmt.Errorf("%s is a %v, not a summary", SDKLatencyMetric, family.GetType())
	}
	out := make(map[LatencyKey]LatencySeries, len(family.GetMetric()))
	for _, m := range family.GetMetric() {
		var key LatencyKey
		for _, l := range m.GetLabel() {
			switch l.GetName() {
			case "api":
				key.API = l.GetValue()
			case "error":
				key.Error = l.GetValue() == "true"
			}
		}
		s := m.GetSummary()
		series := LatencySeries{Count: s.GetSampleCount(), SumMs: s.GetSampleSum(), Quantiles: map[float64]float64{}}
		for _, q := range s.GetQuantile() {
			series.Quantiles[q.GetQuantile()] = q.GetValue()
		}
		out[key] = series
	}
	return out, nil
}
