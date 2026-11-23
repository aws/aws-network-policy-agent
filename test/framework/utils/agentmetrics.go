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

// ProbeLatencyMetric is the agent's histogram of the time to load and to
// attach a pod's TC program, in ms, labeled by op, direction and error.
const ProbeLatencyMetric = "awsnodeagent_ebpf_probe_latency_ms"

// ProbeKey identifies one series of ProbeLatencyMetric.
type ProbeKey struct {
	Op        string // "load" or "attach"
	Direction string // "ingress" or "egress"
	Error     bool
}

// Bucket is one histogram bucket: the number of observations at or below
// UpperMs.
type Bucket struct {
	UpperMs float64
	Count   uint64
}

// ProbeHistogram is one series of ProbeLatencyMetric. Buckets are cumulative,
// sorted by UpperMs, and exclude +Inf, whose count is Count.
type ProbeHistogram struct {
	Count   uint64
	SumMs   float64
	Buckets []Bucket
}

// Since returns the observations made between before and h. When the
// counts went backwards the agent restarted in between, and h alone covers
// the interval since then.
func (h ProbeHistogram) Since(before ProbeHistogram) (ProbeHistogram, error) {
	if h.Count < before.Count {
		return h, nil
	}
	if before.Count == 0 && len(before.Buckets) == 0 {
		return h, nil
	}
	if len(h.Buckets) != len(before.Buckets) {
		return ProbeHistogram{}, fmt.Errorf("bucket layout changed between scrapes: %d buckets, then %d", len(before.Buckets), len(h.Buckets))
	}
	out := ProbeHistogram{Count: h.Count - before.Count, SumMs: h.SumMs - before.SumMs, Buckets: make([]Bucket, len(h.Buckets))}
	for i, b := range h.Buckets {
		if b.UpperMs != before.Buckets[i].UpperMs || b.Count < before.Buckets[i].Count {
			return ProbeHistogram{}, fmt.Errorf("bucket %d changed between scrapes: %+v, then %+v", i, before.Buckets[i], b)
		}
		out.Buckets[i] = Bucket{UpperMs: b.UpperMs, Count: b.Count - before.Buckets[i].Count}
	}
	return out, nil
}

// MeanMs returns the mean observation in ms, or NaN when there are none.
func (h ProbeHistogram) MeanMs() float64 {
	if h.Count == 0 {
		return math.NaN()
	}
	return h.SumMs / float64(h.Count)
}

// QuantileMs estimates the q-quantile in ms the way PromQL's
// histogram_quantile does: it finds the bucket holding the q*Count-th
// observation and interpolates linearly inside it. The estimate never exceeds
// that bucket's upper bound, so for a bucket bound c, QuantileMs(q) <= c
// exactly when at least q of the observations are at or below c. It returns
// NaN when there are no observations and +Inf when the quantile lies above
// the highest finite bound.
func (h ProbeHistogram) QuantileMs(q float64) float64 {
	if h.Count == 0 {
		return math.NaN()
	}
	rank := q * float64(h.Count)
	var lower float64
	var below uint64
	for _, b := range h.Buckets {
		if float64(b.Count) >= rank && b.Count > below {
			return lower + (b.UpperMs-lower)*(rank-float64(below))/float64(b.Count-below)
		}
		lower, below = b.UpperMs, b.Count
	}
	return math.Inf(1)
}

// ParseProbeLatency parses the agent's /metrics output and returns every
// series of ProbeLatencyMetric. It returns an error if two series have the
// same ProbeKey, as they would if the metric gained a label this parser does
// not read, so such series are not silently merged.
func ParseProbeLatency(text string) (map[ProbeKey]ProbeHistogram, error) {
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
	family, ok := families[ProbeLatencyMetric]
	if !ok {
		if len(families) == 0 {
			return nil, fmt.Errorf("metrics are empty")
		}
		// No series yet: the agent has not loaded or attached a program
		// since it started, or its image predates the metric.
		return map[ProbeKey]ProbeHistogram{}, nil
	}
	if family.GetType() != dto.MetricType_HISTOGRAM {
		return nil, fmt.Errorf("%s is a %v, not a histogram", ProbeLatencyMetric, family.GetType())
	}
	out := make(map[ProbeKey]ProbeHistogram, len(family.GetMetric()))
	for _, m := range family.GetMetric() {
		var key ProbeKey
		for _, l := range m.GetLabel() {
			switch l.GetName() {
			case "op":
				key.Op = l.GetValue()
			case "direction":
				key.Direction = l.GetValue()
			case "error":
				key.Error = l.GetValue() == "true"
			}
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%s has more than one series for %+v; it has a label the parser does not read", ProbeLatencyMetric, key)
		}
		h := m.GetHistogram()
		series := ProbeHistogram{Count: h.GetSampleCount(), SumMs: h.GetSampleSum()}
		for _, b := range h.GetBucket() {
			if math.IsInf(b.GetUpperBound(), 1) {
				continue
			}
			series.Buckets = append(series.Buckets, Bucket{UpperMs: b.GetUpperBound(), Count: b.GetCumulativeCount()})
		}
		out[key] = series
	}
	return out, nil
}
