package utils

import (
	"math"
	"strings"
	"testing"
)

// The shape of the agent's /metrics, trimmed to the parts the parser reads and
// to three buckets.
const sampleMetrics = `# HELP awsnodeagent_ebpf_probe_latency_ms Time to load or attach a pod's TC program in ms, by op (load, attach) and direction
# TYPE awsnodeagent_ebpf_probe_latency_ms histogram
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="ingress",error="false",op="load",le="250"} 4
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="ingress",error="false",op="load",le="500"} 18
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="ingress",error="false",op="load",le="1000"} 20
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="ingress",error="false",op="load",le="+Inf"} 20
awsnodeagent_ebpf_probe_latency_ms_sum{direction="ingress",error="false",op="load"} 7000
awsnodeagent_ebpf_probe_latency_ms_count{direction="ingress",error="false",op="load"} 20
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="egress",error="true",op="load",le="250"} 1
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="egress",error="true",op="load",le="500"} 1
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="egress",error="true",op="load",le="1000"} 1
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="egress",error="true",op="load",le="+Inf"} 1
awsnodeagent_ebpf_probe_latency_ms_sum{direction="egress",error="true",op="load"} 3
awsnodeagent_ebpf_probe_latency_ms_count{direction="egress",error="true",op="load"} 1
# HELP awsnodeagent_aws_ebpfsdk_error_count The number of times eBPF SDK returns an error
# TYPE awsnodeagent_aws_ebpfsdk_error_count counter
awsnodeagent_aws_ebpfsdk_error_count{fn="LoadBpfFile"} 1
`

func TestParseProbeLatency(t *testing.T) {
	got, err := ParseProbeLatency(sampleMetrics)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d series, want 2: %v", len(got), got)
	}
	load := got[ProbeKey{Op: "load", Direction: "ingress"}]
	if load.Count != 20 || load.SumMs != 7000 {
		t.Errorf("ingress load count/sum = %d/%v, want 20/7000", load.Count, load.SumMs)
	}
	want := []Bucket{{250, 4}, {500, 18}, {1000, 20}}
	if len(load.Buckets) != len(want) {
		t.Fatalf("buckets = %v, want %v", load.Buckets, want)
	}
	for i := range want {
		if load.Buckets[i] != want[i] {
			t.Errorf("bucket %d = %v, want %v", i, load.Buckets[i], want[i])
		}
	}
	if failed := got[ProbeKey{Op: "load", Direction: "egress", Error: true}]; failed.Count != 1 {
		t.Errorf("failed egress load = %+v, want count 1", failed)
	}
}

// PodManager.ExecInPod trims its output, so the text arrives without the final
// newline that the Prometheus text format requires.
func TestParseProbeLatencyWithoutTrailingNewline(t *testing.T) {
	got, err := ParseProbeLatency(strings.TrimSpace(sampleMetrics))
	if err != nil {
		t.Fatal(err)
	}
	if got[ProbeKey{Op: "load", Direction: "ingress"}].Count != 20 {
		t.Errorf("ingress load = %+v, want count 20", got[ProbeKey{Op: "load", Direction: "ingress"}])
	}
}

// A histogram vec with no observations exports no series, so a node whose
// agent has not loaded a program since it started has the other metrics but
// not this one.
func TestParseProbeLatencyNoObservationsYet(t *testing.T) {
	got, err := ParseProbeLatency("# TYPE other counter\nother 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want no series", got)
	}
}

func TestParseProbeLatencyErrors(t *testing.T) {
	for name, text := range map[string]string{
		"no metrics at all": "",
		"not a histogram":   "# TYPE awsnodeagent_ebpf_probe_latency_ms counter\nawsnodeagent_ebpf_probe_latency_ms 1\n",
		"malformed":         "awsnodeagent_ebpf_probe_latency_ms_bucket{op=\n",
		// A label the parser does not read would merge two series into one key.
		"unread label": `# TYPE awsnodeagent_ebpf_probe_latency_ms histogram
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="ingress",error="false",op="load",family="v4",le="+Inf"} 1
awsnodeagent_ebpf_probe_latency_ms_count{direction="ingress",error="false",op="load",family="v4"} 1
awsnodeagent_ebpf_probe_latency_ms_bucket{direction="ingress",error="false",op="load",family="v6",le="+Inf"} 1
awsnodeagent_ebpf_probe_latency_ms_count{direction="ingress",error="false",op="load",family="v6"} 1
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProbeLatency(text); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func hist(sum float64, cum ...uint64) ProbeHistogram {
	bounds := []float64{10, 50, 1000, 2000}
	h := ProbeHistogram{SumMs: sum}
	for i, c := range cum {
		h.Buckets = append(h.Buckets, Bucket{UpperMs: bounds[i], Count: c})
	}
	h.Count = cum[len(cum)-1]
	return h
}

func TestProbeHistogramSince(t *testing.T) {
	before := hist(100, 5, 5, 10, 10)
	after := hist(700, 5, 5, 28, 30)

	got, err := after.Since(before)
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 20 || got.SumMs != 600 || got.MeanMs() != 30 {
		t.Errorf("delta = count %d sum %v mean %v, want 20 600 30", got.Count, got.SumMs, got.MeanMs())
	}
	if got.Buckets[2].Count != 18 || got.Buckets[3].Count != 20 {
		t.Errorf("delta buckets = %v", got.Buckets)
	}

	// The agent restarted: after alone covers the interval.
	restarted := hist(20, 1, 2, 4, 4)
	if got, err := restarted.Since(before); err != nil || got.Count != 4 {
		t.Errorf("restarted: got %+v, %v, want count 4", got, err)
	}
	// Nothing before: the first scrape had no series.
	if got, err := after.Since(ProbeHistogram{}); err != nil || got.Count != 30 {
		t.Errorf("no before: got %+v, %v, want count 30", got, err)
	}
	// A different bucket layout cannot be subtracted.
	if _, err := after.Since(hist(1, 1, 1)); err == nil {
		t.Error("want an error for a changed bucket layout")
	}
}

func TestProbeHistogramQuantileMs(t *testing.T) {
	// 10 observations: 5 at or below 10 ms, 4 in (50, 1000], 1 in (1000, 2000].
	h := hist(0, 5, 5, 9, 10)
	for _, tc := range []struct {
		q    float64
		want float64
	}{
		{0.5, 10},   // the 5th observation is the last one in the first bucket
		{0.7, 525},  // 2 of the 4 in (50, 1000]: halfway
		{0.9, 1000}, // the 9th is the last at or below 1000
		{0.99, 1900},
	} {
		if got := h.QuantileMs(tc.q); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("q%v = %v, want %v", tc.q, got, tc.want)
		}
	}
	if !math.IsNaN((ProbeHistogram{}).QuantileMs(0.5)) {
		t.Error("no observations: want NaN")
	}
	above := ProbeHistogram{Count: 2, Buckets: []Bucket{{10, 1}, {50, 1}}}
	if !math.IsInf(above.QuantileMs(0.99), 1) {
		t.Error("quantile above the highest bound: want +Inf")
	}
}
