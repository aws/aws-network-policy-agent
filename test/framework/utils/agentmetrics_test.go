package utils

import (
	"math"
	"strings"
	"testing"
)

// The shape of the agent's /metrics, trimmed to the parts the parser reads.
const sampleMetrics = `# HELP awsnodeagent_aws_ebpf_sdk_latency_ms eBPF SDK API call latency in ms
# TYPE awsnodeagent_aws_ebpf_sdk_latency_ms summary
awsnodeagent_aws_ebpf_sdk_latency_ms{api="LoadBpfFile",error="false",quantile="0.5"} 41.5
awsnodeagent_aws_ebpf_sdk_latency_ms{api="LoadBpfFile",error="false",quantile="0.99"} 97.25
awsnodeagent_aws_ebpf_sdk_latency_ms_sum{api="LoadBpfFile",error="false"} 900
awsnodeagent_aws_ebpf_sdk_latency_ms_count{api="LoadBpfFile",error="false"} 20
awsnodeagent_aws_ebpf_sdk_latency_ms{api="LoadBpfFile",error="true",quantile="0.5"} NaN
awsnodeagent_aws_ebpf_sdk_latency_ms{api="LoadBpfFile",error="true",quantile="0.99"} NaN
awsnodeagent_aws_ebpf_sdk_latency_ms_sum{api="LoadBpfFile",error="true"} 3
awsnodeagent_aws_ebpf_sdk_latency_ms_count{api="LoadBpfFile",error="true"} 1
awsnodeagent_aws_ebpf_sdk_latency_ms_sum{api="attachIngressBPFProbe",error="false"} 12
awsnodeagent_aws_ebpf_sdk_latency_ms_count{api="attachIngressBPFProbe",error="false"} 10
# HELP awsnodeagent_aws_ebpfsdk_error_count The number of times eBPF SDK returns an error
# TYPE awsnodeagent_aws_ebpfsdk_error_count counter
awsnodeagent_aws_ebpfsdk_error_count{fn="LoadBpfFile"} 1
`

func TestParseSDKLatency(t *testing.T) {
	got, err := ParseSDKLatency(sampleMetrics)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d series, want 3: %v", len(got), got)
	}

	load := got[LatencyKey{API: "LoadBpfFile"}]
	if load.Count != 20 || load.SumMs != 900 {
		t.Errorf("LoadBpfFile count/sum = %d/%v, want 20/900", load.Count, load.SumMs)
	}
	if load.Quantiles[0.5] != 41.5 || load.Quantiles[0.99] != 97.25 {
		t.Errorf("LoadBpfFile quantiles = %v, want 0.5:41.5 0.99:97.25", load.Quantiles)
	}

	failed := got[LatencyKey{API: "LoadBpfFile", Error: true}]
	if failed.Count != 1 || !math.IsNaN(failed.Quantiles[0.99]) {
		t.Errorf("failed LoadBpfFile = %+v, want count 1 and NaN p99", failed)
	}

	// An agent without objectives exports only _sum and _count.
	attach := got[LatencyKey{API: "attachIngressBPFProbe"}]
	if attach.Count != 10 || len(attach.Quantiles) != 0 {
		t.Errorf("attachIngressBPFProbe = %+v, want count 10 and no quantiles", attach)
	}
}

// PodManager.ExecInPod trims its output, so the text arrives without the final
// newline that the Prometheus text format requires.
func TestParseSDKLatencyWithoutTrailingNewline(t *testing.T) {
	got, err := ParseSDKLatency(strings.TrimSpace(sampleMetrics))
	if err != nil {
		t.Fatal(err)
	}
	if got[LatencyKey{API: "LoadBpfFile"}].Count != 20 {
		t.Errorf("LoadBpfFile = %+v, want count 20", got[LatencyKey{API: "LoadBpfFile"}])
	}
}

// A summary with no observations is not exported, so a node whose agent has
// not loaded a program since it started has the other metrics but not this one.
func TestParseSDKLatencyNoObservationsYet(t *testing.T) {
	got, err := ParseSDKLatency("# TYPE other counter\nother 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want no series", got)
	}
}

func TestParseSDKLatencyErrors(t *testing.T) {
	for name, text := range map[string]string{
		"no metrics at all": "",
		"not a summary":     "# TYPE awsnodeagent_aws_ebpf_sdk_latency_ms counter\nawsnodeagent_aws_ebpf_sdk_latency_ms 1\n",
		"malformed":         "awsnodeagent_aws_ebpf_sdk_latency_ms{api=\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSDKLatency(text); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestMeanMsSince(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after LatencySeries
		wantN         uint64
		wantMean      float64
	}{
		{"delta only", LatencySeries{Count: 10, SumMs: 100}, LatencySeries{Count: 30, SumMs: 700}, 20, 30},
		{"agent restarted", LatencySeries{Count: 50, SumMs: 900}, LatencySeries{Count: 4, SumMs: 20}, 4, 5},
		{"no new observations", LatencySeries{Count: 5, SumMs: 10}, LatencySeries{Count: 5, SumMs: 10}, 0, math.NaN()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, mean := tc.after.MeanMsSince(tc.before)
			if n != tc.wantN {
				t.Errorf("n = %d, want %d", n, tc.wantN)
			}
			if math.IsNaN(tc.wantMean) != math.IsNaN(mean) || (!math.IsNaN(mean) && mean != tc.wantMean) {
				t.Errorf("mean = %v, want %v", mean, tc.wantMean)
			}
		})
	}
}
