package bpflatency

// A plain Go test for the result line. It needs no cluster: run it with
// `go test ./test/integration/bpflatency -run TestResultLine`.

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	fwutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
)

func TestResultLine(t *testing.T) {
	before := map[fwutils.LatencyKey]fwutils.LatencySeries{
		{API: loadAPI}: {Count: 10, SumMs: 2000},
	}
	after := map[fwutils.LatencyKey]fwutils.LatencySeries{
		{API: loadAPI}:          {Count: 30, SumMs: 6200, Quantiles: map[float64]float64{0.5: 208.5049, 0.99: 317.42}},
		{API: attachIngressAPI}: {Count: 10, SumMs: 13.5, Quantiles: map[float64]float64{0.5: math.NaN(), 0.99: 1.52}},
		// attachEgressAPI: an agent without the quantiles, and no calls.
	}
	line, err := resultLine(runInfo{Kernel: "6.12.100", OS: "AL2023", Arch: "amd64", IPFamily: "IPv4", Pods: 10}, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, resultLinePrefix) || strings.Contains(line, "\n") {
		t.Fatalf("want one line starting with %q, got %q", resultLinePrefix, line)
	}

	var got struct {
		Kernel   string `json:"kernel"`
		IPFamily string `json:"ipFamily"`
		Pods     int    `json:"pods"`
		APIs     map[string]struct {
			New    uint64   `json:"new"`
			MeanMs *float64 `json:"meanMs"`
			P50Ms  *float64 `json:"p50Ms"`
			P99Ms  *float64 `json:"p99Ms"`
		} `json:"apis"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, resultLinePrefix)), &got); err != nil {
		t.Fatalf("not JSON: %v: %s", err, line)
	}
	if got.Kernel != "6.12.100" || got.IPFamily != "IPv4" || got.Pods != 10 {
		t.Errorf("run info = %+v", got)
	}

	load := got.APIs[loadAPI]
	if load.New != 20 || *load.MeanMs != 210 || *load.P50Ms != 208.5 || *load.P99Ms != 317.42 {
		t.Errorf("load = new %d mean %v p50 %v p99 %v, want 20 210 208.5 317.42", load.New, *load.MeanMs, *load.P50Ms, *load.P99Ms)
	}
	ingress := got.APIs[attachIngressAPI]
	if ingress.P50Ms != nil || ingress.P99Ms == nil || *ingress.P99Ms != 1.52 {
		t.Errorf("ingress: want null p50 (NaN) and p99 1.52, got %+v", ingress)
	}
	egress := got.APIs[attachEgressAPI]
	if egress.New != 0 || egress.MeanMs != nil || egress.P50Ms != nil || egress.P99Ms != nil {
		t.Errorf("egress: want no calls and all null, got %+v", egress)
	}
}
