package bpflatency

// A plain Go test for the result line. It needs no cluster: run it with
// `go test ./test/integration/bpflatency -run 'TestResultLine|TestMetricsURL|TestApplyEnvOverrides'`.

import (
	"encoding/json"
	"flag"
	"strings"
	"testing"

	fwutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
)

func TestResultLine(t *testing.T) {
	bounds := []float64{1, 10, 250, 500, 1000}
	hist := func(sum float64, cum ...uint64) fwutils.ProbeHistogram {
		h := fwutils.ProbeHistogram{SumMs: sum, Count: cum[len(cum)-1]}
		for i, c := range cum {
			h.Buckets = append(h.Buckets, fwutils.Bucket{UpperMs: bounds[i], Count: c})
		}
		return h
	}
	loadIngress := fwutils.ProbeKey{Op: opLoad, Direction: "ingress"}
	attachIngress := fwutils.ProbeKey{Op: opAttach, Direction: "ingress"}
	before := map[fwutils.ProbeKey]fwutils.ProbeHistogram{
		loadIngress: hist(2000, 0, 0, 10, 10, 10),
	}
	after := map[fwutils.ProbeKey]fwutils.ProbeHistogram{
		// 20 new loads: 10 in (250, 500] and 10 in (500, 1000].
		loadIngress: hist(13000, 0, 0, 10, 20, 30),
		// 10 attaches, the first scrape had none.
		attachIngress: hist(13.5, 9, 10, 10, 10, 10),
		// No egress series: no egress calls.
	}
	info := runInfo{Kernel: "6.12.100", OS: "AL2023", Arch: "amd64", InstanceType: "t3.large",
		AgentImage: "example/agent:v1", IPFamily: "IPv4", Pods: 10}
	line, _, err := resultLine(info, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, resultLinePrefix) || strings.Contains(line, "\n") {
		t.Fatalf("want one line starting with %q, got %q", resultLinePrefix, line)
	}

	var got struct {
		runInfo
		Results map[string]opResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, resultLinePrefix)), &got); err != nil {
		t.Fatalf("not JSON: %v: %s", err, line)
	}
	if got.runInfo != info {
		t.Errorf("run info = %+v, want %+v", got.runInfo, info)
	}

	checkMs := func(name, field string, v *float64, want float64) {
		t.Helper()
		if v == nil {
			t.Errorf("%s %s = null, want %v", name, field, want)
		} else if *v != want {
			t.Errorf("%s %s = %v, want %v", name, field, *v, want)
		}
	}
	load, ok := got.Results["load/ingress"]
	if !ok {
		t.Fatalf("no load/ingress in %v", got.Results)
	}
	if load.New != 20 {
		t.Errorf("load/ingress new = %d, want 20", load.New)
	}
	checkMs("load/ingress", "mean", load.MeanMs, 550)
	checkMs("load/ingress", "p50", load.P50Ms, 500)
	checkMs("load/ingress", "p99", load.P99Ms, 990)

	attach, ok := got.Results["attach/ingress"]
	if !ok {
		t.Fatalf("no attach/ingress in %v", got.Results)
	}
	checkMs("attach/ingress", "p50", attach.P50Ms, 0.56)

	egress, ok := got.Results["load/egress"]
	if !ok {
		t.Fatalf("no load/egress in %v", got.Results)
	}
	if egress.New != 0 || egress.MeanMs != nil || egress.P50Ms != nil || egress.P99Ms != nil {
		t.Errorf("load/egress: want no calls and all null, got %+v", egress)
	}
}

func TestMetricsURL(t *testing.T) {
	for _, tc := range []struct {
		host string
		want string
	}{
		{"", "http://127.0.0.1:8162/metrics"},
		{"0.0.0.0", "http://127.0.0.1:8162/metrics"},
		{"::", "http://127.0.0.1:8162/metrics"},
		{"::1", "http://[::1]:8162/metrics"},
		{"10.0.0.5", "http://10.0.0.5:8162/metrics"},
	} {
		if got := metricsURL(tc.host, 8162); got != tc.want {
			t.Errorf("metricsURL(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	// Put back the values from before the test, not the defaults: the
	// suite's own flags may have been given on the command line.
	saved := map[string]string{}
	for _, o := range envOverrides {
		saved[o.flag] = flag.Lookup(o.flag).Value.String()
	}
	restore := func() {
		for _, o := range envOverrides {
			if err := flag.Lookup(o.flag).Value.Set(saved[o.flag]); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(restore)

	t.Setenv("BPFLATENCY_MAX_LOAD_P99_MS", "3000")
	t.Setenv("BPFLATENCY_PODS", "5")
	if err := applyEnvOverrides(); err != nil {
		t.Fatal(err)
	}
	if *maxLoadP99Ms != 3000 || *podCount != 5 {
		t.Errorf("got load p99 %v pods %d, want 3000 and 5", *maxLoadP99Ms, *podCount)
	}
	if got := flag.Lookup("bpflatency-max-load-p50-ms").Value.String(); got != saved["bpflatency-max-load-p50-ms"] {
		t.Errorf("load p50 = %s with no env var, want it unchanged at %s", got, saved["bpflatency-max-load-p50-ms"])
	}

	for name, value := range map[string]string{
		"BPFLATENCY_MAX_ATTACH_P50_MS": "fast",
		"BPFLATENCY_MAX_ATTACH_P99_MS": "0",
		"BPFLATENCY_PODS":              "-1",
	} {
		t.Run(name, func(t *testing.T) {
			restore()
			t.Setenv(name, value)
			if err := applyEnvOverrides(); err == nil {
				t.Errorf("%s=%s: want an error", name, value)
			}
		})
	}
}
