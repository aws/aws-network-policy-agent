package bpflatency

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw        *framework.Framework
	ctx       context.Context
	namespace = "bpflatency-test"
)

// Ceilings in ms, from three runs of 10 pods per setup (before the agent
// exported per-direction numbers, so load covers ingress and egress together):
//
//	m5.large  amd64 kernel 6.12 IPv4: load p50 209-245 p99 317, attach p99 <= 1.5
//	m5.large  amd64 kernel 6.1  IPv6: load p50 438-472 p99 537-721, attach p99 <= 11.9
//	m6g.large arm64 kernel 6.1  IPv6: load p50 414-440 p99 514, attach p99 <= 1.4
//
// Loads take about twice as long on 6.1 as on 6.12 on amd64 (more verifier
// work; 6.12 was not measured on arm64). The load p50 ceiling is about 2x the
// 6.1 p50, and the p99 ceiling about 3-4x the 6.1 p99, so a load that gets
// twice as slow fails the p50 on 6.1, and four times as slow on 6.12. A
// kernel line that needs a tighter or looser ceiling can pass the flags. The
// default ceilings are bucket bounds of the agent's histogram, which makes the
// quantile check exact; other values are checked against an interpolated
// estimate.
//
// Each setting can also be set from an environment variable (envOverrides),
// because the nightly script's run_ginkgo_suite passes no suite flags. A flag
// given on the command line wins over the variable.
var (
	podCount       = flag.Int("bpflatency-pods", 10, "pods with unique pod identifiers to create on one node (each needs an IP on it, so raise this only on nodes with IPs to spare)")
	maxLoadP50Ms   = flag.Float64("bpflatency-max-load-p50-ms", 1000, "ceiling for the p50 of each direction's program load, in ms")
	maxLoadP99Ms   = flag.Float64("bpflatency-max-load-p99-ms", 2000, "ceiling for the p99 of each direction's program load, in ms")
	maxAttachP50Ms = flag.Float64("bpflatency-max-attach-p50-ms", 10, "ceiling for the p50 of each direction's probe attach, in ms")
	maxAttachP99Ms = flag.Float64("bpflatency-max-attach-p99-ms", 50, "ceiling for the p99 of each direction's probe attach, in ms")
)

// envOverrides maps each flag to the environment variable that can set it.
var envOverrides = []struct{ flag, env string }{
	{"bpflatency-pods", "BPFLATENCY_PODS"},
	{"bpflatency-max-load-p50-ms", "BPFLATENCY_MAX_LOAD_P50_MS"},
	{"bpflatency-max-load-p99-ms", "BPFLATENCY_MAX_LOAD_P99_MS"},
	{"bpflatency-max-attach-p50-ms", "BPFLATENCY_MAX_ATTACH_P50_MS"},
	{"bpflatency-max-attach-p99-ms", "BPFLATENCY_MAX_ATTACH_P99_MS"},
}

// applyEnvOverrides sets each flag not given on the command line from its
// environment variable, when that is set, and checks every setting is
// positive.
func applyEnvOverrides() error {
	given := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, o := range envOverrides {
		v := os.Getenv(o.env)
		if v == "" || given[o.flag] {
			continue
		}
		// Value.Set, not flag.Set, so the flag still counts as not given.
		if err := flag.Lookup(o.flag).Value.Set(v); err != nil {
			return fmt.Errorf("%s=%q: %w", o.env, v, err)
		}
	}
	if *podCount <= 0 {
		return fmt.Errorf("-bpflatency-pods (BPFLATENCY_PODS) must be positive, got %d", *podCount)
	}
	for _, o := range envOverrides[1:] {
		if v, _ := strconv.ParseFloat(flag.Lookup(o.flag).Value.String(), 64); v <= 0 {
			return fmt.Errorf("-%s (%s) must be positive, got %v", o.flag, o.env, v)
		}
	}
	return nil
}

func TestBPFLoadLatency(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "eBPF Program Load Latency Test Suite")
}

var _ = BeforeSuite(func() {
	Expect(applyEnvOverrides()).To(Succeed())
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()
	err := fw.NamespaceManager.CreateNamespace(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	// BeforeSuite can fail before it sets fw.
	if fw == nil {
		return
	}
	err := fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})
