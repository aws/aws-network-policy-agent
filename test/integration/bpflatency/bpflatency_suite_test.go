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

// Ceilings in ms. Baselines on t3.large (the nightly instance type), amd64,
// 3 runs of 10 pods each, per direction (Nov 2026, agent at #820):
//
//	kernel 6.1  IPv4: load mean ingress 127-128, egress 259-275; attach p99 <= 23.5
//	kernel 6.12 IPv4: load mean ingress 241-259, egress 305-335; attach p99 <= 4.9
//	kernel 6.1  IPv6: load mean ingress 770-790, egress 858-885; attach p99 <= 9.9
//	kernel 6.12 IPv6: load mean ingress 207-242, egress 315-360; attach p99 <= 23.5
//
// Kernel 6.1 on IPv6 is the outlier: its verifier takes 3-4x longer on the v6
// programs than any other combination. The default load ceilings (p50 2000,
// p99 3000) are sized for it, so a load there fails after getting about 2.3x
// slower. They are loose for the other combinations, so the nightly script
// sets tighter ones for those through the environment variables below. The
// attach ceilings (p50 10, p99 50) fit all four. The defaults are bucket
// bounds of the agent's histogram, which makes the quantile check exact;
// other values are checked against an interpolated estimate.
//
// Each setting can also be set from an environment variable (envOverrides),
// because the nightly script's run_ginkgo_suite passes no suite flags. A flag
// given on the command line wins over the variable.
var (
	podCount       = flag.Int("bpflatency-pods", 10, "pods with unique pod identifiers to create on one node (each needs an IP on it, so raise this only on nodes with IPs to spare)")
	maxLoadP50Ms   = flag.Float64("bpflatency-max-load-p50-ms", 2000, "ceiling for the p50 of each direction's program load, in ms")
	maxLoadP99Ms   = flag.Float64("bpflatency-max-load-p99-ms", 3000, "ceiling for the p99 of each direction's program load, in ms")
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
