package bpflatency

import (
	"context"
	"flag"
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

// Thresholds in ms, from three runs of 10 pods per setup, the first right after
// the agent restarted (the agent's quantiles cover its last 10 minutes, so the
// later two also include the earlier run's calls):
//
//	m5.large  amd64 kernel 6.12 IPv4: load p50 209-245 p99 317, attach p99 <= 1.5
//	m5.large  amd64 kernel 6.1  IPv6: load p50 438-472 p99 537-721, attach p99 <= 11.9
//	m6g.large arm64 kernel 6.1  IPv6: load p50 414-440 p99 514, attach p99 <= 1.4
//
// Loads take about twice as long on 6.1 as on 6.12 on both architectures (more
// verifier work), so the load defaults are about 2x the 6.1 numbers: a load
// path that gets twice as slow fails on 6.1, and four times as slow on 6.12.
// A kernel line that needs a tighter or looser ceiling can pass the flags.
var (
	podCount       = flag.Int("bpflatency-pods", 10, "pods with unique pod identifiers to create on one node (each needs an IP on it, so raise this only on nodes with IPs to spare)")
	maxLoadP50Ms   = flag.Float64("bpflatency-max-load-p50-ms", 1000, "ceiling for the p50 and the mean of LoadBpfFile, in ms")
	maxLoadP99Ms   = flag.Float64("bpflatency-max-load-p99-ms", 2000, "ceiling for the p99 of LoadBpfFile, in ms")
	maxAttachP50Ms = flag.Float64("bpflatency-max-attach-p50-ms", 10, "ceiling for the p50 and the mean of each probe attach, in ms")
	maxAttachP99Ms = flag.Float64("bpflatency-max-attach-p99-ms", 50, "ceiling for the p99 of each probe attach, in ms")
)

func TestBPFLoadLatency(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "eBPF Program Load Latency Test Suite")
}

var _ = BeforeSuite(func() {
	Expect(*podCount).To(BeNumerically(">", 0), "-bpflatency-pods")
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()
	err := fw.NamespaceManager.CreateNamespace(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	err := fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})
