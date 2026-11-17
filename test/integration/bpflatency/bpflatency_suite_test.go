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

// Thresholds in ms. The defaults are about 2-3x (loads) and 8x or more
// (attaches) a baseline on an m5.large node, kernel 6.12, with a freshly
// restarted agent: LoadBpfFile p50 209 / p99 317, ingress attach p50 1.3 / p99
// 1.5, egress attach p50 0.3 / p99 0.4. Other kernels were not measured; verifier
// work varies with the kernel, so tighten or loosen per kernel line once the
// nightly runs show where each sits.
var (
	podCount       = flag.Int("bpflatency-pods", 10, "pods with unique pod identifiers to create on one node (each needs an IP on it, so raise this only on nodes with IPs to spare)")
	maxLoadP50Ms   = flag.Float64("bpflatency-max-load-p50-ms", 500, "ceiling for the p50 and the mean of LoadBpfFile, in ms")
	maxLoadP99Ms   = flag.Float64("bpflatency-max-load-p99-ms", 1000, "ceiling for the p99 of LoadBpfFile, in ms")
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
