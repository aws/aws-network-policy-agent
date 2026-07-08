package soak

import (
	"context"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	"github.com/aws/aws-network-policy-agent/test/integration/soak/schedule"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	fw        *framework.Framework
	clientset *kubernetes.Clientset
	ctx       context.Context
	cfg       *Config

	namespace = "npa-soak"
)

func TestSoak(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NPA Soak Test Suite")
}

var _ = BeforeSuite(func() {
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()

	// A clientset built from the same kubeconfig, used only to reach the kubelet
	// /stats/summary endpoint via the API-server proxy for per-container memory.
	// The framework exposes a controller-runtime client but not a clientset, and
	// modifying the shared framework would touch every other suite, so the soak
	// owns this one.
	restCfg, err := clientcmd.BuildConfigFromFlags("", framework.GlobalOptions.KubeConfig)
	Expect(err).ToNot(HaveOccurred(), "build rest config for kubelet stats")
	clientset, err = kubernetes.NewForConfig(restCfg)
	Expect(err).ToNot(HaveOccurred(), "build clientset for kubelet stats")

	// Pass Ginkgo's effective suite timeout so Load can reject a --soak-duration
	// that would be truncated before the end-of-run gates run. Ginkgo's default is
	// 1h, so a 4h run needs --ginkgo.timeout raised or Load fails here, loudly,
	// instead of the run silently dying at 1h.
	suiteCfg, _ := GinkgoConfiguration()
	cfg, err = Load(suiteCfg.Timeout)
	// A bad configuration (e.g. a duration too short to exercise every activity,
	// a run that cannot span enough reconcile cycles for the #462 race, or one
	// that will not finish inside the harness timeout) must fail here, before any
	// cluster state is created, not hours into the run.
	Expect(err).ToNot(HaveOccurred(), "invalid soak configuration")

	GinkgoWriter.Printf("soak config: duration=%s nodes=%d reconcile=%s mem-limit=%dMiB\n",
		cfg.Duration, cfg.NodeCount, cfg.ReconcileInterval, cfg.MemoryGrowthLimit/mib)
	sched := cfg.Schedule()
	GinkgoWriter.Printf("cadences: kill=%s policy-update=%s ns-churn=%s probe=%s sample=%s (reconcile-cycles=%d)\n",
		sched.Interval(schedule.AgentKill), sched.Interval(schedule.PolicyHotUpdate),
		sched.Interval(schedule.NamespaceChurn), sched.Interval(schedule.ProbeSweep),
		sched.Interval(schedule.TrendSample), sched.ReconcileCycles())

	Expect(fw.NamespaceManager.CreateNamespace(ctx, namespace)).To(Succeed())

	// Fail fast if network policy enforcement is not working. This is the exact
	// trap a prior run hit: the controller was not emitting PolicyEndpoints, so
	// NPA had nothing to enforce, everything default-allowed, and the whole soak
	// reported a meaningless green.
	assertNetworkPolicyEnforced()
})

var _ = AfterSuite(func() {
	if fw != nil {
		Expect(fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)).To(Succeed())
	}
})
