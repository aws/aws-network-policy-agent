package npsoak

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw        *framework.Framework
	ctx       context.Context
	namespace = "np-soak"

	// soakDuration is how long to churn pods while re-verifying enforcement. Kept
	// short by default so a smoke run is quick; set to hours for a real soak.
	soakDuration time.Duration
)

func init() {
	flag.DurationVar(&soakDuration, "np-soak-duration", 20*time.Minute,
		"how long to churn pods while re-verifying network policy enforcement (min 3m)")
}

func TestNetworkPolicySoak(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Network Policy Soak Suite")
}

// minSoakDuration is the floor below which the churn CronJob (schedule */1, so up
// to ~60s to first fire, then 10 completions) may not record a successful run
// before the window closes. Below this the run would fail on the churn guard, not
// on a real defect, so we reject it up front with a clear message.
const minSoakDuration = 3 * time.Minute

var _ = BeforeSuite(func() {
	Expect(soakDuration).To(BeNumerically(">=", minSoakDuration),
		"--np-soak-duration must be >= %s so the churn CronJob can record a successful "+
			"run; shorter windows fail on the churn guard, not on a real defect", minSoakDuration)

	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()
	Expect(fw.NamespaceManager.CreateNamespace(ctx, namespace)).To(Succeed())
})

var _ = AfterSuite(func() {
	if fw != nil {
		Expect(fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)).To(Succeed())
	}
})
