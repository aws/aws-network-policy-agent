package soak

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

	soakDuration time.Duration

	// Images default to public ECR; override for air-gapped or rate-limited runs.
	// nginxImage is the policy-target server; churnImage is reused for both the churn
	// pods and the probe client (bash /dev/tcp needs no extra runtime).
	nginxImage string
	churnImage string
)

func init() {
	flag.DurationVar(&soakDuration, "np-soak-duration", 20*time.Minute,
		"how long to churn pods while re-verifying network policy enforcement (min 3m)")
	flag.StringVar(&nginxImage, "np-soak-nginx-image", "public.ecr.aws/nginx/nginx:latest",
		"nginx image used for the policy-target server pod")
	flag.StringVar(&churnImage, "np-soak-churn-image", "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
		"image for the churn pods and the probe client (needs bash with /dev/tcp)")
}

func TestNetworkPolicySoak(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Network Policy Soak Suite")
}

// minSoakDuration is the floor below which the */1 churn CronJob may not record a
// successful run before the window closes, failing the churn guard rather than on
// a real defect.
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
