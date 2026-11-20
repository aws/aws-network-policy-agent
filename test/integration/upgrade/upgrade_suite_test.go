package upgrade

import (
	"context"
	"flag"
	"strings"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw        *framework.Framework
	ctx       context.Context
	namespace = "upgrade-test"

	// Set by the flags below. Defined here rather than in framework.Options
	// because only this suite uses them.
	upgradeFromImages imageList
	upgradeToImage    string

	// The agent image on the cluster when the suite started. It is the image
	// under test unless -upgrade-to-image overrides it, and the suite puts it
	// back when it finishes.
	originalAgentImage string
	toImage            string
)

// imageList is a repeatable string flag.
type imageList []string

func (l *imageList) String() string { return strings.Join(*l, ",") }

func (l *imageList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func init() {
	flag.Var(&upgradeFromImages, "upgrade-from-image",
		"Agent image to upgrade from and roll back to. Repeat for more scenarios. "+
			"Defaults to recent releases: "+strings.Join(defaultFromImages(), ", "))
	flag.StringVar(&upgradeToImage, "upgrade-to-image", "",
		"Agent image to upgrade to. Defaults to the agent image already on the cluster, i.e. the image under test")
}

func TestAgentUpgrade(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Agent Upgrade Test Suite")
}

var _ = BeforeSuite(func() {
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()

	originalAgentImage = currentAgentImage()
	toImage = upgradeToImage
	if toImage == "" {
		toImage = originalAgentImage
	}
	GinkgoWriter.Printf("Agent image at suite start: %s\nUpgrade target: %s\n", originalAgentImage, toImage)

	err := fw.NamespaceManager.CreateNamespace(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	// Later suites run against whatever image this suite leaves behind, so put
	// the original one back even if a scenario failed partway.
	if originalAgentImage != "" && currentAgentImage() != originalAgentImage {
		By("Restoring the original agent image: " + originalAgentImage)
		setAgentImage(originalAgentImage)
		waitForDaemonSetRollout()
	}

	err := fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})
