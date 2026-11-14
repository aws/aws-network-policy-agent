package agentflags

import (
	"context"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The specs in this suite change the agent's flags on the aws-node DaemonSet.
// They live apart from the other suites so the scripts can run them after the
// suites that expect the stock agent, and put the DaemonSet's args back if a
// run dies before its own cleanup does (scripts/lib/tests.sh).
var (
	fw        *framework.Framework
	ctx       context.Context
	namespace = "agent-flags-test"
)

func TestAgentFlags(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Agent Flags Test Suite")
}

var _ = BeforeSuite(func() {
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()
	err := fw.NamespaceManager.CreateNamespace(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	err := fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})
