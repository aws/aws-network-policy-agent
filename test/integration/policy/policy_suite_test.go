package policy

import (
	"context"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw        *framework.Framework
	ctx       context.Context
	namespace = "policy"
)

func TestStrictModeNetworkPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Network Policy Test Suite")
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
