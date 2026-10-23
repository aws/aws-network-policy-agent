package dnspolicy

import (
	"context"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw  *framework.Framework
	ctx context.Context
)

func TestDNSPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DNS Policy Test Suite")
}

var _ = BeforeSuite(func() {
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()
})
