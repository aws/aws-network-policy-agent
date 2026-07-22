//go:build soak
// +build soak

// Package soak holds long-running soak tests that are intentionally excluded
// from the regular integration-test cadence (nightly / canary / PR pipelines).
// They are guarded by the `soak` build tag so no build compiles them unless it
// explicitly opts in with `-tags soak`, and the test/integration/soak path is
// pruned from the aggregate `make build-test-binaries` glob. Run them on demand:
//
//	ginkgo build --tags soak ./test/integration/soak/conntrack-race/
//	ginkgo --tags soak ./test/integration/soak/conntrack-race/ -- \
//	  --cluster-kubeconfig=$KUBECONFIG --cluster-name=$CLUSTER --aws-region=$REGION
package soak

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
	namespace = "conntrack-race-soak"
)

func TestConntrackRaceSoak(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Conntrack GC Race Soak Suite")
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
