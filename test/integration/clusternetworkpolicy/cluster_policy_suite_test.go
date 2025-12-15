package clusternetworkpolicy

import (
	"context"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw             *framework.Framework
	ctx            context.Context
	matchAllCIDR   string
	dnsCIDRAddress string
)

func TestClusterNetworkPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ClusterNetworkPolicy Test Suite")
}

var _ = BeforeSuite(func() {
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()

	By("Setting up cluster network policy test values")
	matchAllCIDR = "0.0.0.0/0"
	dnsCIDRAddress = "10.100.0.10/32"
	if fw.Options.IpFamily == "IPv6" {
		dnsCIDRAddress = "fdaf:02eb:b51c::a/128"
		matchAllCIDR = "::/0"
	}

	GinkgoWriter.Printf("IP Family: %s, DNS CIDR: %s\n", fw.Options.IpFamily, dnsCIDRAddress)
})

var _ = AfterSuite(func() {})
