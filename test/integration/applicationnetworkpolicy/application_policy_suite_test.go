package applicationnetworkpolicy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	fw             *framework.Framework
	ctx            context.Context
	matchAllCIDR   string
	dnsCIDRAddress string
)

func TestApplicationNetworkPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ApplicationNetworkPolicy Test Suite")
}

var _ = BeforeSuite(func() {
	// Set up logger to suppress controller-runtime warnings
	ctrllog.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(false)))

	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()

	By("Setting up application network policy test values")
	matchAllCIDR = "0.0.0.0/0"
	if fw.Options.IpFamily == "IPv6" {
		matchAllCIDR = "::/0"
	}

	By("Discovering cluster DNS IP")
	dnsIP := discoverClusterDNSIP()
	if fw.Options.IpFamily == "IPv6" {
		dnsCIDRAddress = dnsIP + "/128"
	} else {
		dnsCIDRAddress = dnsIP + "/32"
	}

	GinkgoWriter.Printf("IP Family: %s, DNS CIDR: %s\n", fw.Options.IpFamily, dnsCIDRAddress)
})

var _ = AfterSuite(func() {})

func discoverClusterDNSIP() string {
	By("Creating temporary pod to discover DNS IP")

	container := manifest.NewAgnHostContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 60"}).
		Build()

	tempPod := &v1.Pod{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "dns-discovery-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			Containers:    []v1.Container{container},
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	createdPod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, tempPod, 30*time.Second)
	Expect(err).ToNot(HaveOccurred())

	By("Reading /etc/resolv.conf from the pod")
	command := []string{"cat", "/etc/resolv.conf"}
	resolvConf, err := fw.PodManager.ExecInPod("default", createdPod.Name, command)
	Expect(err).ToNot(HaveOccurred())

	GinkgoWriter.Printf("resolv.conf content:\n%s\n", resolvConf)

	By("Parsing nameserver from resolv.conf")
	lines := strings.Split(resolvConf, "\n")
	var dnsIP string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dnsIP = parts[1]
				break
			}
		}
	}

	By("Cleaning up DNS discovery pod")
	err = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, createdPod)
	if err != nil {
		GinkgoWriter.Printf("Warning: Failed to delete DNS discovery pod: %v\n", err)
	}

	Expect(dnsIP).ToNot(BeEmpty(), "Failed to find nameserver in /etc/resolv.conf")
	GinkgoWriter.Printf("Discovered DNS IP: %s\n", dnsIP)

	return dnsIP
}
