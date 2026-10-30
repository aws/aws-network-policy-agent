package applicationnetworkpolicy

import (
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// How DNS queries are intercepted and how their answers are turned into allowed IPs.
var _ = Describe("DNS proxy behavior for domain rules", Ordered, func() {
	const testNamespace = "dns-proxy-test-ns"
	var policies []*unstructured.Unstructured
	var deployments []*appsv1.Deployment

	podsOf := func(app string) []v1.Pod {
		pods, err := fw.PodManager.GetPodsWithLabel(ctx, testNamespace, "app", app)
		Expect(err).ToNot(HaveOccurred())
		Expect(pods).ToNot(BeEmpty())
		return pods
	}

	exec := func(pod v1.Pod, script string) (string, error) {
		return fw.PodManager.ExecInPod(testNamespace, pod.Name, []string{"/bin/sh", "-c", script})
	}

	deploy := func(app string, script string) {
		container := manifest.NewAgnHostContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{script + "; while true; do sleep 30; done"}).
			Build()
		deployment, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, manifest.NewDefaultDeploymentBuilder().
			Namespace(testNamespace).
			Name(app).
			Replicas(1).
			AddLabel("app", app).
			Container(container).
			Build())
		Expect(err).ToNot(HaveOccurred())
		deployments = append(deployments, deployment)
	}

	clusterDNSRule := manifest.NewApplicationEgressRuleBuilder().AddPort(53, "UDP").AddPort(53, "TCP").
		BuildEgressRule([]map[string]interface{}{manifest.NewApplicationPodsPeer(
			map[string]string{"kubernetes.io/metadata.name": "kube-system"},
			map[string]string{"k8s-app": "kube-dns"},
		)})

	domainRule := func(port int32, domains ...string) map[string]interface{} {
		return manifest.NewApplicationEgressRuleBuilder().AddPort(port, "TCP").
			BuildEgressRule([]map[string]interface{}{manifest.NewApplicationDomainNamesPeer(domains)})
	}

	allow := func(app string, rules ...map[string]interface{}) {
		builder := manifest.NewApplicationNetworkPolicyBuilder().
			Name("allow-"+app).
			Namespace(testNamespace).
			PodSelector("app", app).
			SetPolicyTypes([]string{"Egress"})
		for _, rule := range rules {
			builder.AddEgressRule(rule)
		}
		policy := builder.Build()
		Expect(fw.ApplicationNetworkPolicyManager.CreateApplicationNetworkPolicy(ctx, policy)).To(Succeed())
		policies = append(policies, policy)
		time.Sleep(10 * time.Second)
	}

	BeforeAll(func() {
		Expect(fw.K8sClient.Create(ctx, &v1.Namespace{ObjectMeta: metaV1.ObjectMeta{Name: testNamespace}})).To(Succeed())
	})

	AfterAll(func() {
		for _, policy := range policies {
			fw.ApplicationNetworkPolicyManager.DeleteApplicationNetworkPolicy(ctx, policy)
		}
		for _, deployment := range deployments {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, deployment)
		}
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, testNamespace)
	})

	It("keeps the ports of every allowed domain that resolves to the same IP", func() {
		// Both names resolve to 1.1.1.1; the second answer must not replace the port of the first.
		deploy("shared-ip", "true")
		allow("shared-ip", clusterDNSRule, domainRule(80, "1-1-1-1.sslip.io"), domainRule(443, "one.one.one.one"))
		pod := podsOf("shared-ip")[0]

		_, err := exec(pod, "nslookup 1-1-1-1.sslip.io && nslookup one.one.one.one")
		Expect(err).ToNot(HaveOccurred())

		_, err = fw.PodManager.ValidateConnection(testNamespace, pod.Name, "https://one.one.one.one", fw.Options.IpFamily)
		Expect(err).ToNot(HaveOccurred())
		_, err = fw.PodManager.ValidateConnection(testNamespace, pod.Name, "http://1-1-1-1.sslip.io", fw.Options.IpFamily)
		Expect(err).ToNot(HaveOccurred())
	})

	It("matches domain names case-insensitively", func() {
		deploy("upper-case", "true")
		allow("upper-case", clusterDNSRule, domainRule(443, "example.com"))
		pod := podsOf("upper-case")[0]

		// The connection uses the IP from the upper case query only, so it is allowed only if that answer was learned.
		out, err := exec(pod, `ip=$(nslookup EXAMPLE.COM | awk '/^Address: / && !/#/ {print $2; exit}') && `+
			`curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve example.com:443:$ip https://example.com`)
		Expect(err).ToNot(HaveOccurred())
		Expect(out).To(Equal("200"))
	})

	It("enforces the domain rules of a new replica from its first request", func() {
		const app = "first-request"
		deploy(app, "curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://example.com > /tmp/first")
		allow(app, clusterDNSRule, domainRule(443, "example.com"))
		existing := podsOf(app)[0].Name

		// New replicas share the policy of the running one; their first request runs as soon as the container starts.
		Expect(fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, testNamespace, app, 4)).To(Succeed())
		// The scale call does not wait for the new pods.
		Eventually(func(g Gomega) {
			pods := podsOf(app)
			g.Expect(pods).To(HaveLen(4))
			for _, pod := range pods {
				g.Expect(pod.Status.Phase).To(Equal(v1.PodRunning))
			}
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
		for _, pod := range podsOf(app) {
			if pod.Name == existing {
				continue
			}
			Eventually(func() string {
				out, _ := exec(pod, "cat /tmp/first")
				return out
			}, time.Minute, 2*time.Second).Should(Equal("200"), "first request of %s", pod.Name)
		}
	})

	It("does not redirect queries the pod sends to another DNS server", func() {
		anyDNS := manifest.NewApplicationEgressRuleBuilder().AddPort(53, "UDP").AddPort(53, "TCP").
			BuildEgressRule([]map[string]interface{}{manifest.NewApplicationIPBlockPeer("0.0.0.0/0", nil)})
		deploy("other-dns", "true")
		allow("other-dns", anyDNS, domainRule(443, "example.com"))
		pod := podsOf("other-dns")[0]

		_, err := exec(pod, "nslookup kubernetes.default.svc.cluster.local")
		Expect(err).ToNot(HaveOccurred(), "the cluster DNS answers cluster names")
		out, err := exec(pod, "nslookup kubernetes.default.svc.cluster.local 8.8.8.8")
		Expect(err).To(HaveOccurred(), "a public DNS server must not answer cluster names: %s", out)
	})
})
