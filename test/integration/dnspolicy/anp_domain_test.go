package dnspolicy

import (
	"strings"
	"time"

	policyv1alpha1 "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/nodeinspect"
	testutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	namespace = "dns-policy-e2e"
	// Pods with this label are selected by the domain policy.
	selectedLabel = "dns-policy"

	exactDomain    = "aws.amazon.com"
	wildcardDomain = "*.s3.us-west-2.amazonaws.com"
	oneLevelName   = "npa-dns-e2e.s3.us-west-2.amazonaws.com"
	twoLevelName   = "npa.dns-e2e.s3.us-west-2.amazonaws.com"
	wildcardApex   = "s3.us-west-2.amazonaws.com"
	otherDomain    = "github.com"
	unresolvedIP   = "1.1.1.1"
)

// ApplicationNetworkPolicy domain rules on one node: what pods can reach (A), how the node is programmed
// to get there (B), how pod and policy changes are applied (C), and the behavior around it (D).
var _ = Describe("ApplicationNetworkPolicy domain rules", Ordered, Label("dnspolicy"), func() {
	var (
		nodeName  string
		inspector *nodeinspect.Inspector
		policy    *policyv1alpha1.ApplicationNetworkPolicy
		// client is selected; apexClient is selected and never resolves a wildcard subdomain, so its
		// ipcache holds no address the wildcard apex could share; unselected is not selected.
		client, apexClient, unselected v1.Pod
	)

	BeforeAll(func() {
		Expect(fw.NamespaceManager.CreateNamespace(ctx, namespace)).To(Succeed())
		nodes := &v1.NodeList{}
		Expect(fw.K8sClient.List(ctx, nodes)).To(Succeed())
		Expect(nodes.Items).NotTo(BeEmpty())
		nodeName = nodes.Items[0].Name

		var err error
		inspector, err = nodeinspect.Start(ctx, fw.PodManager, namespace, nodeName)
		Expect(err).NotTo(HaveOccurred())

		client = deployClient("client", nodeName, true)
		apexClient = deployClient("apex-client", nodeName, true)
		unselected = deployClient("unselected", nodeName, false)

		policy = domainPolicy("allow-domains", true, exactDomain, wildcardDomain)
		Expect(fw.K8sClient.Create(ctx, policy)).To(Succeed())
		expectClosed(client, otherDomain, 443)
	})

	AfterAll(func() {
		if inspector != nil {
			_ = inspector.Stop(ctx)
		}
		Expect(fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)).To(Succeed())
	})

	Context("A: connectivity of a selected pod", func() {
		It("A01 allows the exact domain on the allowed port", func() { expectOpen(client, exactDomain, 443) })
		It("A02 allows a subdomain one level under the wildcard", func() { expectOpen(client, oneLevelName, 443) })
		It("A03 allows a subdomain two levels under the wildcard", func() { expectOpen(client, twoLevelName, 443) })
		It("A04 denies the wildcard apex", func() { expectClosed(apexClient, wildcardApex, 443) })
		It("A05 denies an allowed domain on another port", func() { expectClosed(client, exactDomain, 80) })
		It("A06 resolves but denies a domain that is not allowed", func() {
			Expect(lookup(client, otherDomain)).NotTo(BeEmpty())
			expectClosed(client, otherDomain, 443)
		})
		It("A07 denies an address the pod did not resolve", func() { expectClosed(client, unresolvedIP, 443) })
		It("A08 leaves an unselected pod unrestricted", func() { expectOpen(unselected, otherDomain, 443) })
	})

	Context("B: node programming", func() {
		It("B01 redirects DNS only for selected pods", func() {
			Eventually(inspector.DNSRedirectInterfaces, testutils.EnforcementTimeout, testutils.PollIntervalShort).
				Should(ContainElements(hostVeth(inspector, client), hostVeth(inspector, apexClient)))
			Expect(inspector.DNSRedirectInterfaces()).NotTo(ContainElement(hostVeth(inspector, unselected)))
		})
		It("B02 translates DNS queries of a selected pod to the proxy", func() {
			Expect(lookup(client, exactDomain)).NotTo(BeEmpty())
			Expect(inspector.DNSQueryRedirected(client.Status.PodIP)).To(BeTrue())
			Expect(lookup(unselected, exactDomain)).NotTo(BeEmpty())
			Expect(inspector.DNSQueryRedirected(unselected.Status.PodIP)).To(BeFalse())
		})
		It("B05 writes resolved addresses with an expiry to the pod identifier's ipcache", func() {
			resolved := lookup(client, exactDomain)
			Expect(resolved).NotTo(BeEmpty())
			entries, err := inspector.IPCache(identifier(client))
			Expect(err).NotTo(HaveOccurred())
			Expect(keys(entries)).To(ContainElement(BeElementOf(resolved)))
			now, err := inspector.BootTimeNs()
			Expect(err).NotTo(HaveOccurred())
			for ip, e := range entries {
				Expect(e.ExpiryNs).To(BeNumerically("<=", now+uint64(301*time.Second)), ip)
			}
		})
		It("B07 writes nothing for an unselected pod", func() {
			Expect(lookup(unselected, exactDomain)).NotTo(BeEmpty())
			Expect(inspector.IPCache(identifier(unselected))).To(BeEmpty())
		})
	})

	Context("C: pod and policy lifecycle", func() {
		var scaled v1.Pod

		It("C01 enforces a new replica from its first request", func() {
			Expect(fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, client.Labels["app"], 2)).To(Succeed())
			scaled = otherReplica(client)
			// The first request: the replica's DNS must already reach the proxy for the allowed domain to open.
			Expect(fw.PodManager.TCPProbe(namespace, scaled.Name, exactDomain, 443)).To(Equal("OPEN"))
			Expect(inspector.DNSRedirectInterfaces()).To(ContainElement(hostVeth(inspector, scaled)))
			// Without this, an unenforced replica would pass the check above too.
			expectClosed(scaled, otherDomain, 443)
		})
		It("C04 removes the DNS redirection of a deleted pod", func() {
			veths := map[string]string{client.Name: hostVeth(inspector, client), scaled.Name: hostVeth(inspector, scaled)}
			Expect(fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, client.Labels["app"], 1)).To(Succeed())
			// The scale-down may keep either replica; later cases use the one that is left.
			Eventually(func() ([]v1.Pod, error) {
				return fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", client.Labels["app"])
			},
				testutils.EnforcementTimeout, testutils.PollIntervalShort).Should(HaveLen(1))
			kept := onlyPod(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: client.Labels["app"]}})
			delete(veths, kept.Name)
			client = kept
			for _, veth := range veths {
				Eventually(inspector.DNSRedirectInterfaces, testutils.EnforcementTimeout, testutils.PollIntervalShort).
					ShouldNot(ContainElement(veth))
			}
		})
		It("C03 lifts the restriction and the redirection when the policy is deleted", func() {
			Expect(fw.PodManager.TCPProbe(namespace, client.Name, otherDomain, 443)).To(Equal("CLOSE"))
			Expect(fw.K8sClient.Delete(ctx, policy)).To(Succeed())
			expectOpen(client, otherDomain, 443)
			Eventually(inspector.DNSRedirectInterfaces, testutils.EnforcementTimeout, testutils.PollIntervalShort).
				ShouldNot(ContainElement(hostVeth(inspector, client)))
		})
	})

	Context("D: behavior around domain rules", func() {
		It("D01 a policy without a DNS rule blocks DNS, so no domain is reachable", func() {
			pod := deployClient("no-dns", nodeName, false)
			p := domainPolicy("domains-without-dns", false, exactDomain)
			p.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "no-dns"}}
			Expect(fw.K8sClient.Create(ctx, p)).To(Succeed())
			DeferCleanup(func() { Expect(fw.K8sClient.Delete(ctx, p)).To(Succeed()) })
			expectClosed(pod, exactDomain, 443)
		})
		It("D02 still enforces a NetworkPolicy without domain rules", func() {
			pod := deployClient("np-only", nodeName, false)
			np := &networking.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-egress", Namespace: namespace},
				Spec: networking.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "np-only"}},
					PolicyTypes: []networking.PolicyType{networking.PolicyTypeEgress},
				},
			}
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, np)).To(Succeed())
			DeferCleanup(func() { Expect(fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)).To(Succeed()) })
			expectClosed(pod, otherDomain, 443)
		})
	})
})

// deployClient runs a one-replica busybox deployment on nodeName and returns its pod.
func deployClient(name, nodeName string, selected bool) v1.Pod {
	container := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()
	builder := manifest.NewDefaultDeploymentBuilder().
		Name(name).Namespace(namespace).Replicas(1).Container(container).
		AddLabel("app", name).
		NodeSelector(map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/hostname": nodeName})
	if selected {
		builder = builder.AddLabel(selectedLabel, "enabled")
	}
	dp, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, builder.Build())
	Expect(err).NotTo(HaveOccurred())
	return onlyPod(dp)
}

func onlyPod(dp *appsv1.Deployment) v1.Pod {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", dp.Name)
	Expect(err).NotTo(HaveOccurred())
	Expect(pods).To(HaveLen(1))
	return pods[0]
}

// otherReplica returns a running pod of the same deployment as pod, other than pod.
func otherReplica(pod v1.Pod) v1.Pod {
	var other v1.Pod
	Eventually(func() bool {
		pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", pod.Labels["app"])
		if err != nil {
			return false
		}
		for _, p := range pods {
			if p.Name != pod.Name && p.Status.Phase == v1.PodRunning && p.Status.PodIP != "" {
				other = p
				return true
			}
		}
		return false
	}, testutils.EnforcementTimeout, testutils.PollIntervalShort).Should(BeTrue())
	return other
}

// domainPolicy selects pods with selectedLabel and allows TCP 443 to domains, plus DNS to kube-dns
// when allowDNS is set.
func domainPolicy(name string, allowDNS bool, domains ...string) *policyv1alpha1.ApplicationNetworkPolicy {
	tcp, udp := v1.ProtocolTCP, v1.ProtocolUDP
	https, dns := intstr.FromInt32(443), intstr.FromInt32(53)
	names := make([]policyv1alpha1.DomainName, len(domains))
	for k, d := range domains {
		names[k] = policyv1alpha1.DomainName(d)
	}
	egress := []policyv1alpha1.ApplicationNetworkPolicyEgressRule{{
		To:    []policyv1alpha1.ApplicationNetworkPolicyPeer{{DomainNames: names}},
		Ports: []networking.NetworkPolicyPort{{Protocol: &tcp, Port: &https}},
	}}
	if allowDNS {
		egress = append(egress, policyv1alpha1.ApplicationNetworkPolicyEgressRule{
			To: []policyv1alpha1.ApplicationNetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			}},
			Ports: []networking.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}},
		})
	}
	return &policyv1alpha1.ApplicationNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyv1alpha1.ApplicationNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{selectedLabel: "enabled"}},
			PolicyTypes: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress:      egress,
		},
	}
}

func expectOpen(pod v1.Pod, host string, port int) {
	Eventually(func() (string, error) { return fw.PodManager.TCPProbe(namespace, pod.Name, host, port) },
		testutils.EnforcementTimeout, testutils.ProbeInterval).Should(Equal("OPEN"), "%s -> %s:%d", pod.Name, host, port)
}

// expectClosed waits for the connection to be denied and checks that it stays denied.
func expectClosed(pod v1.Pod, host string, port int) {
	probe := func() (string, error) { return fw.PodManager.TCPProbe(namespace, pod.Name, host, port) }
	Eventually(probe, testutils.EnforcementTimeout, testutils.ProbeInterval).Should(Equal("CLOSE"), "%s -> %s:%d", pod.Name, host, port)
	Consistently(probe, testutils.StabilityWindow, testutils.ProbeInterval).Should(Equal("CLOSE"), "%s -> %s:%d", pod.Name, host, port)
}

// lookup returns the IPv4 addresses busybox nslookup prints for name from pod.
func lookup(pod v1.Pod, name string) []string {
	out, err := fw.PodManager.ExecInPod(namespace, pod.Name, []string{"nslookup", "-type=a", name})
	if err != nil {
		return nil
	}
	var ips []string
	// The answer section follows the server's own "Address:" line.
	answers := out
	if idx := strings.Index(out, "Name:"); idx >= 0 {
		answers = out[idx:]
	}
	for _, line := range strings.Split(answers, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "Address:" {
			ips = append(ips, f[1])
		}
	}
	return ips
}

func hostVeth(inspector *nodeinspect.Inspector, pod v1.Pod) string {
	veth, err := inspector.HostVeth(pod.Status.PodIP)
	Expect(err).NotTo(HaveOccurred())
	return veth
}

func identifier(pod v1.Pod) string { return utils.GetPodIdentifier(pod.Name, pod.Namespace) }

func keys(m map[string]nodeinspect.IPCacheEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
