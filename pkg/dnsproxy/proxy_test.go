package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const podIP = "10.240.0.1" // the client IP of test.ResponseWriter

type fakeEBPF struct {
	ebpf.BpfClient
	withoutContext map[string]bool
	podIdentifier  string
	answers        []npatypes.IPWithTTL
	rules          []byte
	prunes         []func() []byte
}

// UpdateIPCache records a write like bpfClient does: with the rules matched when it writes.
func (f *fakeEBPF) UpdateIPCache(podIdentifier string, answers []npatypes.IPWithTTL, rules func() []byte) error {
	if encoded := rules(); len(encoded) > 0 {
		f.podIdentifier, f.answers, f.rules = podIdentifier, answers, encoded
	}
	return nil
}

func (f *fakeEBPF) PruneIPCache(podIdentifier string, staleRules func() []byte) error {
	f.prunes = append(f.prunes, staleRules)
	return nil
}

func (f *fakeEBPF) HasBPFContext(podIdentifier string) bool {
	return !f.withoutContext[podIdentifier]
}

func domain(name string, priority int, ports ...int32) fwrp.EbpfFirewallRules {
	rule := fwrp.EbpfFirewallRules{DomainName: name, Priority: priority, Action: v1alpha1.ClusterNetworkPolicyRuleActionAccept}
	tcp := corev1.ProtocolTCP
	for _, port := range ports {
		rule.L4Info = append(rule.L4Info, v1alpha1.Port{Protocol: &tcp, Port: &port})
	}
	return rule
}

// ports decodes the start port of each rule in encoded.
func ports(encoded []byte) []uint32 {
	var out []uint32
	for i := 0; i+entrySize <= len(encoded); i += entrySize {
		if protocol := binary.LittleEndian.Uint32(encoded[i:]); protocol != 0 {
			out = append(out, binary.LittleEndian.Uint32(encoded[i+8:]))
		}
	}
	return out
}

// newTestProxy returns a proxy that is not running, with the pod of IP podIP in pod identifier app@ns.
func newTestProxy(f *fakeEBPF) *Proxy {
	p := New(context.Background(), nil, f)
	p.podByIP[podIP] = &pod{podIdentifier: "app@ns"}
	p.startOnce.Do(func() {}) // the tests do not start CoreDNS
	close(p.firstStart)
	return p
}

func TestDomainRuleMatches(t *testing.T) {
	for _, tc := range []struct {
		rule, qname string
		want        bool
	}{
		{"example.com", "example.com.", true},
		{"Example.COM.", "example.com.", true},
		{"example.com", "www.example.com.", false},
		{"*.example.com", "www.example.com.", true},
		{"*.example.com", "a.b.example.com.", true},
		{"*.example.com", "example.com.", false},
		{"*.example.com", "badexample.com.", false},
	} {
		rule := newDomainRules([]fwrp.EbpfFirewallRules{domain(tc.rule, utils.PE_PRIORITY)})[0]
		assert.Equal(t, tc.want, rule.matches(tc.qname), "%s matches %s", tc.rule, tc.qname)
	}
}

func TestNewDomainRules(t *testing.T) {
	t.Run("same encoding as cluster policy rules", func(t *testing.T) {
		baseline := 50 + fwrp.BASELINE_TIER_PRIORITY_OFFSET
		rules := newDomainRules([]fwrp.EbpfFirewallRules{domain("example.com", baseline, 443)})
		assert.Equal(t, uint32(baseline*10+1), binary.LittleEndian.Uint32(rules[0].encoded[4:]))
		assert.Equal(t, uint32(utils.TCP_PROTOCOL_NUMBER), binary.LittleEndian.Uint32(rules[0].encoded[0:]))
	})
	t.Run("no ports allows every protocol and port", func(t *testing.T) {
		rules := newDomainRules([]fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY)})
		assert.Equal(t, uint32(utils.ANY_IP_PROTOCOL), binary.LittleEndian.Uint32(rules[0].encoded[0:]))
	})
	t.Run("only Accept rules", func(t *testing.T) {
		pass := domain("example.com", 10)
		pass.Action = v1alpha1.ClusterNetworkPolicyRuleActionPass
		assert.Empty(t, newDomainRules([]fwrp.EbpfFirewallRules{pass}))
	})
	t.Run("entries leave out the unused ones", func(t *testing.T) {
		rule := newDomainRules([]fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 80, 443)})[0]
		assert.Len(t, rule.entries(), 2)
		assert.Equal(t, []uint32{80, 443}, ports([]byte(strings.Join(rule.entries(), ""))))
	})
}

func TestMatchUnionsEveryMatchingRule(t *testing.T) {
	p := newTestProxy(&fakeEBPF{})
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{
		domain("www.example.com", utils.PE_PRIORITY, 80),
		domain("*.example.com", utils.PE_PRIORITY, 443),
		domain("other.com", utils.PE_PRIORITY, 22),
	}))
	assert.NoError(t, p.SetRules("app@ns", ClusterPolicyEndpoints, []fwrp.EbpfFirewallRules{
		domain("*.com", 10, 8443),
	}))

	podIdentifier, rules := p.match(podIP, "www.example.com.")
	assert.Equal(t, "app@ns", podIdentifier)
	assert.ElementsMatch(t, []uint32{80, 443, 8443}, ports(rules))

	podIdentifier, rules = p.match("10.0.0.99", "www.example.com.")
	assert.Empty(t, podIdentifier, "not a pod whose DNS was redirected")
	assert.Empty(t, rules)

	assert.NoError(t, p.SetRules("app@ns", ClusterPolicyEndpoints, nil))
	_, rules = p.match(podIP, "www.example.com.")
	assert.ElementsMatch(t, []uint32{80, 443}, ports(rules))
}

func TestSetRulesPrunesTheRulesItRemoves(t *testing.T) {
	f := &fakeEBPF{}
	p := newTestProxy(f)
	https, http := domain("example.com", utils.PE_PRIORITY, 443), domain("example.com", utils.PE_PRIORITY, 80)
	other := domain("other.com", utils.PE_PRIORITY, 8080)

	// After a restart the sources set their rules policy by policy; the IPs learned before keep working.
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{http}))
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{http, https, other}))
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{http, https, other}))
	assert.Empty(t, f.prunes, "added and unchanged rules prune nothing")

	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{http, other}))
	assert.Len(t, f.prunes, 1)
	assert.Equal(t, []uint32{443}, ports(f.prunes[0]()), "only the removed rule")

	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{http, https, other}))
	assert.Empty(t, f.prunes[0](), "a rule set again before the prune runs is kept")

	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{https, domain("www.example.com", utils.PE_PRIORITY, 80)}))
	assert.Equal(t, []uint32{8080}, ports(f.prunes[len(f.prunes)-1]()), "port 80 is still allowed, for another name")

	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, nil))
	assert.ElementsMatch(t, []uint32{80, 443}, ports(f.prunes[len(f.prunes)-1]()))
	assert.NotContains(t, p.rules, "app@ns", "a pod identifier without rules is not kept")
}

type fakeRedirect struct {
	mu      sync.Mutex
	set     map[string]bool
	addErr  error
	flushed []string
	deleted bool
}

func (f *fakeRedirect) add(veth string) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.set[veth] = true
	return nil
}

func (f *fakeRedirect) remove(veth string) error {
	delete(f.set, veth)
	return nil
}

func (f *fakeRedirect) forgetDirectFlows(ips []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushed = append(f.flushed, ips...)
}

func (f *fakeRedirect) delete() { f.deleted = true }

func (f *fakeRedirect) flushedIPs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushed
}

// testNode fakes the interfaces of pods: pod <name> has interface "eni-<name>" with IP "ip-<name>",
// unless set otherwise.
type testNode struct {
	gone  map[string]bool     // pods without an interface on the node
	veths map[string]string   // pod name -> interface
	ips   map[string][]string // interface -> IPs
}

func fakeNode(t *testing.T) *testNode {
	node := &testNode{gone: map[string]bool{}, veths: map[string]string{}, ips: map[string][]string{}}
	origVeth, origIPs := utils.GetHostVethName, podIPs
	t.Cleanup(func() { utils.GetHostVethName, podIPs = origVeth, origIPs })
	utils.GetHostVethName = func(name, _ string, _ int, _ []string) (string, error) {
		if node.gone[name] {
			return "", errors.New("no such interface")
		}
		if veth, ok := node.veths[name]; ok {
			return veth, nil
		}
		return "eni-" + name, nil
	}
	podIPs = func(veth string) ([]string, error) {
		if ips, ok := node.ips[veth]; ok {
			return ips, nil
		}
		return []string{"ip-" + strings.TrimPrefix(veth, "eni-")}, nil
	}
	return node
}

// newRedirectingProxy returns a running proxy on a fake node.
func newRedirectingProxy(t *testing.T) (*Proxy, *fakeRedirect, *testNode) {
	node := fakeNode(t)
	r := &fakeRedirect{set: map[string]bool{}}
	p := New(context.Background(), nil, &fakeEBPF{withoutContext: map[string]bool{}})
	p.redirect = r
	p.startOnce.Do(func() {})
	return p, r, node
}

func name(pod string) types.NamespacedName {
	return types.NamespacedName{Namespace: "ns", Name: pod}
}

func TestRedirectFollowsDomainRules(t *testing.T) {
	p, r, _ := newRedirectingProxy(t)
	rules := []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}

	assert.NoError(t, p.AddPod(name("a"), "app@ns"))
	assert.Empty(t, r.set, "no domain rules, no redirect")

	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, rules))
	assert.Equal(t, map[string]bool{"eni-a": true}, r.set)
	podIdentifier, _ := p.match("ip-a", "example.com.")
	assert.Equal(t, "app@ns", podIdentifier)
	assert.Equal(t, []string{"ip-a"}, r.flushedIPs(), "the running pod's direct DNS flows move onto the redirect")

	assert.NoError(t, p.AddPod(name("b"), "app@ns"))
	assert.Len(t, r.set, 2, "a new pod of the workload is redirected at once")
	assert.Equal(t, []string{"ip-a"}, r.flushedIPs(), "a new pod has no flows to move")

	assert.NoError(t, p.SetRules("app@ns", ClusterPolicyEndpoints, rules))
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, nil))
	assert.Len(t, r.set, 2, "the cluster policy rules still need the redirect")

	assert.NoError(t, p.SetRules("app@ns", ClusterPolicyEndpoints, nil))
	assert.Empty(t, r.set)
	podIdentifier, rulesOfA := p.match("ip-a", "example.com.")
	assert.Equal(t, "app@ns", podIdentifier, "queries redirected before are still answered")
	assert.Empty(t, rulesOfA)

	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, rules))
	p.DeletePod(name("a"), "app@ns")
	assert.Equal(t, map[string]bool{"eni-b": true}, r.set)
	podIdentifier, _ = p.match("ip-a", "example.com.")
	assert.Empty(t, podIdentifier)

	assert.NoError(t, p.AddPod(name("b"), "other@ns"))
	assert.Empty(t, r.set, "a pod of the same name in a pod identifier without rules is not redirected")
}

// The CNI does not report the deletion of pods with security groups: a pod of the same name comes back
// with the same interface name and a new IP.
func TestAddPodReplacesAPodWhoseDeletionWasNotReported(t *testing.T) {
	p, r, node := newRedirectingProxy(t)
	assert.NoError(t, p.SetRules("web@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))
	node.ips["eni-web-0"] = []string{"192.0.2.1"}
	assert.NoError(t, p.AddPod(name("web-0"), "web@ns"))

	node.ips["eni-web-0"] = []string{"192.0.2.2"}
	assert.NoError(t, p.AddPod(name("web-0"), "web@ns"))
	podIdentifier, _ := p.match("192.0.2.2", "example.com.")
	assert.Equal(t, "web@ns", podIdentifier, "the new pod's queries are answered")
	podIdentifier, _ = p.match("192.0.2.1", "example.com.")
	assert.Empty(t, podIdentifier)
	assert.Equal(t, map[string]bool{"eni-web-0": true}, r.set)

	entry := p.pods[name("web-0")]
	assert.NoError(t, p.AddRunningPod(name("web-0"), "web@ns"))
	assert.Same(t, entry, p.pods[name("web-0")], "a policy listing the pod keeps it")
}

func TestDeletingAPodKeepsTheIPsOfOtherPods(t *testing.T) {
	p, _, node := newRedirectingProxy(t)
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))
	node.ips["eni-a"], node.ips["eni-b"] = []string{"192.0.2.1"}, []string{"192.0.2.1"}
	assert.NoError(t, p.AddPod(name("a"), "app@ns"))
	assert.NoError(t, p.AddPod(name("b"), "app@ns")) // a was deleted without the agent knowing, b got its IP

	p.DeletePod(name("a"), "app@ns")
	podIdentifier, _ := p.match("192.0.2.1", "example.com.")
	assert.Equal(t, "app@ns", podIdentifier, "the IP is b's now")
}

func TestRulesGoWithTheProgramsOfThePodIdentifier(t *testing.T) {
	p, r, _ := newRedirectingProxy(t)
	f := p.ebpfClient.(*fakeEBPF)
	assert.NoError(t, p.SetRules("app@ns", ClusterPolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", 10, 443)}))
	assert.NoError(t, p.AddPod(name("a"), "app@ns"))

	// The CNI ADD of a replacement pod loaded nothing (the programs were there) and has not added the
	// pod to the proxy yet when the old pod's CNI DEL comes.
	p.DeletePod(name("a"), "app@ns")
	assert.True(t, p.hasRulesLocked("app@ns"), "the programs are still there")
	assert.NoError(t, p.AddPod(name("b"), "app@ns"))
	assert.Contains(t, r.set, "eni-b")

	f.withoutContext["app@ns"] = true
	p.DeletePod(name("b"), "app@ns")
	assert.False(t, p.hasRulesLocked("app@ns"), "no policy update reaches a pod identifier without programs, so its rules go")
}

func TestRedirectFailures(t *testing.T) {
	p, r, node := newRedirectingProxy(t)
	rules := []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, rules))

	node.gone["a"], node.gone["b"] = true, true
	assert.NoError(t, p.AddRunningPod(name("a"), "app@ns"), "a pod a policy lists that left the node is skipped")
	assert.NotContains(t, p.pods, name("a"))
	assert.NoError(t, p.AddRunningPod(name("b"), "no-rules@ns"))
	assert.NotContains(t, p.pods, name("b"), "also without domain rules, so its entry does not stay forever")
	node.gone["a"] = false

	r.addErr = errors.New("netlink error")
	assert.Error(t, p.AddPod(name("a"), "app@ns"))
	assert.Empty(t, r.set)
	r.addErr = nil
	assert.NoError(t, p.AddRunningPod(name("a"), "app@ns"), "a pod that was not redirected is retried")
	assert.Contains(t, r.set, "eni-a")
}

func TestPodsWithStrictModeSecurityGroupsAreNotRedirected(t *testing.T) {
	p, r, node := newRedirectingProxy(t)
	node.veths["a"] = "vlan0123456789a"
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))
	assert.NoError(t, p.AddPod(name("a"), "app@ns"))
	assert.Empty(t, r.set, "their queries would leave through the branch ENI and never reach the proxy")
}

type fakeServer struct{ stopped bool }

func (f *fakeServer) Stop() error {
	f.stopped = true
	return nil
}

func TestTheProxyStartsWithTheFirstDomainRules(t *testing.T) {
	fakeNode(t)
	origBackoff := retryBackoff
	t.Cleanup(func() { retryBackoff = origBackoff })
	retryBackoff = time.Millisecond

	r, server := &fakeRedirect{set: map[string]bool{}}, &fakeServer{}
	p := New(context.Background(), nil, &fakeEBPF{})
	attempts := 0
	p.start = func() (redirector, stopper, error) {
		if attempts++; attempts == 1 {
			return nil, nil, errors.New("kube-dns Service not found")
		}
		return r, server, nil
	}

	assert.NoError(t, p.AddPod(name("a"), "app@ns"))
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))
	assert.Eventually(t, func() bool { return len(r.flushedIPs()) > 0 }, 5*time.Second, time.Millisecond, "a failed start is retried")
	assert.Equal(t, []string{"ip-a"}, r.flushedIPs(), "the pod may have queried the cluster DNS directly while the proxy started")
	p.mu.RLock()
	assert.True(t, r.set["eni-a"])
	p.mu.RUnlock()

	p.Stop()
	assert.True(t, r.deleted)
	assert.True(t, server.stopped)
	p.DeletePod(name("a"), "app@ns") // the CNI can still call after the agent stopped
}

func TestTheCNIAddOfTheFirstPodWaitsForTheProxyItStarts(t *testing.T) {
	fakeNode(t)
	for _, startErr := range []error{nil, errors.New("kube-dns Service not found")} {
		r := &fakeRedirect{set: map[string]bool{}}
		p := New(context.Background(), nil, &fakeEBPF{})
		p.start = func() (redirector, stopper, error) {
			time.Sleep(100 * time.Millisecond)
			if startErr != nil {
				return nil, nil, startErr
			}
			return r, &fakeServer{}, nil
		}

		// The CNI ADD of the first pod of a workload sets the cached rules, then adds the pod.
		assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))
		start := time.Now()
		assert.NoError(t, p.AddPod(name("a"), "app@ns"))
		p.mu.RLock()
		redirected := r.set["eni-a"]
		p.mu.RUnlock()
		assert.Equal(t, startErr == nil, redirected, "redirected before the CNI ADD returns, when the proxy starts")
		assert.Less(t, time.Since(start), firstStartWait, "a failed start is not waited for")
		p.Stop()
	}
}

func TestAStoppedAgentDoesNotKeepTheProxyItStarted(t *testing.T) {
	p := New(context.Background(), nil, &fakeEBPF{})
	p.Stop()
	r, server := &fakeRedirect{set: map[string]bool{}}, &fakeServer{}
	p.adopt(r, server)
	assert.True(t, r.deleted)
	assert.True(t, server.stopped)
	assert.Nil(t, p.redirect)
}

func TestTheProxyStopsRetryingWithTheAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := New(ctx, nil, &fakeEBPF{})
	p.start = func() (redirector, stopper, error) {
		cancel()
		return nil, nil, errors.New("kube-dns Service not found")
	}
	done := make(chan struct{})
	go func() {
		p.run()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run kept retrying after the agent stopped")
	}
}

func TestNilProxyDisablesDomainRules(t *testing.T) {
	var p *Proxy
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", 0)}))
	assert.NoError(t, p.AddPod(name("a"), "app@ns"))
	assert.NoError(t, p.AddRunningPod(name("a"), "app@ns"))
	p.DeletePod(name("a"), "app@ns")
	p.Stop()
}

func TestClusterDNSIP(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	kubeDNS := func(ip string) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kube-dns"}, Spec: corev1.ServiceSpec{ClusterIP: ip}}
	}

	ip, err := clusterDNSIP(context.Background(), fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubeDNS("10.100.0.10")).Build())
	assert.NoError(t, err)
	assert.Equal(t, "10.100.0.10", ip.String())

	_, err = clusterDNSIP(context.Background(), fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubeDNS("fd00::a")).Build())
	assert.ErrorContains(t, err, "no IPv4 ClusterIP")

	start := time.Now()
	_, err = clusterDNSIP(context.Background(), fake.NewClientBuilder().WithScheme(scheme).Build())
	assert.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "a missing Service fails at once instead of delaying the agent start")
}

func TestServeDNS(t *testing.T) {
	answer := func(ttl uint32) plugin.Handler {
		return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}, Target: "edge.example.net."},
				&dns.A{Hdr: dns.RR_Header{Name: "edge.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(192, 0, 2, 1)},
			}
			return dns.RcodeSuccess, w.WriteMsg(m)
		})
	}
	query := func(h *handler, client, name string) (int, *dns.Msg) {
		rec := &recorder{ResponseWriter: &test.ResponseWriter{RemoteIP: client}}
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		rcode, err := h.ServeDNS(context.Background(), rec, req)
		assert.NoError(t, err)
		return rcode, rec.msg
	}

	f := &fakeEBPF{}
	p := newTestProxy(f)
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))

	_, reply := query(&handler{proxy: p, next: answer(0)}, podIP, "EXAMPLE.com.")
	assert.Len(t, reply.Answer, 2, "the answer still reaches the pod")
	assert.Equal(t, "app@ns", f.podIdentifier)
	assert.Equal(t, []npatypes.IPWithTTL{{IP: net.IPv4(192, 0, 2, 1), TTL: zeroTTL}}, f.answers, "the A record at the end of the CNAME chain")
	assert.Equal(t, []uint32{443}, ports(f.rules))

	f.answers = nil
	_, reply = query(&handler{proxy: p, next: answer(30)}, podIP, "other.com.")
	assert.Len(t, reply.Answer, 2)
	assert.Nil(t, f.answers, "names without a rule are resolved but not allowed")

	rcode, reply := query(&handler{proxy: p, next: answer(30)}, "10.0.0.99", "example.com.")
	assert.Equal(t, dns.RcodeRefused, rcode, "a source that is not a redirected pod is refused")
	assert.Nil(t, reply, "and not forwarded")
}

func TestLearnUsesTheRulesWhenTheAnswerArrives(t *testing.T) {
	f := &fakeEBPF{}
	p := newTestProxy(f)
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, []fwrp.EbpfFirewallRules{domain("example.com", utils.PE_PRIORITY, 443)}))
	answer := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(192, 0, 2, 1)}}}

	// The policy is deleted while the query is in flight.
	assert.NoError(t, p.SetRules("app@ns", PolicyEndpoints, nil))
	p.learn("app@ns", "example.com.", answer)
	assert.Nil(t, f.answers)
}

func TestAnswerIPs(t *testing.T) {
	a := func(name string, ip net.IP) dns.RR {
		return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: ip}
	}
	cname := func(name, target string) dns.RR {
		return &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: target}
	}
	answer := &dns.Msg{Answer: []dns.RR{
		a("origin.example.org.", net.IPv4(192, 0, 2, 3)),
		cname("Example.com.", "edge.example.net."),
		a("edge.example.net.", net.IPv4(192, 0, 2, 1)),
		a("unrelated.example.org.", net.IPv4(192, 0, 2, 2)),
		a("edge.example.net.", net.IPv4(169, 254, 169, 254)),
		a("edge.example.net.", net.IPv4(127, 0, 0, 1)),
		cname("edge.example.net.", "origin.example.org."),
		cname("origin.example.org.", "Example.com."), // a loop ends
	}}
	assert.Equal(t, []npatypes.IPWithTTL{{IP: net.IPv4(192, 0, 2, 3), TTL: 30}, {IP: net.IPv4(192, 0, 2, 1), TTL: 30}}, answerIPs("example.com.", answer),
		"the CNAME chain of the question in any order, and no link-local or loopback address")
}

type recorder struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (r *recorder) WriteMsg(m *dns.Msg) error {
	r.msg = m
	return nil
}
