// Package dnsproxy enforces the domain name rules of network policies. DNS queries that pods with
// domain rules send to the cluster DNS are redirected to an embedded CoreDNS forwarder, which writes
// the answer IPs of allowed names into the pod's IP cache before the answer reaches the pod.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Policy sources; each sets its own domain rules for a pod identifier.
	PolicyEndpoints        = "PolicyEndpoint"
	ClusterPolicyEndpoints = "ClusterPolicyEndpoint"

	interfaceName = "dnsproxy"
	listenerPort  = 50052
	// Bounds the queries in flight, so pods flooding the proxy cannot exhaust the agent.
	maxConcurrentQueries = 1000
	// Bounds how long the CNI ADD of a pod whose rules started the proxy waits for it.
	firstStartWait = 5 * time.Second
)

// Link-local, so it is not reachable from off the node. Avoids NodeLocal DNSCache (169.254.20.10),
// the VPC CNI pod gateway (169.254.1.1) and IPv6 egress range (169.254.172.0/22), IMDS and the
// VPC resolver (169.254.169.x), and EKS Pod Identity (169.254.170.23).
var listenerIP = net.IPv4(169, 254, 53, 53)

func log() logger.Logger {
	return logger.Get()
}

type pod struct {
	podIdentifier string
	veth          string   // the host side interface, looked up once the pod identifier has domain rules
	ips           []string // looked up when the pod's DNS is first redirected, mapped to the pod until it is deleted
	redirected    bool
	warned        bool // about security groups in strict mode
}

// redirector is the nftables redirect; tests replace it.
type redirector interface {
	add(veth string) error
	remove(veth string) error
	forgetDirectFlows(ips []string)
	delete()
}

// stopper is the CoreDNS server; tests replace it.
type stopper interface{ Stop() error }

// Proxy is safe to use as a nil pointer, which disables domain rules.
type Proxy struct {
	ctx        context.Context
	reader     client.Reader
	ebpfClient ebpf.BpfClient
	start      func() (redirector, stopper, error) // tests replace it
	startOnce  sync.Once
	firstStart chan struct{} // closed when the first start attempt is over

	mu       sync.RWMutex
	redirect redirector // nil until the proxy runs
	server   stopper
	stopped  bool
	// pod identifier -> policy source -> rules; sources without rules are left out.
	rules   map[string]map[string][]domainRule
	pods    map[types.NamespacedName]*pod
	podByIP map[string]*pod
}

// The CoreDNS plugin has no way to receive arguments other than the Corefile, so it uses the one proxy.
var active *Proxy

//+kubebuilder:rbac:groups="",namespace=kube-system,resources=services,resourceNames=kube-dns,verbs=get

// New returns a proxy that starts in the background when a pod identifier first gets domain rules,
// so nodes without domain rules run nothing.
func New(ctx context.Context, reader client.Reader, ebpfClient ebpf.BpfClient) *Proxy {
	p := &Proxy{
		ctx:        ctx,
		reader:     reader,
		ebpfClient: ebpfClient,
		rules:      map[string]map[string][]domainRule{},
		pods:       map[types.NamespacedName]*pod{},
		podByIP:    map[string]*pod{},
		firstStart: make(chan struct{}),
	}
	p.start = p.startForwarder
	return p
}

var retryBackoff = time.Second // tests shorten it

// run starts the proxy, retrying with back-off until it works or the agent stops, then redirects
// the pods whose pod identifiers have domain rules.
func (p *Proxy) run() {
	first := true
	for backoff := retryBackoff; ; backoff = min(2*backoff, 5*time.Minute) {
		r, server, err := p.start()
		if err == nil {
			p.adopt(r, server)
		}
		if first {
			close(p.firstStart)
			first = false
		}
		if err == nil {
			return
		}
		log().Errorf("Domain rules allow nothing until the DNS proxy starts, retrying in %v: %v", backoff, err)
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (p *Proxy) adopt(r redirector, server stopper) {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		r.delete()
		stopServer(server)
		return
	}
	p.redirect, p.server = r, server
	var redirected []string
	for name, entry := range p.pods {
		ips, err := p.syncLocked(name, entry)
		if err != nil {
			log().Errorf("%v", err)
		}
		redirected = append(redirected, ips...)
	}
	p.unlock(redirected)
}

func (p *Proxy) startForwarder() (redirector, stopper, error) {
	clusterDNS, err := clusterDNSIP(p.ctx, p.reader)
	if err != nil {
		return nil, nil, err
	}
	if err := setupListener(); err != nil {
		return nil, nil, fmt.Errorf("failed to set up the %s interface: %w", interfaceName, err)
	}
	conn, err := nftables.New()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open nftables: %w", err)
	}
	r := newRedirect(conn)
	if err := r.install(clusterDNS, listenerIP, listenerPort); err != nil {
		return nil, nil, fmt.Errorf("failed to set up the DNS redirect: %w", err)
	}
	active = p
	dnsserver.Quiet = true
	corefile := fmt.Sprintf(".:%d {\n\tbind %s\n\t%s\n\tforward . %s:53 {\n\t\tmax_concurrent %d\n\t}\n}\n",
		listenerPort, listenerIP, pluginName, clusterDNS, maxConcurrentQueries)
	server, err := caddy.Start(corefileInput(corefile))
	if err != nil {
		r.delete()
		return nil, nil, fmt.Errorf("failed to start the DNS proxy: %w", err)
	}
	log().Infof("DNS proxy listening on %s:%d, forwarding to %s", listenerIP, listenerPort, clusterDNS)
	return r, server, nil
}

// Stop removes the redirect, so pods query the cluster DNS directly, and stops the proxy.
func (p *Proxy) Stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stopped = true
	if p.redirect != nil {
		p.redirect.delete()
		p.redirect = nil
	}
	server := p.server
	p.mu.Unlock()
	// Not under the lock: in-flight queries take it, and stopping the server waits for them.
	if server != nil {
		stopServer(server)
	}
}

func stopServer(server stopper) {
	if err := server.Stop(); err != nil {
		log().Errorf("failed to stop the DNS proxy: %v", err)
	}
}

// SetRules replaces the domain rules a policy source has for podIdentifier.
func (p *Proxy) SetRules(podIdentifier, source string, rules []fwrp.EbpfFirewallRules) error {
	if p == nil {
		return nil
	}
	domainRules := newDomainRules(rules)
	p.mu.Lock()
	old := p.rules[podIdentifier][source]
	if len(domainRules) > 0 {
		if p.rules[podIdentifier] == nil {
			p.rules[podIdentifier] = map[string][]domainRule{}
		}
		p.rules[podIdentifier][source] = domainRules
		p.startOnce.Do(func() { go p.run() })
	} else {
		delete(p.rules[podIdentifier], source)
		if len(p.rules[podIdentifier]) == 0 {
			delete(p.rules, podIdentifier)
		}
	}
	prune := len(p.staleLocked(podIdentifier, old)) > 0
	var redirected []string
	var errs error
	for name, entry := range p.pods {
		if entry.podIdentifier == podIdentifier {
			ips, err := p.syncLocked(name, entry)
			redirected, errs = append(redirected, ips...), errors.Join(errs, err)
		}
	}
	p.unlock(redirected)

	if prune {
		// IPs learned for rules the pod identifier no longer has stop being allowed now, not at their TTL.
		// Only the rules set since the agent started go: after a restart the sources set their rules
		// policy by policy, and the IPs learned before keep working.
		stale := func() []byte {
			p.mu.RLock()
			defer p.mu.RUnlock()
			return p.staleLocked(podIdentifier, old)
		}
		if err := p.ebpfClient.PruneIPCache(podIdentifier, stale); err != nil {
			log().Debugf("Skipping the IP cache prune for %s: %v", podIdentifier, err)
		}
	}
	return errs
}

// staleLocked returns the encoded entries of rules that no rule of podIdentifier has now.
func (p *Proxy) staleLocked(podIdentifier string, rules []domainRule) []byte {
	current := map[string]bool{}
	for _, sourceRules := range p.rules[podIdentifier] {
		for _, rule := range sourceRules {
			for _, entry := range rule.entries() {
				current[entry] = true
			}
		}
	}
	var stale []byte
	for _, rule := range rules {
		for _, entry := range rule.entries() {
			if !current[entry] {
				stale = append(stale, entry...)
			}
		}
	}
	return stale
}

func (p *Proxy) hasRulesLocked(podIdentifier string) bool {
	return len(p.rules[podIdentifier]) > 0
}

// AddPod redirects the DNS of a pod the CNI just added while its pod identifier has domain rules. A
// pod of the same name the proxy still has is gone: the CNI does not tell the agent about every
// deleted pod (not about pods with security groups, for one).
func (p *Proxy) AddPod(name types.NamespacedName, podIdentifier string) error {
	if p == nil {
		return nil
	}
	// The pod's first queries must be redirected already: when its rules just started the proxy, wait for it.
	p.mu.RLock()
	starting := p.redirect == nil && !p.stopped && p.hasRulesLocked(podIdentifier)
	p.mu.RUnlock()
	if starting {
		select {
		case <-p.firstStart:
		case <-time.After(firstStartWait):
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deleteLocked(name)
	entry := &pod{podIdentifier: podIdentifier}
	p.pods[name] = entry
	_, err := p.syncLocked(name, entry) // a new pod has no DNS flows to move onto the redirect
	return err
}

// AddRunningPod redirects the DNS of a running pod a policy lists while its pod identifier has domain
// rules. The pod the proxy has under that name, if any, is that pod.
func (p *Proxy) AddRunningPod(name types.NamespacedName, podIdentifier string) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	entry, ok := p.pods[name]
	if !ok || entry.podIdentifier != podIdentifier {
		p.deleteLocked(name)
		// Only a pod on the node: a policy can still list a deleted pod, whose entry nothing would delete.
		veth, err := hostVeth(name)
		if err != nil {
			p.mu.Unlock()
			return nil
		}
		entry = &pod{podIdentifier: podIdentifier, veth: veth}
		p.pods[name] = entry
	}
	redirected, err := p.syncLocked(name, entry)
	p.unlock(redirected)
	return err
}

// DeletePod stops redirecting the DNS of a deleted pod. The rules of its pod identifier go with the
// pod identifier's BPF programs: no policy update reaches the agent for a pod identifier without
// pods, so the rules would be stale when its next pod comes.
func (p *Proxy) DeletePod(name types.NamespacedName, podIdentifier string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deleteLocked(name)
	// The CNI ADD that loads the programs again sets the rules after, under p.mu, so they are not dropped.
	if !p.ebpfClient.HasBPFContext(podIdentifier) {
		delete(p.rules, podIdentifier)
	}
}

func (p *Proxy) deleteLocked(name types.NamespacedName) {
	entry, ok := p.pods[name]
	if !ok {
		return
	}
	delete(p.pods, name)
	if entry.redirected && p.redirect != nil {
		if err := p.redirect.remove(entry.veth); err != nil {
			log().Errorf("failed to stop the DNS redirect for pod %s: %v", name, err)
		}
	}
	for _, ip := range entry.ips {
		// Another pod may have the IP by now, when this pod's deletion was never reported.
		if p.podByIP[ip] == entry {
			delete(p.podByIP, ip)
		}
	}
}

// syncLocked redirects the pod's DNS if and only if its pod identifier has domain rules and the proxy
// runs. It returns the pod's IPs when it starts redirecting them.
func (p *Proxy) syncLocked(name types.NamespacedName, entry *pod) ([]string, error) {
	if p.redirect == nil {
		return nil, nil // run syncs every pod once the proxy runs
	}
	want := p.hasRulesLocked(entry.podIdentifier)
	if want && entry.veth == "" {
		veth, err := hostVeth(name)
		if err != nil {
			delete(p.pods, name) // the pod left the node
			return nil, nil
		}
		entry.veth = veth
	}
	if want && strictSecurityGroups(entry.veth) {
		if !entry.warned {
			log().Warnf("Domain rules allow pod %s nothing: security groups for pods in strict mode route its DNS queries out of its branch ENI, past the DNS proxy", name)
			entry.warned = true
		}
		want = false
	}
	switch {
	case want && !entry.redirected:
		if entry.ips == nil {
			ips, err := podIPs(entry.veth)
			if err != nil {
				return nil, fmt.Errorf("failed to get the IPs of pod %s: %w", name, err)
			}
			// Mapped first, so the first redirected query already finds the pod.
			for _, ip := range ips {
				p.podByIP[ip] = entry
			}
			entry.ips = ips
		}
		if err := p.redirect.add(entry.veth); err != nil {
			return nil, fmt.Errorf("failed to redirect the DNS of pod %s: %w", name, err)
		}
		entry.redirected = true
		log().Infof("Redirecting the DNS of pod %s (%s, %v) to the DNS proxy", name, entry.veth, entry.ips)
		return entry.ips, nil
	case !want && entry.redirected:
		if err := p.redirect.remove(entry.veth); err != nil {
			return nil, fmt.Errorf("failed to stop the DNS redirect for pod %s: %w", name, err)
		}
		// The pod's IPs stay mapped, so the queries already redirected are still answered.
		entry.redirected = false
		log().Infof("Stopped redirecting the DNS of pod %s", name)
	}
	return nil, nil
}

// hostVeth returns the host side interface of the pod, or an error when the pod is not on the node.
// shortcut: only the first interface is redirected, it carries the default route; redirect every interface for multi-NIC pods if they need DNS on the others.
func hostVeth(name types.NamespacedName) (string, error) {
	return utils.GetHostVethName(name.Name, name.Namespace, 0, []string{ebpf.POD_VETH_PREFIX, ebpf.BRANCH_ENI_VETH_PREFIX})
}

// strictSecurityGroups reports whether the host side interface is that of a pod with security groups
// in strict mode, whose traffic the node routes out of the pod's branch ENI before local delivery.
func strictSecurityGroups(veth string) bool {
	return strings.HasPrefix(veth, ebpf.BRANCH_ENI_VETH_PREFIX)
}

// unlock releases p.mu, then deletes the conntrack entries of the DNS flows the redirected IPs opened
// before their redirect: NAT is decided on a flow's first packet, so a client reusing its socket would
// keep querying the cluster DNS directly. Outside the lock, as it reads the whole conntrack table.
func (p *Proxy) unlock(redirected []string) {
	r := p.redirect
	p.mu.Unlock()
	if len(redirected) > 0 {
		r.forgetDirectFlows(redirected)
	}
}

// match returns the pod identifier of the pod with IP podIP, or "" for an IP whose DNS the proxy never
// redirected, and the encoded rules of every domain rule of that pod identifier that qname matches.
func (p *Proxy) match(podIP, qname string) (string, []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry := p.podByIP[podIP]
	if entry == nil {
		return "", nil
	}
	return entry.podIdentifier, p.matchLocked(entry.podIdentifier, qname)
}

// matchRules returns the encoded rules of every domain rule of podIdentifier that qname matches.
func (p *Proxy) matchRules(podIdentifier, qname string) []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.matchLocked(podIdentifier, qname)
}

func (p *Proxy) matchLocked(podIdentifier, qname string) []byte {
	var encoded []byte
	for _, domainRules := range p.rules[podIdentifier] {
		for _, rule := range domainRules {
			if rule.matches(qname) {
				encoded = append(encoded, rule.encoded...)
			}
		}
	}
	return encoded
}

func clusterDNSIP(ctx context.Context, reader client.Reader) (net.IP, error) {
	var svc corev1.Service
	if err := reader.Get(ctx, types.NamespacedName{Namespace: "kube-system", Name: "kube-dns"}, &svc); err != nil {
		return nil, fmt.Errorf("failed to get the kube-dns Service: %w", err)
	}
	ip := net.ParseIP(svc.Spec.ClusterIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("kube-dns Service has no IPv4 ClusterIP: %q", svc.Spec.ClusterIP)
	}
	return ip, nil
}

func setupListener() error {
	if _, err := netlink.LinkByName(interfaceName); err != nil {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: interfaceName}}); err != nil {
			return err
		}
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: &net.IPNet{IP: listenerIP, Mask: net.CIDRMask(32, 32)}}); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// podIPs returns the IPs routed to the pod's host side interface, in any route table.
var podIPs = func(veth string) ([]string, error) {
	link, err := netlink.LinkByName(veth)
	if err != nil {
		return nil, err
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_UNSPEC},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, route := range routes {
		if route.Dst != nil {
			if ones, bits := route.Dst.Mask.Size(); ones == bits {
				ips = append(ips, route.Dst.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no host routes on %s", veth)
	}
	return ips, nil
}

type corefileInput string

func (c corefileInput) Body() []byte       { return []byte(c) }
func (c corefileInput) Path() string       { return "Corefile" }
func (c corefileInput) ServerType() string { return "dns" }
