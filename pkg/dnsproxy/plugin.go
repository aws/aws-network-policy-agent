package dnsproxy

import (
	"context"
	"strings"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const (
	pluginName = "dnspolicy"
	// A zero TTL answer must still allow the connection the client opens right after it.
	zeroTTL = 5
)

func init() {
	// First in the chain, so it sees every query before forward answers it.
	dnsserver.Directives = append([]string{pluginName}, dnsserver.Directives...)
	plugin.Register(pluginName, func(c *caddy.Controller) error {
		c.Next()
		if c.NextArg() {
			return plugin.Error(pluginName, c.ArgErr())
		}
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			return &handler{proxy: active, next: next}
		})
		return nil
	})
}

// handler records the answer IPs of the names a pod is allowed to resolve before the answer is sent.
type handler struct {
	proxy *Proxy
	next  plugin.Handler
}

func (h *handler) Name() string { return pluginName }

func (h *handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	podIP, qname := state.IP(), state.Name()
	podIdentifier, rules := h.proxy.match(podIP, qname)
	if podIdentifier == "" {
		// Only pods whose DNS was redirected use the proxy; refuse other sources without forwarding their queries.
		return dns.RcodeRefused, nil
	}
	if len(rules) > 0 {
		w = &answerWriter{ResponseWriter: w, learn: func(answer *dns.Msg) { h.proxy.learn(podIdentifier, qname, answer) }}
	}
	return plugin.NextOrFailure(h.Name(), h.next, ctx, w, r)
}

type answerWriter struct {
	dns.ResponseWriter
	learn func(*dns.Msg)
}

func (w *answerWriter) WriteMsg(answer *dns.Msg) error {
	w.learn(answer)
	return w.ResponseWriter.WriteMsg(answer)
}

// learn writes the answer IPs of qname into the IP cache of podIdentifier with the rules that allow it.
func (p *Proxy) learn(podIdentifier, qname string, answer *dns.Msg) {
	ips := answerIPs(qname, answer)
	if len(ips) == 0 {
		return
	}
	// Matched again under the IP cache lock, so rules removed while the query was in flight are not
	// written back after their prune.
	rules := func() []byte { return p.matchRules(podIdentifier, qname) }
	if err := p.ebpfClient.UpdateIPCache(podIdentifier, ips, rules); err != nil {
		log().Errorf("Failed to allow the DNS answer IPs %v for %s: %v", ips, podIdentifier, err)
	}
}

// answerIPs returns the A records of qname and of the names its CNAME chain leads to, except
// loopback, link-local (IMDS) and unspecified addresses.
func answerIPs(qname string, answer *dns.Msg) []npatypes.IPWithTTL {
	targets := map[string][]string{} // CNAME owner -> targets
	for _, rr := range answer.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			owner := strings.ToLower(cname.Hdr.Name)
			targets[owner] = append(targets[owner], strings.ToLower(cname.Target))
		}
	}
	// The records can come in any order.
	names := map[string]bool{qname: true}
	for next := []string{qname}; len(next) > 0; next = next[1:] {
		for _, target := range targets[next[0]] {
			if !names[target] {
				names[target] = true
				next = append(next, target)
			}
		}
	}
	var ips []npatypes.IPWithTTL
	for _, rr := range answer.Answer {
		a, ok := rr.(*dns.A)
		if !ok || !names[strings.ToLower(a.Hdr.Name)] || a.A.IsLoopback() || a.A.IsLinkLocalUnicast() || a.A.IsUnspecified() {
			continue
		}
		ttl := a.Hdr.Ttl
		if ttl == 0 {
			ttl = zeroTTL
		}
		ips = append(ips, npatypes.IPWithTTL{IP: a.A, TTL: ttl})
	}
	return ips
}
