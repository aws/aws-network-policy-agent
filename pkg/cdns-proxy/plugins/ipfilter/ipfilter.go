package ipfilter

import (
	"context"
	"net"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func log() logger.Logger {
	return logger.Get()
}

type contextKey string

const IPFilterMatchKey = contextKey("ipfiltermatch")

// IPFilter is a plugin that supports matchName and matchPattern.
// this plugin is only be responsible for matching Domain name and if matches writing responses in ebpf map
type IPFilter struct {
	Next plugin.Handler
}

func (i *IPFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// log().Info("IPFilter: received DNS query")
	ipStr, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log().Errorf("IPFilter: Failed to parse client IP: %v", err)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	// get podIp to PodId mapping
	podId, err := filter.GetPodId(ipStr)
	if err != nil {
		log().Errorf("IPFilter: Failed to get PodId for IP %s: err %v", ipStr, err)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	filter, ok := filter.GetIPFilter(podId)
	if !ok {
		log().Errorf("IPFilter: No filter for PodId %s PodIP %s", podId, ipStr)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	state := request.Request{W: w, Req: r}

	allowed, l4Rules := filter.IsAllowed(state.QName())
	log().Debugf("IPFilter: qname %s , qtype %s, allowed %v", state.QName(), state.Type(), allowed)

	if !allowed {
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	ctx = context.WithValue(ctx, IPFilterMatchKey, true)

	// Create a recorder to capture the response from the next plugin
	rec := &ResponseRecorder{
		ResponseWriter: w,
		Msg:            nil,
		req:            r,
		PodId:          podId,
		L4Rules:        l4Rules,
	}

	// Call the next plugin in the chain
	return plugin.NextOrFailure(i.Name(), i.Next, ctx, rec, r)
}

func (i *IPFilter) Name() string { return "ipfilter" }

// ResponseRecorder is a dns.ResponseWriter that captures the response
type ResponseRecorder struct {
	dns.ResponseWriter
	Msg     *dns.Msg
	req     *dns.Msg
	PodId   string
	L4Rules []npatypes.L4Rule
}

// WriteMsg records the response and passes it on to the client
func (r *ResponseRecorder) WriteMsg(res *dns.Msg) error {
	ipsWithTTL := []npatypes.IPWithTTL{}
	const defaultTTL uint32 = 300 // Default TTL of 5 minutes if no TTL found

	for _, answer := range res.Answer {
		if t, ok := answer.(*dns.A); ok {
			ttl := t.Hdr.Ttl
			if ttl == 0 {
				ttl = defaultTTL
			}
			ipsWithTTL = append(ipsWithTTL, npatypes.IPWithTTL{
				IP:  t.A,
				TTL: ttl,
			})
			// log().Debugf("IPFilter: Extracted IPv4 %v with TTL: %d seconds", t.A, ttl)
		}
	}

	if len(ipsWithTTL) > 0 {
		filter.BpfClient.WriteIPsForPod(r.PodId, ipsWithTTL, r.L4Rules)
	}

	r.Msg = res
	return r.ResponseWriter.WriteMsg(res)
}
