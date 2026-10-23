package cdnsproxy

import (

	// import our plugin to register them

	"context"
	"fmt"

	_ "github.com/aws/aws-network-policy-agent/pkg/cdns-proxy/plugins/ipfilter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/coredns/caddy"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/log"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/coredns/coredns/core/dnsserver"
)

func init() {
	// Register our custom plugins
	dnsserver.Directives = append([]string{"ipfilter"}, dnsserver.Directives...)
}

type DNSProxy struct {
	log           logger.Logger
	ebpfClient    ebpf.BpfClient
	upstreamAddr  string
	listenerAddr  string
	caddyInstance *caddy.Instance
}

func NewDNSProxy(log logger.Logger, ebpfClient ebpf.BpfClient, upstreamAddr string, listenerAddr string) *DNSProxy {
	return &DNSProxy{
		log:          log,
		ebpfClient:   ebpfClient,
		upstreamAddr: upstreamAddr,
		listenerAddr: listenerAddr,
	}
}

func (p *DNSProxy) Start(ctx context.Context, corefileContent string) error {
	p.log.Infof("starting dns proxy with Corefile content %s", corefileContent)
	c, err := caddy.Start(&Input{
		corefile: []byte(corefileContent),
	})
	if err != nil {
		return fmt.Errorf("error is starting dns proxy %w", err)
	}

	p.caddyInstance = c
	p.log.Infof("started dns proxy")

	return nil
}

func (p *DNSProxy) Stop() error {
	p.log.Info("stopping dns proxy")
	return p.caddyInstance.Stop()
}

// Helpers from the test package:
type Input struct {
	corefile []byte
}

func NewInput(corefile string) *Input {
	return &Input{corefile: []byte(corefile)}
}

// Body implements the Input interface.
func (i *Input) Body() []byte { return i.corefile }

// Path implements the Input interface.
func (i *Input) Path() string { return "Corefile" }

// ServerType implements the Input interface.
func (i *Input) ServerType() string { return "dns" }
