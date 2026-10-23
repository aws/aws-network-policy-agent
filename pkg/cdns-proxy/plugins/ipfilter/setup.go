package ipfilter

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() {
	plugin.Register("ipfilter", SetupIPFilter)
}

func SetupIPFilter(c *caddy.Controller) error {
	c.Next()
	if c.NextArg() {
		return plugin.Error("ipfilter", c.ArgErr())
	}

	// Add the plugin to the middleware chain
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &IPFilter{
			Next: next,
		}
	})

	return nil
}
