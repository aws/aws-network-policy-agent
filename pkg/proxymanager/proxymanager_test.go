package proxymanager

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestHostRouteIP(t *testing.T) {
	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		assert.NoError(t, err)
		return n
	}
	for _, tc := range []struct {
		name   string
		routes []netlink.Route
		want   string
	}{
		{name: "pod route", routes: []netlink.Route{{Dst: cidr("10.0.1.23/32")}}, want: "10.0.1.23"},
		{name: "default and subnet routes are skipped", routes: []netlink.Route{{Dst: nil}, {Dst: cidr("10.0.0.0/24")}, {Dst: cidr("10.0.1.24/32")}}, want: "10.0.1.24"},
		{name: "no host route", routes: []netlink.Route{{Dst: cidr("10.0.0.0/16")}}, want: ""},
		{name: "no routes", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hostRouteIP(tc.routes))
		})
	}
}
