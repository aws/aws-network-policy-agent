package nodeinspect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRouteDev(t *testing.T) {
	dev, err := parseRouteDev("10.0.1.23 dev eni2d3286f75b3 src 10.0.1.5 uid 0 \\    cache")
	require.NoError(t, err)
	assert.Equal(t, "eni2d3286f75b3", dev)

	_, err = parseRouteDev("unreachable")
	assert.Error(t, err)
}

func TestParseNftInterfaces(t *testing.T) {
	out := `table ip dns_redirect {
	chain prerouting {
		type nat hook prerouting priority -120; policy accept;
		iifname "eni2d3286f75b3*" ip protocol udp udp dport 53 dnat to 169.254.20.10:50052
		iifname "eni2d3286f75b3*" ip protocol tcp tcp dport 53 dnat to 169.254.20.10:50052
		iifname "vlan9a1b2c3d4e5" ip protocol udp udp dport 53 dnat to 169.254.20.10:50052
	}
}`
	assert.Equal(t, []string{"eni2d3286f75b3", "vlan9a1b2c3d4e5"}, parseNftInterfaces(out))
	assert.Empty(t, parseNftInterfaces("table ip dns_redirect {\n\tchain prerouting {\n\t}\n}"))
}

func TestParseIPCacheDump(t *testing.T) {
	out := `[{"key":["0x34","0xd9","0x0c","0x05"],"value":["0x00","0xca","0x9a","0x3b","0x00","0x00","0x00","0x00","0x06","0x00"]}]`
	entries, err := parseIPCacheDump(out)
	require.NoError(t, err)
	assert.Equal(t, map[string]IPCacheEntry{"52.217.12.5": {ExpiryNs: 1_000_000_000}}, entries)

	empty, err := parseIPCacheDump("[]")
	require.NoError(t, err)
	assert.Empty(t, empty)

	_, err = parseIPCacheDump(`[{"key":["0x0a"],"value":["0x00"]}]`)
	assert.Error(t, err)
}
