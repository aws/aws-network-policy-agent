package conntrack

import (
	"reflect"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// fieldNames returns the exported field names of t in declaration order.
// Anonymous (padding) fields are skipped.
func fieldNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "" || f.Anonymous {
			continue
		}
		if !f.IsExported() {
			continue
		}
		names = append(names, f.Name)
	}
	return names
}

// TestConntrackKeyShape guards CleanupConntrackMap against silent drift.
//
// CleanupConntrackMap copies ConntrackKey field-by-field when hydrating the
// local cache from the BPF map. If a new field is added to ConntrackKey
// without updating that copy block, the cached key will silently zero the
// new field, causing DeleteMapEntry to miss real BPF entries.
//
// On field add, audit the hydrate-copy and kernel-cache-lookup blocks in
// CleanupConntrackMap, the corresponding blocks in Cleanupv6ConntrackMap,
// and the conntrack key formatter in pkg/clihelper/show.go. Then update
// the expected list below.
//
// Padding fields (anonymous _ uint8/uint16) are intentionally excluded —
// they exist for kernel struct alignment and aren't named in copy blocks.
func TestConntrackKeyShape(t *testing.T) {
	expected := []string{
		"Source_ip", "Source_port", "Dest_ip", "Dest_port",
		"Protocol", "Owner_ip", "Ifindex",
	}
	got := fieldNames(reflect.TypeOf(utils.ConntrackKey{}))
	assert.Equal(t, expected, got,
		"ConntrackKey shape changed — review GC hydrate/lookup paths in CleanupConntrackMap and CLI dump in show.go before updating this list")
}

// TestConntrackKeyV6Shape is the IPv6 counterpart drift sentinel.
func TestConntrackKeyV6Shape(t *testing.T) {
	expected := []string{
		"Source_ip", "Source_port", "Dest_ip", "Dest_port",
		"Protocol", "Owner_ip", "Ifindex",
	}
	got := fieldNames(reflect.TypeOf(utils.ConntrackKeyV6{}))
	assert.Equal(t, expected, got,
		"ConntrackKeyV6 shape changed — review GC hydrate/lookup paths in Cleanupv6ConntrackMap before updating this list")
}
