package conntrack

import (
	"errors"
	"reflect"
	"testing"
	"unsafe"

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

// TestConntrackValLayout verifies that ConntrackVal matches the BPF
// struct conntrack_value layout: 1 byte val + 7 pad + 8 byte last_seen = 16.
func TestConntrackValLayout(t *testing.T) {
	val := utils.ConntrackVal{}
	assert.Equal(t, uintptr(16), unsafe.Sizeof(val),
		"ConntrackVal size must be 16 bytes to match BPF struct conntrack_value")

	// LastSeen at offset 8 (after val + 7-byte pad)
	lastSeenOffset := unsafe.Offsetof(val.LastSeen)
	assert.Equal(t, uintptr(8), lastSeenOffset,
		"ConntrackVal.LastSeen must be at offset 8")
}

// TestKtimeGetNs verifies that ktimeGetNs returns a sane monotonic value.
func TestKtimeGetNs(t *testing.T) {
	ts1 := ktimeGetNs()
	assert.NotZero(t, ts1, "ktimeGetNs should return non-zero monotonic time")

	ts2 := ktimeGetNs()
	assert.GreaterOrEqual(t, ts2, ts1,
		"ktimeGetNs must be monotonically non-decreasing")
}

// TestEntryActiveFromRead is the core GC-race guard predicate. It decides
// whether a delete candidate (absent from the kernel snapshot) must be KEPT
// because the datapath refreshed its last_seen during this GC cycle — the
// port-reuse race. Delete only when the entry is genuinely stale.
func TestEntryActiveFromRead(t *testing.T) {
	const gcStart = uint64(1_000_000)

	cases := []struct {
		name    string
		val     utils.ConntrackVal
		readErr error
		want    bool // true => active => KEEP (skip delete)
	}{
		{
			name: "refreshed after gcStart -> keep (port-reuse race)",
			val:  utils.ConntrackVal{Value: 1, LastSeen: gcStart + 500},
			want: true,
		},
		{
			name: "stale before gcStart -> delete",
			val:  utils.ConntrackVal{Value: 1, LastSeen: gcStart - 500},
			want: false,
		},
		{
			name: "exactly gcStart -> keep (>= boundary)",
			val:  utils.ConntrackVal{Value: 1, LastSeen: gcStart},
			want: true,
		},
		{
			name:    "re-read failed -> keep (fail-safe)",
			val:     utils.ConntrackVal{},
			readErr: errors.New("ENOENT"),
			want:    true,
		},
		{
			name: "zero last_seen, stale -> delete",
			val:  utils.ConntrackVal{Value: 1, LastSeen: 0},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := entryActiveFromRead(tc.val, tc.readErr, gcStart)
			assert.Equal(t, tc.want, got)
		})
	}
}
