package clihelper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFormatLastSeen covers the human-readable rendering of the conntrack
// last_seen stamp, including the cases where an age cannot be computed.
func TestFormatLastSeen(t *testing.T) {
	const now = uint64(10_000_000_000) // 10s on the monotonic clock

	cases := []struct {
		name     string
		lastSeen uint64
		now      uint64
		want     string
	}{
		{
			name:     "sub-second age",
			lastSeen: now - 400_000_000, // 400ms ago
			now:      now,
			want:     "400ms ago",
		},
		{
			name:     "seconds age",
			lastSeen: now - 1_400_000_000, // 1.4s ago
			now:      now,
			want:     "1.4s ago",
		},
		{
			name:     "minutes age",
			lastSeen: now,                   // 10s on the clock
			now:      now + 144_000_000_000, // 2m24s later
			want:     "2m24s ago",
		},
		{
			name:     "never stamped -> never",
			lastSeen: 0,
			now:      now,
			want:     "never",
		},
		{
			name:     "stamped at now -> zero age",
			lastSeen: now,
			now:      now,
			want:     "0s ago",
		},
		{
			name:     "stamped after our clock read -> clamped, not negative",
			lastSeen: now + 500_000_000,
			now:      now,
			want:     "0s ago",
		},
		{
			name:     "clock unavailable -> clamped",
			lastSeen: now,
			now:      0,
			want:     "0s ago",
		},
		{
			name:     "never wins over unavailable clock",
			lastSeen: 0,
			now:      0,
			want:     "never",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, formatLastSeen(tc.lastSeen, tc.now))
		})
	}
}

// TestKtimeGetNs verifies the CLI's monotonic clock read, which must share a
// domain with the datapath's bpf_ktime_get_ns() for ages to be meaningful.
func TestKtimeGetNs(t *testing.T) {
	t1 := ktimeGetNs()
	assert.NotZero(t, t1, "ktimeGetNs should return non-zero monotonic time")

	t2 := ktimeGetNs()
	assert.GreaterOrEqual(t, t2, t1, "ktimeGetNs must be monotonically non-decreasing")
}
