//go:build linux
// +build linux

package utils

import (
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

// TestGetHostVethName_RealNetlink_TriggersRetries is the strongest end-to-end
// guard for the retry path: it exercises GetHostVethName against the actual
// netlink.LinkByName syscall (not a sentinel, not a fake, not an override of
// isLinkNotFoundError). If a future netlink version changes the concrete
// type returned for a missing link, this test catches it; all
// matcher-override-based tests would silently still pass.
//
// Linux-only because netlink.LinkByName is a no-op stub on other platforms.
func TestGetHostVethName_RealNetlink_TriggersRetries(t *testing.T) {
	// Probe netlink first; if the test environment cannot open an
	// AF_NETLINK socket (rare, but possible in heavily sandboxed CI),
	// skip rather than fail on infrastructure noise. We only want to fail
	// when the retry/matcher contract itself regresses.
	if _, err := netlink.LinkByName("definitely-not-a-real-link-aws-npa-test"); err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			t.Skipf("netlink not usable in this environment, skipping: %v", err)
		}
	}

	originalFunc := getLinkByNameFunc
	originalBackoff := GetHostVethNameBackoff
	t.Cleanup(func() {
		getLinkByNameFunc = originalFunc
		GetHostVethNameBackoff = originalBackoff
	})

	GetHostVethNameBackoff = fastBackoff(3)

	exhaustedBefore := testutil.ToFloat64(vethLookupRetries.WithLabelValues("exhausted"))

	var calls int32
	getLinkByNameFunc = func(name string) (netlink.Link, error) {
		atomic.AddInt32(&calls, 1)
		return netlink.LinkByName(name)
	}

	// "no-such-pod"/"no-such-ns" hashes to a deterministic 11-char suffix
	// that is astronomically unlikely to collide with any real interface
	// name on the test host.
	got, err := GetHostVethName("no-such-pod", "no-such-ns", 0, []string{"eni", "vlan"})
	assert.Empty(t, got)
	assert.Error(t, err)
	// 3 attempts x 2 prefixes = 6 lookups. If the production
	// isLinkNotFoundError matcher fails to recognize whatever concrete
	// error type netlink actually returned, we would see exactly 2.
	assert.Equal(t, int32(6), atomic.LoadInt32(&calls),
		"production matcher must recognize the real netlink miss type and drive retries")
	assert.Equal(t, exhaustedBefore+1, testutil.ToFloat64(vethLookupRetries.WithLabelValues("exhausted")))
}
