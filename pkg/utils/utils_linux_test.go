//go:build linux
// +build linux

package utils

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
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
	// when the retry/matcher contract itself regresses. Use errors.As so
	// a wrapped LinkNotFoundError is still recognized as a "netlink works"
	// signal rather than incorrectly skipping.
	if _, err := netlink.LinkByName("definitely-not-a-real-link-aws-npa-test"); err != nil {
		var lnf netlink.LinkNotFoundError
		if !errors.As(err, &lnf) {
			t.Skipf("netlink not usable in this environment, skipping: %v", err)
		}
	}

	const (
		podName      = "no-such-pod"
		podNamespace = "no-such-ns"
	)
	// Belt-and-suspenders: on a busy test host (e.g. a real EKS node) an
	// interface named eni<hash> or vlan<hash> for our chosen pod/ns could
	// in theory exist. Probability is astronomically low, but the test
	// asserts an exact lookup count so any collision turns into a hard
	// failure. Skip if either computed name resolves to a real link.
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", podNamespace, podName)))
	hashSuffix := hex.EncodeToString(h.Sum(nil))[:11]
	for _, prefix := range []string{"eni", "vlan"} {
		name := prefix + hashSuffix
		if _, err := netlink.LinkByName(name); err == nil {
			t.Skipf("computed test interface %q already exists on this host; "+
				"would collide with the retry-count assertion, skipping", name)
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

	got, err := GetHostVethName(podName, podNamespace, 0, []string{"eni", "vlan"})
	assert.Empty(t, got)
	assert.Error(t, err)
	// 3 attempts x 2 prefixes = 6 lookups. If the production
	// isLinkNotFoundError matcher fails to recognize whatever concrete
	// error type netlink actually returned, we would see exactly 2.
	assert.Equal(t, int32(6), atomic.LoadInt32(&calls),
		"production matcher must recognize the real netlink miss type and drive retries")
	assert.Equal(t, exhaustedBefore+1, testutil.ToFloat64(vethLookupRetries.WithLabelValues("exhausted")))
}
