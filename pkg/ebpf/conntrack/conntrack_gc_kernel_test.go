package conntrack

import (
	"os"
	"runtime"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// These tests run against the kernel's conntrack table, in a new network
// namespace so the table starts empty and the host's is untouched. The flows
// are created over ctnetlink, so no traffic is needed. The tests skip unless
// run as root on a kernel with ctnetlink. CI runs them as root with
// CONNTRACK_KERNEL_TESTS=required, which turns a skip into a failure so the
// step cannot pass without running them.

// testFlowTimeout is the conntrack timeout of created flows, in seconds. It
// outlasts the test.
const testFlowTimeout = 300

// enterTestNetns locks the test goroutine to its thread and moves the thread
// into a new network namespace until the test ends. It skips the test if that
// is not possible or the namespace has no ctnetlink.
func enterTestNetns(t *testing.T) {
	t.Helper()
	skip := t.Skipf
	if os.Getenv("CONNTRACK_KERNEL_TESTS") == "required" {
		skip = t.Fatalf
	}
	if os.Geteuid() != 0 {
		skip("needs root to create a network namespace")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		skip("get network namespace: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		skip("create network namespace: %v", err)
	}
	t.Cleanup(func() {
		ns.Close()
		defer orig.Close()
		if err := netns.Set(orig); err != nil {
			// Leave the thread locked, so it exits with the goroutine instead
			// of running other goroutines in the test namespace.
			t.Errorf("restore network namespace: %v", err)
			return
		}
		runtime.UnlockOSThread()
	})
	if _, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET); err != nil {
		skip("ctnetlink not available: %v", err)
	}
}

// createFlow adds flow to the kernel conntrack table, in the default zone.
func createFlow(t *testing.T, flow *netlink.ConntrackFlow) {
	t.Helper()
	f := *flow
	f.TimeOut = testFlowTimeout
	require.NoError(t, netlink.ConntrackCreate(netlink.ConntrackTable, netlink.InetFamily(f.FamilyType), &f))
}

// TestRemoveStaleEntriesKernel runs a GC pass against kernel flows, with the BPF
// map reads and deletes replaced.
func TestRemoveStaleEntriesKernel(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		enterTestNetns(t)
		createFlow(t, testFlow(false, protoTCP, podA, 40000, remote, 443, remote, 443))
		createFlow(t, testFlow(false, protoTCP, podA, 40001, vip, 80, podB, 8080))
		createFlow(t, testFlow(false, protoGRE, podA, 0, remote, 0, remote, 0))
		createFlow(t, testFlow(false, protoSCTP, podA, 40002, remote, 9000, remote, 9000))

		kept := []utils.ConntrackKey{
			v4Key(podA, 40000, remote, 443, protoTCP, podA, 7),
			v4Key(podA, 40000, remote, 443, protoTCP, remote, 7),
			v4Key(podA, 40001, vip, 80, protoTCP, podA, 7),
			// The DNAT'd flow's key towards the backend, found by the inverse GET.
			v4Key(podA, 40001, podB, 8080, protoTCP, podB, 9),
			v4Key(podA, 0, remote, 0, protoGRE, podA, 7),
		}
		// active matches no flow, but the datapath touched it during the pass.
		active := v4Key(podA, 40098, remote, 443, protoTCP, podA, 7)
		stale := []utils.ConntrackKey{
			v4Key(podA, 40099, remote, 443, protoTCP, podA, 7),
			v4Key(podA, 40000, remote, 53, protoUDP, podA, 7),
			v4Key(podA, 0, podB, 0, protoGRE, podA, 7),
			// A reverse-direction key: a GET finds the flow by its reply tuple,
			// but the flow does not produce this key.
			v4Key(remote, 443, podA, 40000, protoTCP, remote, 7),
			// netlink reports no SCTP ports, so an entry with ports matches no
			// flow even though the kernel has it.
			v4Key(podA, 40002, remote, 9000, protoSCTP, podA, 7),
		}
		c := &conntrackClient{localConntrackV4Cache: keySet(append(append(kept, stale...), active))}
		deleted := make(map[utils.ConntrackKey]bool)
		n, err := c.removeStaleV4Entries(testGCStart,
			func(k utils.ConntrackKey, _ uint64) bool { return k == active },
			func(k utils.ConntrackKey) { deleted[k] = true })
		require.NoError(t, err)
		assert.Equal(t, keySet(stale), deleted)
		assert.Equal(t, len(stale), n)
	})
	t.Run("v6", func(t *testing.T) {
		enterTestNetns(t)
		createFlow(t, testFlow(true, protoTCP, podA6, 40000, remote6, 443, remote6, 443))
		createFlow(t, testFlow(true, protoTCP, podA6, 40001, vip6, 80, podB6, 8080))
		createFlow(t, testFlow(true, protoGRE, podA6, 0, remote6, 0, remote6, 0))
		createFlow(t, testFlow(true, protoSCTP, podA6, 40002, remote6, 9000, remote6, 9000))

		kept := []utils.ConntrackKeyV6{
			v6Key(podA6, 40000, remote6, 443, protoTCP, podA6, 7),
			v6Key(podA6, 40000, remote6, 443, protoTCP, remote6, 7),
			v6Key(podA6, 40001, vip6, 80, protoTCP, podA6, 7),
			v6Key(podA6, 40001, podB6, 8080, protoTCP, podB6, 9),
			v6Key(podA6, 0, remote6, 0, protoGRE, podA6, 7),
		}
		active := v6Key(podA6, 40098, remote6, 443, protoTCP, podA6, 7)
		stale := []utils.ConntrackKeyV6{
			v6Key(podA6, 40099, remote6, 443, protoTCP, podA6, 7),
			v6Key(podA6, 40000, remote6, 53, protoUDP, podA6, 7),
			v6Key(podA6, 0, podB6, 0, protoGRE, podA6, 7),
			v6Key(remote6, 443, podA6, 40000, protoTCP, remote6, 7),
			v6Key(podA6, 40002, remote6, 9000, protoSCTP, podA6, 7),
		}
		c := &conntrackClient{enableIPv6: true, localConntrackV6Cache: keySet(append(append(kept, stale...), active))}
		deleted := make(map[utils.ConntrackKeyV6]bool)
		n, err := c.removeStaleV6Entries(testGCStart,
			func(k utils.ConntrackKeyV6, _ uint64) bool { return k == active },
			func(k utils.ConntrackKeyV6) { deleted[k] = true })
		require.NoError(t, err)
		assert.Equal(t, keySet(stale), deleted)
		assert.Equal(t, len(stale), n)
	})
}

// withoutNetAdmin drops CAP_NET_ADMIN from the test thread's effective
// capabilities until the test ends, so the kernel answers its ctnetlink
// requests with EPERM.
func withoutNetAdmin(t *testing.T) {
	t.Helper()
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	require.NoError(t, unix.Capget(&hdr, &caps[0]))
	orig := caps
	caps[0].Effective &^= 1 << unix.CAP_NET_ADMIN
	require.NoError(t, unix.Capset(&hdr, &caps[0]))
	t.Cleanup(func() { require.NoError(t, unix.Capset(&hdr, &orig[0])) })
}

// TestRemoveStaleEntriesReadErrorKernel checks that a GC pass deletes nothing
// when the kernel refuses its reads, for an entry that is looked up and for one
// that is matched by a protocol dump.
func TestRemoveStaleEntriesReadErrorKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		v4   utils.ConntrackKey
		v6   utils.ConntrackKeyV6
	}{
		{"TCP entry", v4Key(podA, 40099, remote, 443, protoTCP, podA, 7), v6Key(podA6, 40099, remote6, 443, protoTCP, podA6, 7)},
		{"GRE entry", v4Key(podA, 0, podB, 0, protoGRE, podA, 7), v6Key(podA6, 0, podB6, 0, protoGRE, podA6, 7)},
	} {
		t.Run(tc.name+"/v4", func(t *testing.T) {
			enterTestNetns(t)
			c := &conntrackClient{localConntrackV4Cache: keySet([]utils.ConntrackKey{tc.v4})}
			withoutNetAdmin(t)
			n, err := c.removeStaleV4Entries(testGCStart,
				func(utils.ConntrackKey, uint64) bool { return false },
				func(k utils.ConntrackKey) { t.Errorf("deleted %v", k) })
			assert.ErrorIs(t, err, unix.EPERM)
			assert.Zero(t, n)
		})
		t.Run(tc.name+"/v6", func(t *testing.T) {
			enterTestNetns(t)
			c := &conntrackClient{enableIPv6: true, localConntrackV6Cache: keySet([]utils.ConntrackKeyV6{tc.v6})}
			withoutNetAdmin(t)
			n, err := c.removeStaleV6Entries(testGCStart,
				func(utils.ConntrackKeyV6, uint64) bool { return false },
				func(k utils.ConntrackKeyV6) { t.Errorf("deleted %v", k) })
			assert.ErrorIs(t, err, unix.EPERM)
			assert.Zero(t, n)
		})
	}
}
