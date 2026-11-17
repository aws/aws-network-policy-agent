package conntrack

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

// withKernelFlows makes the GC read flows as the kernel conntrack table for
// family. If readErr is set, reading the table fails with it. A read that fails
// with netlink.ErrDumpInterrupted also returns the flows, as
// netlink.ConntrackTableList does.
func withKernelFlows(t *testing.T, family netlink.InetFamily, flows []*netlink.ConntrackFlow, readErr error) {
	orig := listConntrackFlows
	t.Cleanup(func() { listConntrackFlows = orig })
	listConntrackFlows = func(table netlink.ConntrackTableType, fam netlink.InetFamily) ([]*netlink.ConntrackFlow, error) {
		assert.Equal(t, netlink.ConntrackTableType(netlink.ConntrackTable), table)
		assert.Equal(t, family, fam)
		if readErr != nil && !errors.Is(readErr, netlink.ErrDumpInterrupted) {
			return nil, readErr
		}
		return flows, readErr
	}
}
