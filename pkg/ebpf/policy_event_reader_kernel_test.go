package ebpf

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf/events"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestPolicyEventReaderSkipsAcceptKernel drives the production reader loop
// (events.ConfigurePolicyEventsLogging) over a real ring buffer. The datapath
// is set to scope all, so the kernel writes ACCEPT records. The reader runs
// with denyOnly at debug level and must skip them: an ACCEPT record must not
// reach the flow log, while a DENY record must. Removing the reader's skip
// makes the ACCEPT line appear, so the test fails. The DENY line is awaited
// first: once it is logged, the reader has already consumed the ACCEPT record
// before it, so the ACCEPT's absence is meaningful.
func TestPolicyEventReaderSkipsAcceptKernel(t *testing.T) {
	dir, _ := requireBPFKernelTests(t)
	fam := family{"v4", netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.1.2:80"),
		EVENTS_BINARY, TC_EGRESS_BINARY, []string{TC_INGRESS_BINARY}}
	progs := loadFamily(t, dir, fam, fam.ingressBinaries[0])
	allowTCPPortRule(t, progs.ingress, false)

	// Send the flow log to a file the test can read. Debug level is needed so
	// that ACCEPT lines would be written if the reader did not skip them.
	logPath := filepath.Join(t.TempDir(), "flow.log")
	logger.New("debug", logPath, logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
	t.Cleanup(func() {
		logger.New(logger.DEFAULT_LOG_LEVEL, logger.DEFAULT_LOG_LOCATION,
			logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
	})

	// Datapath scope all: the kernel writes the ACCEPT record, so the only thing
	// keeping it out of the log is the reader loop's skip under denyOnly below.
	require.NoError(t, writeTCConfig(progs.config, false, POLICY_EVENT_SCOPE_ALL))
	dupFD, err := unix.Dup(int(progs.events.MapFD))
	require.NoError(t, err)
	// ConfigurePolicyEventsLogging owns the FD it is given and starts the reader.
	require.NoError(t, events.ConfigurePolicyEventsLogging(false, dupFD, false, true))

	// One allowed connection (ACCEPT, which scope deny must not log) and one
	// denied connection (DENY, which must be logged).
	srcPort := fam.client.Port()
	connect := func(dstPort uint16) {
		t.Helper()
		srcPort++
		seg := tcpSegment{
			src:   netip.AddrPortFrom(fam.client.Addr(), srcPort),
			dst:   netip.AddrPortFrom(fam.pod.Addr(), dstPort),
			seq:   0x11223344,
			flags: tcpFlagSyn,
		}
		testRun(t, progs.ingressFD, seg.packet())
	}
	connect(scopeTestAllowedPort)
	connect(scopeTestDeniedPort)

	require.Eventually(t, func() bool {
		return strings.Contains(readFileOrEmpty(logPath), "DENY")
	}, 5*time.Second, 50*time.Millisecond, "DENY line never reached the flow log")
	assert.NotContains(t, readFileOrEmpty(logPath), "ACCEPT",
		"scope deny: the reader must not log ACCEPT events")
}

func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
