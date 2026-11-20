package ebpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	// data_t.verdict in v4events.bpf.c and v6events.bpf.c.
	policyEventVerdictDeny   = 0
	policyEventVerdictAccept = 1
	// Byte offsets of data_t.verdict: an IPv4 address is 4 bytes, an IPv6 one 16.
	policyEventV4VerdictOffset = 20
	policyEventV6VerdictOffset = 44
	// The ingress map's value is an array of this many rules of this size,
	// ended early by an entry whose protocol is reservedIPProtocol
	// (tc.v4ingress.bpf.c).
	scopeTestMaxRules      = 24
	scopeTestRuleSize      = 12
	scopeTestReservedProto = 255
	scopeTestAllowedPort   = 80
	scopeTestDeniedPort    = 81
)

// allowTCPPortRule writes an ingress rule that allows TCP to port 80 from any
// address. A connection to any other port matches no rule and is denied, so
// the pod gets both verdicts from one rule.
func allowTCPPortRule(t *testing.T, ingress goebpfmaps.BpfMap, ipv6 bool) {
	t.Helper()
	ipLen := 4
	if ipv6 {
		ipLen = 16
	}
	key := make([]byte, 4+ipLen) // prefix length 0 matches every address
	val := make([]byte, scopeTestMaxRules*scopeTestRuleSize)
	binary.LittleEndian.PutUint32(val[0:], ipProtoTCP)
	binary.LittleEndian.PutUint32(val[4:], scopeTestAllowedPort)
	// The end port stays 0; the second entry ends the list.
	binary.LittleEndian.PutUint32(val[scopeTestRuleSize:], scopeTestReservedProto)
	require.NoError(t, ingress.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&val[0])), 0))
}

// readPolicyEventVerdicts returns the verdict of every record written to
// policy_events since the last call. It stops at the first read that waits out
// the deadline, so a write that never happened gives an empty result.
func readPolicyEventVerdicts(t *testing.T, rd *ringbuf.Reader, verdictOffset int) []uint32 {
	t.Helper()
	var verdicts []uint32
	var rec ringbuf.Record
	for {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		err := rd.ReadInto(&rec)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return verdicts
		}
		require.NoError(t, err)
		require.Greater(t, len(rec.RawSample), verdictOffset+3, "short policy event record")
		verdicts = append(verdicts, binary.LittleEndian.Uint32(rec.RawSample[verdictOffset:]))
	}
}

// TestPolicyEventScopeKernel checks what the ingress program writes to
// policy_events for each scope the agent can set in aws_tc_config. A new allowed
// connection writes an ACCEPT record only when the scope is "all". A denied one
// writes its DENY record in both scopes.
func TestPolicyEventScopeKernel(t *testing.T) {
	dir, _ := requireBPFKernelTests(t)
	families := []family{
		{"v4", netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.1.2:80"),
			EVENTS_BINARY, TC_EGRESS_BINARY, []string{TC_INGRESS_BINARY}},
		{"v6", netip.MustParseAddrPort("[fd00::1]:40000"), netip.MustParseAddrPort("[fd00:1::2]:80"),
			EVENTS_V6_BINARY, TC_V6_EGRESS_BINARY, []string{TC_V6_INGRESS_BINARY}},
	}
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			ipv6 := fam.name == "v6"
			verdictOffset := policyEventV4VerdictOffset
			if ipv6 {
				verdictOffset = policyEventV6VerdictOffset
			}
			progs := loadFamily(t, dir, fam, fam.ingressBinaries[0])
			allowTCPPortRule(t, progs.ingress, ipv6)
			// The reader needs a cilium map; duplicate the FD so that map owns its own.
			dupFD, err := unix.Dup(int(progs.events.MapFD))
			require.NoError(t, err)
			ringMap, err := cebpf.NewMapFromFD(dupFD)
			require.NoError(t, err)
			rd, err := ringbuf.NewReader(ringMap)
			require.NoError(t, err)
			t.Cleanup(func() { _ = rd.Close(); _ = ringMap.Close() })

			// Every connection uses a new source port. A repeated flow would be
			// found in conntrack and skip the write sites under test.
			srcPort := fam.client.Port()
			connect := func(dstPort uint16) uint32 {
				t.Helper()
				srcPort++
				seg := tcpSegment{
					src:   netip.AddrPortFrom(fam.client.Addr(), srcPort),
					dst:   netip.AddrPortFrom(fam.pod.Addr(), dstPort),
					seq:   0x11223344,
					flags: tcpFlagSyn,
				}
				verdict, _ := testRun(t, progs.ingressFD, seg.packet())
				return verdict
			}

			require.NoError(t, writeTCConfig(progs.config, false, POLICY_EVENT_SCOPE_ALL))
			assert.Equal(t, uint32(tcActOK), connect(scopeTestAllowedPort), "allowed port passes")
			assert.Equal(t, []uint32{policyEventVerdictAccept}, readPolicyEventVerdicts(t, rd, verdictOffset),
				"scope all: an allowed connection writes ACCEPT")
			assert.Equal(t, uint32(tcActShot), connect(scopeTestDeniedPort), "other port dropped")
			assert.Equal(t, []uint32{policyEventVerdictDeny}, readPolicyEventVerdicts(t, rd, verdictOffset),
				"scope all: a denied connection writes DENY")

			require.NoError(t, writeTCConfig(progs.config, false, POLICY_EVENT_SCOPE_DENY))
			assert.Equal(t, uint32(tcActOK), connect(scopeTestAllowedPort), "allowed port still passes")
			assert.Empty(t, readPolicyEventVerdicts(t, rd, verdictOffset),
				"scope deny: an allowed connection writes nothing")
			assert.Equal(t, uint32(tcActShot), connect(scopeTestDeniedPort), "other port still dropped")
			assert.Equal(t, []uint32{policyEventVerdictDeny}, readPolicyEventVerdicts(t, rd, verdictOffset),
				"scope deny: a denied connection still writes DENY")

			require.NoError(t, writeTCConfig(progs.config, false, POLICY_EVENT_SCOPE_ALL))
		})
	}
}
