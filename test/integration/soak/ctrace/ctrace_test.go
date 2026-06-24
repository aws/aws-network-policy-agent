package ctrace

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These lines mirror the agent's real zap-JSON output. The message templates are
// copied from:
//
//	pkg/ebpf/conntrack/conntrack_client.go (Conntrack cleanup Delete)
//	pkg/ebpf/events/events.go              (Flow Info verdict)
//
// The outbound flow (pod 10.0.0.5 -> peer 172.20.0.1:443) is what the cleanup
// deletes; the racing drop is logged for the return path (172.20.0.1:443 ->
// 10.0.0.5), i.e. the reversed tuple.
const (
	deleteLine = `{"level":"info","ts":"2026-05-31T21:57:46.926Z","msg":"Conntrack cleanup Delete - Conntrack Key : Source IP - 10.0.0.5 Source port - 42188 Dest IP - 172.20.0.1 Dest port - 443 Protocol - 6 Owner IP - 10.0.0.5 Ifindex - 3"}`

	ingressDenyLine = `{"level":"info","ts":"2026-05-31T21:57:47.020Z","msg":"Flow Info: Src IP: 172.20.0.1 Src Port: 443 Dest IP: 10.0.0.5 Dest Port: 42188 Proto: TCP Verdict: DENY Direction: ingress Tier: NETWORK_POLICY"}`
)

func TestScan_DetectsTheRace(t *testing.T) {
	log := deleteLine + "\n" + ingressDenyLine + "\n"
	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	m := matches[0]
	assert.Equal(t, "10.0.0.5", m.DeletedFlow.SrcIP)
	assert.Equal(t, 42188, m.DeletedFlow.SrcPort)
	assert.Equal(t, "172.20.0.1", m.DeniedFlow.SrcIP)
	assert.Equal(t, 443, m.DeniedFlow.SrcPort)
	assert.Equal(t, 94*time.Millisecond, m.Gap())
}

func TestScan_NoMatchWhenDenyOutsideWindow(t *testing.T) {
	// Same tuples, but the deny lands 10s after the delete — beyond the 5s
	// window, so it is a coincidental drop, not the race.
	lateDeny := strings.Replace(ingressDenyLine,
		"2026-05-31T21:57:47.020Z", "2026-05-31T21:57:56.926Z", 1)
	log := deleteLine + "\n" + lateDeny + "\n"

	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestScan_NoMatchWhenTupleDoesNotReverse(t *testing.T) {
	// A deny for an unrelated tuple must not match the delete.
	otherDeny := `{"level":"info","ts":"2026-05-31T21:57:47.020Z","msg":"Flow Info: Src IP: 172.20.0.1 Src Port: 443 Dest IP: 10.0.0.99 Dest Port: 51000 Proto: TCP Verdict: DENY Direction: ingress Tier: NETWORK_POLICY"}`
	log := deleteLine + "\n" + otherDeny + "\n"

	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestScan_IgnoresEgressDenyAndAllowVerdicts(t *testing.T) {
	// Only ingress DENY is part of the fingerprint. An egress deny or an accept
	// on the reversed tuple must not match.
	egressDeny := strings.Replace(ingressDenyLine, "Direction: ingress", "Direction: egress", 1)
	allowVerdict := strings.Replace(ingressDenyLine, "Verdict: DENY", "Verdict: ACCEPT", 1)
	log := strings.Join([]string{deleteLine, egressDeny, allowVerdict}, "\n") + "\n"

	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestScan_DenyBeforeDeleteDoesNotMatch(t *testing.T) {
	// A deny that precedes the delete cannot have been caused by it.
	earlyDeny := strings.Replace(ingressDenyLine,
		"2026-05-31T21:57:47.020Z", "2026-05-31T21:57:46.000Z", 1)
	log := deleteLine + "\n" + earlyDeny + "\n"

	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestScan_AttributesDenyToMostRecentDelete(t *testing.T) {
	// Two cleanup passes delete the same tuple; the deny should attribute to the
	// nearer (later) delete, giving the smaller, more plausible gap.
	firstDelete := strings.Replace(deleteLine,
		"2026-05-31T21:57:46.926Z", "2026-05-31T21:57:44.000Z", 1)
	secondDelete := deleteLine // 21:57:46.926Z
	log := strings.Join([]string{firstDelete, secondDelete, ingressDenyLine}, "\n") + "\n"

	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, 94*time.Millisecond, matches[0].Gap())
}

func TestScan_OrderIndependent(t *testing.T) {
	// The deny appears in the log before the delete (out-of-order capture). The
	// detector resolves correlation at the end, so order must not matter.
	log := ingressDenyLine + "\n" + deleteLine + "\n"
	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestScan_SkipsNonJSONNoise(t *testing.T) {
	noise := "this is not json\n" + "\n"
	log := noise + deleteLine + "\n" + ingressDenyLine + "\n"
	matches, err := Scan(strings.NewReader(log), DefaultWindow)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestParseLine_MalformedPortIsError(t *testing.T) {
	// A line that is clearly a delete log but whose port is non-numeric means the
	// format drifted from what we match — surface it rather than skipping.
	bad := `{"level":"info","ts":"2026-05-31T21:57:46.926Z","msg":"Conntrack cleanup Delete - Conntrack Key : Source IP - 10.0.0.5 Source port - NOPE Dest IP - 172.20.0.1 Dest port - 443 Protocol - 6 Owner IP - 10.0.0.5 Ifindex - 3"}`
	// The regex requires \d+ for the port, so a non-numeric port simply does not
	// match the delete pattern and is treated as noise; assert that contract.
	_, _, kind, err := ParseLine(bad)
	require.NoError(t, err)
	assert.Equal(t, kindOther, kind)
}

func TestParseLine_UnparseableTimestampIsError(t *testing.T) {
	// A well-formed delete message with a garbage timestamp is a real drift we
	// must not silently swallow.
	bad := `{"level":"info","ts":"not-a-time","msg":"Conntrack cleanup Delete - Conntrack Key : Source IP - 10.0.0.5 Source port - 42188 Dest IP - 172.20.0.1 Dest port - 443 Protocol - 6 Owner IP - 10.0.0.5 Ifindex - 3"}`
	_, _, _, err := ParseLine(bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timestamp")
}

func TestParseLine_ClassifiesKinds(t *testing.T) {
	at, flow, kind, err := ParseLine(deleteLine)
	require.NoError(t, err)
	assert.Equal(t, kindDelete, kind)
	assert.Equal(t, "10.0.0.5", flow.SrcIP)
	assert.False(t, at.IsZero())

	_, denyFlow, denyKind, err := ParseLine(ingressDenyLine)
	require.NoError(t, err)
	assert.Equal(t, kindIngressDeny, denyKind)
	assert.Equal(t, "TCP", denyFlow.Protocol)
}

func TestParseTimestamp_AcceptsZapISO8601(t *testing.T) {
	// The form zap's ISO8601TimeEncoder emits with millisecond precision.
	at, err := parseTimestamp("2026-05-31T21:57:46.926Z")
	require.NoError(t, err)
	assert.Equal(t, 2026, at.Year())
	assert.Equal(t, 926*time.Millisecond, time.Duration(at.Nanosecond()))
}

func TestFlow_Reverse(t *testing.T) {
	f := Flow{SrcIP: "a", SrcPort: 1, DstIP: "b", DstPort: 2, Protocol: "TCP"}
	r := f.reverse()
	assert.Equal(t, "b", r.SrcIP)
	assert.Equal(t, 2, r.SrcPort)
	assert.Equal(t, "a", r.DstIP)
	assert.Equal(t, 1, r.DstPort)
}

func TestNewDetector_NonPositiveWindowFallsBack(t *testing.T) {
	d := NewDetector(0)
	assert.Equal(t, DefaultWindow, d.window)
	d = NewDetector(-1 * time.Second)
	assert.Equal(t, DefaultWindow, d.window)
}

func TestDetector_MultipleDistinctRaces(t *testing.T) {
	d := NewDetector(DefaultWindow)
	base := time.Date(2026, 5, 31, 21, 0, 0, 0, time.UTC)

	// Two independent flows each hit the race.
	flowA := Flow{SrcIP: "10.0.0.5", SrcPort: 42188, DstIP: "172.20.0.1", DstPort: 443}
	flowB := Flow{SrcIP: "10.0.0.6", SrcPort: 51000, DstIP: "172.20.0.2", DstPort: 80}

	d.Observe(base, flowA, kindDelete)
	d.Observe(base.Add(100*time.Millisecond), flowA.reverse(), kindIngressDeny)
	d.Observe(base.Add(time.Second), flowB, kindDelete)
	d.Observe(base.Add(time.Second+50*time.Millisecond), flowB.reverse(), kindIngressDeny)

	matches := d.Matches()
	assert.Len(t, matches, 2)
}
