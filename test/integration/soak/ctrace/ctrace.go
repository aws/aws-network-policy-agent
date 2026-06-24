// Package ctrace detects the conntrack-cleanup race described in
// github.com/aws/aws-network-policy-agent#462 from the agent's own policy event
// logs.
//
// The race: the agent periodically reconciles its eBPF conntrack map against the
// kernel's. It snapshots the kernel table, then deletes any eBPF entry missing
// from the snapshot. If a connection reuses the same 5-tuple during that delete
// window, the agent deletes an entry the kernel has just reinstalled, and the
// return packet — which relied on that entry to be allowed past an ingress policy
// — is dropped with a NETWORK_POLICY DENY verdict.
//
// The fingerprint is therefore a "Conntrack cleanup Delete" for some 5-tuple
// immediately followed (within a short window) by an ingress DENY on that tuple's
// *return path* — i.e. the reverse 5-tuple, since the delete is logged for the
// outbound flow and the drop is logged for the inbound response. Detector
// correlates the two and reports each matched pair.
//
// This package parses logs only; it has no Kubernetes or AWS dependency, so the
// correlation logic is unit-testable against captured log lines. The agent emits
// these lines as zap JSON (one object per line) when run with
// --enable-policy-event-logs=true.
package ctrace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

// Flow is the 5-tuple the detector keys on. Owner IP and ifindex from the delete
// log are intentionally excluded: the DENY verdict log does not carry them, so
// they cannot participate in correlation.
type Flow struct {
	SrcIP    string
	SrcPort  int
	DstIP    string
	DstPort  int
	Protocol string // "TCP", "UDP", ... as the agent renders it; "" when unknown (delete logs omit a name)
}

// reverse returns the flow with source and destination swapped. A cleanup Delete
// is logged for the outbound flow (src=pod); the racing drop is logged for the
// inbound response (src=peer), so the two correlate only after reversing one side.
func (f Flow) reverse() Flow {
	return Flow{
		SrcIP:   f.DstIP,
		SrcPort: f.DstPort,
		DstIP:   f.SrcIP,
		DstPort: f.SrcPort,
	}
}

// addr is the IP:port pair used to correlate a delete with its reversed drop,
// independent of protocol (the delete log renders protocol as a number, the drop
// log as a name, so protocol cannot be compared directly).
type addr struct {
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
}

func (f Flow) addr() addr {
	return addr{srcIP: f.SrcIP, srcPort: f.SrcPort, dstIP: f.DstIP, dstPort: f.DstPort}
}

// deleteEvent is a parsed "Conntrack cleanup Delete" log line.
type deleteEvent struct {
	at   time.Time
	flow Flow
}

// denyEvent is a parsed ingress NETWORK_POLICY DENY "Flow Info" log line.
type denyEvent struct {
	at   time.Time
	flow Flow
}

// Match is one confirmed instance of the race: a cleanup delete followed within
// the correlation window by an ingress deny on the reversed tuple.
type Match struct {
	// DeletedFlow is the outbound 5-tuple whose eBPF conntrack entry was deleted.
	DeletedFlow Flow
	// DeniedFlow is the inbound return 5-tuple that was then dropped.
	DeniedFlow Flow
	// DeleteAt and DenyAt bound the race window for this pair.
	DeleteAt time.Time
	DenyAt   time.Time
}

// Gap is how long after the delete the deny landed. A short gap is the signature;
// a long one is more likely a coincidental unrelated drop.
func (m Match) Gap() time.Duration { return m.DenyAt.Sub(m.DeleteAt) }

// Detector correlates cleanup deletes with subsequent reversed-tuple ingress
// denies. It is single-pass and order-tolerant: callers feed parsed events in any
// order, and Matches resolves the correlation at the end.
//
// The zero value is not usable; construct with NewDetector.
type Detector struct {
	window  time.Duration
	deletes []deleteEvent
	denies  []denyEvent
}

// DefaultWindow is the maximum delete→deny gap that still counts as the race. The
// issue reports the deny landing "within ~50ms to a few seconds" of the delete;
// 5s leaves margin for log-timestamp jitter without admitting unrelated drops.
const DefaultWindow = 5 * time.Second

// NewDetector returns a Detector that correlates within window. A non-positive
// window falls back to DefaultWindow so a misconfigured caller still gets the
// documented behavior rather than a detector that matches nothing.
func NewDetector(window time.Duration) *Detector {
	if window <= 0 {
		window = DefaultWindow
	}
	return &Detector{window: window}
}

// Observe records one parsed event. Unrelated events (egress denies, allow
// verdicts, non-conntrack logs) are dropped by the parser before they reach here.
func (d *Detector) Observe(at time.Time, flow Flow, kind eventKind) {
	switch kind {
	case kindDelete:
		d.deletes = append(d.deletes, deleteEvent{at: at, flow: flow})
	case kindIngressDeny:
		d.denies = append(d.denies, denyEvent{at: at, flow: flow})
	}
}

// Matches returns every confirmed race instance. A deny matches a delete when the
// deny's tuple equals the delete's reversed tuple and the deny lands in
// (delete, delete+window]. Each deny is attributed to at most one delete — the
// most recent qualifying one — so a burst of deletes on the same tuple does not
// inflate the count beyond the number of observed denies.
func (d *Detector) Matches() []Match {
	// Index deletes by reversed address so each deny needs only a map lookup.
	// A tuple can be deleted repeatedly, so keep a time-ordered slice per key.
	byReverse := make(map[addr][]deleteEvent, len(d.deletes))
	for _, del := range d.deletes {
		key := del.flow.reverse().addr()
		byReverse[key] = append(byReverse[key], del)
	}

	var matches []Match
	for _, deny := range d.denies {
		candidates := byReverse[deny.flow.addr()]
		best, ok := mostRecentWithin(candidates, deny.at, d.window)
		if !ok {
			continue
		}
		matches = append(matches, Match{
			DeletedFlow: best.flow,
			DeniedFlow:  deny.flow,
			DeleteAt:    best.at,
			DenyAt:      deny.at,
		})
	}
	return matches
}

// mostRecentWithin returns the latest delete at or before denyAt and no earlier
// than denyAt-window. Picking the most recent qualifying delete attributes the
// deny to the cleanup pass that most plausibly caused it.
func mostRecentWithin(candidates []deleteEvent, denyAt time.Time, window time.Duration) (deleteEvent, bool) {
	var best deleteEvent
	found := false
	earliest := denyAt.Add(-window)
	for _, c := range candidates {
		if c.at.After(denyAt) || c.at.Before(earliest) {
			continue
		}
		if !found || c.at.After(best.at) {
			best = c
			found = true
		}
	}
	return best, found
}

// eventKind tags a parsed log line for Observe.
type eventKind int

const (
	kindOther eventKind = iota
	kindDelete
	kindIngressDeny
)

// --- parsing of the agent's real zap-JSON policy event logs ---

// logLine is the subset of the agent's zap JSON we read. The agent encodes with
// zap's production config, so the message is under "msg" and the ISO8601
// timestamp under "ts".
type logLine struct {
	Timestamp string `json:"ts"`
	Message   string `json:"msg"`
}

// These patterns match the exact Infof templates the agent emits:
//
//	pkg/ebpf/conntrack/conntrack_client.go:
//	  "Conntrack cleanup Delete - Conntrack Key : Source IP - %s Source port - %d
//	   Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d"
//
//	pkg/ebpf/events/events.go:
//	  "Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s
//	   Verdict: %s Direction: %s Tier: %s"
//
// They are anchored on the leading literal so an unrelated log line that happens
// to contain "Dest IP" cannot be mis-parsed.
var (
	deleteRE = regexp.MustCompile(
		`^Conntrack cleanup Delete - Conntrack Key : ` +
			`Source IP - (\S+) Source port - (\d+) ` +
			`Dest IP - (\S+) Dest port - (\d+) ` +
			`Protocol - (\d+)`)

	flowInfoRE = regexp.MustCompile(
		`^Flow Info: ` +
			`Src IP: (\S+) Src Port: (\d+) ` +
			`Dest IP: (\S+) Dest Port: (\d+) ` +
			`Proto: (\S+) Verdict: (\S+) Direction: (\S+) Tier: (\S+)`)
)

// timeLayouts covers the ISO8601 forms zap's ISO8601TimeEncoder can produce
// across configs (with and without sub-second precision and zone spelling).
var timeLayouts = []string{
	"2006-01-02T15:04:05.000Z0700",
	"2006-01-02T15:04:05Z07:00",
	time.RFC3339Nano,
	time.RFC3339,
}

// ParseLine parses one zap-JSON log line into an event. It returns kindOther for
// any line that is not a conntrack delete or an ingress NETWORK_POLICY deny —
// including egress denies and allow verdicts, which are not part of the race
// fingerprint. A line that is the right kind but has an unparseable timestamp or
// field is a real problem (the format drifted from what we match), so it returns
// an error rather than being silently skipped.
func ParseLine(line string) (at time.Time, flow Flow, kind eventKind, err error) {
	var parsed logLine
	if jsonErr := json.Unmarshal([]byte(line), &parsed); jsonErr != nil {
		// Not JSON: treat as noise rather than failing the whole scan, so a
		// stray non-JSON line in a captured log can't abort detection.
		return time.Time{}, Flow{}, kindOther, nil
	}

	if m := deleteRE.FindStringSubmatch(parsed.Message); m != nil {
		flow, err = flowFromDelete(m)
		if err != nil {
			return time.Time{}, Flow{}, kindOther, err
		}
		at, err = parseTimestamp(parsed.Timestamp)
		if err != nil {
			return time.Time{}, Flow{}, kindOther, err
		}
		return at, flow, kindDelete, nil
	}

	if m := flowInfoRE.FindStringSubmatch(parsed.Message); m != nil {
		// Only ingress DENY verdicts are part of the race; everything else is a
		// legitimate, expected log line.
		verdict, direction := m[6], m[7]
		if verdict != "DENY" || direction != "ingress" {
			return time.Time{}, Flow{}, kindOther, nil
		}
		flow, err = flowFromFlowInfo(m)
		if err != nil {
			return time.Time{}, Flow{}, kindOther, err
		}
		at, err = parseTimestamp(parsed.Timestamp)
		if err != nil {
			return time.Time{}, Flow{}, kindOther, err
		}
		return at, flow, kindIngressDeny, nil
	}

	return time.Time{}, Flow{}, kindOther, nil
}

func flowFromDelete(m []string) (Flow, error) {
	srcPort, err := strconv.Atoi(m[2])
	if err != nil {
		return Flow{}, fmt.Errorf("delete log: source port %q: %w", m[2], err)
	}
	dstPort, err := strconv.Atoi(m[4])
	if err != nil {
		return Flow{}, fmt.Errorf("delete log: dest port %q: %w", m[4], err)
	}
	// Protocol is a number here and a name in the deny log, so it is not used for
	// correlation; we leave Flow.Protocol empty for deletes.
	return Flow{SrcIP: m[1], SrcPort: srcPort, DstIP: m[3], DstPort: dstPort}, nil
}

func flowFromFlowInfo(m []string) (Flow, error) {
	srcPort, err := strconv.Atoi(m[2])
	if err != nil {
		return Flow{}, fmt.Errorf("flow info: src port %q: %w", m[2], err)
	}
	dstPort, err := strconv.Atoi(m[4])
	if err != nil {
		return Flow{}, fmt.Errorf("flow info: dest port %q: %w", m[4], err)
	}
	return Flow{SrcIP: m[1], SrcPort: srcPort, DstIP: m[3], DstPort: dstPort, Protocol: m[5]}, nil
}

func parseTimestamp(ts string) (time.Time, error) {
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, ts); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", ts)
}

// Scan reads zap-JSON log lines from r, feeds each into a Detector built with the
// given window, and returns the confirmed matches. It is the one-call entry point
// the soak harness uses against a captured agent log. A malformed line of the
// right kind aborts the scan with an error (the format drifted); pure noise lines
// are skipped.
func Scan(r io.Reader, window time.Duration) ([]Match, error) {
	detector := NewDetector(window)
	scanner := bufio.NewScanner(r)
	// Policy event lines can be long; raise the per-line cap well above the
	// default 64KiB so a long FQDN/owner field can't truncate a line mid-parse.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		at, flow, kind, err := ParseLine(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		if kind != kindOther {
			detector.Observe(at, flow, kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading agent log: %w", err)
	}
	return detector.Matches(), nil
}
