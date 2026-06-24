package soak

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Violation is a single soak failure: a moment where the agent did something the
// soak forbids (mis-enforced policy, dropped return traffic, leaked BPF state,
// grew memory past budget). Violations carry enough context to debug from the
// report alone.
type Violation struct {
	// Kind groups violations by failure class for the end-of-run summary.
	Kind ViolationKind
	// At is when the violation was observed.
	At time.Time
	// Detail is a human-readable description with the specifics (tuple, node,
	// measured-vs-limit) needed to investigate.
	Detail string
}

// ViolationKind enumerates the soak's failure classes. They map one-to-one to the
// pass/fail criteria in DESIGN.md §5.
type ViolationKind int

const (
	MisEnforcement     ViolationKind = iota // false-allow or false-deny on a probe
	ConntrackRace                           // the #462 delete->deny race fired
	ConnDisruption                          // a long-lived connection broke
	BPFLeak                                 // BPF prog/map count did not return to baseline
	ConntrackGrowth                         // conntrack table grew without bound
	MemoryGrowth                            // NPA container memory grew past budget
	ProgrammingLatency                      // policy took too long to take effect
	RecoveryFailure                         // agent did not recover after a kill
)

func (k ViolationKind) String() string {
	switch k {
	case MisEnforcement:
		return "mis-enforcement"
	case ConntrackRace:
		return "conntrack-race(#462)"
	case ConnDisruption:
		return "connection-disruption"
	case BPFLeak:
		return "bpf-leak"
	case ConntrackGrowth:
		return "conntrack-growth"
	case MemoryGrowth:
		return "memory-growth"
	case ProgrammingLatency:
		return "programming-latency"
	case RecoveryFailure:
		return "recovery-failure"
	default:
		return fmt.Sprintf("violation(%d)", int(k))
	}
}

// Recorder collects violations from the concurrent activity loops. Those loops run
// off the main goroutine, where Ginkgo assertions are unsafe, so they record here
// and the spec asserts on an empty Recorder at the end. It is safe for concurrent
// use.
type Recorder struct {
	mu         sync.Mutex
	violations []Violation
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder { return &Recorder{} }

// Record appends a violation. now is passed in rather than read from the clock so
// callers (and tests) control the timestamp and the recorder stays free of a
// hidden time dependency.
func (r *Recorder) Record(kind ViolationKind, now time.Time, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.violations = append(r.violations, Violation{
		Kind:   kind,
		At:     now,
		Detail: fmt.Sprintf(format, args...),
	})
}

// Len reports how many violations have been recorded.
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.violations)
}

// CountByKind returns the number of recorded violations of a given kind. It lets
// the spec assert on specific failure classes (e.g. "zero #462 races") rather than
// only on the total.
func (r *Recorder) CountByKind(kind ViolationKind) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.violations {
		if v.Kind == kind {
			n++
		}
	}
	return n
}

// Summary renders all violations grouped by kind and ordered by time, suitable for
// a failure message. It returns "" when there are none, so the caller can use a
// non-empty summary as both the pass/fail signal and the report.
func (r *Recorder) Summary() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.violations) == 0 {
		return ""
	}

	byKind := make(map[ViolationKind][]Violation)
	for _, v := range r.violations {
		byKind[v.Kind] = append(byKind[v.Kind], v)
	}

	kinds := make([]ViolationKind, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })

	var b []byte
	b = append(b, fmt.Sprintf("%d soak violation(s):\n", len(r.violations))...)
	for _, k := range kinds {
		vs := byKind[k]
		sort.Slice(vs, func(i, j int) bool { return vs[i].At.Before(vs[j].At) })
		b = append(b, fmt.Sprintf("  %s (%d):\n", k, len(vs))...)
		for _, v := range vs {
			b = append(b, fmt.Sprintf("    [%s] %s\n", v.At.Format(time.RFC3339), v.Detail)...)
		}
	}
	return string(b)
}
