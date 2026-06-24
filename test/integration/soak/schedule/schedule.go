// Package schedule turns a single soak duration into the full set of activity
// cadences the harness runs on, and proves up front that the chosen duration can
// actually exercise every activity at least once.
//
// Duration is the master knob. Every periodic activity (agent kills, policy
// hot-updates, namespace churn, probe sweeps, trend sampling) is expressed as a
// fraction of the total duration and then clamped to a sane floor/ceiling. The
// effect is that the same suite is correct whether it runs for 20 minutes or 24
// hours: a short smoke run still triggers at least one of every rare-but-important
// event instead of silently skipping them, and a long run does not drown in
// needlessly frequent ones.
//
// The package is deliberately free of Kubernetes, AWS, and time-of-day
// dependencies so the derivation and its invariants can be unit-tested offline.
package schedule

import (
	"errors"
	"fmt"
	"time"
)

// Cadence names one periodic activity in the soak loop. Cadences are derived from
// the total duration rather than configured directly so that callers reason about
// "how long should this soak run" instead of hand-tuning a dozen intervals.
type Cadence int

const (
	// AgentKill deletes the agent pod on one node, then validates recovery.
	AgentKill Cadence = iota
	// PolicyHotUpdate mutates a live NetworkPolicy in place.
	PolicyHotUpdate
	// NamespaceChurn creates and tears down a namespace and its workloads.
	NamespaceChurn
	// ProbeSweep runs the full allow/deny probe matrix once.
	ProbeSweep
	// TrendSample captures BPF, memory, and conntrack counts for trend analysis.
	TrendSample
)

func (c Cadence) String() string {
	switch c {
	case AgentKill:
		return "agent-kill"
	case PolicyHotUpdate:
		return "policy-hot-update"
	case NamespaceChurn:
		return "namespace-churn"
	case ProbeSweep:
		return "probe-sweep"
	case TrendSample:
		return "trend-sample"
	default:
		return fmt.Sprintf("cadence(%d)", int(c))
	}
}

// rule describes how one cadence is derived from the total duration: an integer
// divisor, then clamped into [floor, ceiling]. A zero ceiling means "no ceiling".
//
// Divisors are chosen so that at the 4h default the cadences land on the values
// the design calls for (kill ~1h, hot-update ~12m clamped to 5m, sweep ~2m), and
// so that even a short run clears the minimum-event invariants in Validate.
type rule struct {
	divisor int
	floor   time.Duration
	ceiling time.Duration
}

var rules = map[Cadence]rule{
	AgentKill:       {divisor: 4, floor: 0, ceiling: 0},
	PolicyHotUpdate: {divisor: 20, floor: 1 * time.Minute, ceiling: 5 * time.Minute},
	NamespaceChurn:  {divisor: 8, floor: 2 * time.Minute, ceiling: 0},
	ProbeSweep:      {divisor: 120, floor: 15 * time.Second, ceiling: 2 * time.Minute},
	TrendSample:     {divisor: 48, floor: 1 * time.Minute, ceiling: 5 * time.Minute},
}

// minEvents is the number of times each activity must fire over the run for the
// soak to be meaningful. These are the invariants Validate enforces; they are the
// reason a too-short duration is rejected at startup rather than silently
// producing a run that never killed the agent or never completed a churn cycle.
var minEvents = map[Cadence]int{
	AgentKill:       1,
	PolicyHotUpdate: 3,
	NamespaceChurn:  1,
	ProbeSweep:      5,
	TrendSample:     3,
}

// Options configures a Schedule. The zero value is usable: Total falls back to
// DefaultDuration and every Override is optional. A non-zero Override pins that
// cadence's interval exactly, bypassing both the divisor and the clamp — this is
// the escape hatch for reproducing a specific timing without rescaling the run.
type Options struct {
	// Total is the steady-state soak window. Setup and teardown happen outside
	// it. Defaults to DefaultDuration when zero.
	Total time.Duration

	// Overrides pins specific cadence intervals. A cadence absent from the map
	// (or mapped to zero) is derived from Total instead.
	Overrides map[Cadence]time.Duration

	// ReconcileInterval is the agent's conntrack-cache cleanup period. It is not
	// a cadence the harness drives; it is supplied so Validate can guarantee the
	// run spans enough reconcile cycles for the #462 cleanup race to be
	// reachable. Defaults to DefaultReconcileInterval when zero.
	ReconcileInterval time.Duration
}

const (
	// DefaultDuration is the soak window when none is given: long enough to cross
	// several reconcile cycles and accumulate a real memory trend.
	DefaultDuration = 4 * time.Hour

	// DefaultReconcileInterval mirrors the agent's conntrack-cache-cleanup-period
	// default of 300s. Keep in sync with pkg/config.defaultConntrackCacheCleanupPeriod.
	DefaultReconcileInterval = 5 * time.Minute

	// minReconcileCycles is how many agent cleanup cycles the run must span for
	// the cleanup-vs-reuse race window (GitHub #462) to actually occur.
	minReconcileCycles = 2
)

// Schedule is the resolved set of cadences for one soak run. It is immutable once
// built; callers read intervals through Interval and trust that Validate has
// already rejected any duration that cannot exercise every activity.
type Schedule struct {
	total             time.Duration
	reconcileInterval time.Duration
	intervals         map[Cadence]time.Duration
}

// New resolves opts into a Schedule and validates it. It returns an error rather
// than a partially-built Schedule when the duration is too short to exercise every
// activity, so the caller fails fast at startup instead of part-way through a
// multi-hour run that was never going to be meaningful.
func New(opts Options) (*Schedule, error) {
	total := opts.Total
	if total <= 0 {
		total = DefaultDuration
	}
	reconcile := opts.ReconcileInterval
	if reconcile <= 0 {
		reconcile = DefaultReconcileInterval
	}

	s := &Schedule{
		total:             total,
		reconcileInterval: reconcile,
		intervals:         make(map[Cadence]time.Duration, len(rules)),
	}
	for cadence, r := range rules {
		if override, ok := opts.Overrides[cadence]; ok && override > 0 {
			s.intervals[cadence] = override
			continue
		}
		s.intervals[cadence] = derive(total, r)
	}

	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// derive computes total/divisor and clamps it into the rule's [floor, ceiling].
func derive(total time.Duration, r rule) time.Duration {
	interval := total / time.Duration(r.divisor)
	if r.floor > 0 && interval < r.floor {
		interval = r.floor
	}
	if r.ceiling > 0 && interval > r.ceiling {
		interval = r.ceiling
	}
	return interval
}

// Total returns the steady-state soak window.
func (s *Schedule) Total() time.Duration { return s.total }

// Interval returns the resolved interval for a cadence. It panics on an unknown
// cadence: every Cadence constant is populated in New, so a miss means the caller
// passed a value that is not a Cadence, which is a programming error, not a
// runtime condition to handle.
func (s *Schedule) Interval(c Cadence) time.Duration {
	interval, ok := s.intervals[c]
	if !ok {
		panic(fmt.Sprintf("schedule: no interval for %v", c))
	}
	return interval
}

// Occurrences reports how many times a cadence fires over the full run. It floors
// the result: a cadence that fires once at the very start of the window counts as
// one occurrence, not two.
func (s *Schedule) Occurrences(c Cadence) int {
	return int(s.total / s.Interval(c))
}

// ReconcileCycles reports how many agent cleanup cycles the run spans. The #462
// race needs at least minReconcileCycles to be reachable.
func (s *Schedule) ReconcileCycles() int {
	return int(s.total / s.reconcileInterval)
}

// ErrTooShort is returned by Validate (and therefore New) when the duration cannot
// satisfy the minimum-event invariants. Callers can test for it with errors.Is.
var ErrTooShort = errors.New("soak duration too short to exercise every activity")

// Validate enforces the invariants that make a run meaningful: every activity
// fires at least its required number of times, and the run spans enough reconcile
// cycles for the #462 cleanup race to occur. It is called by New; it is exported
// so a caller that mutates Options across runs can re-check without rebuilding.
func (s *Schedule) Validate() error {
	var problems []string

	for cadence, required := range minEvents {
		if got := s.Occurrences(cadence); got < required {
			problems = append(problems, fmt.Sprintf(
				"%s fires %d time(s), need >= %d (interval %s over %s)",
				cadence, got, required, s.Interval(cadence), s.total))
		}
	}

	if cycles := s.ReconcileCycles(); cycles < minReconcileCycles {
		problems = append(problems, fmt.Sprintf(
			"run spans %d reconcile cycle(s), need >= %d for the #462 cleanup race "+
				"(duration %s / reconcile %s)",
			cycles, minReconcileCycles, s.total, s.reconcileInterval))
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrTooShort, problems)
}
