package schedule

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_DefaultDuration(t *testing.T) {
	s, err := New(Options{})
	require.NoError(t, err)
	assert.Equal(t, DefaultDuration, s.Total())
	assert.Equal(t, DefaultReconcileInterval, s.reconcileInterval)
}

func TestNew_DerivesCadencesAtFourHours(t *testing.T) {
	s, err := New(Options{Total: 4 * time.Hour})
	require.NoError(t, err)

	// At 4h the divisors land on the design's intended values, with the
	// hot-update and sweep cadences pinned by their ceilings.
	assert.Equal(t, 1*time.Hour, s.Interval(AgentKill))         // 4h / 4
	assert.Equal(t, 5*time.Minute, s.Interval(PolicyHotUpdate)) // 4h / 20 = 12m, clamped to 5m ceiling
	assert.Equal(t, 30*time.Minute, s.Interval(NamespaceChurn)) // 4h / 8
	assert.Equal(t, 2*time.Minute, s.Interval(ProbeSweep))      // 4h / 120 = 2m, at ceiling
	assert.Equal(t, 5*time.Minute, s.Interval(TrendSample))     // 4h / 48 = 5m, at ceiling
}

func TestDerive_ClampsToFloorAndCeiling(t *testing.T) {
	tests := []struct {
		name  string
		total time.Duration
		rule  rule
		want  time.Duration
	}{
		{
			name:  "below floor is raised",
			total: 1 * time.Minute,
			rule:  rule{divisor: 120, floor: 15 * time.Second, ceiling: 2 * time.Minute},
			want:  15 * time.Second, // 1m/120 = 0.5s, raised to floor
		},
		{
			name:  "above ceiling is lowered",
			total: 24 * time.Hour,
			rule:  rule{divisor: 20, floor: 1 * time.Minute, ceiling: 5 * time.Minute},
			want:  5 * time.Minute, // 24h/20 = 72m, lowered to ceiling
		},
		{
			name:  "within range is unclamped",
			total: 4 * time.Hour,
			rule:  rule{divisor: 4, floor: 0, ceiling: 0},
			want:  1 * time.Hour,
		},
		{
			name:  "zero ceiling means no upper bound",
			total: 24 * time.Hour,
			rule:  rule{divisor: 8, floor: 2 * time.Minute, ceiling: 0},
			want:  3 * time.Hour, // 24h/8, no ceiling applied
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, derive(tt.total, tt.rule))
		})
	}
}

func TestNew_OverrideBypassesDivisorAndClamp(t *testing.T) {
	s, err := New(Options{
		Total: 4 * time.Hour,
		Overrides: map[Cadence]time.Duration{
			// 10s is below the ProbeSweep floor; an explicit override must still
			// win, because the override exists precisely to pin unusual timings.
			ProbeSweep: 10 * time.Second,
			AgentKill:  90 * time.Minute,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, s.Interval(ProbeSweep))
	assert.Equal(t, 90*time.Minute, s.Interval(AgentKill))
	// Untouched cadences still derive from Total.
	assert.Equal(t, 30*time.Minute, s.Interval(NamespaceChurn))
}

func TestNew_ZeroOverrideIsIgnored(t *testing.T) {
	// A zero override is the map's zero value and must be treated as "not set",
	// otherwise an unset entry would pin the interval to 0 and divide-by-zero in
	// Occurrences.
	s, err := New(Options{
		Total:     4 * time.Hour,
		Overrides: map[Cadence]time.Duration{ProbeSweep: 0},
	})
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, s.Interval(ProbeSweep))
}

func TestNew_RejectsTooShortDuration(t *testing.T) {
	// Two minutes cannot fire 3 hot-updates (floor 1m) or span 2 reconcile cycles
	// (5m each), so New must reject it rather than build a meaningless run.
	_, err := New(Options{Total: 2 * time.Minute})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooShort)
}

func TestNew_RejectsTooFewReconcileCycles(t *testing.T) {
	// Long enough to satisfy every event-count invariant, but the agent's
	// reconcile interval is so large the run spans under two cycles, so the #462
	// race is unreachable and the run must be rejected.
	_, err := New(Options{
		Total:             1 * time.Hour,
		ReconcileInterval: 45 * time.Minute,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooShort)
}

func TestNew_ShortButValidSmokeRun(t *testing.T) {
	// A 20-minute smoke at the default 5m reconcile: 4 reconcile cycles, and every
	// activity clears its minimum. This is the lower bound we expect CI to use.
	s, err := New(Options{Total: 20 * time.Minute})
	require.NoError(t, err)

	for cadence, required := range minEvents {
		assert.GreaterOrEqualf(t, s.Occurrences(cadence), required,
			"%s should fire at least %d times in a 20m smoke", cadence, required)
	}
	assert.GreaterOrEqual(t, s.ReconcileCycles(), minReconcileCycles)
}

func TestValidate_ErrorNamesEveryFailingInvariant(t *testing.T) {
	// The error must enumerate each problem so an operator can see exactly why a
	// duration was rejected, not just that it was.
	s := &Schedule{
		total:             2 * time.Minute,
		reconcileInterval: 5 * time.Minute,
		intervals: map[Cadence]time.Duration{
			AgentKill:       1 * time.Hour,
			PolicyHotUpdate: 1 * time.Minute,
			NamespaceChurn:  2 * time.Minute,
			ProbeSweep:      15 * time.Second,
			TrendSample:     1 * time.Minute,
		},
	}
	err := s.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), AgentKill.String())
	assert.Contains(t, err.Error(), "reconcile cycle")
}

func TestOccurrences_FloorsPartialEvents(t *testing.T) {
	s, err := New(Options{Total: 4 * time.Hour})
	require.NoError(t, err)
	// 4h with a 1h kill interval -> exactly 4 kills.
	assert.Equal(t, 4, s.Occurrences(AgentKill))
}

func TestInterval_PanicsOnUnknownCadence(t *testing.T) {
	s, err := New(Options{Total: 4 * time.Hour})
	require.NoError(t, err)
	assert.Panics(t, func() { s.Interval(Cadence(999)) })
}

func TestCadence_String(t *testing.T) {
	assert.Equal(t, "agent-kill", AgentKill.String())
	assert.Equal(t, "probe-sweep", ProbeSweep.String())
	assert.Equal(t, "cadence(999)", Cadence(999).String())
}

func TestErrTooShort_IsWrapped(t *testing.T) {
	_, err := New(Options{Total: 1 * time.Second})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTooShort))
}
