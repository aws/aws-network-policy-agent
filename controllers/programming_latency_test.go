package controllers

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// histSampleCount reads the cumulative sample count of a package-level
// histogram. Tests assert on before/after deltas so they stay independent of
// execution order and -count=N reruns; do not add t.Parallel() to tests that
// share these histograms.
func histSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	m := &dto.Metric{}
	assert.NoError(t, h.Write(m))
	return m.GetHistogram().GetSampleCount()
}

func triggerAnnotations(triggerTime string) map[string]string {
	if triggerTime == "" {
		return nil
	}
	return map[string]string{LastChangeTriggerTimeAnnotation: triggerTime}
}

func TestChangeTriggerTime(t *testing.T) {
	now := time.Now()
	startedAt := now.Add(-1 * time.Hour)
	fresh := now.Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
	fresher := now.Add(-1 * time.Second).UTC().Format(time.RFC3339Nano)
	beforeStart := now.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	pe1 := EndpointRequest{Endpoint: types.NamespacedName{Name: "pe-1", Namespace: "ns"}, Parent: "np"}
	pe2 := EndpointRequest{Endpoint: types.NamespacedName{Name: "pe-2", Namespace: "ns"}, Parent: "np"}
	pe1UnderOtherParent := EndpointRequest{Endpoint: pe1.Endpoint, Parent: "other-np"}

	type call struct {
		req         EndpointRequest
		triggerTime string
	}
	tests := []struct {
		name     string
		calls    []call
		consumed int
	}{
		{name: "no annotations", calls: []call{{pe1, ""}}, consumed: 0},
		{name: "unparseable annotation", calls: []call{{pe1, "not-a-timestamp"}}, consumed: 0},
		{name: "annotation predates agent start (restart guard)", calls: []call{{pe1, beforeStart}}, consumed: 0},
		{name: "fresh annotation consumed once", calls: []call{{pe1, fresh}}, consumed: 1},
		{
			name:     "repeat reconcile with unchanged annotation is skipped (issue #644)",
			calls:    []call{{pe1, fresh}, {pe1, fresh}, {pe1, fresh}},
			consumed: 1,
		},
		{
			name:     "changed annotation consumed again",
			calls:    []call{{pe1, fresh}, {pe1, fresh}, {pe1, fresher}},
			consumed: 2,
		},
		{
			name:     "same annotation on different PEs consumed per PE",
			calls:    []call{{pe1, fresh}, {pe2, fresh}},
			consumed: 2,
		},
		{
			name:     "a name that moves to another parent is consumed again",
			calls:    []call{{pe1, fresh}, {pe1UnderOtherParent, fresh}},
			consumed: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var consumedTimes sync.Map
			consumed := 0
			for _, c := range tt.calls {
				if _, ok := changeTriggerTime(triggerAnnotations(c.triggerTime), startedAt, c.req, &consumedTimes); ok {
					consumed++
				}
			}
			assert.Equal(t, tt.consumed, consumed)
		})
	}
}

func newTestLatencyTracker() (*programmingLatencyTracker, prometheus.Histogram) {
	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "test_programming_latency_seconds"})
	return newProgrammingLatencyTracker(histogram), histogram
}

// pass runs one successful programming pass for podIdentifier.
func pass(tracker *programmingLatencyTracker, podIdentifier string, wrote bool) {
	tracker.finish(podIdentifier, tracker.begin(podIdentifier), wrote)
}

func TestProgrammingLatencyTracker(t *testing.T) {
	triggeredAt := time.Now().Add(-2 * time.Second)

	t.Run("one sample once every queued identifier is programmed", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(triggeredAt, []string{"a@ns", "b@ns"})

		pass(tracker, "a@ns", true)
		assert.Equal(t, uint64(0), histSampleCount(t, histogram), "b@ns has not landed yet")
		pass(tracker, "b@ns", true)
		assert.Equal(t, uint64(1), histSampleCount(t, histogram))

		pass(tracker, "a@ns", true)
		pass(tracker, "b@ns", true)
		assert.Equal(t, uint64(1), histSampleCount(t, histogram), "later passes do not re-observe a landed change")
		assert.Empty(t, tracker.pending, "nothing is left pending")
	})

	t.Run("a failed pass defers the sample to the retry that lands it", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(triggeredAt, []string{"a@ns"})

		// Failed passes call begin but never finish.
		tracker.begin("a@ns")
		tracker.begin("a@ns")
		assert.Equal(t, uint64(0), histSampleCount(t, histogram))

		pass(tracker, "a@ns", true)
		require.Equal(t, uint64(1), histSampleCount(t, histogram))
		m := &dto.Metric{}
		require.NoError(t, histogram.Write(m))
		assert.GreaterOrEqual(t, m.GetHistogram().GetSampleSum(), 2.0, "the sample covers the time since the trigger, retries included")
	})

	t.Run("a change with nothing written on this node is consumed without a sample", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(triggeredAt, []string{"a@ns", "b@ns"})

		pass(tracker, "a@ns", false)
		pass(tracker, "b@ns", false)
		assert.Equal(t, uint64(0), histSampleCount(t, histogram))
		assert.Empty(t, tracker.pending)
	})

	t.Run("one identifier writing is enough for the change to be measured", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(triggeredAt, []string{"a@ns", "b@ns"})

		pass(tracker, "a@ns", true)
		pass(tracker, "b@ns", false)
		assert.Equal(t, uint64(1), histSampleCount(t, histogram))
	})

	t.Run("a change that queued nothing is not tracked", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(triggeredAt, nil)
		assert.Empty(t, tracker.pending)
		assert.Equal(t, uint64(0), histSampleCount(t, histogram))
	})

	t.Run("a change tracked during a pass waits for the next pass", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		landing := tracker.begin("a@ns")
		tracker.track(triggeredAt, []string{"a@ns"})
		tracker.finish("a@ns", landing, true)
		assert.Equal(t, uint64(0), histSampleCount(t, histogram), "the pass began before the change was queued")

		pass(tracker, "a@ns", true)
		assert.Equal(t, uint64(1), histSampleCount(t, histogram))
	})

	t.Run("two changes landed by one pass record one sample each", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(triggeredAt, []string{"a@ns"})
		tracker.track(triggeredAt.Add(time.Second), []string{"a@ns"})

		pass(tracker, "a@ns", true)
		assert.Equal(t, uint64(2), histSampleCount(t, histogram))
	})

	t.Run("an identifier that never lands holds a bounded number of changes", func(t *testing.T) {
		tracker, _ := newTestLatencyTracker()
		for i := 0; i < 3*maxPendingChangesPerIdentifier; i++ {
			tracker.track(triggeredAt, []string{"stuck@ns"})
		}
		assert.Len(t, tracker.pending["stuck@ns"], maxPendingChangesPerIdentifier)
	})

	t.Run("negative latency (clock skew) is skipped", func(t *testing.T) {
		tracker, histogram := newTestLatencyTracker()
		tracker.track(time.Now().Add(time.Hour), []string{"a@ns"})

		pass(tracker, "a@ns", true)
		assert.Equal(t, uint64(0), histSampleCount(t, histogram))
		assert.Empty(t, tracker.pending, "a skewed change is still consumed")
	})
}

// A reconcile for a slice that no longer belongs to the requested parent forgets the trigger
// time consumed under that parent, so a recreated slice is observed again, and leaves the
// entry under the slice's new parent alone.
func TestReconcile_DepartingSliceForgetsItsTriggerTime(t *testing.T) {
	fx := newPEFixture(t)
	// After the reconciler started, or the restart guard ignores it.
	fresh := time.Now().UTC().Format(time.RFC3339Nano)
	fx.setSlices(sliceSpec{name: "np-1-aaaaa", parent: "beta",
		pods:    []podRef{localPod("web-aaa", "10.1.1.1")},
		ingress: []ruleRef{allow("192.168.90.1/32")}})
	pe := fx.store["np-1-aaaaa"]
	pe.Annotations = triggerAnnotations(fresh)
	fx.store["np-1-aaaaa"] = pe

	alpha, beta := fx.request("np-1-aaaaa", "alpha"), fx.request("np-1-aaaaa", "beta")
	fx.r.lastObservedTriggerTimes.Store(alpha, fresh)

	before := histSampleCount(t, policyProgrammingLatency)
	require.NoError(t, fx.reconcileUnder("np-1-aaaaa", "beta"))
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before)

	require.NoError(t, fx.reconcileUnder("np-1-aaaaa", "alpha"))
	_, tracked := fx.r.lastObservedTriggerTimes.Load(alpha)
	assert.False(t, tracked, "the departed parent's entry must be forgotten")
	_, tracked = fx.r.lastObservedTriggerTimes.Load(beta)
	assert.True(t, tracked, "the new parent's entry must survive the old parent's reconcile")

	require.NoError(t, fx.reconcileUnder("np-1-aaaaa", "beta"))
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before, "a resync does not re-observe")
}
