package soak

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecorder_Empty(t *testing.T) {
	r := NewRecorder()
	assert.Equal(t, 0, r.Len())
	assert.Empty(t, r.Summary())
}

func TestRecorder_RecordsAndCounts(t *testing.T) {
	r := NewRecorder()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	r.Record(MisEnforcement, now, "deny probe to %s reached", "10.0.0.1")
	r.Record(ConntrackRace, now.Add(time.Second), "delete->deny on %s:%d", "10.0.0.5", 42188)
	r.Record(ConntrackRace, now.Add(2*time.Second), "again")

	assert.Equal(t, 3, r.Len())
	assert.Equal(t, 1, r.CountByKind(MisEnforcement))
	assert.Equal(t, 2, r.CountByKind(ConntrackRace))
	assert.Equal(t, 0, r.CountByKind(MemoryGrowth))
}

func TestRecorder_SummaryGroupsByKindAndOrdersByTime(t *testing.T) {
	r := NewRecorder()
	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	r.Record(ConntrackRace, base.Add(3*time.Second), "third")
	r.Record(MisEnforcement, base.Add(1*time.Second), "first")
	r.Record(ConntrackRace, base.Add(2*time.Second), "second")

	summary := r.Summary()
	assert.Contains(t, summary, "3 soak violation(s)")
	assert.Contains(t, summary, "mis-enforcement (1)")
	assert.Contains(t, summary, "conntrack-race(#462) (2)")
	// Within the conntrack-race group, "second" must appear before "third".
	assert.Less(t, indexOf(summary, "second"), indexOf(summary, "third"))
}

func TestRecorder_ConcurrentRecord(t *testing.T) {
	r := NewRecorder()
	now := time.Now()
	const goroutines, perGoroutine = 8, 100

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				r.Record(BPFLeak, now, "leak")
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, goroutines*perGoroutine, r.Len())
	assert.Equal(t, goroutines*perGoroutine, r.CountByKind(BPFLeak))
}

func TestViolationKind_String(t *testing.T) {
	assert.Equal(t, "conntrack-race(#462)", ConntrackRace.String())
	assert.Equal(t, "memory-growth", MemoryGrowth.String())
	assert.Equal(t, "violation(99)", ViolationKind(99).String())
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
