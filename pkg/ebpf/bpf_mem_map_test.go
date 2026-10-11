package ebpf

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// sdkErr formats errno the way aws-ebpf-sdk-go does (%s, not %w).
func sdkErr(errno unix.Errno) error {
	return fmt.Errorf("unable to update map: %s", errno)
}

// fakeBpfMapOps fakes the kernel map and injects per-key errors.
type fakeBpfMapOps struct {
	kernel map[string][]byte

	// updateErrs[key] gives one result per attempt; the last one repeats.
	updateErrs map[string][]error
	deleteErrs map[string][]error

	updateCalls map[string]int
	deleteCalls map[string]int
}

func newFakeOps() *fakeBpfMapOps {
	return &fakeBpfMapOps{
		kernel:      map[string][]byte{},
		updateErrs:  map[string][]error{},
		deleteErrs:  map[string][]error{},
		updateCalls: map[string]int{},
		deleteCalls: map[string]int{},
	}
}

func (f *fakeBpfMapOps) UpdateMapEntry(key, value []byte) error {
	k := string(key)
	f.updateCalls[k]++

	if errs := f.updateErrs[k]; len(errs) > 0 {
		i := min(f.updateCalls[k], len(errs)) - 1
		if err := errs[i]; err != nil {
			return err
		}
	}

	f.kernel[k] = append([]byte(nil), value...)
	return nil
}

func (f *fakeBpfMapOps) DeleteMapEntry(key []byte) error {
	k := string(key)
	f.deleteCalls[k]++
	if errs := f.deleteErrs[k]; len(errs) > 0 {
		i := min(f.deleteCalls[k], len(errs)) - 1
		if err := errs[i]; err != nil {
			return err
		}
	}
	delete(f.kernel, k)
	return nil
}

func (f *fakeBpfMapOps) GetMapEntry(key, value []byte) error { return nil }
func (f *fakeBpfMapOps) GetAllMapKeys() ([]string, error)    { return nil, nil }

// newTestMap returns a map whose kernel and shadow contents are both seeded.
func newTestMap(f *fakeBpfMapOps, seed map[string][]byte) *InMemoryBpfMap {
	contents := map[string][]byte{}
	for k, v := range seed {
		contents[k] = v
		f.kernel[k] = v
	}
	return &InMemoryBpfMap{
		bpfMap:   &maps.BpfMap{MapID: 1},
		ops:      f,
		contents: contents,
	}
}

// recordSleeps replaces mapRetrySleep with a recorder that returns the total.
func recordSleeps(t *testing.T) *time.Duration {
	t.Helper()
	var total time.Duration
	prev := mapRetrySleep
	mapRetrySleep = func(d time.Duration) { total += d }
	t.Cleanup(func() { mapRetrySleep = prev })
	return &total
}

// key and val mirror NPA's 8-byte LPM trie key and an 8-byte value.
func key(n byte) string { return string([]byte{n, 0, 0, 0, 0, 0, 0, 0}) }
func val(n byte) []byte { return []byte{n, 0, 0, 0, 0, 0, 0, 0} }

// A transient ENOMEM is retried immediately, without sleeping.
func TestBulkRefresh_TransientENOMEMRecoversWithoutSleeping(t *testing.T) {
	f := newFakeOps()
	f.updateErrs[key(1)] = []error{sdkErr(unix.ENOMEM), nil}
	m := newTestMap(f, nil)
	slept := recordSleeps(t)

	err := m.BulkRefresh(map[string][]byte{key(1): val(1)})

	assert.NoError(t, err)
	assert.Equal(t, 2, f.updateCalls[key(1)], "should succeed on the first retry")
	assert.Equal(t, val(1), f.kernel[key(1)])
	assert.Equal(t, val(1), m.contents[key(1)])
	assert.Zero(t, *slept, "first retry must not sleep")
}

// One failing key must not stop the other updates or the deletes.
func TestBulkRefresh_OneFailingKeyDoesNotAbandonTheRefresh(t *testing.T) {
	f := newFakeOps()
	f.updateErrs[key(1)] = []error{sdkErr(unix.ENOMEM)}
	m := newTestMap(f, map[string][]byte{key(8): val(8), key(9): val(9)})

	err := m.BulkRefresh(map[string][]byte{
		key(1): val(1), // fails permanently
		key(2): val(2),
		key(3): val(3),
		key(4): val(4),
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot allocate memory")

	for _, n := range []byte{2, 3, 4} {
		assert.Equal(t, val(n), f.kernel[key(n)], "add %d must land despite the failing key", n)
		assert.Equal(t, val(n), m.contents[key(n)])
	}
	assert.NotContains(t, f.kernel, key(1))
	assert.NotContains(t, m.contents, key(1))

	for _, n := range []byte{8, 9} {
		assert.NotContains(t, f.kernel, key(n), "stale entry %d must be deleted", n)
		assert.NotContains(t, m.contents, key(n))
		assert.Equal(t, 1, f.deleteCalls[key(n)])
	}
}

// Permanent errnos are not retried.
func TestBulkRefresh_PermanentErrnosAreNotRetried(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EINVAL, unix.ENOSPC, unix.EBADF} {
		t.Run(unix.ErrnoName(errno), func(t *testing.T) {
			f := newFakeOps()
			f.updateErrs[key(1)] = []error{sdkErr(errno)}
			m := newTestMap(f, nil)
			slept := recordSleeps(t)

			err := m.BulkRefresh(map[string][]byte{key(1): val(1)})

			assert.Error(t, err)
			assert.Equal(t, 1, f.updateCalls[key(1)], "must not retry a permanent errno")
			assert.Zero(t, *slept, "a permanent errno must not sleep")
		})
	}
}

// The sleep budget and retried-entry cap bound the time spent under the lock.
func TestBulkRefresh_RetryBudgetBoundsTheLockHold(t *testing.T) {
	f := newFakeOps()
	desired := map[string][]byte{}
	for i := range 200 {
		k := key(byte(i))
		desired[k] = val(byte(i))
		f.updateErrs[k] = []error{sdkErr(unix.ENOMEM)}
	}
	m := newTestMap(f, nil)
	slept := recordSleeps(t)

	err := m.BulkRefresh(desired)

	assert.Error(t, err)
	assert.LessOrEqual(t, *slept, mapRetrySleepBudget,
		"total sleep must stay within mapRetrySleepBudget, not scale with key count")

	retried := 0
	for k := range desired {
		if f.updateCalls[k] > 1 {
			retried++
		}
	}
	assert.LessOrEqual(t, retried, maxRetriedEntriesPerRefresh)
}

// ENOENT on delete is success.
func TestBulkRefresh_ENOENTOnDeleteIsSuccess(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8)})
	f.deleteErrs[key(8)] = []error{sdkErr(unix.ENOENT)}

	err := m.BulkRefresh(map[string][]byte{})

	assert.NoError(t, err, "an already-absent key must not be reported as a failure")
	assert.NotContains(t, m.contents, key(8), "shadow map must drop the key so it is not re-swept forever")
}

// A real delete failure is returned.
func TestBulkRefresh_RealDeleteFailureIsSurfaced(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8), key(9): val(9)})
	f.deleteErrs[key(8)] = []error{sdkErr(unix.EPERM)}

	err := m.BulkRefresh(map[string][]byte{})

	assert.Error(t, err)
	assert.Contains(t, m.contents, key(8), "a key still in the kernel must stay in the shadow map")
	assert.Equal(t, 1, f.deleteCalls[key(9)])
	assert.NotContains(t, m.contents, key(9))
}

// Transient errnos on delete are retried too.
func TestBulkRefresh_TransientDeleteErrnoIsRetried(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8)})
	f.deleteErrs[key(8)] = []error{sdkErr(unix.ENOMEM), nil}

	err := m.BulkRefresh(map[string][]byte{})

	assert.NoError(t, err, "a transient delete errno must not reach the CNI pod-add path")
	assert.Equal(t, 2, f.deleteCalls[key(8)], "delete should be retried once")
	assert.NotContains(t, f.kernel, key(8))
	assert.NotContains(t, m.contents, key(8))
}

// ENOENT on delete removes the key from the shadow map.
func TestBulkRefresh_ENOENTOnDeleteLeavesNoKernelEntry(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8)})
	delete(f.kernel, key(8)) // the kernel entry really is gone
	f.deleteErrs[key(8)] = []error{sdkErr(unix.ENOENT)}

	assert.NoError(t, m.BulkRefresh(map[string][]byte{}))
	assert.NotContains(t, f.kernel, key(8), "kernel must not retain the entry")
	assert.NotContains(t, m.contents, key(8), "shadow map must drop it so it stops being re-swept")
}

// An empty key is dropped instead of failing every refresh.
func TestBulkRefresh_UnusableEntriesAreDroppedNotLooped(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{"": val(1)})

	assert.NoError(t, m.BulkRefresh(map[string][]byte{}), "an unusable entry must not error forever")
	assert.NotContains(t, m.contents, "", "it must be dropped from the shadow map")
	assert.NoError(t, m.BulkRefresh(map[string][]byte{}), "and must not reappear on the next refresh")
}

// A persistent errno stops the refresh after maxFailuresPerRefresh failures.
func TestBulkRefresh_SystemicErrnoIsBounded(t *testing.T) {
	f := newFakeOps()
	desired := map[string][]byte{}
	for i := range 200 {
		k := key(byte(i))
		desired[k] = val(byte(i))
		f.updateErrs[k] = []error{sdkErr(unix.ENOSPC)} // permanent: no retries, no sleep
	}
	m := newTestMap(f, nil)

	err := m.BulkRefresh(desired)

	assert.Error(t, err)
	attempted := 0
	for k := range desired {
		attempted += f.updateCalls[k]
	}
	assert.LessOrEqual(t, attempted, maxFailuresPerRefresh+1,
		"must stop after maxFailuresPerRefresh instead of walking all 200 keys")
	assert.Contains(t, err.Error(), "deferred to the next reconcile",
		"truncation must be reported, never silent")
}

func TestRetryTransientMutation(t *testing.T) {
	t.Run("transient errno is absorbed with no sleep on the first retry", func(t *testing.T) {
		calls := 0
		budget := retryBudget{sleep: mapRetrySleepBudget}
		slept := recordSleeps(t)
		err := retryTransientMutation("test", 1, func() error {
			calls++
			if calls == 1 {
				return sdkErr(unix.ENOMEM)
			}
			return nil
		}, &budget)
		assert.NoError(t, err)
		assert.Equal(t, 2, calls)
		assert.Zero(t, *slept, "the first retry must not sleep")
	})

	t.Run("permanent errno is not retried", func(t *testing.T) {
		calls := 0
		budget := retryBudget{sleep: mapRetrySleepBudget}
		err := retryTransientMutation("test", 1, func() error {
			calls++
			return sdkErr(unix.EINVAL)
		}, &budget)
		assert.Error(t, err)
		assert.Equal(t, 1, calls, "EINVAL must burn no budget")
	})

	t.Run("persistent transient errno gives up bounded and reports the errno", func(t *testing.T) {
		calls := 0
		budget := retryBudget{sleep: mapRetrySleepBudget}
		err := retryTransientMutation("test", 1, func() error {
			calls++
			return sdkErr(unix.ENOMEM)
		}, &budget)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot allocate memory")
		assert.LessOrEqual(t, calls, 1+len(mapUpdateRetryDelays))
		assert.Greater(t, calls, 1, "a transient errno must be retried at least once")
	})
}

// Failed updates must not use up the delete phase's failure cap.
func TestBulkRefresh_FailedUpdatesDoNotSuppressDeleteSweep(t *testing.T) {
	f := newFakeOps()
	recordSleeps(t)

	stale := map[string][]byte{key(250): val(250), key(251): val(251)}
	m := newTestMap(f, stale)

	desired := map[string][]byte{}
	for i := range maxFailuresPerRefresh + 10 {
		k := key(byte(i))
		desired[k] = val(byte(i))
		f.updateErrs[k] = []error{sdkErr(unix.ENOSPC)}
	}

	err := m.BulkRefresh(desired)
	assert.Error(t, err, "the failed adds must still be reported")

	for k := range stale {
		assert.Equal(t, 1, f.deleteCalls[k], "every stale key must be swept despite the failed updates")
		assert.NotContains(t, f.kernel, k, "the revoked entry must be gone from the kernel map")
		assert.NotContains(t, m.contents, k, "and from the shadow map")
	}
}

// Each final failure is counted with its errno label.
func TestBulkRefresh_FinalFailuresAreCountedByErrno(t *testing.T) {
	f := newFakeOps()
	recordSleeps(t)
	m := newTestMap(f, nil)
	f.updateErrs[key(1)] = []error{sdkErr(unix.ENOSPC)}

	before := counterValue(t, bpfMapOpErr.WithLabelValues("update", "ENOSPC"))
	assert.Error(t, m.BulkRefresh(map[string][]byte{key(1): val(1)}))
	assert.Equal(t, 1.0, counterValue(t, bpfMapOpErr.WithLabelValues("update", "ENOSPC"))-before)
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	assert.NoError(t, c.Write(m))
	return m.GetCounter().GetValue()
}

// At most maxRetriedEntriesPerRefresh entries are retried, even when retries
// would succeed.
func TestBulkRefresh_RetriedEntryCapHoldsWhenRetriesSucceed(t *testing.T) {
	f := newFakeOps()
	recordSleeps(t)
	desired := map[string][]byte{}
	for i := range maxRetriedEntriesPerRefresh + 20 {
		k := key(byte(i))
		desired[k] = val(byte(i))
		f.updateErrs[k] = []error{sdkErr(unix.ENOMEM), nil}
	}
	m := newTestMap(f, nil)

	_ = m.BulkRefresh(desired)

	retried := 0
	for k := range desired {
		if f.updateCalls[k] > 1 {
			retried++
		}
	}
	assert.Equal(t, maxRetriedEntriesPerRefresh, retried,
		"beyond the cap, a transient errno is left to the controller requeue rather than retried under the lock")
}

// A transient errno that outlasts every retry is counted as exhausted.
func TestBulkRefresh_ExhaustedRetriesAreCounted(t *testing.T) {
	f := newFakeOps()
	recordSleeps(t)
	m := newTestMap(f, nil)
	f.updateErrs[key(1)] = []error{sdkErr(unix.ENOMEM)}

	before := counterValue(t, bpfMapMutationRetriesExhausted.WithLabelValues("ENOMEM"))
	assert.Error(t, m.BulkRefresh(map[string][]byte{key(1): val(1)}))
	assert.Equal(t, 1.0, counterValue(t, bpfMapMutationRetriesExhausted.WithLabelValues("ENOMEM"))-before)
}

func TestWritePodState_RetriesTransientErrno(t *testing.T) {
	slept := recordSleeps(t)
	calls := 0
	// Succeeding only on the last retry needs a sleep budget.
	err := writePodState("pod_state_update", "pod_state test", 1, func() error {
		calls++
		if calls < len(mapUpdateRetryDelays)+1 {
			return sdkErr(unix.ENOMEM)
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, len(mapUpdateRetryDelays)+1, calls)
	assert.Positive(t, *slept)
}

func TestWritePodState_FinalFailureIsCountedUnderItsOp(t *testing.T) {
	recordSleeps(t)
	c := bpfMapOpErr.WithLabelValues("pod_state_create", "ENOSPC")
	before := counterValue(t, c)
	calls := 0
	err := writePodState("pod_state_create", "pod_state test", 1, func() error {
		calls++
		return sdkErr(unix.ENOSPC)
	})
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "a permanent errno is not retried")
	assert.Equal(t, 1.0, counterValue(t, c)-before)
}

// An empty value leaves the shadow map matching the kernel, so the key is
// still deleted later.
func TestBulkRefresh_UnusableUpdateKeepsShadowInStepWithKernel(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(1): val(1)})

	assert.NoError(t, m.BulkRefresh(map[string][]byte{key(1): {}}))
	assert.Equal(t, 0, f.updateCalls[key(1)], "an empty value is never written")
	assert.Equal(t, val(1), m.contents[key(1)], "the shadow map still matches the kernel")

	assert.NoError(t, m.BulkRefresh(map[string][]byte{}))
	assert.NotContains(t, f.kernel, key(1), "a key that leaves the desired set is still swept")
}

func TestBulkRefresh_DeleteFailuresAreBounded(t *testing.T) {
	f := newFakeOps()
	recordSleeps(t)
	installed := map[string][]byte{}
	for i := range maxFailuresPerRefresh + 10 {
		k := key(byte(i))
		installed[k] = val(byte(i))
		f.deleteErrs[k] = []error{sdkErr(unix.EPERM)}
	}
	m := newTestMap(f, installed)

	err := m.BulkRefresh(map[string][]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("stopped after 0 update and %d delete failures", maxFailuresPerRefresh))
	attempted := 0
	for k := range installed {
		attempted += f.deleteCalls[k]
	}
	assert.Equal(t, maxFailuresPerRefresh, attempted)
}

// A permanent errno after a transient one stops the retries and is not counted
// as exhausted.
func TestRetryTransientMutation_TransientThenPermanentIsNotExhausted(t *testing.T) {
	recordSleeps(t)
	enomem := bpfMapMutationRetriesExhausted.WithLabelValues("ENOMEM")
	einval := bpfMapMutationRetriesExhausted.WithLabelValues("EINVAL")
	beforeENOMEM, beforeEINVAL := counterValue(t, enomem), counterValue(t, einval)
	calls := 0
	budget := retryBudget{sleep: mapRetrySleepBudget}
	err := retryTransientMutation("test", 1, func() error {
		calls++
		if calls == 1 {
			return sdkErr(unix.ENOMEM)
		}
		return sdkErr(unix.EINVAL)
	}, &budget)
	assert.ErrorContains(t, err, unix.EINVAL.Error())
	assert.Equal(t, 2, calls)
	assert.Equal(t, 0.0, counterValue(t, enomem)-beforeENOMEM)
	assert.Equal(t, 0.0, counterValue(t, einval)-beforeEINVAL)
}
