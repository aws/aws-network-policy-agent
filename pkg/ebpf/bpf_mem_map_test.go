package ebpf

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// sdkErr reproduces exactly how aws-ebpf-sdk-go renders a failed map syscall:
// fmt.Errorf with %s, which discards the typed errno. Tests must build failures
// this way, otherwise they would exercise the errors.Is branch of utils.IsErrno
// that the pinned SDK never reaches.
func sdkErr(errno unix.Errno) error {
	return fmt.Errorf("unable to update map: %s", errno)
}

// fakeBpfMapOps scripts per-key syscall failures and records an in-memory
// "kernel" so a test can assert what actually landed. Hand-rolled to match the
// house style of bpf_client_mock.go; the SDK's generated mocks cannot satisfy
// bpfMapOps because maps.BpfMapAPIs does not declare GetAllMapKeys.
type fakeBpfMapOps struct {
	kernel map[string][]byte

	// updateErrs[key] is consumed one entry per attempt; nil means success. Once
	// exhausted the last element repeats, so a single-element slice models a
	// permanently failing key.
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

// newTestMap builds an InMemoryBpfMap over the fake, seeded with contents that
// are already programmed in the kernel, bypassing loadFromKernel.
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

// key and val mirror NPA's 8-byte LPM trie key and an 8-byte value.
func key(n byte) string { return string([]byte{n, 0, 0, 0, 0, 0, 0, 0}) }
func val(n byte) []byte { return []byte{n, 0, 0, 0, 0, 0, 0, 0} }

// A transient ENOMEM must be absorbed inside BulkRefresh, and the recovery must
// cost no sleep: the kernel refill raised by the failing allocation has already
// landed by the time the errno reaches userspace, so the first retry is
// deliberately sleepless.
func TestBulkRefresh_TransientENOMEMRecoversWithoutSleeping(t *testing.T) {
	f := newFakeOps()
	f.updateErrs[key(1)] = []error{sdkErr(unix.ENOMEM), nil}
	m := newTestMap(f, nil)

	start := time.Now()
	err := m.BulkRefresh(map[string][]byte{key(1): val(1)})
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.Equal(t, 2, f.updateCalls[key(1)], "should succeed on the first retry")
	assert.Equal(t, val(1), f.kernel[key(1)])
	assert.Equal(t, val(1), m.contents[key(1)])
	assert.Less(t, elapsed, time.Millisecond, "first retry must not sleep")
}

// The #686 regression guard: one permanently failing key must not abandon the
// other adds or the stale-entry delete sweep. This fails against the pre-fix
// code, which returned on the first error, before the delete loop.
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

	// Every other add landed.
	for _, n := range []byte{2, 3, 4} {
		assert.Equal(t, val(n), f.kernel[key(n)], "add %d must land despite the failing key", n)
		assert.Equal(t, val(n), m.contents[key(n)])
	}
	// The failing key is in neither the kernel nor the shadow map.
	assert.NotContains(t, f.kernel, key(1))
	assert.NotContains(t, m.contents, key(1))

	// Both stale entries were swept. Retaining these is the policy-gap half of
	// the bug: presence of a key in the trie IS the allow decision.
	for _, n := range []byte{8, 9} {
		assert.NotContains(t, f.kernel, key(n), "stale entry %d must be deleted", n)
		assert.NotContains(t, m.contents, key(n))
		assert.Equal(t, 1, f.deleteCalls[key(n)])
	}
}

// Permanent errnos must not be retried: BulkRefresh holds a write lock that is
// on the CNI pod-add path, a full trie returns ENOSPC, and a malformed key
// returns EINVAL. Retrying either only extends the lock hold.
func TestBulkRefresh_PermanentErrnosAreNotRetried(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EINVAL, unix.ENOSPC, unix.EBADF} {
		t.Run(unix.ErrnoName(errno), func(t *testing.T) {
			f := newFakeOps()
			f.updateErrs[key(1)] = []error{sdkErr(errno)}
			m := newTestMap(f, nil)

			start := time.Now()
			err := m.BulkRefresh(map[string][]byte{key(1): val(1)})
			elapsed := time.Since(start)

			assert.Error(t, err)
			assert.Equal(t, 1, f.updateCalls[key(1)], "must not retry a permanent errno")
			assert.Less(t, elapsed, time.Millisecond)
		})
	}
}

// The sleep budget and retried-entry cap are the lock-hold guarantee. Without
// them a persistently failing allocator would sleep once per key, and at 65536
// max_entries that blocks pod sandbox setup for seconds.
func TestBulkRefresh_RetryBudgetBoundsTheLockHold(t *testing.T) {
	f := newFakeOps()
	desired := map[string][]byte{}
	for i := range 200 {
		k := key(byte(i))
		desired[k] = val(byte(i))
		f.updateErrs[k] = []error{sdkErr(unix.ENOMEM)}
	}
	m := newTestMap(f, nil)

	start := time.Now()
	err := m.BulkRefresh(desired)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Less(t, elapsed, 60*time.Millisecond,
		"total sleep must stay near mapRetrySleepBudget (%v), not scale with key count", mapRetrySleepBudget)

	retried := 0
	for k := range desired {
		if f.updateCalls[k] > 1 {
			retried++
		}
	}
	assert.LessOrEqual(t, retried, maxRetriedEntriesPerRefresh)
}

// ENOENT on delete means the kernel entry is already gone, which is the desired
// state. Treating it as an error would return non-nil forever and put a correct
// PolicyEndpoint into a permanent requeue loop.
func TestBulkRefresh_ENOENTOnDeleteIsSuccess(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8)})
	f.deleteErrs[key(8)] = []error{sdkErr(unix.ENOENT)}

	err := m.BulkRefresh(map[string][]byte{})

	assert.NoError(t, err, "an already-absent key must not be reported as a failure")
	assert.NotContains(t, m.contents, key(8), "shadow map must drop the key so it is not re-swept forever")
}

// A genuine delete failure must be surfaced. The pre-fix delete loop logged and
// discarded every one, so a retained entry the policy no longer allows was
// invisible.
func TestBulkRefresh_RealDeleteFailureIsSurfaced(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8), key(9): val(9)})
	f.deleteErrs[key(8)] = []error{sdkErr(unix.EPERM)}

	err := m.BulkRefresh(map[string][]byte{})

	assert.Error(t, err)
	assert.Contains(t, m.contents, key(8), "a key still in the kernel must stay in the shadow map")
	// The sweep continued past the failure.
	assert.Equal(t, 1, f.deleteCalls[key(9)])
	assert.NotContains(t, m.contents, key(9))
}

// A transient errno on the DELETE sweep must be retried and absorbed, exactly as
// on the add path. Without this, one EINTR/ENOMEM on BPF_MAP_DELETE_ELEM
// propagates through updateEbpfMap -> UpdateEbpfMaps -> rpc_handler's
// EnforceNpToPod, which returns it and leaves the pod in ContainerCreating.
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

// ENOENT means the entry is already gone. Assert the KERNEL state too, not just
// the shadow map - dropping the key while the kernel still holds it would retain
// a stale allow entry for the map's lifetime with no error and no requeue.
func TestBulkRefresh_ENOENTOnDeleteLeavesNoKernelEntry(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{key(8): val(8)})
	delete(f.kernel, key(8)) // the kernel entry really is gone
	f.deleteErrs[key(8)] = []error{sdkErr(unix.ENOENT)}

	assert.NoError(t, m.BulkRefresh(map[string][]byte{}))
	assert.NotContains(t, f.kernel, key(8), "kernel must not retain the entry")
	assert.NotContains(t, m.contents, key(8), "shadow map must drop it so it stops being re-swept")
}

// An unusable entry must be DROPPED, not merely reported. Reporting it forever
// would make BulkRefresh return non-nil on every refresh, pinning the caller's
// requeue ladder at its cap with no path to convergence.
func TestBulkRefresh_UnusableEntriesAreDroppedNotLooped(t *testing.T) {
	f := newFakeOps()
	m := newTestMap(f, map[string][]byte{"": val(1)})

	assert.NoError(t, m.BulkRefresh(map[string][]byte{}), "an unusable entry must not error forever")
	assert.NotContains(t, m.contents, "", "it must be dropped from the shadow map")
	assert.NoError(t, m.BulkRefresh(map[string][]byte{}), "and must not reappear on the next refresh")
}

// A systemic errno must not issue one syscall and one log line per pending key
// while m.mutex - which gates CNI pod add - is held.
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

// retryTransientMutation is the policy shared by BulkRefresh and the direct
// pod_state writes in bpf_client.go. Exercise it on its own so a regression in
// either call site cannot hide behind the other.
func TestRetryTransientMutation(t *testing.T) {
	t.Run("transient errno is absorbed with no sleep on the first retry", func(t *testing.T) {
		calls := 0
		budget := retryBudget{sleep: mapRetrySleepBudget}
		start := time.Now()
		err := retryTransientMutation("test", 1, func() error {
			calls++
			if calls == 1 {
				return sdkErr(unix.ENOMEM)
			}
			return nil
		}, &budget)
		assert.NoError(t, err)
		assert.Equal(t, 2, calls)
		assert.Less(t, time.Since(start), time.Millisecond)
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
