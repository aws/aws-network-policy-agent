package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"golang.org/x/sys/unix"
)

const (
	// mapRetrySleepBudget caps the total sleep across ONE BulkRefresh. Note a
	// single UpdateEbpfMaps performs two refreshes (ingress then egress) per pod
	// identifier, so one EnforceNpToPod can admit a multiple of this - the bound
	// is per map, not per CNI operation.
	// BulkRefresh holds m.mutex for its whole duration and that lock is on the
	// CNI pod-add critical path (pkg/rpc/rpc_handler.go), so a per-entry ladder
	// with no shared budget could block pod sandbox setup for seconds. The first
	// retry is sleepless and never draws on this, and per the kernel mechanism
	// described on utils.IsRetryableMapErrno it is the attempt that actually
	// works - so recovering from the Graviton5 ENOMEM costs zero sleep.
	mapRetrySleepBudget = 10 * time.Millisecond

	// maxRetriedEntriesPerRefresh bounds how many entries in one refresh may be
	// retried at all. The allocator's free list is seeded with a single object
	// only at per-CPU cache birth, so the exposure is at most one event per
	// (map, CPU) for the map's entire life. Beyond this, something other than the
	// refill race is wrong and the caller's requeue - not a tighter loop under a
	// lock - is the right answer.
	maxRetriedEntriesPerRefresh = 64

	// maxFailuresPerRefresh bounds how many failing entries one refresh will
	// attempt and report. Not aborting on the first failure is deliberate, but an
	// unbounded loop over a systemic errno (a saturated trie returning ENOSPC, a
	// closed fd returning EBADF) would issue up to max_entries syscalls, log that
	// many errors, and build an errors.Join string of the same order - all while
	// holding m.mutex, which is on the CNI pod-add critical path. Past this count
	// the refresh stops early and reports a truncation summary; the caller's
	// requeue is the right place to converge, not a tighter loop under a lock.
	maxFailuresPerRefresh = 64
)

// mapUpdateRetryDelays is the wait before each retry. The first entry is 0
// deliberately: the kernel refill that the failing allocation itself raised has
// already completed by the time the errno reaches userspace, so an immediate
// retry on the same CPU succeeds. The later steps cover an IPI masked longer than
// measured, and a retry that resumed on a different, still-cold CPU - Go offers
// no CPU affinity, so the retry is convergent but probabilistic, which is why the
// caller's requeue is required rather than merely defence in depth.
var mapUpdateRetryDelays = []time.Duration{0, 50 * time.Microsecond, 250 * time.Microsecond, 1 * time.Millisecond}

// bpfMapOps is the kernel-mutating subset of the SDK's map API, expressed in
// []byte so tests can inject syscall failures without touching unsafe. Production
// always holds an sdkMapOps. The SDK's own maps.BpfMapAPIs cannot be reused here
// because it does not declare GetAllMapKeys, which loadFromKernel needs.
type bpfMapOps interface {
	UpdateMapEntry(key, value []byte) error
	DeleteMapEntry(key []byte) error
	GetMapEntry(key, value []byte) error
	GetAllMapKeys() ([]string, error)
}

// sdkMapOps adapts *maps.BpfMap to bpfMapOps. Every uintptr conversion in this
// file lives here, and each is passed straight into the syscall wrapper with the
// backing slice kept alive across the call - a uintptr is not a reference as far
// as the collector is concerned.
type sdkMapOps struct {
	m *maps.BpfMap
}

func (s sdkMapOps) UpdateMapEntry(key, value []byte) error {
	err := s.m.UpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func (s sdkMapOps) DeleteMapEntry(key []byte) error {
	err := s.m.DeleteMapEntry(uintptr(unsafe.Pointer(&key[0])))
	runtime.KeepAlive(key)
	return err
}

func (s sdkMapOps) GetMapEntry(key, value []byte) error {
	err := s.m.GetMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func (s sdkMapOps) GetAllMapKeys() ([]string, error) { return s.m.GetAllMapKeys() }

// InMemoryBpfMap provides an in-memory representation of an eBPF map
// with synchronized updates to the underlying kernel map
type InMemoryBpfMap struct {
	// Underlying BPF map
	bpfMap *maps.BpfMap
	// Kernel-mutating subset of bpfMap, swappable in tests
	ops bpfMapOps
	// In-memory representation of the map contents
	contents map[string][]byte
	// Mutex for thread safety
	mutex sync.RWMutex
}

// NewInMemoryBpfMap creates a new in-memory representation of an eBPF map
// and optionally loads the initial state from the kernel
func NewInMemoryBpfMap(bpfMap *maps.BpfMap) (*InMemoryBpfMap, error) {
	m := &InMemoryBpfMap{
		bpfMap:   bpfMap,
		ops:      sdkMapOps{m: bpfMap},
		contents: make(map[string][]byte),
	}

	log().Infof("creating new In memory map via loading bpfmap: %+v", bpfMap)
	if err := m.loadFromKernel(); err != nil {
		return nil, err
	}
	log().Infof("created in mem map for bpfmap: %+v", bpfMap)

	return m, nil
}

// loadFromKernel loads the current state of the eBPF map from the kernel
func (m *InMemoryBpfMap) loadFromKernel() error {
	startTime := time.Now()

	defer func() {
		totalTime := time.Since(startTime)
		log().Infof("loadFromKernel completed in %v ms, loaded %d entries from kernel map",
			totalTime.Milliseconds(), len(m.contents))
	}()

	log().Infof("Starting loadFromKernel operation")

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Clear current contents
	m.contents = make(map[string][]byte)

	// Get all keys from the kernel map
	keys, err := m.ops.GetAllMapKeys()
	if err != nil {
		log().Errorf("Failed to get keys from kernel map: %v", err)
		return err
	}

	// For each key, get the value and store in memory
	for _, key := range keys {
		keyByte := []byte(key)

		// Create a buffer for the value based on map's value size
		value := make([]byte, m.bpfMap.MapMetaData.ValueSize)

		if err := m.ops.GetMapEntry(keyByte, value); err != nil {
			log().Errorf("Failed to get value for key %s: %v", key, err)
			return err
		}

		m.contents[key] = value
	}

	log().Infof("Loaded %d entries from kernel map", len(m.contents))
	return nil
}

// retryBudget is per-BulkRefresh state shared across every entry, so a
// persistently failing allocator cannot extend the m.mutex hold time by sleeping
// once per key.
type retryBudget struct {
	sleep   time.Duration
	entries int
}

// mutateWithRetry runs one map mutation, retrying only errnos that clear on
// their own. Permanent errnos return on the first attempt, so they burn no
// budget. Both updates and deletes go through here: the allocator race this
// retry exists for is not specific to BPF_MAP_UPDATE_ELEM, and leaving deletes
// unretried would make a transient errno on the delete sweep propagate to
// pkg/rpc/rpc_handler.go, which returns it from EnforceNpToPod and fails CNI
// pod creation.
func (m *InMemoryBpfMap) mutateWithRetry(op string, mutate func() error, budget *retryBudget) error {
	return retryTransientMutation(op, int(m.bpfMap.MapID), mutate, budget)
}

// retryTransientMutation is the retry policy itself, independent of
// InMemoryBpfMap so that direct kernel writes which do not go through
// BulkRefresh can share it. Every path that writes a BPF map from userspace
// should use this: the allocator race is a property of bpf_mem_alloc, not of any
// particular map or call site, so leaving a write unretried just relocates the
// exposure.
func retryTransientMutation(op string, mapID int, mutate func() error, budget *retryBudget) error {
	err := mutate()
	if err == nil || !utils.IsRetryableMapErrno(err) {
		return err
	}
	if budget.entries >= maxRetriedEntriesPerRefresh {
		// Give up without retrying, but still count it: this is exactly when the
		// cap is binding, so under-reporting here would invert the tripwire.
		bpfMapUpdateRetriesExhausted.WithLabelValues(utils.MapErrnoLabel(err)).Inc()
		return err
	}
	budget.entries++

	for attempt, delay := range mapUpdateRetryDelays {
		if delay > 0 {
			if delay > budget.sleep {
				break
			}
			time.Sleep(delay)
			budget.sleep -= delay
		}

		label := utils.MapErrnoLabel(err)
		bpfMapUpdateRetries.WithLabelValues(label).Inc()

		retryErr := mutate()
		if retryErr == nil {
			log().Infof("map %d: %s recovered from %s on retry %d/%d",
				mapID, op, label, attempt+1, len(mapUpdateRetryDelays))
			return nil
		}

		err = retryErr
		if !utils.IsRetryableMapErrno(err) {
			break
		}
	}

	if utils.IsRetryableMapErrno(err) {
		bpfMapUpdateRetriesExhausted.WithLabelValues(utils.MapErrnoLabel(err)).Inc()
	}
	return err
}

// BulkRefresh efficiently handles both additions and deletions in a single operation
func (m *InMemoryBpfMap) BulkRefresh(newMapContents map[string][]byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Find entries to add or update
	toAdd := make(map[string][]byte)
	for k, v := range newMapContents {
		currentVal, exists := m.contents[k]
		if !exists || !bytes.Equal(currentVal, v) {
			toAdd[k] = v
		}
	}

	// Find entries to delete
	toDelete := make([]string, 0)
	for k := range m.contents {
		if _, exists := newMapContents[k]; !exists {
			toDelete = append(toDelete, k)
		}
	}

	budget := retryBudget{sleep: mapRetrySleepBudget}
	var errs []error
	applied, deleted, failures, truncated := 0, 0, 0, false

	// Apply updates to kernel
	for k, v := range toAdd {
		if failures >= maxFailuresPerRefresh {
			truncated = true
			break
		}
		keyByte := []byte(k)
		if len(keyByte) == 0 || len(v) == 0 {
			// Drop it rather than only reporting it. A malformed entry we keep
			// re-deriving would make BulkRefresh return non-nil forever, pinning
			// the caller's requeue ladder at its cap with no path to convergence.
			log().Errorf("map %d: dropping unusable entry, key len %d value len %d",
				m.bpfMap.MapID, len(keyByte), len(v))
			delete(m.contents, k)
			continue
		}

		key, val := keyByte, v
		if err := m.mutateWithRetry("BPF_MAP_UPDATE_ELEM",
			func() error { return m.ops.UpdateMapEntry(key, val) }, &budget); err != nil {
			failures++
			label := utils.MapErrnoLabel(err)
			log().Errorf("Failed to update kernel map %d during bulk refresh for key %x (errno %s): %v",
				m.bpfMap.MapID, keyByte, label, err)
			bpfMapOpErr.WithLabelValues("update", label).Inc()
			// Deliberately do not abort. Aborting here left the kernel holding an
			// arbitrary, Go-map-iteration-randomized subset of the new entries AND
			// every stale entry the policy no longer allows, because the delete
			// sweep below was skipped too. The error is returned at the end so the
			// caller requeues and converges.
			errs = append(errs, fmt.Errorf("update key %x: %w", keyByte, err))
			continue
		}

		// Update in-memory after successful kernel update
		m.contents[k] = v
		applied++
	}

	// Apply deletes to kernel
	for _, k := range toDelete {
		if failures >= maxFailuresPerRefresh {
			truncated = true
			break
		}
		keyByte := []byte(k)
		if len(keyByte) == 0 {
			// Unusable and unfixable: drop it so it stops reappearing in toDelete.
			log().Errorf("map %d: dropping unusable zero-length key from shadow map", m.bpfMap.MapID)
			delete(m.contents, k)
			continue
		}

		key := keyByte
		err := m.mutateWithRetry("BPF_MAP_DELETE_ELEM",
			func() error { return m.ops.DeleteMapEntry(key) }, &budget)

		// ENOENT means the kernel entry is already gone, which is the state we
		// wanted. Treating it as an error would return non-nil forever and put a
		// correct PolicyEndpoint into a permanent requeue loop.
		if err != nil && !utils.IsErrno(err, unix.ENOENT) {
			label := utils.MapErrnoLabel(err)
			log().Errorf("Failed to delete from kernel map %d for key %x (errno %s): %v",
				m.bpfMap.MapID, keyByte, label, err)
			bpfMapOpErr.WithLabelValues("delete", label).Inc()
			failures++
			// Keep sweeping the remaining stale keys, but surface the failure: a
			// retained entry the policy no longer allows is a policy gap, and this
			// loop used to discard the error entirely.
			errs = append(errs, fmt.Errorf("delete key %x: %w", keyByte, err))
			continue
		}

		// Remove from in-memory if kernel delete operation is successful
		delete(m.contents, k)
		deleted++
	}

	if truncated {
		errs = append(errs, fmt.Errorf("stopped after %d failures; remaining entries deferred to the next reconcile", failures))
		log().Errorf("map %d: bulk refresh truncated after %d failures", m.bpfMap.MapID, failures)
	}
	log().Infof("Bulk refresh: added/updated %d of %d entries, deleted %d of %d entries, failures %d",
		applied, len(toAdd), deleted, len(toDelete), failures)
	return errors.Join(errs...)
}

// GetUnderlyingMap returns the underlying BpfMap
func (m *InMemoryBpfMap) GetUnderlyingMap() *maps.BpfMap {
	return m.bpfMap
}
