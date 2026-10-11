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
	// mapRetrySleepBudget caps the total retry sleep in one BulkRefresh, which
	// holds m.mutex on the CNI pod-add path.
	mapRetrySleepBudget = 10 * time.Millisecond

	// maxRetriedEntriesPerRefresh caps how many entries one BulkRefresh retries.
	maxRetriedEntriesPerRefresh = 64

	// maxFailuresPerRefresh caps failed updates, and separately failed deletes,
	// in one BulkRefresh before it stops and leaves the rest to the requeue.
	maxFailuresPerRefresh = 64
)

// mapUpdateRetryDelays is the wait before each retry. The first retry is
// immediate because the kernel has usually refilled its allocator cache by the
// time the error is returned.
var mapUpdateRetryDelays = []time.Duration{0, 50 * time.Microsecond, 250 * time.Microsecond, 1 * time.Millisecond}

// mapRetrySleep is replaced in tests.
var mapRetrySleep = time.Sleep

// bpfMapOps is the subset of the SDK map API used by InMemoryBpfMap, so tests
// can fake the kernel.
type bpfMapOps interface {
	UpdateMapEntry(key, value []byte) error
	DeleteMapEntry(key []byte) error
	GetMapEntry(key, value []byte) error
	GetAllMapKeys() ([]string, error)
}

// sdkMapOps adapts *maps.BpfMap to bpfMapOps.
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

// retryBudget is shared by all entries in one BulkRefresh.
type retryBudget struct {
	sleep   time.Duration
	entries int
}

// mutateWithRetry runs one map update or delete with retryTransientMutation.
func (m *InMemoryBpfMap) mutateWithRetry(op string, mutate func() error, budget *retryBudget) error {
	return retryTransientMutation(op, int(m.bpfMap.MapID), mutate, budget)
}

// retryTransientMutation runs mutate and retries it on transient errnos
// (ENOMEM, EAGAIN, EINTR) within budget. Other errors are returned at once.
func retryTransientMutation(op string, mapID int, mutate func() error, budget *retryBudget) error {
	err := mutate()
	if err == nil || !utils.IsRetryableMapErrno(err) {
		return err
	}
	if budget.entries >= maxRetriedEntriesPerRefresh {
		bpfMapMutationRetriesExhausted.WithLabelValues(utils.MapErrnoLabel(err)).Inc()
		return err
	}
	budget.entries++

	for attempt, delay := range mapUpdateRetryDelays {
		if delay > 0 {
			if delay > budget.sleep {
				break
			}
			mapRetrySleep(delay)
			budget.sleep -= delay
		}

		label := utils.MapErrnoLabel(err)
		bpfMapMutationRetries.WithLabelValues(label).Inc()

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
		bpfMapMutationRetriesExhausted.WithLabelValues(utils.MapErrnoLabel(err)).Inc()
	}
	return err
}

// recordMapOpFailure counts a map mutation that failed after retries and
// returns its errno label.
func recordMapOpFailure(op string, err error) string {
	label := utils.MapErrnoLabel(err)
	bpfMapOpErr.WithLabelValues(op, label).Inc()
	return label
}

// writePodState runs a pod_state map write with the same retry as BulkRefresh.
func writePodState(metricOp, op string, mapID int, write func() error) error {
	budget := retryBudget{sleep: mapRetrySleepBudget}
	err := retryTransientMutation(op, mapID, write, &budget)
	if err != nil {
		recordMapOpFailure(metricOp, err)
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
	applied, deleted, truncated := 0, 0, false
	updateFailures, deleteFailures := 0, 0

	// Apply updates to kernel
	for k, v := range toAdd {
		if updateFailures >= maxFailuresPerRefresh {
			truncated = true
			break
		}
		keyByte := []byte(k)
		if len(keyByte) == 0 || len(v) == 0 {
			// sdkMapOps would panic on an empty slice. Leave m.contents as is
			// so it still matches the kernel.
			log().Errorf("map %d: skipping unusable entry, key len %d value len %d",
				m.bpfMap.MapID, len(keyByte), len(v))
			continue
		}

		key, val := keyByte, v
		if err := m.mutateWithRetry("BPF_MAP_UPDATE_ELEM",
			func() error { return m.ops.UpdateMapEntry(key, val) }, &budget); err != nil {
			updateFailures++
			label := recordMapOpFailure("update", err)
			log().Errorf("Failed to update kernel map %d during bulk refresh for key %x (errno %s): %v",
				m.bpfMap.MapID, keyByte, label, err)
			// Keep going so the remaining updates and the deletes still run.
			errs = append(errs, fmt.Errorf("update key %x: %w", keyByte, err))
			continue
		}

		// Update in-memory after successful kernel update
		m.contents[k] = v
		applied++
	}

	// Apply deletes to kernel, even if some updates failed.
	for _, k := range toDelete {
		if deleteFailures >= maxFailuresPerRefresh {
			truncated = true
			break
		}
		keyByte := []byte(k)
		if len(keyByte) == 0 {
			log().Errorf("map %d: dropping unusable zero-length key from shadow map", m.bpfMap.MapID)
			delete(m.contents, k)
			continue
		}

		key := keyByte
		err := m.mutateWithRetry("BPF_MAP_DELETE_ELEM",
			func() error { return m.ops.DeleteMapEntry(key) }, &budget)

		// ENOENT means the entry is already gone.
		if err != nil && !utils.IsErrno(err, unix.ENOENT) {
			label := recordMapOpFailure("delete", err)
			log().Errorf("Failed to delete from kernel map %d for key %x (errno %s): %v",
				m.bpfMap.MapID, keyByte, label, err)
			deleteFailures++
			errs = append(errs, fmt.Errorf("delete key %x: %w", keyByte, err))
			continue
		}

		// Remove from in-memory if kernel delete operation is successful
		delete(m.contents, k)
		deleted++
	}

	if truncated {
		errs = append(errs, fmt.Errorf("stopped after %d update and %d delete failures; remaining entries deferred to the next reconcile",
			updateFailures, deleteFailures))
		log().Errorf("map %d: bulk refresh truncated after %d update and %d delete failures",
			m.bpfMap.MapID, updateFailures, deleteFailures)
	}
	log().Infof("Bulk refresh: added/updated %d of %d entries, deleted %d of %d entries, failures %d",
		applied, len(toAdd), deleted, len(toDelete), updateFailures+deleteFailures)
	return errors.Join(errs...)
}

// GetUnderlyingMap returns the underlying BpfMap
func (m *InMemoryBpfMap) GetUnderlyingMap() *maps.BpfMap {
	return m.bpfMap
}
