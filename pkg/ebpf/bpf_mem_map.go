package ebpf

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
)

// InMemoryBpfMap provides an in-memory representation of an eBPF map
// with synchronized updates to the underlying kernel map
type InMemoryBpfMap struct {
	// Underlying BPF map
	bpfMap *maps.BpfMap
	// Optional test hooks for the kernel mutations. Nil means "use bpfMap", so a
	// zero-value InMemoryBpfMap works; see updateEntryOrSDK/deleteEntryOrSDK.
	updateEntry func(key, value []byte) error
	deleteEntry func(key []byte) error
	// In-memory representation of the map contents
	contents map[string][]byte
	// Mutex for thread safety
	mutex sync.RWMutex
}

// newInMemoryBpfMap is the constructor shadowMapForLocked uses. It is a variable so
// tests can build shadow maps without a kernel.
var newInMemoryBpfMap = NewInMemoryBpfMap

// updateEntryOrSDK and deleteEntryOrSDK write to the kernel, honouring a test
// hook when one is installed. The backing slice is kept alive across the call,
// since a uintptr is not a reference as far as the collector is concerned.
func (m *InMemoryBpfMap) updateEntryOrSDK(key, value []byte) error {
	if m.updateEntry != nil {
		return m.updateEntry(key, value)
	}
	err := m.bpfMap.UpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func (m *InMemoryBpfMap) deleteEntryOrSDK(key []byte) error {
	if m.deleteEntry != nil {
		return m.deleteEntry(key)
	}
	err := m.bpfMap.DeleteMapEntry(uintptr(unsafe.Pointer(&key[0])))
	runtime.KeepAlive(key)
	return err
}

// NewInMemoryBpfMap creates a new in-memory representation of an eBPF map
// and optionally loads the initial state from the kernel
func NewInMemoryBpfMap(bpfMap *maps.BpfMap) (*InMemoryBpfMap, error) {
	m := &InMemoryBpfMap{
		bpfMap:   bpfMap,
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
	keys, err := m.bpfMap.GetAllMapKeys()
	if err != nil {
		log().Errorf("Failed to get keys from kernel map: %v", err)
		return err
	}

	// For each key, get the value and store in memory
	for _, key := range keys {
		keyByte := []byte(key)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))

		// Create a buffer for the value based on map's value size
		value := make([]byte, m.bpfMap.MapMetaData.ValueSize)
		valuePtr := uintptr(unsafe.Pointer(&value[0]))

		if err := m.bpfMap.GetMapEntry(keyPtr, valuePtr); err != nil {
			log().Errorf("Failed to get value for key %s: %v", key, err)
			return err
		}

		m.contents[key] = value
	}

	log().Infof("Loaded %d entries from kernel map", len(m.contents))
	return nil
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

	var failedKeys []string
	var firstErr error

	// Apply updates to kernel
	for k, v := range toAdd {
		keyByte := []byte(k)

		if err := m.updateEntryOrSDK(keyByte, v); err != nil {
			// Carry on rather than return. Aborting here would leave the kernel
			// holding a random subset of the new entries and skip the stale-entry
			// sweep below, so a policy the user revoked would stay in force.
			failedKeys = append(failedKeys, fmt.Sprintf("%x", keyByte))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		// Update in-memory after successful kernel update
		m.contents[k] = v
	}

	// Apply deletes to kernel
	for _, k := range toDelete {
		keyByte := []byte(k)

		if err := m.deleteEntryOrSDK(keyByte); err != nil {
			log().Errorf("Failed to delete from kernel map for key %s: %v", k, err)
			// Continue with other deletions
		} else {
			// Remove from in-memory if kernel delete operation is successful
			delete(m.contents, k)
		}
	}

	log().Infof("Bulk refresh: added/updated %d of %d entries, deleted %d entries",
		len(toAdd)-len(failedKeys), len(toAdd), len(toDelete))

	if firstErr != nil {
		// Log the full key list once here, and return a short error: this error is
		// logged again at every layer on the way up to the reconciler.
		log().Errorf("Failed to update kernel map %d during bulk refresh for keys %v: %v",
			m.bpfMap.MapID, failedKeys, firstErr)
		return fmt.Errorf("%d of %d map updates failed (%s): %w",
			len(failedKeys), len(toAdd), summarizeKeys(failedKeys), firstErr)
	}
	return nil
}

// summarizeKeys renders at most a few keys, so a systemic failure cannot put
// one line per entry into the returned error.
func summarizeKeys(keys []string) string {
	const max = 3
	if len(keys) <= max {
		return strings.Join(keys, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(keys[:max], ", "), len(keys)-max)
}

// GetUnderlyingMap returns the underlying BpfMap
func (m *InMemoryBpfMap) GetUnderlyingMap() *maps.BpfMap {
	return m.bpfMap
}
