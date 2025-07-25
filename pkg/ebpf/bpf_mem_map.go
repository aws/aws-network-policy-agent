package ebpf

import (
	"bytes"
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

	// Apply updates to kernel
	for k, v := range toAdd {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
		valuePtr := uintptr(unsafe.Pointer(&v[0]))

		if err := m.bpfMap.UpdateMapEntry(keyPtr, valuePtr); err != nil {
			log().Errorf("Failed to update kernel map during bulk refresh for key %s: %v", k, err)
			return err
		}

		// Update in-memory after successful kernel update
		m.contents[k] = v
	}

	// Apply deletes to kernel
	for _, k := range toDelete {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))

		if err := m.bpfMap.DeleteMapEntry(keyPtr); err != nil {
			log().Errorf("Failed to delete from kernel map for key %s: %v", k, err)
			// Continue with other deletions
		} else {
			// Remove from in-memory if kernel delete operation is successful
			delete(m.contents, k)
		}
	}

	log().Infof("Bulk refresh: added/updated %d entries, deleted %d entries", len(toAdd), len(toDelete))
	return nil
}

// GetUnderlyingMap returns the underlying BpfMap
func (m *InMemoryBpfMap) GetUnderlyingMap() *maps.BpfMap {
	return m.bpfMap
}
