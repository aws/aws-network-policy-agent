package ebpf

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestKeyedMutex_ExclusivePerKeyUnderChurn(t *testing.T) {
	var k keyedMutex
	keys := []string{"a@ns", "b@ns", "c@ns"}
	holders := make(map[string]*int32, len(keys))
	for _, key := range keys {
		holders[key] = new(int32)
	}

	var violations int32
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := keys[(g+i)%len(keys)]
				k.Lock(key)
				if atomic.AddInt32(holders[key], 1) != 1 {
					atomic.AddInt32(&violations, 1)
				}
				atomic.AddInt32(holders[key], -1)
				k.Unlock(key)
			}
		}(g)
	}
	wg.Wait()

	assert.Zero(t, violations, "two goroutines held the same key at once")
	assert.Zero(t, k.len(), "released keys must not be retained")
}

// A goroutine waiting on a key keeps its mutex alive, so a caller arriving after
// the holder releases queues behind the waiter instead of running alongside it.
func TestKeyedMutex_WaiterKeepsKeyExclusive(t *testing.T) {
	var k keyedMutex
	const key = "ds@ns"

	k.Lock(key) // e.g. CNI DEL tearing down the identifier's last pod

	waiterHolds := make(chan struct{})
	releaseWaiter := make(chan struct{})
	go func() { // e.g. a PolicyEndpoint reconcile queued behind it
		k.Lock(key)
		close(waiterHolds)
		<-releaseWaiter
		k.Unlock(key)
	}()
	assert.Eventually(t, func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.locks[key] != nil && k.locks[key].refs == 2
	}, time.Second, time.Millisecond)

	k.Unlock(key)
	<-waiterHolds

	lateHolds := make(chan struct{})
	go func() { // e.g. the replacement pod's CNI ADD
		k.Lock(key)
		close(lateHolds)
		k.Unlock(key)
	}()
	select {
	case <-lateHolds:
		t.Fatal("late caller acquired the key while the waiter still held it")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseWaiter)
	<-lateHolds
	assert.Eventually(t, func() bool { return k.len() == 0 }, time.Second, time.Millisecond)
}

func TestKeyedMutex_UnlockOfUnlockedKeyPanics(t *testing.T) {
	var k keyedMutex
	assert.Panics(t, func() { k.Unlock("never-locked@ns") })
}
