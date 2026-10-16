package ebpf

import "sync"

// keyedMutex hands out one mutex per key and drops it once nobody holds or
// waits on it. Dropping on release, rather than when the caller decides the key
// is finished, is what keeps it exclusive: a goroutine already waiting on a
// key's mutex keeps that mutex alive, so a later Lock of the same key queues
// behind it instead of getting a fresh mutex and running concurrently.
//
// The zero value is ready to use.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refCountedMutex
}

type refCountedMutex struct {
	sync.Mutex
	// refs counts goroutines holding or waiting on the mutex; guarded by keyedMutex.mu
	refs int
}

func (k *keyedMutex) Lock(key string) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = make(map[string]*refCountedMutex)
	}
	m, ok := k.locks[key]
	if !ok {
		m = &refCountedMutex{}
		k.locks[key] = m
	}
	m.refs++
	k.mu.Unlock()

	m.Lock()
}

func (k *keyedMutex) Unlock(key string) {
	k.mu.Lock()
	m, ok := k.locks[key]
	if !ok {
		k.mu.Unlock()
		panic("keyedMutex: unlock of unknown key " + key)
	}
	m.refs--
	if m.refs == 0 {
		delete(k.locks, key)
	}
	k.mu.Unlock()

	m.Unlock()
}

// len reports how many keys currently have a holder or waiter.
func (k *keyedMutex) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.locks)
}
