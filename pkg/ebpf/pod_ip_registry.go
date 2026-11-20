package ebpf

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"
)

// podIPRegistry is a bidirectional, goroutine-safe map between a pod's primary
// IP and its Kubernetes identity, used to attribute drop metrics to workloads.
//
// Both directions are updated under a single RWMutex so that Register and
// Deregister are atomic across the two maps. Resolve takes a read lock only,
// keeping it cheap on the ring-buffer hot path.
type podIPRegistry struct {
	mu       sync.RWMutex
	ipToName map[string]types.NamespacedName
	nameToIP map[types.NamespacedName]string
}

func newPodIPRegistry() *podIPRegistry {
	return &podIPRegistry{
		ipToName: make(map[string]types.NamespacedName),
		nameToIP: make(map[types.NamespacedName]string),
	}
}

// register maps ip → pod and pod → ip.
//
// Two consistency invariants are maintained under the lock:
//   - If the pod already has a different IP registered (IP changed on the same
//     pod), the old IP entry is removed before the new one is written.
//   - If the new IP is already owned by a different pod (IP reuse), that pod's
//     reverse entry is removed before the new owner is written, so a later
//     Deregister for the old owner does not evict the new owner's entry.
func (r *podIPRegistry) register(ip string, pod types.NamespacedName) {
	if ip == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove the stale IP entry when the same pod gets a new IP (Scenario A).
	if oldIP, ok := r.nameToIP[pod]; ok && oldIP != ip {
		delete(r.ipToName, oldIP)
	}
	// Remove the previous owner's reverse entry when an IP is reused (Scenario B).
	if oldPod, ok := r.ipToName[ip]; ok && oldPod != pod {
		delete(r.nameToIP, oldPod)
	}

	r.ipToName[ip] = pod
	r.nameToIP[pod] = ip
}

// deregister removes the pod's IP registration.
//
// The IP entry is only deleted when it still points to this pod. If another
// pod has since claimed the same IP (IP reuse), their entry is left intact.
func (r *podIPRegistry) deregister(pod types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ip, ok := r.nameToIP[pod]
	if !ok {
		return
	}
	delete(r.nameToIP, pod)
	// Guard: only remove the IP entry if it still belongs to this pod.
	if current, exists := r.ipToName[ip]; exists && current == pod {
		delete(r.ipToName, ip)
	}
}

// resolve returns the namespace and name of the pod at addr, or empty strings
// when the IP is not registered. It takes a read lock only and is safe to call
// from the ring-buffer goroutine concurrently with register/deregister.
func (r *podIPRegistry) resolve(addr string) (namespace, name string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if nn, ok := r.ipToName[addr]; ok {
		return nn.Namespace, nn.Name
	}
	return "", ""
}
