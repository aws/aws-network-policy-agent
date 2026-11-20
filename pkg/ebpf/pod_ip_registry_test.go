package ebpf

import (
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func nn(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func TestPodIPRegistry_BasicRegistration(t *testing.T) {
	r := newPodIPRegistry()
	r.register("10.0.0.1", nn("default", "pod-a"))

	ns, name := r.resolve("10.0.0.1")
	if ns != "default" || name != "pod-a" {
		t.Fatalf("got %s/%s, want default/pod-a", ns, name)
	}
}

func TestPodIPRegistry_UnknownIP(t *testing.T) {
	r := newPodIPRegistry()
	ns, name := r.resolve("10.0.0.99")
	if ns != "" || name != "" {
		t.Fatalf("expected empty for unknown IP, got %s/%s", ns, name)
	}
}

// Scenario A from the review: pod receives a new IP. The old IP must no longer
// resolve to the pod after re-registration.
func TestPodIPRegistry_PodIPChange(t *testing.T) {
	r := newPodIPRegistry()
	pod := nn("default", "pod-a")

	r.register("10.0.0.1", pod)
	r.register("10.0.0.2", pod) // pod gets a new IP

	// Old IP must be gone.
	ns, name := r.resolve("10.0.0.1")
	if ns != "" || name != "" {
		t.Errorf("old IP still resolves after IP change: got %s/%s", ns, name)
	}
	// New IP must resolve.
	ns, name = r.resolve("10.0.0.2")
	if ns != "default" || name != "pod-a" {
		t.Errorf("new IP doesn't resolve: got %s/%s", ns, name)
	}
}

// Scenario B from the review: IP is reused by a new pod. Deleting the old pod
// must not remove the new pod's entry.
func TestPodIPRegistry_IPReuse(t *testing.T) {
	r := newPodIPRegistry()
	podA := nn("default", "pod-a")
	podB := nn("default", "pod-b")

	r.register("10.0.0.1", podA)
	r.register("10.0.0.1", podB) // same IP reused by pod-b

	// IP now resolves to pod-b.
	ns, name := r.resolve("10.0.0.1")
	if ns != "default" || name != "pod-b" {
		t.Errorf("IP should resolve to pod-b, got %s/%s", ns, name)
	}

	// Deleting pod-a must not evict pod-b's mapping.
	r.deregister(podA)
	ns, name = r.resolve("10.0.0.1")
	if ns != "default" || name != "pod-b" {
		t.Errorf("pod-b's mapping was incorrectly removed when pod-a was deleted: got %s/%s", ns, name)
	}
}

func TestPodIPRegistry_Deregister(t *testing.T) {
	r := newPodIPRegistry()
	pod := nn("default", "pod-a")

	r.register("10.0.0.1", pod)
	r.deregister(pod)

	ns, name := r.resolve("10.0.0.1")
	if ns != "" || name != "" {
		t.Errorf("IP still resolves after deregistration: got %s/%s", ns, name)
	}
}

func TestPodIPRegistry_DeregisterUnknown(t *testing.T) {
	r := newPodIPRegistry()
	// Must not panic for a pod that was never registered.
	r.deregister(nn("default", "never-registered"))
}

func TestPodIPRegistry_ConcurrentAccess(t *testing.T) {
	r := newPodIPRegistry()
	const goroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pod := nn("default", "pod-a")
			r.register("10.0.0.1", pod)
			r.resolve("10.0.0.1")
			r.deregister(pod)
		}(i)
	}
	wg.Wait()
}
