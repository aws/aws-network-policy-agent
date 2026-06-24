// Package kubestats reads per-container working-set memory from the kubelet's
// /stats/summary endpoint and tracks how much it grows over a soak run.
//
// The soak's >50 MiB memory-growth criterion (ORR X-2) is about one container —
// the NPA sidecar aws-eks-nodeagent — not the whole aws-node pod, which also holds
// the CNI. The kubelet summary reports memory per container, sourced from the same
// cadvisor data CloudWatch Container Insights uses, but reachable with only the
// kubeconfig the test framework already has. That keeps the soak free of AWS
// credentials while still measuring the exact signal the criterion names.
//
// This package is pure: it parses a summary payload and does the growth
// arithmetic. Fetching the payload over the kubelet proxy is the suite's job, so
// the parsing and threshold logic stay unit-testable offline.
package kubestats

import (
	"encoding/json"
	"fmt"
)

// Summary is the subset of the kubelet /stats/summary response we read. The real
// payload has far more; we decode only what the working-set lookup needs.
type Summary struct {
	Node NodeStats  `json:"node"`
	Pods []PodStats `json:"pods"`
}

// NodeStats identifies which node a summary came from.
type NodeStats struct {
	NodeName string `json:"nodeName"`
}

// PodStats is one pod's entry, with its containers.
type PodStats struct {
	PodRef     PodReference     `json:"podRef"`
	Containers []ContainerStats `json:"containers"`
}

// PodReference names a pod within the summary.
type PodReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ContainerStats is one container's stats. Only memory is decoded.
type ContainerStats struct {
	Name   string      `json:"name"`
	Memory MemoryStats `json:"memory"`
}

// MemoryStats carries the working-set bytes cadvisor reports. The field is a
// pointer so we can tell "reported zero" from "not reported": a container that has
// not yet published memory stats omits the field entirely, which must not be read
// as a legitimate 0-byte working set.
type MemoryStats struct {
	WorkingSetBytes *uint64 `json:"workingSetBytes"`
}

// ParseSummary decodes a kubelet /stats/summary payload.
func ParseSummary(data []byte) (Summary, error) {
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		return Summary{}, fmt.Errorf("parse kubelet summary: %w", err)
	}
	return s, nil
}

// ContainerWorkingSet returns the working-set bytes of the named container in the
// named pod. It returns an error when the pod or container is absent, or when the
// container has not reported memory yet, so a missing measurement is never
// silently treated as zero growth.
func (s Summary) ContainerWorkingSet(namespace, pod, container string) (uint64, error) {
	for _, p := range s.Pods {
		if p.PodRef.Namespace != namespace || p.PodRef.Name != pod {
			continue
		}
		for _, c := range p.Containers {
			if c.Name != container {
				continue
			}
			if c.Memory.WorkingSetBytes == nil {
				return 0, fmt.Errorf("container %s/%s/%s has not reported working-set memory yet",
					namespace, pod, container)
			}
			return *c.Memory.WorkingSetBytes, nil
		}
		return 0, fmt.Errorf("container %q not found in pod %s/%s", container, namespace, pod)
	}
	return 0, fmt.Errorf("pod %s/%s not found in kubelet summary", namespace, pod)
}

// GrowthTracker follows a single container's working-set memory across repeated
// samples and reports whether it grew past a budget. It records the first sample
// as the baseline (callers take it after warm-up so startup allocation is not
// counted) and the highest sample as the peak, so growth is peak-minus-baseline —
// a transient spike that later settles still counts, because a leak is defined by
// the worst sustained point, not the final reading alone.
//
// The zero value is not usable; construct with NewGrowthTracker.
type GrowthTracker struct {
	limitBytes uint64
	haveBase   bool
	baseline   uint64
	peak       uint64
}

// NewGrowthTracker returns a tracker that flags growth strictly greater than
// limitBytes.
func NewGrowthTracker(limitBytes uint64) *GrowthTracker {
	return &GrowthTracker{limitBytes: limitBytes}
}

// Observe records one working-set sample. The first call sets the baseline.
func (g *GrowthTracker) Observe(workingSetBytes uint64) {
	if !g.haveBase {
		g.baseline = workingSetBytes
		g.peak = workingSetBytes
		g.haveBase = true
		return
	}
	if workingSetBytes > g.peak {
		g.peak = workingSetBytes
	}
}

// Growth returns peak-minus-baseline in bytes. It returns 0 before any sample and
// never goes negative (the peak is always >= baseline by construction).
func (g *GrowthTracker) Growth() uint64 {
	if !g.haveBase {
		return 0
	}
	return g.peak - g.baseline
}

// Baseline returns the first observed working set, or 0 if none yet.
func (g *GrowthTracker) Baseline() uint64 { return g.baseline }

// Peak returns the highest observed working set, or 0 if none yet.
func (g *GrowthTracker) Peak() uint64 { return g.peak }

// Exceeded reports whether growth has passed the budget. It is false before any
// sample: with no data there is no evidence of a leak.
func (g *GrowthTracker) Exceeded() bool {
	return g.haveBase && g.Growth() > g.limitBytes
}
