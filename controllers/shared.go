package controllers

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

// Helpers shared by the PolicyEndpoint and ClusterPolicyEndpoint reconcilers. Both follow the
// same shape -- record what a policy selects, queue the affected pod identifiers, then attach
// and program each identifier -- so the pieces that carry no controller-specific state live
// here once rather than being kept in step by hand in both files.

// attachOutcome counts what attachProbesForIdentifier skipped, so a caller can tell a pass that
// only skipped from one that failed.
type attachOutcome struct {
	// skipped is the number of pods whose attach cannot be retried into success.
	skipped int
}

// attachProbesForIdentifier attaches eBPF probes for every pod in targetPods that belongs to
// podIdentifier. It returns what it did and the joined failures, counting skips in the outcome
// rather than returning them as an error.
//
// Skips are kept out of the error on purpose. ErrProbeAttachSkipped marks an attach no retry
// can resolve, but errors.Is matches when any arm of a join carries it, so returning a skip
// alongside a real failure would let one skipped pod convince the caller that a map-write
// ENOMEM or a sibling pod's genuine attach failure also needs no retry.
//
// A failure is recorded and the loop continues rather than returning: GetPodIdentifier strips
// the last name segment, so replicas of one workload share this identifier and the single pair
// of eBPF maps behind it. Returning on the first failure would leave the co-located replicas
// unattached and skip the caller's map write, stranding them on the rules from before this
// change -- and on the cluster path those rules can be missing a Deny.
//
// Callers must still check HasBPFContext before programming: AttacheBPFProbes skips pods
// already deleted from the node, so an endpoint can list a pod that has no programs here.
func attachProbesForIdentifier(ebpfClient ebpf.BpfClient, podIdentifier string,
	targetPods []npatypes.Pod) (attachOutcome, error) {

	var outcome attachOutcome
	var attachErr error
	for _, pod := range targetPods {
		if utils.GetPodIdentifier(pod.Name, pod.Namespace) != podIdentifier {
			log().Debugf("Target Pod doesn't belong to the current pod Identifier: Name: %s Pod ID: %s",
				pod.Name, podIdentifier)
			continue
		}

		// podConfirmedLive=false: endpoints can still list pods already deleted from this node.
		if _, err := ebpfClient.AttacheBPFProbes(pod.NamespacedName, podIdentifier,
			ebpf.INTERFACE_COUNT_UNKNOWN, false); err != nil {
			if errors.Is(err, ebpf.ErrProbeAttachSkipped) {
				outcome.skipped++
				log().Warnf("Skipped eBPF probe attach for pod %s namespace %s: %v",
					pod.Name, pod.Namespace, err)
				continue
			}
			attachErr = errors.Join(attachErr, fmt.Errorf(
				"failed to attach eBPF probes for pod %s namespace %s : %w", pod.Name, pod.Namespace, err))
			continue
		}

		log().Debugf("eBPF probes in place for pod: %s in namespace %s", pod.Name, pod.Namespace)
	}
	return outcome, attachErr
}

// recordedLocalIdentifiers returns the identifiers recorded for slice and for liveSlices. A
// slice's record differs from its policy's last local set only if the slice was missing from the
// policy's last reconcile: deleted since, or deleted and recreated under the same name, or moved
// to another parent and back, before its own reconcile ran.
func recordedLocalIdentifiers(records *sync.Map, slice *EndpointRequest, liveSlices []EndpointRequest) []string {
	var podIdentifiers []string
	// Every slice one reconcile recorded shares one []string, so each is read once.
	seen := map[*string]bool{}
	load := func(req EndpointRequest) {
		v, ok := records.Load(req)
		if !ok {
			return
		}
		ids := v.([]string)
		if len(ids) == 0 || seen[&ids[0]] {
			return
		}
		seen[&ids[0]] = true
		podIdentifiers = append(podIdentifiers, ids...)
	}
	if slice != nil {
		load(*slice)
	}
	for _, live := range liveSlices {
		load(live)
	}
	return podIdentifiers
}

// recordSliceLocalIdentifiers keeps, for every live slice of a policy, the identifiers the policy
// selects pods of on this node, and forgets a deleted slice's entry once its deletion has been
// reconciled. A slice's entry is the policy's whole local set as of the last reconcile that saw
// the slice live, so the slice's deletion cleans up whatever the policy selected here then,
// including pods only its siblings listed, and whether or not the slice's own reconcile ran.
func recordSliceLocalIdentifiers(records *sync.Map, slice *EndpointRequest, sliceDeleted bool,
	liveSlices []EndpointRequest, localPods map[string][]npatypes.Pod) {
	if slice != nil && sliceDeleted {
		records.Delete(*slice)
	}
	if len(localPods) == 0 {
		for _, live := range liveSlices {
			records.Delete(live)
		}
		return
	}
	// Shared by every entry, and never modified.
	podIdentifiers := slices.Sorted(maps.Keys(localPods))
	for _, live := range liveSlices {
		records.Store(live, podIdentifiers)
	}
}
