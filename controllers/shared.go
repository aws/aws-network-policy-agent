package controllers

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

// Helpers shared by the PolicyEndpoint and ClusterPolicyEndpoint reconcilers. Both follow the
// same shape -- derive the pods a policy selects, clean up the ones it no longer does, attach
// probes for what remains -- so the pieces that carry no controller-specific state live here
// once rather than being kept in step by hand in both files.

// trackFailedCleanups returns the pods to commit as this policy's tracked set, and the
// identifier set to commit alongside them.
//
// The tracked set is the pods the policy still programs plus the pods whose cleanup failed.
// Committing the failures keeps them discoverable, so the next reconcile derives exactly those
// as stale again and retries only them; dropping them would lose the failure, because the
// retry derives its cleanup list from what was committed.
//
// Neither input is mutated: targetPods is cloned before the append so a full backing array
// cannot be written through, and the identifier map is cloned before the failures are added.
func trackFailedCleanups(targetPods, failedCleanups []npatypes.Pod,
	clusterWidePodIdentifiers map[string]bool) ([]npatypes.Pod, map[string]bool) {

	trackedPods := append(slices.Clone(targetPods), failedCleanups...)

	trackedPodIdentifiers := maps.Clone(clusterWidePodIdentifiers)
	if trackedPodIdentifiers == nil {
		// maps.Clone(nil) is nil, which cannot be assigned to below.
		trackedPodIdentifiers = make(map[string]bool, len(failedCleanups))
	}
	for _, pod := range failedCleanups {
		trackedPodIdentifiers[utils.GetPodIdentifier(pod.Name, pod.Namespace)] = true
	}
	return trackedPods, trackedPodIdentifiers
}

// attachOutcome counts what attachProbesForIdentifier did, so a caller can tell a pass that
// only skipped from one that attached nothing at all.
type attachOutcome struct {
	// attached is the number of pods whose probes are now in place.
	attached int
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

		outcome.attached++
		log().Debugf("eBPF probes in place for pod: %s in namespace %s", pod.Name, pod.Namespace)
	}
	return outcome, attachErr
}
