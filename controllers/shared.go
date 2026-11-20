package controllers

import (
	"errors"
	"fmt"

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
