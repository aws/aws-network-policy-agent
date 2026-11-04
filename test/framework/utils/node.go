package utils

import (
	"context"

	"github.com/samber/lo"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SchedulableNodes returns ready Linux worker nodes that pods can be pinned to with NodeName.
// NodeName bypasses the scheduler, so it skips nodes the agent does not run on or that would
// evict the pods: non-Linux, Fargate, cordoned, NoExecute-tainted, not ready.
func SchedulableNodes(ctx context.Context, k8sClient client.Client) ([]string, error) {
	nodes := &v1.NodeList{}
	if err := k8sClient.List(ctx, nodes, client.MatchingLabels{"kubernetes.io/os": "linux"}); err != nil {
		return nil, err
	}
	var ready []string
	for _, n := range nodes.Items {
		if n.Spec.Unschedulable || n.Labels["eks.amazonaws.com/compute-type"] == "fargate" {
			continue
		}
		if lo.ContainsBy(n.Spec.Taints, func(t v1.Taint) bool { return t.Effect == v1.TaintEffectNoExecute }) {
			continue
		}
		if lo.ContainsBy(n.Status.Conditions, func(c v1.NodeCondition) bool {
			return c.Type == v1.NodeReady && c.Status == v1.ConditionTrue
		}) {
			ready = append(ready, n.Name)
		}
	}
	return ready, nil
}
