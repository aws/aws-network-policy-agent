package framework

import (
	"context"
	"time"

	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The node agent's container in the aws-node DaemonSet, whose args the suites
// that test agent flags change.
const (
	agentDaemonSet      = "aws-node"
	agentNamespace      = "kube-system"
	agentContainer      = "aws-eks-nodeagent"
	agentRolloutTimeout = 10 * time.Minute
)

// AgentArgs returns a copy of the node agent container's args.
func (f *Framework) AgentArgs(ctx context.Context) []string {
	return append([]string(nil), agentContainerOf(f.agentDaemonSet(ctx)).Args...)
}

// SetAgentArgs sets the node agent container's args and waits for aws-node to
// roll out, so the next step runs against agents started with them.
func (f *Framework) SetAgentArgs(ctx context.Context, args []string) {
	ds := f.agentDaemonSet(ctx)
	agentContainerOf(ds).Args = args
	Expect(f.K8sClient.Update(ctx, ds)).To(Succeed())
	Eventually(func() bool {
		ds := f.agentDaemonSet(ctx)
		s := ds.Status
		return s.ObservedGeneration >= ds.Generation && s.UpdatedNumberScheduled == s.DesiredNumberScheduled &&
			s.NumberReady == s.DesiredNumberScheduled && s.NumberAvailable == s.DesiredNumberScheduled
	}, agentRolloutTimeout, 5*time.Second).Should(BeTrue(), "aws-node did not roll out")
}

func (f *Framework) agentDaemonSet(ctx context.Context) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{}
	Expect(f.K8sClient.Get(ctx, client.ObjectKey{Namespace: agentNamespace, Name: agentDaemonSet}, ds)).To(Succeed())
	return ds
}

func agentContainerOf(ds *appsv1.DaemonSet) *v1.Container {
	var c *v1.Container
	for i := range ds.Spec.Template.Spec.Containers {
		if ds.Spec.Template.Spec.Containers[i].Name == agentContainer {
			c = &ds.Spec.Template.Spec.Containers[i]
		}
	}
	Expect(c).ToNot(BeNil(), "no %s container in the %s DaemonSet", agentContainer, agentDaemonSet)
	return c
}
