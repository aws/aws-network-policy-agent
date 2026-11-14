package agentflags

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// The agent container in the aws-node DaemonSet.
	agentDaemonSet = "aws-node"
	agentNamespace = "kube-system"
	agentContainer = "aws-eks-nodeagent"
	rolloutTimeout = 10 * time.Minute
)

// createPod creates pod, registers its deletion and waits for it to run.
func createPod(pod *v1.Pod) *v1.Pod {
	// Registered before the wait, so a pod that never starts is still deleted.
	DeferCleanup(func() { Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)).To(Succeed()) })
	running, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 3*time.Minute)
	Expect(err).ToNot(HaveOccurred())
	Expect(running.Status.PodIP).ToNot(BeEmpty())
	return running
}

func createPolicy(policy *network.NetworkPolicy) {
	Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
	DeferCleanup(func() { Expect(fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)).To(Succeed()) })
}

func agentArgs() []string {
	ds := agentDaemonSetObject()
	return append([]string(nil), agentContainerOf(ds).Args...)
}

// setAgentArgs sets the agent container's args and waits for the DaemonSet to
// roll out.
func setAgentArgs(args []string) {
	ds := agentDaemonSetObject()
	agentContainerOf(ds).Args = args
	Expect(fw.K8sClient.Update(ctx, ds)).To(Succeed())
	Eventually(func() bool {
		ds := agentDaemonSetObject()
		s := ds.Status
		return s.ObservedGeneration >= ds.Generation && s.UpdatedNumberScheduled == s.DesiredNumberScheduled &&
			s.NumberReady == s.DesiredNumberScheduled && s.NumberAvailable == s.DesiredNumberScheduled
	}, rolloutTimeout, 5*time.Second).Should(BeTrue(), "aws-node did not roll out")
}

func agentDaemonSetObject() *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: agentNamespace, Name: agentDaemonSet}, ds)).To(Succeed())
	return ds
}

func agentContainerOf(ds *appsv1.DaemonSet) *v1.Container {
	for i := range ds.Spec.Template.Spec.Containers {
		if ds.Spec.Template.Spec.Containers[i].Name == agentContainer {
			return &ds.Spec.Template.Spec.Containers[i]
		}
	}
	Fail("no " + agentContainer + " container in the " + agentDaemonSet + " DaemonSet")
	return nil
}
