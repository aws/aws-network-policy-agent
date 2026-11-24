package agentflags

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
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
