package framework

import (
	"context"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CreateSingleReplicaAndGetPod creates dp, waits until it is ready, and returns
// its pod.
//
// A Deployment rather than a standalone pod because GetPodIdentifier
// (pkg/utils/utils.go) drops a pod name's last "-" segment: two standalone pods
// can end up with the same identifier, and so share a set of BPF programs and
// policy maps, while ReplicaSet pod names (<deployment>-<hash>-<suffix>) give
// each pod its own.
func (f *Framework) CreateSingleReplicaAndGetPod(ctx context.Context, dp *appsv1.Deployment) *v1.Pod {
	// Both are read below rather than set here, so a Deployment that asks for
	// anything else fails naming its own mistake instead of on the single-pod
	// assert. An empty selector would match every pod in the namespace.
	Expect(dp.Spec.Replicas).To(HaveValue(BeEquivalentTo(1)), "%s is not a single-replica Deployment", dp.Name)
	Expect(dp.Spec.Selector.MatchLabels).ToNot(BeEmpty(), "%s has no label selector", dp.Name)

	_, err := f.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, dp)
	Expect(err).ToNot(HaveOccurred())

	pods, err := f.deploymentPods(ctx, dp)
	Expect(err).ToNot(HaveOccurred())
	// More than one means a pod of an earlier spec is still there, and the
	// caller would exec into or read the IP of the wrong one.
	Expect(pods).To(HaveLen(1), "expected one pod for Deployment %s", dp.Name)
	Expect(pods[0].Status.PodIP).ToNot(BeEmpty(), "pod %s has no IP", pods[0].Name)
	return &pods[0]
}

// DeleteDeploymentAndWaitForPodGone deletes dp and waits for its pod to go.
// The manager's delete returns once the API server accepts it, and the pod is
// removed in the background, so without the wait the next spec's single-pod
// lookup can still find this one.
func (f *Framework) DeleteDeploymentAndWaitForPodGone(ctx context.Context, dp *appsv1.Deployment) {
	// NotFound is ignored so this still cleans up after a create that failed
	// before the Deployment existed.
	Expect(client.IgnoreNotFound(f.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, dp))).To(Succeed())
	Eventually(func() ([]v1.Pod, error) {
		return f.deploymentPods(ctx, dp)
	}, utils.CleanupTimeout, utils.PollIntervalShort).Should(BeEmpty(), "pods of Deployment %s were not deleted", dp.Name)
}

// deploymentPods lists the pods matching dp's own selector, so callers do not
// have to agree with the Deployment builder on which label to look up.
func (f *Framework) deploymentPods(ctx context.Context, dp *appsv1.Deployment) ([]v1.Pod, error) {
	pods := &v1.PodList{}
	err := f.K8sClient.List(ctx, pods,
		client.InNamespace(dp.Namespace), client.MatchingLabels(dp.Spec.Selector.MatchLabels))
	return pods.Items, err
}
