package soak

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// PolicyEndpoint group/version/resource. NPA consumes PolicyEndpoints produced by
// the Network Policy Controller; if the controller is not producing them, NPA has
// nothing to enforce and every probe in the soak is vacuous. Keep in sync with
// api/v1alpha1.GroupVersion.
const (
	policyEndpointGroup    = "networking.k8s.aws"
	policyEndpointVersion  = "v1alpha1"
	policyEndpointResource = "policyendpoints"
)

// assertNetworkPolicyEnforced is the fail-fast setup precondition. It applies a
// throwaway ingress-deny policy to a probe pod and confirms the controller emits a
// PolicyEndpoint for it within a timeout. Without that, enforcement is off (the CNI
// addon's network-policy feature is disabled, or the controller is down), the whole
// cluster default-allows, and a green soak would be meaningless. This is the exact
// trap a prior real run hit, so the soak refuses to start rather than report a
// false pass.
//
// It runs in the suite namespace, cleans up its throwaway objects, and fails the
// suite (via Expect) if enforcement is not observed.
func assertNetworkPolicyEnforced() {
	const probeLabel = "npa-soak-np-precheck"

	By("verifying network policy is actually enforced (PolicyEndpoint is produced)")

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      probeLabel,
			Namespace: namespace,
			Labels:    map[string]string{"app": probeLabel},
		},
		Spec: v1.PodSpec{
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name: "sleep", Image: driverImage, Command: []string{"sleep", "300"},
			}},
		},
	}
	created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, podReadyTimeout)
	Expect(err).ToNot(HaveOccurred(), "np-precheck pod did not start")
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, created)

	policy := &network.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: probeLabel, Namespace: namespace},
		Spec: network.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": probeLabel}},
			PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
		},
	}
	Expect(fw.K8sClient.Create(ctx, policy)).To(Succeed(), "create np-precheck policy")
	defer fw.K8sClient.Delete(ctx, policy)

	// The controller translates the NetworkPolicy into a PolicyEndpoint in the same
	// namespace. Poll for at least one to appear.
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 2*time.Minute, true,
		func(context.Context) (bool, error) {
			n, err := countPolicyEndpoints(namespace)
			if err != nil {
				// A transient API error is not a verdict; keep polling.
				GinkgoWriter.Printf("np-precheck: list PolicyEndpoints: %v\n", err)
				return false, nil
			}
			return n > 0, nil
		})
	Expect(err).ToNot(HaveOccurred(),
		"network policy is not being enforced: no PolicyEndpoint was produced for a "+
			"deny policy within the timeout. Enable the CNI network-policy feature "+
			"(--enable-network-policy=true) and confirm the Network Policy Controller "+
			"is running before starting the soak.")
}

// countPolicyEndpoints returns the number of PolicyEndpoint objects in a namespace,
// read through the clientset's REST client so the soak needs no CRD scheme
// registration and stays environment-agnostic.
func countPolicyEndpoints(ns string) (int, error) {
	raw, err := clientset.RESTClient().Get().
		AbsPath("apis", policyEndpointGroup, policyEndpointVersion,
			"namespaces", ns, policyEndpointResource).
		DoRaw(ctx)
	if err != nil {
		return 0, fmt.Errorf("list policyendpoints in %s: %w", ns, err)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("decode policyendpoint list: %w", err)
	}
	return len(list.Items), nil
}
