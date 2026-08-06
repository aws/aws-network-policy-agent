package policy

import (
	"fmt"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*
Dataplane validation for the two remaining PolicyEndpoint deselection triggers.
selector_narrowing_test.go covers the first trigger (the NetworkPolicy podSelector is
narrowed). This file covers:

  - Pod label removal: the podSelector is untouched, the POD loses the label. The pod
    keeps running, so the agent must clear its policy maps and move
    egress_pod_state_map[POD_STATE_MAP_KEY] from POLICIES_APPLIED to the mode default
    in place. The label is patched on a bare pod, never on a Deployment template -
    patching a template recreates the pod and a fresh pod would pass even with the bug.

  - Two policies selecting one pod: dropping the pod from one of them must leave the
    other policy's rules programmed (the pod still has a PolicyEndpoint, so the
    reset-with-nil-rules path must not run). Only when the pod is dropped from the
    second policy as well does the reset happen.
*/

const (
	// Pod-label-removal scenario. Pod names avoid a "-<suffix>" form: the agent
	// derives the pin-path identifier by dropping everything after the last "-",
	// so names sharing a prefix would collapse onto one identifier.
	labelRemovalPolicyName    = "label-removal-egress-deny"
	labelRemovalSelectorKey   = "selector-group"
	labelRemovalSelectorValue = "labelremoval"
	labelRemovalClientName    = "labelremovalclient"
	labelRemovalServerName    = "labelremovalserver"

	// Two-policy scenario.
	multiPolicyAllowName         = "multi-policy-allow-server"
	multiPolicyDenyName          = "multi-policy-deny-all"
	multiPolicyAllowKey          = "multipolicy-allow-group"
	multiPolicyDenyKey           = "multipolicy-deny-group"
	multiPolicySelectorValue     = "multipolicy"
	multiPolicyClientName        = "multipolicyclient"
	multiPolicyAllowedServerName = "multipolicyallowedserver"
	multiPolicyBlockedServerName = "multipolicyblockedserver"
)

var _ = Describe("PolicyEndpoint Selector Narrowing on Pod Label Removal", Ordered, func() {
	var (
		serverPod  *v1.Pod
		clientPod  *v1.Pod
		serverIP   string
		clientNode string
		policy     *network.NetworkPolicy
		liveClient podSnapshot
	)

	It("should clear stale egress state when the pod loses the selector label, without a pod restart", func() {
		By("Deploying a target server pod exposing a probe-able port", func() {
			serverPod = buildNarrowingServer(labelRemovalServerName)
			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			serverIP = pod.Status.PodIP
			Expect(serverIP).ToNot(BeEmpty())
		})

		By("Deploying a client pod carrying the selector label", func() {
			clientPod = buildIdleClient(labelRemovalClientName,
				map[string]string{labelRemovalSelectorKey: labelRemovalSelectorValue})
			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			clientNode = pod.Spec.NodeName
			Expect(clientNode).ToNot(BeEmpty())
		})

		By("Applying an egress-deny policy whose podSelector matches the client label", func() {
			policy = manifest.NewNetworkPolicyBuilder().
				Namespace(namespace).
				Name(labelRemovalPolicyName).
				PodSelector(labelRemovalSelectorKey, labelRemovalSelectorValue).
				SetPolicyType(false, true).
				Build()

			printNetworkPolicyYAML(policy)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
		})

		By("Verifying the client cannot reach the server", func() {
			Eventually(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, labelRemovalClientName, serverIP, narrowingProbePort)
			}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
				"expected egress from %s to the server to be denied", labelRemovalClientName)
		})

		By("Confirming the client's egress pod state is POLICIES_APPLIED before the label is removed", func() {
			withBPFCheckPod(clientNode, func(checkPodName string) {
				Eventually(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(labelRemovalClientName, namespace))
				}, podStateTimeout, podStateInterval).Should(Equal(statePoliciesApplied),
					"egress_pod_state_map[%d] should be POLICIES_APPLIED while the policy selects %s",
					podStateMapKey, labelRemovalClientName)
			})
		})

		By("Removing the selector label from the live pod", func() {
			// Snapshot first so the post-transition assertion compares against the
			// instance that was actually denied.
			liveClient = snapshotPod(labelRemovalClientName)
			removePodLabel(labelRemovalClientName, labelRemovalSelectorKey)
		})

		By("Verifying the client recovers connectivity without a restart", func() {
			// Polling waits for the controller to regenerate the PolicyEndpoint and
			// for the agent to reconcile it - no fixed sleep.
			Eventually(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, labelRemovalClientName, serverIP, narrowingProbePort)
			}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s should regain egress once it no longer carries the selector label", labelRemovalClientName)
		})

		By("Confirming the same pod instance served the whole transition", func() {
			expectSamePodInstance(labelRemovalClientName, liveClient)
		})

		By("Confirming the client's egress pod state is reset to DEFAULT_ALLOW", func() {
			withBPFCheckPod(clientNode, func(checkPodName string) {
				Eventually(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(labelRemovalClientName, namespace))
				}, podStateTimeout, podStateInterval).Should(Equal(stateDefaultAllow),
					"egress_pod_state_map[%d] should fall back to DEFAULT_ALLOW once no policy selects %s",
					podStateMapKey, labelRemovalClientName)
			})
		})
	})

	AfterAll(func() {
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		}
		for _, pod := range []*v1.Pod{clientPod, serverPod} {
			if pod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
			}
		}
	})
})

var _ = Describe("PolicyEndpoint Selector Narrowing with Multiple Policies", Ordered, func() {
	var (
		allowedServerPod *v1.Pod
		blockedServerPod *v1.Pod
		clientPod        *v1.Pod
		allowedServerIP  string
		blockedServerIP  string
		clientNode       string
		allowPolicy      *network.NetworkPolicy
		denyPolicy       *network.NetworkPolicy
		liveClient       podSnapshot
	)

	It("should keep the remaining policy's rules when the pod is dropped from only one of two policies", func() {
		By("Deploying two server pods - one the allow policy permits, one it does not", func() {
			allowedServerPod = buildNarrowingServer(multiPolicyAllowedServerName)
			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, allowedServerPod, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			allowedServerIP = pod.Status.PodIP
			Expect(allowedServerIP).ToNot(BeEmpty())

			blockedServerPod = buildNarrowingServer(multiPolicyBlockedServerName)
			pod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, blockedServerPod, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			blockedServerIP = pod.Status.PodIP
			Expect(blockedServerIP).ToNot(BeEmpty())
		})

		By("Deploying a client pod carrying both policies' selector labels", func() {
			clientPod = buildIdleClient(multiPolicyClientName, map[string]string{
				multiPolicyAllowKey: multiPolicySelectorValue,
				multiPolicyDenyKey:  multiPolicySelectorValue,
			})
			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			clientNode = pod.Spec.NodeName
			Expect(clientNode).ToNot(BeEmpty())
		})

		By("Applying two policies against the same client - one allows the first server, one denies all egress", func() {
			// NetworkPolicy semantics union the allow sets, so with both policies in
			// place egress is permitted to the allowed server only. That gives us a
			// concrete rule (not just an isolation flag) whose survival we can observe.
			allowRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, allowedServerIP+hostMask(fw.Options.IpFamily)).
				AddPort(narrowingProbePort, v1.ProtocolTCP).
				Build()

			allowPolicy = manifest.NewNetworkPolicyBuilder().
				Namespace(namespace).
				Name(multiPolicyAllowName).
				PodSelector(multiPolicyAllowKey, multiPolicySelectorValue).
				AddEgressRule(allowRule).
				Build()

			denyPolicy = manifest.NewNetworkPolicyBuilder().
				Namespace(namespace).
				Name(multiPolicyDenyName).
				PodSelector(multiPolicyDenyKey, multiPolicySelectorValue).
				SetPolicyType(false, true).
				Build()

			printNetworkPolicyYAML(allowPolicy)
			printNetworkPolicyYAML(denyPolicy)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, allowPolicy)).To(Succeed())
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyPolicy)).To(Succeed())
		})

		By("Verifying both policies are enforced - allowed server reachable, other server denied", func() {
			Eventually(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, multiPolicyClientName, blockedServerIP, narrowingProbePort)
			}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
				"%s must not reach a server no policy allows", multiPolicyClientName)

			Eventually(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, multiPolicyClientName, allowedServerIP, narrowingProbePort)
			}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s should reach the server the allow policy permits", multiPolicyClientName)
		})

		By("Confirming the client's egress pod state is POLICIES_APPLIED", func() {
			withBPFCheckPod(clientNode, func(checkPodName string) {
				Eventually(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(multiPolicyClientName, namespace))
				}, podStateTimeout, podStateInterval).Should(Equal(statePoliciesApplied),
					"egress_pod_state_map[%d] should be POLICIES_APPLIED while both policies select %s",
					podStateMapKey, multiPolicyClientName)
			})
		})

		By("Dropping the client from the deny-all policy only", func() {
			// Snapshot first so the post-transition assertion compares against the
			// instance that was actually under both policies.
			liveClient = snapshotPod(multiPolicyClientName)
			removePodLabel(multiPolicyClientName, multiPolicyDenyKey)
		})

		By("Verifying the allow policy's rules survive - only its destination stays reachable", func() {
			// The window is the same budget the enforcement assertions use, so the
			// controller has regenerated the PolicyEndpoint and the agent has
			// reconciled it well inside it. A regression that clears the maps with nil
			// rules shows up here as the blocked server becoming reachable.
			Consistently(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, multiPolicyClientName, blockedServerIP, narrowingProbePort)
			}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
				"%s is still selected by the allow policy, so egress outside its rules must stay denied",
				multiPolicyClientName)

			Consistently(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, multiPolicyClientName, allowedServerIP, narrowingProbePort)
			}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
				"the allow policy's rule for %s must stay programmed", multiPolicyClientName)
		})

		By("Confirming the client's egress pod state stays POLICIES_APPLIED", func() {
			withBPFCheckPod(clientNode, func(checkPodName string) {
				Consistently(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(multiPolicyClientName, namespace))
				}, utils.StabilityWindow, podStateInterval).Should(Equal(statePoliciesApplied),
					"egress_pod_state_map[%d] must stay POLICIES_APPLIED while one policy still selects %s",
					podStateMapKey, multiPolicyClientName)
			})
		})

		By("Dropping the client from the allow policy as well", func() {
			removePodLabel(multiPolicyClientName, multiPolicyAllowKey)
		})

		By("Verifying egress is finally unrestricted", func() {
			Eventually(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, multiPolicyClientName, blockedServerIP, narrowingProbePort)
			}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s should regain full egress once no policy selects it", multiPolicyClientName)
		})

		By("Confirming the same pod instance served the whole transition", func() {
			expectSamePodInstance(multiPolicyClientName, liveClient)
		})

		By("Confirming the client's egress pod state is reset to DEFAULT_ALLOW", func() {
			withBPFCheckPod(clientNode, func(checkPodName string) {
				Eventually(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(multiPolicyClientName, namespace))
				}, podStateTimeout, podStateInterval).Should(Equal(stateDefaultAllow),
					"egress_pod_state_map[%d] should fall back to DEFAULT_ALLOW once no policy selects %s",
					podStateMapKey, multiPolicyClientName)
			})
		})
	})

	AfterAll(func() {
		for _, np := range []*network.NetworkPolicy{allowPolicy, denyPolicy} {
			if np != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			}
		}
		for _, pod := range []*v1.Pod{clientPod, allowedServerPod, blockedServerPod} {
			if pod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
			}
		}
	})
})

// buildNarrowingServer returns a server pod that keeps a TCP listener up on
// narrowingProbePort. busybox `nc -l` exits after one connection, so re-listen in a
// loop.
func buildNarrowingServer(name string) *v1.Pod {
	cmd := fmt.Sprintf("while true; do nc -l -p %d; done", narrowingProbePort)
	srv := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{cmd}).
		Build()

	return manifest.NewDefaultPodBuilder().
		Name(name).
		Namespace(namespace).
		AddLabel("app", name).
		Container(srv).
		Build()
}

// buildIdleClient returns an idle pod we exec probes into, carrying exactly the
// labels given. Unlike buildNarrowingClient it adds no implicit selector label, so
// the caller controls which policies select it.
func buildIdleClient(name string, labels map[string]string) *v1.Pod {
	ctnr := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()

	builder := manifest.NewDefaultPodBuilder().
		Name(name).
		Namespace(namespace).
		Container(ctnr)

	for key, value := range labels {
		builder = builder.AddLabel(key, value)
	}
	return builder.Build()
}

// removePodLabel drops labelKey from a live pod with a merge patch. The pod keeps
// running, which is the whole point: patching a Deployment's pod template would
// recreate the pod and a fresh pod would come up clean even with the bug present.
func removePodLabel(podName string, labelKey string) {
	Eventually(func() error {
		current := &v1.Pod{}
		if err := fw.K8sClient.Get(ctx,
			client.ObjectKey{Namespace: namespace, Name: podName}, current); err != nil {
			return err
		}
		if _, ok := current.Labels[labelKey]; !ok {
			return nil
		}
		updated := current.DeepCopy()
		delete(updated.Labels, labelKey)
		// MergeFrom renders the removal as a null value for the key.
		return fw.PodManager.PatchPod(ctx, current, updated)
	}, policyUpdateTimeout, utils.PollIntervalShort).Should(Succeed())

	Eventually(func() (map[string]string, error) {
		current := &v1.Pod{}
		if err := fw.K8sClient.Get(ctx,
			client.ObjectKey{Namespace: namespace, Name: podName}, current); err != nil {
			return nil, err
		}
		return current.Labels, nil
	}, policyUpdateTimeout, utils.PollIntervalShort).ShouldNot(HaveKey(labelKey),
		"label %s should be gone from pod %s", labelKey, podName)
}

// podSnapshot captures a running pod's identity so a later assertion can prove the
// recovery happened on the same instance instead of on a replacement.
type podSnapshot struct {
	uid          types.UID
	createdUnix  int64
	restartCount int32
}

func snapshotPod(podName string) podSnapshot {
	pod := &v1.Pod{}
	Expect(fw.K8sClient.Get(ctx,
		client.ObjectKey{Namespace: namespace, Name: podName}, pod)).To(Succeed())

	return podSnapshot{
		uid:          pod.UID,
		createdUnix:  pod.CreationTimestamp.Unix(),
		restartCount: totalRestarts(pod),
	}
}

// expectSamePodInstance asserts the pod was neither recreated nor restarted since
// the snapshot - the fix is about a live pod recovering in place.
func expectSamePodInstance(podName string, before podSnapshot) {
	pod := &v1.Pod{}
	Expect(fw.K8sClient.Get(ctx,
		client.ObjectKey{Namespace: namespace, Name: podName}, pod)).To(Succeed())

	Expect(pod.UID).To(Equal(before.uid),
		"pod %s was recreated - it must stay live across the transition", podName)
	Expect(pod.CreationTimestamp.Unix()).To(Equal(before.createdUnix),
		"pod %s creationTimestamp changed - it was replaced", podName)
	Expect(totalRestarts(pod)).To(Equal(before.restartCount),
		"pod %s containers restarted - recovery must not require a restart", podName)
	Expect(pod.Status.Phase).To(Equal(v1.PodRunning),
		"pod %s should still be running", podName)
}

func totalRestarts(pod *v1.Pod) int32 {
	var total int32
	for _, status := range pod.Status.ContainerStatuses {
		total += status.RestartCount
	}
	return total
}
