package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*
Dataplane validation for PolicyEndpoint stale cleanup on selector narrowing.

When a NetworkPolicy's podSelector is narrowed, the deselected pod loses its last
PolicyEndpoint. The agent must clear that pod's policy maps and move
egress_pod_state_map[POD_STATE_MAP_KEY] from POLICIES_APPLIED back to the mode
default (DEFAULT_ALLOW in standard mode) so traffic recovers without a pod restart.
Before the fix the maps kept the stale deny state and the pod stayed cut off.
*/

const (
	// Mirrors pkg/ebpf: POD_STATE_MAP_KEY is the namespaced-policy key in the
	// per-pod pod_state map (key 1 is the cluster-policy slot).
	podStateMapKey = 0
	// Mirrors pkg/ebpf pod states.
	statePoliciesApplied = 0
	stateDefaultAllow    = 1

	// Mirrors pkg/utils.TC_EGRESS_POD_STATE_MAP — the per-pod egress state map
	// name as reported by `aws-eks-na-cli ebpf loaded-ebpfdata`.
	egressPodStateMapName = "egress_pod_state_map"

	// These constants are duplicated rather than imported so the integration
	// suite stays independent of the agent packages, which pull in linux-only
	// eBPF and netlink dependencies.

	narrowingProbePort  = 8080
	narrowingPodTimeout = 2 * time.Minute
	podStateTimeout     = 2 * time.Minute
	podStateInterval    = 5 * time.Second
	policyUpdateTimeout = 30 * time.Second
	narrowingLabelKey   = "app"
	narrowingLabelValue = "narrowingclient"
	narrowingModeKey    = "network-mode"
	narrowingModeValue  = "private"
	narrowingPolicyName = "selector-narrowing-egress-deny"
	narrowingServerName = "narrowingserver"
	narrowingOpenClient = "selectoropen"
	narrowingPrivClient = "selectorprivate"
)

var _ = Describe("PolicyEndpoint Selector Narrowing", Ordered, func() {
	var (
		serverPod     *v1.Pod
		openClient    *v1.Pod
		privateClient *v1.Pod
		serverIP      string
		openNodeName  string
		policy        *network.NetworkPolicy
	)

	It("should clear stale egress state so a deselected pod recovers without a restart", func() {
		By("Deploying a target server pod exposing a probe-able port", func() {
			// busybox `nc -l` exits after one connection, so re-listen in a loop.
			cmd := fmt.Sprintf("while true; do nc -l -p %d; done", narrowingProbePort)
			srv := manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{cmd}).
				Build()

			serverPod = manifest.NewDefaultPodBuilder().
				Name(narrowingServerName).
				Namespace(namespace).
				AddLabel("app", narrowingServerName).
				Container(srv).
				Build()

			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			serverIP = pod.Status.PodIP
			Expect(serverIP).ToNot(BeEmpty())
		})

		By("Deploying both client pods - selectoropen (unlabelled) and selectorprivate (network-mode=private)", func() {
			// Pod names deliberately avoid a "-<suffix>" form: the agent derives the
			// pin-path identifier by dropping everything after the last "-", so
			// "client-open" and "client-private" would collapse to one identifier and
			// the per-pod maps could no longer be told apart.
			openClient = buildNarrowingClient(narrowingOpenClient, nil)
			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, openClient, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
			openNodeName = pod.Spec.NodeName
			Expect(openNodeName).ToNot(BeEmpty())

			privateClient = buildNarrowingClient(narrowingPrivClient,
				map[string]string{narrowingModeKey: narrowingModeValue})
			_, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, privateClient, narrowingPodTimeout)
			Expect(err).ToNot(HaveOccurred())
		})

		By("Applying a broad egress-deny policy whose podSelector matches both clients", func() {
			policy = manifest.NewNetworkPolicyBuilder().
				Namespace(namespace).
				Name(narrowingPolicyName).
				PodSelector(narrowingLabelKey, narrowingLabelValue).
				SetPolicyType(false, true).
				Build()

			printNetworkPolicyYAML(policy)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())
		})

		By("Verifying neither client can reach the server", func() {
			for _, clientName := range []string{narrowingOpenClient, narrowingPrivClient} {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, clientName, serverIP, narrowingProbePort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"expected egress from %s to the server to be denied", clientName)
			}
		})

		By("Confirming selectoropen's egress pod state is POLICIES_APPLIED before narrowing", func() {
			withBPFCheckPod(openNodeName, func(checkPodName string) {
				Eventually(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(narrowingOpenClient, namespace))
				}, podStateTimeout, podStateInterval).Should(Equal(statePoliciesApplied),
					"egress_pod_state_map[%d] should be POLICIES_APPLIED while the policy selects %s",
					podStateMapKey, narrowingOpenClient)
			})
		})

		By("Narrowing the podSelector to network-mode=private", func() {
			// Retry on conflict - the API server may have a newer resourceVersion.
			Eventually(func() error {
				current := &network.NetworkPolicy{}
				if err := fw.K8sClient.Get(ctx,
					client.ObjectKey{Namespace: namespace, Name: narrowingPolicyName}, current); err != nil {
					return err
				}
				current.Spec.PodSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{narrowingModeKey: narrowingModeValue},
				}
				return fw.K8sClient.Update(ctx, current)
			}, policyUpdateTimeout, utils.PollIntervalShort).Should(Succeed())
		})

		By("Verifying selectoropen recovers connectivity without a restart", func() {
			// Polling here is what waits for the controller to regenerate the
			// PolicyEndpoint and for the agent to reconcile it - no fixed sleep.
			Eventually(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, narrowingOpenClient, serverIP, narrowingProbePort)
			}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
				"%s should regain egress once the policy no longer selects it", narrowingOpenClient)
		})

		By("Verifying selectorprivate is still denied", func() {
			Consistently(func() (string, error) {
				return fw.PodManager.TCPProbe(namespace, narrowingPrivClient, serverIP, narrowingProbePort)
			}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
				"%s is still selected by the narrowed policy and must stay denied", narrowingPrivClient)
		})

		By("Confirming selectoropen's egress pod state is reset to DEFAULT_ALLOW", func() {
			withBPFCheckPod(openNodeName, func(checkPodName string) {
				Eventually(func() (int, error) {
					return egressPodState(checkPodName, podIdentifierFor(narrowingOpenClient, namespace))
				}, podStateTimeout, podStateInterval).Should(Equal(stateDefaultAllow),
					"egress_pod_state_map[%d] should fall back to DEFAULT_ALLOW once no policy selects %s",
					podStateMapKey, narrowingOpenClient)
			})
		})
	})

	AfterAll(func() {
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		}
		for _, pod := range []*v1.Pod{openClient, privateClient, serverPod} {
			if pod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
			}
		}
	})
})

// buildNarrowingClient returns an idle client pod we exec probes into. Every client
// carries the broad selector label; extraLabels adds the narrowed selector label.
func buildNarrowingClient(name string, extraLabels map[string]string) *v1.Pod {
	ctnr := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()

	builder := manifest.NewDefaultPodBuilder().
		Name(name).
		Namespace(namespace).
		AddLabel(narrowingLabelKey, narrowingLabelValue).
		Container(ctnr)

	for key, value := range extraLabels {
		builder = builder.AddLabel(key, value)
	}
	return builder.Build()
}

// withBPFCheckPod runs fn against a privileged pod on nodeName that can inspect the
// node's BPF state through chroot. The pod is torn down when fn returns.
func withBPFCheckPod(nodeName string, fn func(checkPodName string)) {
	checkPod := utils.BuildBPFCheckPod(namespace, nodeName)
	checkPod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, narrowingPodTimeout)
	Expect(err).ToNot(HaveOccurred())
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)

	fn(checkPod.Name)
}

// egressPodState reads egress_pod_state_map[POD_STATE_MAP_KEY] for podIdentifier by
// resolving the map ID from `ebpf loaded-ebpfdata` and then dumping that map.
// Errors are returned (not asserted) so callers can poll with Eventually while the
// agent reconciles.
func egressPodState(checkPodName string, podIdentifier string) (int, error) {
	output, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	if err != nil {
		return -1, fmt.Errorf("loaded-ebpfdata exec failed: %w", err)
	}

	state, err := utils.ParseLoadedEBPFData(output)
	if err != nil {
		return -1, fmt.Errorf("parse loaded-ebpfdata: %w", err)
	}

	mapKey := podIdentifier + "/" + egressPodStateMapName
	mapID, ok := state.MapIDs[mapKey]
	if !ok {
		return -1, fmt.Errorf("map %q not found in loaded bpf data (available: %v)", mapKey, mapNames(state))
	}

	dump, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "dump-maps", strconv.Itoa(mapID)})
	if err != nil {
		return -1, fmt.Errorf("dump-maps %d exec failed: %w", mapID, err)
	}

	states := parsePodStateDump(dump)
	value, ok := states[podStateMapKey]
	if !ok {
		return -1, fmt.Errorf("key %d absent from map %q (id %d), dump:\n%s", podStateMapKey, mapKey, mapID, dump)
	}
	GinkgoWriter.Printf("%s (map id %d) key %d state = %d\n", mapKey, mapID, podStateMapKey, value)
	return value, nil
}

// parsePodStateDump parses `ebpf dump-maps <id>` output for a HASH pod_state map:
//
//	Key :  0
//	State -  1
//	*******************************
func parsePodStateDump(output string) map[int]int {
	states := make(map[int]int)
	currentKey := -1

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Key :"):
			key, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Key :")))
			if err != nil {
				currentKey = -1
				continue
			}
			currentKey = key
		case strings.HasPrefix(line, "State -"):
			value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "State -")))
			if err != nil || currentKey < 0 {
				continue
			}
			states[currentKey] = value
			currentKey = -1
		}
	}
	return states
}

// podIdentifierFor mirrors pkg/utils.GetPodIdentifier: "." becomes "_", everything
// after the last "-" in the pod name is dropped, and the namespace is joined with
// "@". Kept local so this suite does not depend on the agent's linux-only packages.
func podIdentifierFor(podName string, podNamespace string) string {
	prefix := strings.ReplaceAll(podName, ".", "_")
	if idx := strings.LastIndex(prefix, "-"); idx != -1 {
		prefix = prefix[:idx]
	}
	return prefix + "@" + podNamespace
}

func mapNames(state utils.BPFState) []string {
	names := make([]string, 0, len(state.MapIDs))
	for name := range state.MapIDs {
		names = append(names, name)
	}
	return names
}
