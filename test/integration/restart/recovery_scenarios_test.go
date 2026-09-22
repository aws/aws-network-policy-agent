package restart

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
)

/*
Recovery Scenarios Test Suite

Four test cases covering the recovery paths:
1. Policy lifecycle across restarts — maps update correctly post-recovery
2. Program pin deletion → partial recovery → reconcile heals
3. Map pin deletion → partial recovery → reconcile heals (program dropped, reloaded fresh)
4. Shared progFD protection — delete one pod of a shared set, program stays alive
*/

var _ = Describe("Recovery Scenarios", Ordered, func() {

	var (
		checkPod *v1.Pod
		nodeName string
	)

	BeforeAll(func() {
		// We need at least one pod to determine a node; create the check pod later
		// once we know the node.
	})

	AfterAll(func() {
		if checkPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
		}
	})

	Describe("Test 1: Policy Lifecycle Across Restarts", Ordered, func() {
		var (
			serverPod     *v1.Pod
			clientPod     *v1.Pod
			networkPolicy *network.NetworkPolicy
			serverIP      string
			preRestartIDs map[int]bool
		)

		It("validates deny → restart → allow → restart → delete policy → restart with state cross-check", func() {
			By("Creating server and client pods")
			serverPod = &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "policy-lifecycle-server", Namespace: namespace,
					Labels: map[string]string{"app": "policy-lifecycle"},
				},
				Spec: v1.PodSpec{Containers: []v1.Container{{
					Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
					Ports: []v1.ContainerPort{{ContainerPort: 80}},
				}}},
			}
			var err error
			serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
			nodeName = serverPod.Spec.NodeName
			serverIP = serverPod.Status.PodIP

			clientPod = &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "policy-lifecycle-client", Namespace: namespace,
					Labels: map[string]string{"app": "policy-lifecycle-client"},
				},
				Spec: v1.PodSpec{
					NodeName:   nodeName,
					Containers: []v1.Container{{Name: "curl", Image: "public.ecr.aws/docker/library/python:3.11-slim", Command: []string{"sleep", "3600"}}},
				},
			}
			clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())

			// Create the check pod on the same node
			checkPod = buildRecoveryCheckPod(nodeName)
			checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
			recoveryCheckPod = checkPod

			By("Step 1: Apply deny-all ingress policy")
			networkPolicy = &network.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-lifecycle-deny", Namespace: namespace},
				Spec: network.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "policy-lifecycle"}},
					PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				},
			}
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
			time.Sleep(bpfSettleInterval)

			By("Verify traffic is BLOCKED")
			Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))

			By("Step 2: Rollout restart DS")
			rolloutRestartDaemonSet()
			waitForDaemonSetRollout()
			time.Sleep(bpfSettleInterval)

			By("Validate state: capture prog IDs from TC")
			vethName := utils.HostVethName(namespace, serverPod.Name, podVethPrefix, 0)
			preRestartIDs = tcAttachedProgIDSet(vethName)
			Expect(preRestartIDs).To(HaveLen(2), "expected 2 prog IDs attached at veth after restart")

			By("Validate: CLI prog IDs match TC prog IDs")
			allState := dumpAllBPFStateFromCLI()
			for pin, progID := range allState.ProgIDs {
				if strings.Contains(pin, "policy-lifecycle") {
					Expect(preRestartIDs).To(HaveKey(progID),
						"CLI prog ID %d for pin %s not found on TC veth", progID, pin)
				}
			}

			By("Verify traffic still BLOCKED after restart")
			Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))

			By("Step 3: Update policy to allow ingress from client")
			// Re-fetch to get latest resourceVersion
			updatedPolicy := &network.NetworkPolicy{}
			Expect(fw.K8sClient.Get(ctx, client.ObjectKeyFromObject(networkPolicy), updatedPolicy)).To(Succeed())
			updatedPolicy.Spec.Ingress = []network.NetworkPolicyIngressRule{{
				From: []network.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "policy-lifecycle-client"}},
				}},
			}}
			Expect(fw.K8sClient.Update(ctx, updatedPolicy)).To(Succeed())
			networkPolicy = updatedPolicy
			time.Sleep(bpfSettleInterval)

			By("Verify traffic is now ALLOWED")
			Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("CONNECTED"))

			By("Step 4: Rollout restart DS again")
			rolloutRestartDaemonSet()
			waitForDaemonSetRollout()
			time.Sleep(bpfSettleInterval)

			By("Validate state: prog IDs preserved (same programs reused)")
			postRestartIDs := tcAttachedProgIDSet(vethName)
			Expect(postRestartIDs).To(Equal(preRestartIDs),
				"prog IDs should be preserved across same-binary restart")

			By("Verify traffic still ALLOWED after second restart")
			Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("CONNECTED"))

			By("Step 5: Delete the allow policy (revert to no policy = default allow)")
			Expect(fw.K8sClient.Delete(ctx, networkPolicy)).To(Succeed())
			time.Sleep(bpfSettleInterval)

			By("Verify traffic ALLOWED (no policy = no enforcement)")
			Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("CONNECTED"))

			By("Step 6: Rollout restart DS one more time")
			rolloutRestartDaemonSet()
			waitForDaemonSetRollout()
			time.Sleep(bpfSettleInterval)

			By("Validate state: progs still attached at veth")
			finalIDs := tcAttachedProgIDSet(vethName)
			Expect(finalIDs).ToNot(BeEmpty(), "progs should still be attached after final restart")
		})

		AfterAll(func() {
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if clientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
			}
			if networkPolicy != nil {
				_ = fw.K8sClient.Delete(ctx, networkPolicy)
			}
		})
	})

	Describe("Test 2: Program Pin Deletion → Partial Recovery → Reconcile Heals", Ordered, func() {
		var (
			serverPod     *v1.Pod
			networkPolicy *network.NetworkPolicy
		)

		It("recovers after a program pin is manually deleted", func() {
			By("Creating a pod targeted by a network policy")
			serverPod = &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pin-delete-server", Namespace: namespace,
					Labels: map[string]string{"app": "pin-delete"},
				},
				Spec: v1.PodSpec{Containers: []v1.Container{{
					Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
					Ports: []v1.ContainerPort{{ContainerPort: 80}},
				}}},
			}
			var err error
			serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
			if nodeName == "" {
				nodeName = serverPod.Spec.NodeName
			}

			// Ensure check pod exists on this node
			if recoveryCheckPod == nil {
				checkPod = buildRecoveryCheckPod(nodeName)
				checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
				Expect(err).ToNot(HaveOccurred())
				recoveryCheckPod = checkPod
			}
			time.Sleep(bpfSettleInterval)

			networkPolicy = &network.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "pin-delete-policy", Namespace: namespace},
				Spec: network.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "pin-delete"}},
					PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
					Ingress:     []network.NetworkPolicyIngressRule{{From: []network.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}},
				},
			}
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
			time.Sleep(bpfSettleInterval)

			By("Capturing pre-state: prog IDs on TC veth")
			vethName := utils.HostVethName(namespace, serverPod.Name, podVethPrefix, 0)
			preProgIDs := tcAttachedProgIDSet(vethName)
			Expect(preProgIDs).To(HaveLen(2))

			By("Deleting the ingress program pin from bpffs")
			podIdentifier := getPodIdentifierFromCLI(serverPod.Name)
			ingressPinPath := fmt.Sprintf("/sys/fs/bpf/globals/aws/programs/%s_handle_ingress", podIdentifier)
			execInCheckPod([]string{"chroot", "/host", "rm", "-f", ingressPinPath})

			By("Verifying pin is gone")
			out, _ := execInCheckPodSoft([]string{"chroot", "/host", "ls", ingressPinPath})
			Expect(out).To(Or(ContainSubstring("No such file"), BeEmpty()))

			By("Rollout restart DS — triggers recovery")
			rolloutRestartDaemonSet()
			waitForDaemonSetRollout()
			time.Sleep(bpfSettleInterval)

			// After recovery + reconcile, the pin should be recreated
			By("Waiting for reconcile to heal — pin should be recreated")
			Eventually(func() bool {
				out := execInCheckPod([]string{"chroot", "/host", "ls", "/sys/fs/bpf/globals/aws/programs/"})
				return strings.Contains(out, podIdentifier+"_handle_ingress")
			}, 30*time.Second, 2*time.Second).Should(BeTrue(), "ingress pin should be recreated by reconcile")

			By("Validating TC still has progs attached (may have new prog ID for ingress)")
			postProgIDs := tcAttachedProgIDSet(vethName)
			Expect(postProgIDs).To(HaveLen(2), "both ingress and egress progs should be attached")

			By("Verify enforcement still works")
			// Create a quick client to test
			clientPod := &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pin-delete-client", Namespace: namespace,
					Labels: map[string]string{"app": "pin-delete-client"},
				},
				Spec: v1.PodSpec{
					NodeName:   nodeName,
					Containers: []v1.Container{{Name: "curl", Image: "public.ecr.aws/docker/library/python:3.11-slim", Command: []string{"sleep", "300"}}},
				},
			}
			clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
			defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)

			Expect(execConnect(namespace, clientPod.Name, serverPod.Status.PodIP, 80)).To(Equal("CONNECTED"))
		})

		AfterAll(func() {
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if networkPolicy != nil {
				_ = fw.K8sClient.Delete(ctx, networkPolicy)
			}
		})
	})

	Describe("Test 3: Map Pin Deletion → Partial Recovery → Reconcile Heals", Ordered, func() {
		var (
			serverPod     *v1.Pod
			networkPolicy *network.NetworkPolicy
		)

		It("recovers after a map pin is manually deleted (program dropped during recovery, then reloaded)", func() {
			By("Creating a pod targeted by a network policy")
			serverPod = &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "map-delete-server", Namespace: namespace,
					Labels: map[string]string{"app": "map-delete"},
				},
				Spec: v1.PodSpec{Containers: []v1.Container{{
					Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
					Ports: []v1.ContainerPort{{ContainerPort: 80}},
				}}},
			}
			var err error
			serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, podReadyTimeout)
			Expect(err).ToNot(HaveOccurred())
			if nodeName == "" {
				nodeName = serverPod.Spec.NodeName
			}

			// Ensure check pod exists on this node
			if recoveryCheckPod == nil {
				checkPod = buildRecoveryCheckPod(nodeName)
				checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
				Expect(err).ToNot(HaveOccurred())
				recoveryCheckPod = checkPod
			}
			time.Sleep(bpfSettleInterval)

			networkPolicy = &network.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "map-delete-policy", Namespace: namespace},
				Spec: network.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "map-delete"}},
					PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
					Ingress:     []network.NetworkPolicyIngressRule{{From: []network.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}},
				},
			}
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
			time.Sleep(bpfSettleInterval)

			By("Capturing pre-state: prog IDs on TC veth")
			vethName := utils.HostVethName(namespace, serverPod.Name, podVethPrefix, 0)
			preProgIDs := tcAttachedProgIDSet(vethName)
			Expect(preProgIDs).To(HaveLen(2))

			By("Deleting the ingress MAP pin from bpffs (not the program)")
			podIdentifier := getPodIdentifierFromCLI(serverPod.Name)
			mapPinPath := fmt.Sprintf("/sys/fs/bpf/globals/aws/maps/%s_ingress_map", podIdentifier)
			execInCheckPod([]string{"chroot", "/host", "rm", "-f", mapPinPath})

			By("Rollout restart DS — recovery should partially fail for this pod's ingress program")
			rolloutRestartDaemonSet()
			waitForDaemonSetRollout()
			time.Sleep(bpfSettleInterval)

			// The reconcile should reload the program (overwriting the stale pin)
			By("Waiting for reconcile to heal — program and map pins should be recreated")
			Eventually(func() bool {
				out := execInCheckPod([]string{"chroot", "/host", "ls", "/sys/fs/bpf/globals/aws/maps/"})
				return strings.Contains(out, podIdentifier+"_ingress_map")
			}, 30*time.Second, 2*time.Second).Should(BeTrue(), "ingress map pin should be recreated by reconcile")

			By("Validating TC has progs attached (ingress should have new prog ID)")
			postProgIDs := tcAttachedProgIDSet(vethName)
			Expect(postProgIDs).To(HaveLen(2), "both progs should be attached after heal")

			By("Verify enforcement still works")
			clientPod := &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "map-delete-client", Namespace: namespace,
					Labels: map[string]string{"app": "map-delete-client"},
				},
				Spec: v1.PodSpec{
					NodeName:   nodeName,
					Containers: []v1.Container{{Name: "curl", Image: "public.ecr.aws/docker/library/python:3.11-slim", Command: []string{"sleep", "300"}}},
				},
			}
			var clientErr error
			clientPod, clientErr = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
			Expect(clientErr).ToNot(HaveOccurred())
			defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)

			Expect(execConnect(namespace, clientPod.Name, serverPod.Status.PodIP, 80)).To(Equal("CONNECTED"))
		})

		AfterAll(func() {
			if serverPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			}
			if networkPolicy != nil {
				_ = fw.K8sClient.Delete(ctx, networkPolicy)
			}
		})
	})

	Describe("Test 4: Shared ProgFD Protection — Delete One Pod, Program Stays for Siblings", Ordered, func() {
		var (
			networkPolicy *network.NetworkPolicy
			pod1          *v1.Pod
			pod2          *v1.Pod
		)

		It("does not delete shared program pins when one of multiple pods sharing a podIdentifier is deleted", func() {
			By("Creating two pods that share the same podIdentifier (same RS hash pattern)")
			// Use a deployment with 2 replicas to get shared podIdentifier
			labels := map[string]string{"app": "shared-prog"}
			replicas := int32(2)
			deploy := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-prog", Namespace: namespace},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Selector: &metav1.LabelSelector{MatchLabels: labels},
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: labels},
						Spec: v1.PodSpec{
							NodeName:   nodeName,
							Containers: []v1.Container{{Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest", Ports: []v1.ContainerPort{{ContainerPort: 80}}}},
						},
					},
				},
			}

			// Determine node if not set
			if nodeName == "" {
				nodes := &v1.NodeList{}
				Expect(fw.K8sClient.List(ctx, nodes)).To(Succeed())
				Expect(nodes.Items).ToNot(BeEmpty())
				nodeName = nodes.Items[0].Name
				deploy.Spec.Template.Spec.NodeName = nodeName
			}

			Expect(fw.K8sClient.Create(ctx, deploy)).To(Succeed())
			defer func() {
				_ = fw.K8sClient.Delete(ctx, deploy)
				time.Sleep(10 * time.Second)
			}()

			// Wait for both pods
			Eventually(func() int {
				pods := &v1.PodList{}
				_ = fw.K8sClient.List(ctx, pods, client.InNamespace(namespace), client.MatchingLabels(labels))
				running := 0
				for _, p := range pods.Items {
					if p.Status.Phase == v1.PodRunning {
						running++
					}
				}
				return running
			}, podReadyTimeout, 2*time.Second).Should(Equal(2))

			By("Applying a network policy to trigger probe attachment")
			networkPolicy = &network.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-prog-policy", Namespace: namespace},
				Spec: network.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: labels},
					PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
					Ingress:     []network.NetworkPolicyIngressRule{{From: []network.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}},
				},
			}
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())

			// Ensure check pod exists on this node
			if recoveryCheckPod == nil {
				var cpErr error
				checkPod = buildRecoveryCheckPod(nodeName)
				checkPod, cpErr = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, podReadyTimeout)
				Expect(cpErr).ToNot(HaveOccurred())
				recoveryCheckPod = checkPod
			}
			time.Sleep(bpfSettleInterval)

			By("Getting both pods and their shared podIdentifier")
			pods := &v1.PodList{}
			Expect(fw.K8sClient.List(ctx, pods, client.InNamespace(namespace), client.MatchingLabels(labels))).To(Succeed())
			Expect(pods.Items).To(HaveLen(2))
			pod1 = &pods.Items[0]
			pod2 = &pods.Items[1]

			By("Verifying both pods share the same prog IDs (shared program)")
			veth1 := utils.HostVethName(namespace, pod1.Name, podVethPrefix, 0)
			veth2 := utils.HostVethName(namespace, pod2.Name, podVethPrefix, 0)
			progIDs1 := tcAttachedProgIDSet(veth1)
			progIDs2 := tcAttachedProgIDSet(veth2)
			Expect(progIDs1).To(Equal(progIDs2), "both pods should share the same prog IDs")

			By("Capturing the pin state before deletion")
			podIdentifier := getPodIdentifierFromCLI(pod1.Name)
			pinsBefore := listProgramPinBasenames()
			Expect(pinsBefore).To(ContainElement(podIdentifier + "_handle_ingress"))

			By("Deleting one of the two pods")
			Expect(fw.K8sClient.Delete(ctx, pod1)).To(Succeed())
			time.Sleep(bpfSettleInterval)

			By("Verifying program pins still exist (shared, not deleted)")
			pinsAfter := listProgramPinBasenames()
			Expect(pinsAfter).To(ContainElement(podIdentifier+"_handle_ingress"),
				"shared ingress program pin should NOT be deleted when one pod is removed")
			Expect(pinsAfter).To(ContainElement(podIdentifier+"_handle_egress"),
				"shared egress program pin should NOT be deleted when one pod is removed")

			By("Verifying surviving pod still has progs attached on TC")
			postProgIDs := tcAttachedProgIDSet(veth2)
			Expect(postProgIDs).To(Equal(progIDs2), "surviving pod's TC attachment should be unchanged")
		})

		AfterAll(func() {
			if networkPolicy != nil {
				_ = fw.K8sClient.Delete(ctx, networkPolicy)
			}
		})
	})
})

// getPodIdentifierFromCLI gets the pod identifier for a pod by looking it up
// in the CLI's loaded-ebpfdata dump. This ensures we use the same identifier
// the agent uses, avoiding test-vs-agent naming divergence.
func getPodIdentifierFromCLI(podName string) string {
	allState := dumpAllBPFStateFromCLI()
	for pin, id := range allState.PodIdentifiers {
		// The pin basename contains the podIdentifier; find it by checking if
		// the pod name prefix matches.
		_ = id
		if strings.Contains(pin, "_handle_ingress") {
			identifier := strings.TrimSuffix(pin, "_handle_ingress")
			// Check if this identifier could belong to our pod by verifying
			// the pod name starts with the identifier prefix (before @)
			parts := strings.SplitN(identifier, "@", 2)
			if len(parts) == 2 {
				// Pod name minus the last random segment should match the
				// identifier prefix
				nameParts := strings.Split(podName, "-")
				prefix := strings.Join(nameParts[:len(nameParts)-1], "-")
				if strings.ReplaceAll(prefix, ".", "_") == parts[0] {
					return identifier
				}
			}
		}
	}
	Fail(fmt.Sprintf("could not find pod identifier for pod %s in CLI dump", podName))
	return ""
}
