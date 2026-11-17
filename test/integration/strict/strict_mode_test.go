package strict

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const serverPort = 8080

var _ = Describe("Strict Mode Test Cases", func() {
	Context("when pod is launched", func() {
		var clientPod *v1.Pod
		var podName = "clientpod"

		BeforeEach(func() {
			By("Creating an idle client pod", func() {
				clientPod = deployIdlePod(podName, namespace)
			})
		})

		It("by default should not have connectivity to external network", func() {
			host, port := externalProbeTarget(fw.Options.IpFamily)
			By("verifying egress to the external endpoint is denied", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, podName, host, port)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"strict mode should deny egress from a pod with no network policy")
			})
			By("verifying the deny persists", func() {
				Consistently(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, podName, host, port)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
					"deny should not flap while no policy allows the traffic")
			})
		})

		AfterEach(func() {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		})
	})

	Context("when a network policy is applied which allows communication between client and server", func() {
		var (
			serverPod           *v1.Pod
			clientDeployment    *appsv1.Deployment
			serverPodIP         string
			dadWatchers         map[string]*v1.Pod
			serverName          = "serverpod"
			clientName          = "clientdeploy"
			serverNetworkPolicy *network.NetworkPolicy
			clientNetworkPolicy *network.NetworkPolicy
		)

		BeforeEach(func() {
			By("Deploying a server pod with allow all ingress network policy", func() {
				ingressPeer := manifest.NewIngressRuleBuilder().
					AddPeer(nil, nil, "0.0.0.0/0").
					AddPeer(nil, nil, "::/0").
					AddPort(serverPort, v1.ProtocolTCP).
					Build()

				serverNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("server-ingress-policy").
					PodSelector("app", serverName).
					AddIngressRule(ingressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())

				serverContainer := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: serverPort}).
					Build()

				serverPod = manifest.NewDefaultPodBuilder().
					Name(serverName).
					Namespace(namespace).
					AddLabel("app", serverName).
					Container(serverContainer).
					Build()

				pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 1*time.Minute)
				Expect(err).ToNot(HaveOccurred())
				serverPodIP = pod.Status.PodIP
			})

			By("Deploying an idle client deployment and an egress policy to allow communication with server", func() {
				egressPeer := manifest.NewEgressRuleBuilder().
					AddPeer(nil, map[string]string{"app": serverName}, "").
					AddPort(serverPort, v1.ProtocolTCP).
					Build()

				clientNetworkPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("client-egress-policy").
					PodSelector("app", clientName).
					AddEgressRule(egressPeer).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, clientNetworkPolicy)
				Expect(err).ToNot(HaveOccurred())

				clientDeployment = deployIdleDeployment(clientName, namespace, 1)
			})
		})

		It("allows egress once the policy is enforced, and a second replica sharing the policy is also allowed", func() {
			var firstPod, secondPod string

			By("resolving the first client replica", func() {
				firstPod = podNameForReplica(namespace, clientName, "")
			})

			// First pod cold-starts in strict default-deny; allowed once the egress rule is programmed.
			By("verifying the first replica eventually reaches the server", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, firstPod, serverPodIP, serverPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"first replica should reach the server once the egress policy is programmed")
			})

			// On IPv6 the new host veth's link-local address is tentative for ~1-2s while the node
			// runs duplicate address detection, and the pod's first connection can fail in that
			// window with no policy involved. Watchers are started on every node before the
			// scale-up so the wait below adds only the remaining DAD time, not a pod start.
			if fw.Options.IpFamily == "IPv6" {
				By("starting a host-network DAD watcher on each node", func() {
					dadWatchers = deployDADWatchers(namespace)
				})
			}

			By("scaling the client deployment to 2", func() {
				err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, clientName, 2)
				Expect(err).ToNot(HaveOccurred())
				secondPod = podNameForReplica(namespace, clientName, firstPod)
			})

			if fw.Options.IpFamily == "IPv6" {
				By("waiting for the second replica's host veth to finish DAD", func() {
					waitForHostVethDAD(dadWatchers, namespace, secondPod)
				})
			}

			// Second replica shares the pod identifier's already-programmed maps, so it must be
			// allowed from its first packet with no cold-start deny. podNameForReplica returns it
			// only once Running, so Consistently probes from the start: a replica that wrongly
			// cold-started would show an early CLOSE. (Eventually here would mask that by waiting
			// out the deny, breaking the "instantaneous" contract.)
			By("verifying the second replica reaches the server without a cold-start deny", func() {
				Consistently(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, secondPod, serverPodIP, serverPort)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
					"second replica should reach the server immediately via the shared policy maps")
			})

			By("verifying connectivity is stable for the first replica", func() {
				Consistently(func() (string, error) {
					return fw.PodManager.TCPProbe(namespace, firstPod, serverPodIP, serverPort)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
					"allow should not flap once the policy is enforced")
			})
		})

		AfterEach(func() {
			for _, w := range dadWatchers {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, w)
			}
			dadWatchers = nil
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, clientDeployment)
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverNetworkPolicy)
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, clientNetworkPolicy)
		})
	})
})

// externalProbeTarget returns an off-cluster host and port for the cluster's IP family.
func externalProbeTarget(ipFamily string) (string, int) {
	if ipFamily == "IPv6" {
		return "2001:4860:4860::8888", 53
	}
	return "8.8.8.8", 53
}

// deployIdlePod creates a running busybox pod that sleeps, so probes can be exec'd on demand.
func deployIdlePod(name, ns string) *v1.Pod {
	ctnr := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()

	pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, manifest.NewDefaultPodBuilder().
		Name(name).
		Namespace(ns).
		Container(ctnr).
		Build(), 2*time.Minute)
	Expect(err).ToNot(HaveOccurred())
	return pod
}

// deployIdleDeployment creates a busybox deployment whose pods sleep, so probes can be exec'd on demand.
func deployIdleDeployment(name, ns string, replicas int) *appsv1.Deployment {
	ctnr := manifest.NewBusyBoxContainerBuilder().
		ImageRepository(fw.Options.TestImageRegistry).
		Command([]string{"/bin/sh", "-c"}).
		Args([]string{"sleep 1000000"}).
		Build()

	deployment := manifest.NewDefaultDeploymentBuilder().
		Name(name).
		Replicas(replicas).
		Namespace(ns).
		AddLabel("app", name).
		Container(ctnr).
		Build()

	dp, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, deployment)
	Expect(err).ToNot(HaveOccurred())
	return dp
}

// podNameForReplica polls for a Running pod with app=name, skipping excludeName. It gates
// on Running so callers get an exec-ready pod: a pod is listed by label before its
// container starts, and exec-ing that early fails with "container not found".
func podNameForReplica(ns, name, excludeName string) string {
	var podName string
	Eventually(func() bool {
		pods, err := fw.PodManager.GetPodsWithLabel(ctx, ns, "app", name)
		if err != nil {
			return false
		}
		for _, pod := range pods {
			if pod.Name != excludeName && pod.Status.Phase == v1.PodRunning {
				podName = pod.Name
				return true
			}
		}
		return false
	}, utils.ProbeTimeout, utils.ProbeInterval).Should(BeTrue(), "expected a running client replica with app=%s", name)
	return podName
}

// deployDADWatchers starts one idle host-network pod per node and returns them by node name.
func deployDADWatchers(ns string) map[string]*v1.Pod {
	nodes := &v1.NodeList{}
	Expect(fw.K8sClient.List(ctx, nodes)).To(Succeed())
	watchers := map[string]*v1.Pod{}
	for _, node := range nodes.Items {
		// Client pods only land on schedulable nodes without NoSchedule/NoExecute taints.
		if node.Spec.Unschedulable || slices.ContainsFunc(node.Spec.Taints, func(t v1.Taint) bool {
			return t.Effect == v1.TaintEffectNoSchedule || t.Effect == v1.TaintEffectNoExecute
		}) {
			continue
		}
		ctnr := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{"sleep 1000000"}).
			Build()
		pod := manifest.NewDefaultPodBuilder().
			Name("dad-watch-" + node.Name).
			Namespace(ns).
			Container(ctnr).
			NodeName(node.Name).
			Build()
		pod.Spec.HostNetwork = true
		created, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		watchers[node.Name] = created
	}
	return watchers
}

// waitForHostVethDAD waits until the host side of podName's veth has a link-local address
// that is no longer tentative. The veth name is a prefix plus the first 11 hex characters of
// sha1("<namespace>.<pod>"), so the hash identifies it in /proc/net/if_inet6.
func waitForHostVethDAD(watchers map[string]*v1.Pod, ns, podName string) {
	pod := &v1.Pod{}
	Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: podName}, pod)).To(Succeed())
	watcher, ok := watchers[pod.Spec.NodeName]
	Expect(ok).To(BeTrue(), "no DAD watcher on node %s", pod.Spec.NodeName)
	h := sha1.Sum([]byte(fmt.Sprintf("%s.%s", ns, podName)))
	hash := hex.EncodeToString(h[:])[:11]

	Eventually(func() (bool, error) {
		out, err := fw.PodManager.ExecInPod(ns, watcher.Name, []string{"cat", "/proc/net/if_inet6"})
		if err != nil {
			return false, err
		}
		for _, line := range strings.Split(out, "\n") {
			// address ifindex prefixlen scope flags ifname
			f := strings.Fields(line)
			if len(f) != 6 || !strings.HasSuffix(f[5], hash) || f[3] != "20" {
				continue
			}
			flags, err := strconv.ParseUint(f[4], 16, 32)
			if err != nil {
				return false, err
			}
			return flags&0x40 == 0, nil // IFA_F_TENTATIVE
		}
		return false, nil
	}, 10*time.Second, 200*time.Millisecond).Should(BeTrue(),
		"host veth of %s should leave IPv6 DAD within 10s", podName)
}
