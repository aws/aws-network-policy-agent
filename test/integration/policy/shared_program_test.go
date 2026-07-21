// Package policy — shared eBPF program lifecycle test.
//
// What is tested:
//   - Pods belonging to the same ReplicaSet share a single eBPF program FD
//     (keyed by podIdentifier). This test verifies the reference-counting guard
//     (isProgFdShared) that prevents premature unpinning.
//   - A 2-replica deployment is created with a deny-all ingress policy. Both
//     replicas are verified to block an unauthorized client.
//   - One replica is deleted (scale 2 → 1). The remaining replica must still
//     enforce the deny rule, proving the shared program was not unpinned when
//     the first pod was removed.
//   - All replicas are removed (scale 1 → 0). A privileged node-shell pod is
//     deployed on each node that hosted a server replica, and aws-eks-na-cli
//     is used to confirm that no BPF programs or maps with the deployment name
//     remain pinned under /sys/fs/bpf.
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Shared eBPF Program", func() {
	Context("when pods in a ReplicaSet share a BPF program", func() {
		var (
			serverDeployment *appsv1.Deployment
			unauthClientPod  *v1.Pod
			serverPolicy     *network.NetworkPolicy
		)

		const (
			sharedServerName = "shared-server"
			sharedUnauthName = "shared-unauth-client"
		)

		BeforeEach(func() {
			By("Creating server deployment with 2 replicas", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"/agnhost netexec"}).
					AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
					Build()

				serverDeployment = manifest.NewDefaultDeploymentBuilder().
					Name(sharedServerName).
					Namespace(namespace).
					Replicas(2).
					AddLabel("app", sharedServerName).
					Container(container).
					Build()

				_, err := fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating deny-all ingress policy for server pods", func() {
				serverPolicy = manifest.NewNetworkPolicyBuilder().
					Namespace(namespace).
					Name("shared-server-deny-all").
					PodSelector("app", sharedServerName).
					SetPolicyType(true, false).
					Build()

				err := fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, serverPolicy)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Creating unauthorized client pod", func() {
				container := manifest.NewAgnHostContainerBuilder().
					ImageRepository(fw.Options.TestImageRegistry).
					Args([]string{"sleep 3600"}).
					Build()

				pod := manifest.NewDefaultPodBuilder().
					Name(sharedUnauthName).
					Namespace(namespace).
					AddLabel("app", sharedUnauthName).
					Container(container).
					Build()

				var err error
				unauthClientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
				Expect(err).ToNot(HaveOccurred())
			})

			time.Sleep(15 * time.Second)
		})

		It("should not unpin the BPF program when one replica is deleted, and clean up after all are deleted", func() {
			By("Collecting IPs and nodes of both server replicas", func() {
				pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", sharedServerName)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(pods)).To(Equal(2), "expected 2 server replicas")
			})

			By("Verifying both replicas deny the unauthorized client", func() {
				pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", sharedServerName)
				Expect(err).ToNot(HaveOccurred())

				for _, pod := range pods {
					podIP := pod.Status.PodIP
					if fw.Options.IpFamily == "IPv6" {
						podIP = fmt.Sprintf("[%s]", podIP)
					}
					_, err := fw.PodManager.ExecInPod(namespace, sharedUnauthName,
						[]string{"wget", "--spider", "-T", "5", fmt.Sprintf("http://%s:8080", podIP)})
					Expect(err).To(HaveOccurred(), "replica %s should deny unauthorized client", pod.Name)
				}
			})

			By("Recording the nodes hosting server pods before scale-down", func() {
				pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", sharedServerName)
				Expect(err).ToNot(HaveOccurred())
				// nodeNames is used below for BPF cleanup verification
				nodeNames := map[string]struct{}{}
				for _, pod := range pods {
					nodeNames[pod.Spec.NodeName] = struct{}{}
				}
				Expect(len(nodeNames)).To(BeNumerically(">=", 1))

				By("Scaling down to 1 replica", func() {
					err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, sharedServerName, 1)
					Expect(err).ToNot(HaveOccurred())
					time.Sleep(10 * time.Second)
				})

				By("Verifying the remaining replica still denies the unauthorized client (program not unpinned)", func() {
					remaining, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", sharedServerName)
					Expect(err).ToNot(HaveOccurred())
					Expect(len(remaining)).To(Equal(1))

					podIP := remaining[0].Status.PodIP
					if fw.Options.IpFamily == "IPv6" {
						podIP = fmt.Sprintf("[%s]", podIP)
					}
					_, err = fw.PodManager.ExecInPod(namespace, sharedUnauthName,
						[]string{"wget", "--spider", "-T", "5", fmt.Sprintf("http://%s:8080", podIP)})
					Expect(err).To(HaveOccurred(), "remaining replica should still deny unauthorized client")
				})

				By("Scaling down to 0 replicas", func() {
					err := fw.DeploymentManager.ScaleDeploymentAndWaitTillReady(ctx, namespace, sharedServerName, 0)
					Expect(err).ToNot(HaveOccurred())
					// Allow NPA time to unpin and clean up BPF programs.
					time.Sleep(30 * time.Second)
				})

				By("Verifying no BPF artifacts remain for the server deployment on each node", func() {
					for nodeName := range nodeNames {
						checkPodName := fmt.Sprintf("shared-check-%s", nodeName[len(nodeName)-8:])
						checkPod := buildSharedNodeCheckPod(checkPodName, nodeName)

						_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
						Expect(err).ToNot(HaveOccurred())

						output, err := fw.PodManager.ExecInPod(namespace, checkPodName,
							[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
						Expect(err).ToNot(HaveOccurred())

						assertNoBPFArtifactsFor(sharedServerName, output, nodeName)

						fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
					}
				})
			})
		})

		AfterEach(func() {
			if serverPolicy != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, serverPolicy)
			}
			if serverDeployment != nil {
				fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeployment)
			}
			if unauthClientPod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, unauthClientPod)
			}
		})
	})
})

func buildSharedNodeCheckPod(name, nodeName string) *v1.Pod {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			HostPID:       true,
			HostNetwork:   true,
			RestartPolicy: v1.RestartPolicyNever,
			NodeSelector:  map[string]string{"kubernetes.io/os": "linux"},
			Containers: []v1.Container{
				{
					Name:            "check",
					Image:           "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
					ImagePullPolicy: v1.PullIfNotPresent,
					Command:         []string{"sleep", "3600"},
					SecurityContext: &v1.SecurityContext{
						Privileged: &privileged,
					},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []v1.Volume{
				{
					Name: "host-root",
					VolumeSource: v1.VolumeSource{
						HostPath: &v1.HostPathVolumeSource{
							Path: "/",
							Type: &hostPathDir,
						},
					},
				},
			},
		},
	}
}

func assertNoBPFArtifactsFor(deploymentName, output, nodeName string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		Expect(line).ToNot(ContainSubstring(deploymentName),
			"leaked BPF artifact found on node %s: %s", nodeName, line)
	}
}
