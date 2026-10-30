package ebpf

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*
Ingress Object Load Check

The agent loads one ingress object per node: the ct-deny one where the kernel
has the nf_conntrack kfuncs, and the regular one otherwise. On a kernel with the
kfuncs nothing else loads the regular object, so a change that broke it would
only show on nodes without them. This runs check-bpf-load-agent from the test
agent image on every node. It loads both of the agent's ingress objects for the
cluster's IP family on that node's kernel and checks that the regular object
loads everywhere, and the ct-deny object loads exactly where the kfuncs are
present.
*/
var _ = Describe("Ingress Object Load Check", func() {
	It("should load the regular ingress object on every node, and the ct-deny object where the kernel has the kfuncs [CtDeny]", func() {
		image, ok := testAgentImage()
		if !ok {
			Skip("no test agent image: --test-image-registry is " + fw.Options.TestImageRegistry)
		}
		family := "v4"
		if fw.Options.IpFamily == "IPv6" {
			family = "v6"
		}
		regular, ctDeny := "tc."+family+"ingress.bpf.o", "tc."+family+"ingress.ctdeny.bpf.o"

		nodes := &v1.NodeList{}
		Expect(fw.K8sClient.List(ctx, nodes)).To(Succeed())
		Expect(nodes.Items).ToNot(BeEmpty())
		for _, node := range nodes.Items {
			By("Loading the ingress objects on " + node.Name)
			out := runLoadCheck(image, node.Name, family)
			GinkgoWriter.Printf("%s:\n%s\n", node.Name, out)
			if strings.Contains(out, "check-bpf-load-agent") && strings.Contains(out, "no such file") {
				Skip("the test agent image has no check-bpf-load-agent yet; publish it from test/agent")
			}
			Expect(out).To(ContainSubstring("LOAD "+regular+" OK"),
				"%s: the regular ingress object did not load", node.Name)
			if strings.Contains(out, "KFUNCS present") {
				Expect(out).To(ContainSubstring("LOAD "+ctDeny+" OK"),
					"%s: the kernel has the kfuncs but the ct-deny object did not load", node.Name)
			} else {
				Expect(out).To(ContainSubstring("KFUNCS absent"), "%s: no kfunc result", node.Name)
				Expect(out).To(ContainSubstring("LOAD "+ctDeny+" FAIL"),
					"%s: the kernel lacks the kfuncs but the ct-deny object loaded", node.Name)
			}
		}
	})
})

// testAgentImage returns the test agent image, which is published only to the
// private test registry (scripts/lib/cleanup.sh uses the same path).
func testAgentImage() (string, bool) {
	r := fw.Options.TestImageRegistry
	if r == "" || r == "registry.k8s.io" {
		return "", false
	}
	return r + "/networking-e2e-test-images/aws-network-policy-test-agent:latest", true
}

// runLoadCheck runs check-bpf-load-agent on nodeName and returns its output.
func runLoadCheck(image, nodeName, family string) string {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("loadcheck%d", time.Now().UnixNano()), Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName, RestartPolicy: v1.RestartPolicyNever,
			// The host's PID namespace, to find the agent and read its objects
			// through /proc/<pid>/root.
			HostPID: true,
			Containers: []v1.Container{{
				Name: "loadcheck", Image: image,
				Command:         []string{"./check-bpf-load-agent", "-family", family},
				SecurityContext: &v1.SecurityContext{Privileged: &privileged},
				VolumeMounts:    []v1.VolumeMount{{Name: "bpffs", MountPath: "/sys/fs/bpf"}},
			}},
			Volumes: []v1.Volume{{
				Name:         "bpffs",
				VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &hostPathDir}},
			}},
		},
	}
	// The pod either completes or fails; a missing binary or image shows up as a failure.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	created, err := fw.PodManager.CreateAndWaitTillPodIsCompleted(waitCtx, pod)
	defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
	logs, logErr := fw.PodManager.PodLogs(namespace, pod.Name)
	if err != nil {
		msg := ""
		if created != nil {
			for _, cs := range created.Status.ContainerStatuses {
				if t := cs.State.Terminated; t != nil {
					msg = t.Message
				}
			}
		}
		return fmt.Sprintf("pod error: %v %s\n%s %v", err, msg, logs, logErr)
	}
	Expect(logErr).ToNot(HaveOccurred())
	return logs
}
