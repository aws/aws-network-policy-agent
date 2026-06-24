package soak

import (
	"fmt"
	"time"

	"github.com/aws/aws-network-policy-agent/test/integration/soak/driver"
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// driverImage is the image the port-reuse driver runs in. amazonlinux:2023-minimal
// is the image the other suites in this repo standardize on and it ships curl at
// /usr/bin/curl, which is all the driver script needs. (The curlimages/curl image
// is not published under public.ecr.aws, so it is not an option here.)
const driverImage = "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal"

// launchPortReuseClient deploys the #462 port-reuse driver as a long-lived pod on
// the given node. The pod runs the driver command (built and unit-tested in the
// driver package) until the soak deletes it, making short-lived port-reuse
// outbound connections to the open destination in cfg.
//
// The driver pod itself carries the ingress-deny policy (applied by the suite), so
// its return traffic relies on conntrack — faithful to GitHub #462, where the
// protected pod is the one making outbound connections. It is co-located with the
// destination so the flow stays node-local and the conntrack entry the race
// deletes lives on the node under test.
func launchPortReuseClient(node string, cfg driver.PortReuseConfig) (*v1.Pod, error) {
	script, err := cfg.Command()
	if err != nil {
		return nil, fmt.Errorf("build port-reuse command: %w", err)
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reuseDriverLabel,
			Namespace: namespace,
			// The app label must match the driver-deny policy's selector so the
			// driver pod is the policy-protected one whose return traffic relies on
			// conntrack — the #462 precondition.
			Labels: map[string]string{"app": reuseDriverLabel},
		},
		Spec: v1.PodSpec{
			NodeName: node,
			// Never restart: the driver loop is written to run forever, so an exit
			// is itself a signal. A restart would also reset RestartCount and mask
			// the disruption it is meant to surface.
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name:    "driver",
				Image:   driverImage,
				Command: []string{"/bin/sh", "-c", script},
			}},
		},
	}
	return fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, podReadyTimeout)
}

// checkPortReuseClientHealth records a violation if the driver pod stopped running
// or its container restarted. A driver that is no longer Running means its
// connection loop exited — under #462 the loop tolerates individual drops, so an
// exit points at a harder failure (the client could not sustain traffic at all).
//
// This is the behavioral half of #462 detection: the log-signature half is
// scanForConntrackRace. Together they catch the race both by its fingerprint and
// by its effect on a real client.
func checkPortReuseClientHealth(rec *Recorder, podName string) {
	pod := &v1.Pod{}
	if err := fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, pod); err != nil {
		GinkgoWriter.Printf("portreuse-client: get failed: %v\n", err)
		return
	}

	if pod.Status.Phase != v1.PodRunning && pod.Status.Phase != v1.PodSucceeded {
		rec.Record(ConnDisruption, time.Now(),
			"port-reuse driver pod phase=%s (connection loop did not sustain traffic)", pod.Status.Phase)
	}

	for _, cs := range pod.Status.ContainerStatuses {
		if cs.RestartCount > 0 {
			rec.Record(ConnDisruption, time.Now(),
				"port-reuse driver container restarted %d time(s) (connection broke)", cs.RestartCount)
		}
	}
}
