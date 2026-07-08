package soak

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// livenessClientLabel marks the long-lived pod that holds a persistent connection
// to an allowed server. It exits non-zero on any request failure, so RestartCount
// rising means a connection was disrupted. This is Gate 2's signal: "no
// established-connection disruption across churn, hot-updates, and agent kills."
const livenessClientLabel = "npa-soak-liveness"

// launchLivenessClient deploys a pod that opens a persistent connection to the
// target server and heartbeats on it with a tight request loop. If any request
// fails (connection reset, timeout, refused), the process exits non-zero.
//
// RestartPolicyOnFailure means kubelet restarts it on each failure, incrementing
// RestartCount. The soak gates on RestartCount == 0 at the end: any increment means
// an established connection broke during the run.
//
// The target server must be reachable by an explicit allow policy so the return
// path relies on NPA's conntrack, which is what an agent kill stresses. Placing
// the liveness client on a different node from the server exercises cross-node
// enforcement.
func launchLivenessClient(nodeName, targetIP string, targetPort int) (*v1.Pod, error) {
	// Hold a genuinely persistent connection with near-continuous traffic. A single
	// curl invocation fetches a large batch of sequential requests over ONE HTTP/1.1
	// keep-alive connection (URL globbing [1-100000]), with no per-request idle gap,
	// so traffic is essentially always in flight and a dropped return packet cannot
	// hide in a sleep gap. --keepalive-time keeps the TCP connection warm. If the
	// batch ever fails (--fail-early exits on the first failed request), the process
	// exits non-zero, kubelet restarts it (RestartPolicyOnFailure), and RestartCount
	// rises. The outer loop re-establishes after a completed batch. This is Gate 2:
	// an established connection that must survive churn, hot-updates, and kills.
	script := fmt.Sprintf(`set -eu
target="http://%s:%d/?[1-100000]"
echo "liveness-client: persistent keep-alive stream to %s:%d (exit non-zero on ANY drop)"
while true; do
  curl -sS --fail-early --keepalive-time 5 --max-time 3600 -o /dev/null "$target"
done`, targetIP, targetPort, targetIP, targetPort)

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      livenessClientLabel,
			Namespace: namespace,
			Labels:    map[string]string{"app": livenessClientLabel},
		},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyOnFailure,
			Containers: []v1.Container{{
				Name:    "liveness",
				Image:   driverImage,
				Command: []string{"/bin/sh", "-c", script},
			}},
		},
	}
	return fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, podReadyTimeout)
}

// checkLivenessClientHealth records a ConnDisruption violation if the liveness
// client pod's container restarted at any point during the run. One restart means
// one dropped request on an established connection, which is the signal for Gate 2.
func checkLivenessClientHealth(rec *Recorder) {
	pod := &v1.Pod{}
	if err := fw.K8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: livenessClientLabel}, pod); err != nil {
		GinkgoWriter.Printf("liveness-client: get failed: %v\n", err)
		rec.Record(ConnDisruption, time.Now(),
			"liveness client pod not readable: %v", err)
		return
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "liveness" && cs.RestartCount > 0 {
			rec.Record(ConnDisruption, time.Now(),
				"liveness client RestartCount=%d (established connection broke %d time(s))",
				cs.RestartCount, cs.RestartCount)
		}
	}
}
