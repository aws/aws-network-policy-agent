//go:build soak
// +build soak

package soak

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*
Conntrack GC Race Soak Test  (aws/aws-network-policy-agent#462)

Reproduces the conntrack-cleanup snapshot-vs-iterate race and validates the
last_seen fix. A high-rate SO_REUSEADDR "port-reuser" churns short-lived TCP
connections through the eBPF conntrack map while a victim pod behind a
restrictive ingress policy takes return traffic. On stock NPA the periodic
cleanup deletes a live entry whose ephemeral port was just reused, and the
return packet is DENYed (the freeze). The fix stamps last_seen on every
datapath hit and makes cleanup re-read it, SKIPPING deletion of any entry
refreshed since GC started.

This is a soak test: it needs a few cleanup cycles (cleanup period 300s → a
diff/delete pass every ~150s) to coincide with a reuse. It early-exits as soon
as the fix signature is confirmed and caps at 30 minutes. It is guarded by the
`soak` build tag and lives outside the regular integration cadence — see the
package doc in conntrack_race_suite_test.go for how to run it.

Assertions are two-sided so the test cannot pass for the wrong reason:
  - LIVENESS (fail fast): cleanup is running (Delete count climbing) AND the
    reuser is churning. A silent no-load run FAILS instead of green-on-nothing.
  - FIX ENGAGED: "Conntrack cleanup Skip (in use)" count > 0 — the guard fired
    on a live/reused entry. (Stock never emits this line.)
  - NO WEDGE: return-flow "Verdict DENY" count == 0 over the observation window.

On STOCK NPA this test FAILS (Skip stays 0, DENY climbs). On the PATCHED image
it PASSES (Skip > 0, DENY == 0). Tagged [Race][Soak].
*/

const (
	raceSoakCap       = 30 * time.Minute
	racePollInterval  = 30 * time.Second
	raceWarmup        = 90 * time.Second
	npaLogPath        = "/host/var/log/aws-routed-eni/network-policy-agent.log"
	reuserReplicas    = 6
	skipConfirmCycles = 2 // require Skip>0 seen on ≥2 polls before concluding pass
)

var _ = Describe("Conntrack GC Race [Race][Soak]", func() {

	BeforeEach(func() {
		if fw.Options.IpFamily == "IPv6" {
			Skip("repro drives IPv4 apiserver/echo return flows")
		}
	})

	var (
		victimPod *v1.Pod
		echoPod   *v1.Pod
		echoSvc   *v1.Service
		reuserDep *appsv1.Deployment
		checkPod  *v1.Pod
		victimNP  *network.NetworkPolicy
		reuserIng *network.NetworkPolicy
		reuserEg  *network.NetworkPolicy
		node      string
		echoVIP   string
	)

	AfterEach(func() {
		// best-effort teardown
		if checkPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
		}
		if reuserDep != nil {
			fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, reuserDep)
		}
		for _, np := range []*network.NetworkPolicy{victimNP, reuserIng, reuserEg} {
			if np != nil {
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			}
		}
		if echoSvc != nil {
			fw.ServiceManager.DeleteService(ctx, echoSvc)
		}
		for _, p := range []*v1.Pod{echoPod, victimPod} {
			if p != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
	})

	It("skips live/reused conntrack entries during cleanup instead of denying return traffic", func() {
		By("Creating echo target (nginx, port-reuser target)")
		echoPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "echo-server", Namespace: namespace,
				Labels: map[string]string{"app": "echo-server"},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
					Ports: []v1.ContainerPort{{ContainerPort: 80}},
				}},
			},
		}
		var err error
		echoPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, echoPod, 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		node = echoPod.Spec.NodeName
		Expect(node).ToNot(BeEmpty())

		By("Exposing echo target via ClusterIP Service on :80")
		echoSvc = &v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: namespace},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{"app": "echo-server"},
				Ports:    []v1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(80), Protocol: v1.ProtocolTCP}},
			},
		}
		echoSvc, err = fw.ServiceManager.CreateService(ctx, echoSvc)
		Expect(err).ToNot(HaveOccurred())
		echoVIP = getServiceClusterIP(namespace, "echo-server")
		Expect(echoVIP).ToNot(BeEmpty())

		By("Applying restrictive ingress policy to victim (allow only TCP/8086)")
		victimNP = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "victim-restrictive", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "victim"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					Ports: []network.NetworkPolicyPort{{
						Protocol: protoPtr(v1.ProtocolTCP), Port: portPtr(8086),
					}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, victimNP)).To(Succeed())

		By("Creating victim pod (short-lived LIST loop to echo VIP, Connection: close)")
		// The victim mirrors the customer's monitor: 1 short-lived TCP conn/sec on a
		// fresh ephemeral port to a policy-tracked peer, so its return flows sit in
		// the conntrack map and are exposed to the cleanup race.
		victimScript := fmt.Sprintf(`import urllib.request,time
while True:
 try:
  urllib.request.urlopen("http://%s:80/",timeout=2).read()
 except Exception:pass
 time.sleep(1)`, echoVIP)
		victimPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "victim", Namespace: namespace,
				Labels: map[string]string{"app": "victim"},
			},
			Spec: v1.PodSpec{
				NodeName: node,
				Containers: []v1.Container{{
					Name: "victim", Image: "public.ecr.aws/docker/library/python:3.11-slim",
					Command: []string{"python3", "-c", victimScript},
				}},
			},
		}
		victimPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, victimPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())

		By("Applying ingress+egress policy to port-reuser (puts its flows in eBPF conntrack)")
		reuserIng = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "port-reuser-ingress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "port-reuser"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					Ports: []network.NetworkPolicyPort{{Protocol: protoPtr(v1.ProtocolTCP), Port: portPtr(80)}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, reuserIng)).To(Succeed())
		reuserEg = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "port-reuser-egress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "port-reuser"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeEgress},
				Egress: []network.NetworkPolicyEgressRule{{
					Ports: []network.NetworkPolicyPort{{Protocol: protoPtr(v1.ProtocolTCP), Port: portPtr(80)}},
					To: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "echo-server"}},
					}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, reuserEg)).To(Succeed())

		By("Deploying port-reuser amplifier (SO_REUSEADDR TIME_WAIT reuse)")
		reuserDep = buildReuserDeployment(node, echoVIP)
		reuserDep, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, reuserDep)
		Expect(err).ToNot(HaveOccurred())

		By("Deploying privileged check pod to read the NPA log on the test node")
		// NB: not utils.BuildBPFCheckPod — that pod sleeps 300s and would die
		// mid-soak (this test can run up to 30m). Use sleep infinity so the pod
		// stays available for the whole observation window.
		checkPod = buildLogReaderPod(node)
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())

		By("Warming up so the conntrack map fills and cleanup begins")
		time.Sleep(raceWarmup)

		By("Confirming liveness: reuser churning + cleanup running (fail fast otherwise)")
		Eventually(func() int { return reuserOK(namespace) }, 2*time.Minute, 15*time.Second).
			Should(BeNumerically(">", 1000), "port-reuser is not generating connections")
		Eventually(func() int { return logCount(checkPod, "Conntrack cleanup Delete") }, 6*time.Minute, racePollInterval).
			Should(BeNumerically(">", 0), "conntrack cleanup never ran — workload/agent not exercising GC")

		By("Soaking: pass on Skip>0 (guard fired) AND DENY==0; fail on any DENY; cap 30m")
		deadline := time.Now().Add(raceSoakCap)
		skipSeen := 0
		for time.Now().Before(deadline) {
			deny := logCount(checkPod, "Verdict DENY")
			skip := logCount(checkPod, "Skip (in use)")

			// logCount returns -1 on a transient exec-into-checkpod error; skip
			// that poll rather than treating it as a signal.
			if deny < 0 || skip < 0 {
				time.Sleep(racePollInterval)
				continue
			}

			// Hard fail the instant the race fires (this is the bug — DENY on a
			// live reused return flow). On stock NPA this is what trips.
			Expect(deny).To(Equal(0),
				fmt.Sprintf("conntrack race fired: %d Verdict DENY lines — cleanup deleted a live reused entry", deny))

			if skip > 0 {
				skipSeen++
				if skipSeen >= skipConfirmCycles {
					By(fmt.Sprintf("PASS: guard fired (Skip (in use)=%d over %d polls), 0 DENY", skip, skipSeen))
					return
				}
			}
			time.Sleep(racePollInterval)
		}
		Fail("30m cap reached without observing 'Conntrack cleanup Skip (in use)' — " +
			"fix guard never engaged (or churn too low to exercise the reuse path)")
	})
})

// --- helpers ---

func protoPtr(p v1.Protocol) *v1.Protocol { return &p }
func portPtr(n int32) *intstr.IntOrString { v := intstr.FromInt(int(n)); return &v }

// buildLogReaderPod is a privileged pod pinned to the test node that host-mounts
// /var/log so the soak can grep the NPA log. Unlike utils.BuildBPFCheckPod it
// sleeps indefinitely, so it survives the full (up to 30m) observation window.
func buildLogReaderPod(node string) *v1.Pod {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "log-reader", Namespace: namespace},
		Spec: v1.PodSpec{
			NodeName: node, HostPID: true, HostNetwork: true, RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name: "reader", Image: "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
				Command:         []string{"sleep", "infinity"},
				SecurityContext: &v1.SecurityContext{Privileged: &privileged},
				VolumeMounts:    []v1.VolumeMount{{Name: "host-root", MountPath: "/host"}},
			}},
			Volumes: []v1.Volume{{
				Name:         "host-root",
				VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/", Type: &hostPathDir}},
			}},
		},
	}
}

// logCount greps the on-node NPA log via the privileged check pod. Retries once
// on a transient exec error; returns -1 only if both attempts fail (caller skips
// that poll rather than treating -1 as a signal).
func logCount(checkPod *v1.Pod, pattern string) int {
	cmd := []string{"sh", "-c", fmt.Sprintf("grep -c '%s' %s 2>/dev/null || true", pattern, npaLogPath)}
	for attempt := 0; attempt < 2; attempt++ {
		out, err := fw.PodManager.ExecInPod(namespace, checkPod.Name, cmd)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(out))
		if convErr != nil {
			return 0 // grep -c prints 0 on no match; empty/garbage → treat as 0
		}
		return n
	}
	return -1
}

// reuserOK sums the port-reuser pods' cumulative successful-connection counters
// from their STATS log lines ("[STATS] ok=N err=M").
func reuserOK(ns string) int {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, ns, "app", "port-reuser")
	if err != nil {
		return 0
	}
	total := 0
	for _, p := range pods {
		logs, lerr := fw.PodManager.PodLogs(ns, p.Name)
		if lerr != nil {
			continue
		}
		for _, ln := range strings.Split(logs, "\n") {
			if idx := strings.LastIndex(ln, "ok="); idx >= 0 {
				rest := ln[idx+3:]
				end := strings.IndexAny(rest, " \t")
				if end < 0 {
					end = len(rest)
				}
				if v, e := strconv.Atoi(rest[:end]); e == nil {
					total += v // last STATS line wins per pod (loop overwrites)
				}
			}
		}
	}
	return total
}

func getServiceClusterIP(ns, name string) string {
	svc, err := fw.ServiceManager.GetService(ctx, ns, name)
	if err != nil {
		return ""
	}
	return svc.Spec.ClusterIP
}

// buildReuserDeployment builds the SO_REUSEADDR port-reuser amplifier: each replica
// runs 4 threads opening short-lived TCP connections to the echo VIP, binding a
// cycled ephemeral port with SO_REUSEADDR to force reuse of TIME_WAIT ports. This
// is what makes the conntrack-cleanup snapshot go stale fast enough to hit the race.
func buildReuserDeployment(node, target string) *appsv1.Deployment {
	replicas := int32(reuserReplicas)
	script := fmt.Sprintf(`import socket,time,itertools,threading
TARGET=(%q,80)
pi=itertools.cycle(range(32768,60999))
lock=threading.Lock()
stats={"ok":0,"err":0}
def np():
 with lock:return next(pi)
def probe():
 while True:
  p=np();s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  try:
   s.bind(('',p));s.settimeout(1);s.connect(TARGET);s.close()
   with lock:stats["ok"]+=1
  except Exception:
   with lock:stats["err"]+=1
  finally:
   try:s.close()
   except:pass
  time.sleep(0.004)
for _ in range(4):threading.Thread(target=probe,daemon=True).start()
while True:
 time.sleep(30)
 with lock:print("[STATS] ok=%%d err=%%d"%%(stats["ok"],stats["err"]),flush=True)`, target)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "port-reuser", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "port-reuser"}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "port-reuser"}},
				Spec: v1.PodSpec{
					NodeName: node,
					Containers: []v1.Container{{
						Name:    "reuser",
						Image:   "public.ecr.aws/docker/library/python:3.11-slim",
						Command: []string{"python3", "-c", script},
					}},
				},
			},
		},
	}
}
