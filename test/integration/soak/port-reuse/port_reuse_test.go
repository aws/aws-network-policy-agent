//go:build soak
// +build soak

package soak

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*
Source-Port-Reuse Soak Test  (aws/aws-network-policy-agent#462)

Soaks an ephemeral-source-port-reuse workload and fails if a policy-protected pod
loses return traffic at any point.

Shape: a "victim" pod behind a restrictive ingress policy drives short-lived TLS
requests at the apiserver with Connection: close, so every request lands on a
fresh ephemeral port and its return flow sits in the eBPF conntrack map. Alongside
it, SO_REUSEADDR "port-reuser" replicas churn short-lived connections to force
reuse of ports in TIME_WAIT, keeping the conntrack map turning over and the
userspace conntrack cleanup busy.

The assertion is deliberately simple: run the workload for the full duration and
fail on ANY Verdict DENY. Every pod here has its return traffic allowed by
conntrack state, so a DENY means a conntrack entry for a live flow went missing.
That makes this a regression net for the whole workload shape — conntrack
cleanup, policy-map handling, probe reattach, resource exhaustion over time —
rather than a probe for one specific code path. If a DENY appears, the NPA log
carries the 5-tuple and the surrounding cleanup trace needed to debug it.

The log-reader pod tails DENY events to its own stdout and the test reads them with
PodLogs, which proved far more reliable than exec'ing a grep under this workload. A
read can still fail, so a failed read is a skipped poll and a pass additionally
requires minPollCoverage of the polls to have actually read the log — a run that was
mostly blind fails instead of reporting success.

It runs the full soakDuration with no early exit, so a slow-developing problem has
time to appear. Guarded by the `soak` build tag and excluded from the regular
integration cadence; see the package doc in port_reuse_suite_test.go.

Assertions:
  - LIVENESS (fail fast): reuser is churning AND cleanup is running. A silent
    no-load run FAILS rather than passing on nothing.
  - CONNECTIVITY: zero Verdict DENY over the whole run.
  - COVERAGE: the run actually observed most of the soak window.

Tagged [PortReuse][Soak].
*/

const (
	soakDuration     = 30 * time.Minute
	soakPollInterval = 30 * time.Second
	soakWarmup       = 90 * time.Second
	npaLogPath       = "/host/var/log/aws-routed-eni/network-policy-agent.log"

	// 3 replicas x 4 threads at ~250 conn/sec each: ~1k/sec per pod, ~3k/sec
	// aggregate. Each replica cycles its own ~28k ephemeral-port range independently
	// (itertools.cycle is per-process), so a given port comes back around about
	// every 28s per pod.
	//
	// A flow is only at risk while the same ephemeral port can be reused between the
	// userspace cleanup taking its kernel conntrack snapshot and walking the eBPF
	// map, so the port range has to cycle on a timescale comparable to that span.
	// These are the parameters from the reported workload, matched verbatim (3
	// replicas, 4 threads, 4ms), so the soak exercises the same shape that produced
	// the original failure: enough SO_REUSEADDR reuse to keep ports recycling
	// against the cleanup walk, without loading the node hard enough to disturb pod
	// liveness probes.
	reuserReplicas     = 3
	reuserThreads      = 4
	reuserSleepPerConn = "0.004"

	// Pinned rather than :latest so a new upstream image cannot change what this
	// soak exercises without a code change.
	echoImage = "public.ecr.aws/nginx/nginx:1.31"

	// One port end to end: the echo container, the Service port and targetPort, and
	// both port-reuser NetworkPolicy rules. NetworkPolicy egress matches the
	// destination port after service translation, so remapping ports across the
	// Service here would deny the reuser's own traffic and mask what the soak is
	// meant to observe.
	echoPort = 80

	// The victim's ingress policy allows only a port it never serves on, so its
	// return traffic is admitted purely by conntrack state.
	victimAllowedPort = 8086
	// The victim drives short-lived TLS requests at the apiserver, each on a fresh
	// ephemeral port, to keep a population of return flows in the conntrack map.
	// A near-idle victim leaves too few flows at risk for the soak to observe
	// anything, so the rate is deliberately well above one request per second.
	victimThreads  = 8
	victimSleep    = "0.02" // per-thread pause between requests; ~200 req/sec aggregate in practice
	victimPipPkg   = "requests==2.32.3"
	victimSAName   = "victim-lister"
	victimRoleName = "victim-pod-lister"
	victimBindName = "victim-pod-lister-binding"

	// The agent's flow-event line is not formatted identically across address
	// families: the IPv4 path logs "Verdict DENY" (pkg/ebpf/events/events.go) and
	// the IPv6 path "Verdict: DENY". Match both, or the detector is silently blind
	// on one family while every other gate still reports a healthy run. The same
	// pattern feeds the log-reader's grep and the Go-side matcher so they cannot
	// drift apart.
	denyLogPattern = "Verdict:? DENY"
	cleanupLogLine = "Done cleanup of conntrack map"

	logReadAttempts = 4 // total attempts per log read (1 initial + 3 retries, ~12s of backoff)
	// How long the cleanup-event stream may go quiet before the log-reader is
	// treated as no longer following the log. The agent emits one event per cleanup
	// period, so this has to be generous enough to cover the largest period a run
	// might use (the default is 300s) plus jitter — a threshold tuned to a short
	// period will fail runs where cleanup is simply infrequent.
	maxCleanupGap = 12 * time.Minute
	// A pass is only meaningful if the run watched for most of the soak, so require
	// this share of polls to have actually read the log.
	minPollCoverage = 80.0
)

var denyLogRE = regexp.MustCompile(denyLogPattern)

var _ = Describe("Source Port Reuse [PortReuse][Soak]", func() {

	// isV6 selects the address family for the workload. The conntrack path under
	// test is family-independent, so the same soak runs on either.
	isV6 := func() bool { return fw.Options.IpFamily == "IPv6" }

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
		// Best-effort teardown: delete errors are deliberately ignored so one
		// failure cannot stop the rest from being cleaned up, and so a teardown
		// hiccup does not mask the spec's own result. The suite drops the whole
		// namespace afterwards regardless.
		if checkPod != nil {
			_ = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
		}
		if reuserDep != nil {
			_ = fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, reuserDep)
		}
		for _, np := range []*network.NetworkPolicy{victimNP, reuserIng, reuserEg} {
			if np != nil {
				_ = fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			}
		}
		if echoSvc != nil {
			_ = fw.ServiceManager.DeleteService(ctx, echoSvc)
		}
		for _, p := range []*v1.Pod{echoPod, victimPod} {
			if p != nil {
				_ = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p)
			}
		}
		// The victim's RBAC is namespaced, so the suite's namespace teardown would
		// remove it anyway; delete it here so the spec leaves nothing behind if the
		// namespace outlives it.
		_ = fw.K8sClient.Delete(ctx, &rbac.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: victimBindName, Namespace: namespace}})
		_ = fw.K8sClient.Delete(ctx, &rbac.Role{
			ObjectMeta: metav1.ObjectMeta{Name: victimRoleName, Namespace: namespace}})
		_ = fw.K8sClient.Delete(ctx, &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: victimSAName, Namespace: namespace}})
	})

	It("keeps return traffic flowing to a policy-protected pod under sustained source-port reuse", func() {
		By("Creating echo target (port-reuser target)")
		// The stock image's default server block is `listen 80;` only, which binds
		// IPv4 alone — on an IPv6 cluster every reuser connection would be refused.
		// Write a server block that listens on both families so the same manifest
		// works either way.
		echoConf := fmt.Sprintf(
			"server { listen %d; listen [::]:%d; location / { return 200 \"ok\\n\"; } }",
			echoPort, echoPort)
		echoPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "echo-server", Namespace: namespace,
				Labels: map[string]string{"app": "echo-server"},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "nginx", Image: echoImage,
					Ports:   []v1.ContainerPort{{ContainerPort: echoPort}},
					Command: []string{"sh", "-c"},
					Args: []string{fmt.Sprintf(
						"printf %s > /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'",
						shellQuote(echoConf))},
				}},
			},
		}
		var err error
		echoPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, echoPod, 3*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		node = echoPod.Spec.NodeName
		Expect(node).ToNot(BeEmpty())

		By(fmt.Sprintf("Exposing echo target via ClusterIP Service on :%d", echoPort))
		echoSvc = &v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: namespace},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{"app": "echo-server"},
				Ports:    []v1.ServicePort{{Port: echoPort, TargetPort: intstr.FromInt(echoPort), Protocol: v1.ProtocolTCP}},
			},
		}
		echoSvc, err = fw.ServiceManager.CreateService(ctx, echoSvc)
		Expect(err).ToNot(HaveOccurred())
		echoVIP = getServiceClusterIP(namespace, "echo-server")
		Expect(echoVIP).ToNot(BeEmpty())

		By(fmt.Sprintf("Applying restrictive ingress policy to victim (allow only TCP/%d)", victimAllowedPort))
		victimNP = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "victim-restrictive", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "victim"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					Ports: []network.NetworkPolicyPort{{
						Protocol: protoPtr(v1.ProtocolTCP), Port: portPtr(victimAllowedPort),
					}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, victimNP)).To(Succeed())

		By("Granting the victim pod list access so it can drive apiserver requests")
		Expect(createVictimRBAC()).To(Succeed())

		By(fmt.Sprintf("Creating victim pod (%d threads, Connection: close, requests to the apiserver)",
			victimThreads))
		// Short-lived TLS requests to the apiserver on a fresh ephemeral port each
		// time, so the victim keeps a steady population of return flows in the
		// conntrack map while the reuser churns ports around them. Rate matters: a
		// near-idle victim leaves too few flows at risk to observe anything.
		victimScript := fmt.Sprintf(`import threading,time,requests
TOKEN=open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
URL="https://kubernetes.default.svc:443/api/v1/namespaces/%s/pods?limit=1"
HEADERS={"Authorization":"Bearer "+TOKEN,"Connection":"close"}
lock=threading.Lock()
stats={"ok":0,"err":0}
def loop():
 while True:
  try:
   requests.get(URL,headers=HEADERS,verify=CA,timeout=5)
   with lock:stats["ok"]+=1
  except Exception:
   with lock:stats["err"]+=1
  time.sleep(%s)
for _ in range(%d):threading.Thread(target=loop,daemon=True).start()
while True:
 time.sleep(30)
 with lock:print("[STATS] ok={} err={}".format(stats["ok"],stats["err"]),flush=True)`,
			namespace, victimSleep, victimThreads)
		victimPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "victim", Namespace: namespace,
				Labels: map[string]string{"app": "victim"},
			},
			Spec: v1.PodSpec{
				NodeName:           node,
				ServiceAccountName: victimSAName,
				Containers: []v1.Container{{
					Name: "victim", Image: "public.ecr.aws/docker/library/python:3.11-slim",
					Command: []string{"sh", "-c"},
					// requests is pinned: an unpinned install would let a future
					// release change this pod's behaviour with no change to the test.
					Args: []string{fmt.Sprintf(
						"pip install --quiet --root-user-action=ignore %s && python3 -c %s",
						victimPipPkg, shellQuote(victimScript))},
				}},
			},
		}
		// Longer than the other pods: the image installs `requests` on startup.
		victimPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, victimPod, 4*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(victimPod.Status.PodIP).ToNot(BeEmpty(), "victim pod must have an IP to take return traffic")

		By("Applying ingress+egress policy to port-reuser (puts its flows in eBPF conntrack)")
		reuserIng = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "port-reuser-ingress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "port-reuser"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					Ports: []network.NetworkPolicyPort{{Protocol: protoPtr(v1.ProtocolTCP), Port: portPtr(echoPort)}},
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
					Ports: []network.NetworkPolicyPort{{Protocol: protoPtr(v1.ProtocolTCP), Port: portPtr(echoPort)}},
					To: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "echo-server"}},
					}},
				}},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, reuserEg)).To(Succeed())

		By("Deploying port-reuser amplifier (SO_REUSEADDR TIME_WAIT reuse)")
		reuserDep = buildReuserDeployment(node, echoVIP, isV6())
		reuserDep, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, reuserDep)
		Expect(err).ToNot(HaveOccurred())

		By("Deploying log-reader pod to read the NPA log on the test node")
		// The NPA log is per-node and shared, so scope DENYs to this workload's pod
		// IPs. Node-wide counting would fail the soak on a neighbouring pod's own
		// policy correctly denying traffic, which is not a conntrack loss. Both the
		// victim and the reusers are included: the reusers are where port reuse
		// happens and where most DENYs surface when the race fires.
		reuserPods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", "port-reuser")
		Expect(err).ToNot(HaveOccurred())
		Expect(reuserPods).ToNot(BeEmpty())
		watchedIPs := []string{victimPod.Status.PodIP}
		for _, p := range reuserPods {
			Expect(p.Status.PodIP).ToNot(BeEmpty(), "port-reuser pod has no IP to watch")
			watchedIPs = append(watchedIPs, p.Status.PodIP)
		}
		// NB: not utils.BuildBPFCheckPod — that pod sleeps 300s and would die
		// mid-soak. Use sleep infinity so the pod stays available for the whole
		// soakDuration.
		checkPod = buildLogReaderPod(node, watchedIPs)
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())

		By("Warming up so the conntrack map fills and cleanup begins")
		time.Sleep(soakWarmup)

		By("Confirming liveness: reuser churning + cleanup running (fail fast otherwise)")
		Eventually(func() int { return statsOK(namespace, "port-reuser") }, 2*time.Minute, 15*time.Second).
			Should(BeNumerically(">", 1000), "port-reuser is not generating connections")
		// The victim's return flows are what this soak actually observes, so a victim
		// that silently fails every request would weaken the run with no signal. Its
		// script swallows exceptions and keeps running, so it has to be gated here.
		// The window is wider than the reuser's: the container reports Running as soon
		// as the shell starts, but the victim installs its HTTP client before printing
		// any stats, so a slow package fetch must not be read as a dead workload.
		Eventually(func() int { return statsOK(namespace, "victim") }, 5*time.Minute, 15*time.Second).
			Should(BeNumerically(">", 100), "victim is not driving apiserver requests")
		Eventually(func() int { _, cleanups := eventCounts(checkPod); return cleanups },
			6*time.Minute, soakPollInterval).
			Should(BeNumerically(">", 0), "conntrack cleanup never ran — workload/agent not exercising GC")

		By(fmt.Sprintf("Soaking port reuse for %s — fail on any Verdict DENY", soakDuration))
		deadline := time.Now().Add(soakDuration)
		polls, skipped, cleanups := 0, 0, 0
		lastCleanupAt := time.Now()
		for time.Now().Before(deadline) {
			deny, c := eventCounts(checkPod)

			// -1 means the read itself failed; skip that poll rather than treating
			// it as a signal.
			if deny < 0 {
				skipped++
				time.Sleep(soakPollInterval)
				continue
			}
			polls++

			// The agent emits a cleanup event once per cleanup period, so the count
			// has to keep climbing. A read that succeeds but returns a frozen stdout
			// (the reader's tail died) looks identical to a clean run, so treat a long
			// silence as a broken observer rather than a pass. This is measured in
			// time, not polls, because the cleanup period is a runtime setting and can
			// be many multiples of the poll interval.
			if c > cleanups {
				cleanups, lastCleanupAt = c, time.Now()
			} else if quiet := time.Since(lastCleanupAt); quiet > maxCleanupGap {
				Fail(fmt.Sprintf("no new conntrack cleanup events for %s (stuck at %d) — "+
					"the log-reader has stopped following the NPA log, so a DENY would go unseen",
					quiet.Round(time.Second), cleanups))
			}

			// Every pod in this workload has its return traffic allowed by conntrack
			// state, so any DENY means a conntrack entry for a live flow went
			// missing, whatever lost it.
			Expect(deny).To(Equal(0),
				fmt.Sprintf("lost return traffic: %d Verdict DENY events during the soak. "+
					"A conntrack entry for a live flow went missing — see the NPA log for the "+
					"5-tuple and the surrounding 'Conntrack cleanup' trace.", deny))

			time.Sleep(soakPollInterval)
		}

		// The loop sleeps after its last read, so the final interval would otherwise
		// go unobserved. Counts are cumulative from the reader's start, so one more
		// read closes that window exactly.
		if deny, c := eventCounts(checkPod); deny < 0 {
			skipped++
		} else {
			polls++
			if c > cleanups {
				cleanups = c
			}
			Expect(deny).To(Equal(0),
				fmt.Sprintf("lost return traffic: %d Verdict DENY events during the soak. "+
					"A conntrack entry for a live flow went missing — see the NPA log for the "+
					"5-tuple and the surrounding 'Conntrack cleanup' trace.", deny))
		}

		// A read succeeds even against a terminated pod, so a log-reader that died
		// late would look like a clean, fully-covered run. Confirm the observer
		// outlived the soak before trusting the zero-DENY result.
		observed := &v1.Pod{}
		Expect(fw.K8sClient.Get(ctx,
			types.NamespacedName{Namespace: namespace, Name: checkPod.Name}, observed)).To(Succeed())
		Expect(observed.Status.Phase).To(Equal(v1.PodRunning),
			fmt.Sprintf("log-reader was not Running at end of soak (phase %s) — reads may have "+
				"returned frozen output, so the DENY count cannot be trusted", observed.Status.Phase))

		// A pass only means something if the run actually watched for most of the
		// soak. Reporting success after mostly-failed reads would hide a DENY that
		// happened in a blind window, so require real coverage rather than just one
		// successful poll.
		attempts := polls + skipped
		Expect(attempts).To(BeNumerically(">", 0),
			"the soak loop never polled — soakDuration and soakPollInterval are inconsistent")
		coverage := float64(polls) / float64(attempts) * 100
		Expect(coverage).To(BeNumerically(">=", minPollCoverage),
			fmt.Sprintf("only observed %.0f%% of the %s soak (%d polls succeeded, %d failed to read the log) — "+
				"a DENY could have gone unseen, so this run proves nothing",
				coverage, soakDuration, polls, skipped))

		By(fmt.Sprintf("PASS: %s of port-reuse churn, 0 Verdict DENY "+
			"(%d cleanup passes, %.0f%% poll coverage: %d ok / %d failed)",
			soakDuration, cleanups, coverage, polls, skipped))
	})
})

// --- helpers ---

func protoPtr(p v1.Protocol) *v1.Protocol { return &p }

// shellQuote wraps s in single quotes for `sh -c`, escaping any embedded quotes,
// so a script can be passed through a shell without the shell reinterpreting it.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// createVictimRBAC gives the victim pod permission to list pods, which is all it
// needs to drive requests at the apiserver. Namespaced RoleBinding rather than a
// ClusterRoleBinding: the victim only ever lists in its own namespace, and the
// suite's namespace teardown removes the binding with it.
func createVictimRBAC() error {
	sa := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: victimSAName, Namespace: namespace},
	}
	if err := fw.K8sClient.Create(ctx, sa); err != nil {
		return err
	}
	role := &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{Name: victimRoleName, Namespace: namespace},
		Rules: []rbac.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"},
		}},
	}
	if err := fw.K8sClient.Create(ctx, role); err != nil {
		return err
	}
	binding := &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: victimBindName, Namespace: namespace},
		Subjects: []rbac.Subject{{
			Kind: rbac.ServiceAccountKind, Name: victimSAName, Namespace: namespace,
		}},
		RoleRef: rbac.RoleRef{
			Kind: "Role", Name: victimRoleName, APIGroup: rbac.GroupName,
		},
	}
	return fw.K8sClient.Create(ctx, binding)
}
func portPtr(n int32) *intstr.IntOrString { v := intstr.FromInt(int(n)); return &v }

// buildLogReaderPod is pinned to the test node, read-only host-mounts just the NPA
// log directory, and tails the DENY events out to its own stdout so the test can
// read them with PodLogs.
//
// Reading via PodLogs rather than exec'ing a grep matters: under this workload the
// exec dial timed out on most polls, leaving the test blind for the majority of a
// run. A log read is a far lighter request than a SPDY exec upgrade that spawns a
// process, and has not failed since. Both subresources are proxied by the apiserver
// to the node's kubelet though, so the read is not immune — that is why a failed
// read is a skipped poll and why minPollCoverage gates the pass.
//
// -F follows across the agent's log rotation, and stdbuf keeps grep from buffering
// matches for minutes at a time. It only needs to read one file, so it drops
// Privileged/HostPID/HostNetwork and mounts a single directory read-only rather
// than the whole host root.
func buildLogReaderPod(node string, watchedIPs []string) *v1.Pod {
	readOnlyRootFS := true
	hostPathDir := v1.HostPathDirectory
	// A DENY only counts if it names one of this workload's pods. Escape the dots so
	// an IP literal cannot match a neighbouring address by wildcard.
	ipAlt := strings.ReplaceAll(strings.Join(watchedIPs, "|"), ".", `\.`)
	tail := fmt.Sprintf("tail -n 0 -F %s 2>/dev/null | stdbuf -oL grep --line-buffered -E '(%s).*%s|%s'",
		npaLogPath, ipAlt, denyLogPattern, cleanupLogLine)
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "log-reader", Namespace: namespace},
		Spec: v1.PodSpec{
			NodeName: node, RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				// -minimal is enough: it carries tail, grep and stdbuf via
				// coreutils-single, which is all the tail pipeline needs.
				Name: "reader", Image: "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
				Command:         []string{"sh", "-c", tail},
				SecurityContext: &v1.SecurityContext{ReadOnlyRootFilesystem: &readOnlyRootFS},
				VolumeMounts:    []v1.VolumeMount{{Name: "npa-log", MountPath: "/host/var/log/aws-routed-eni", ReadOnly: true}},
			}},
			Volumes: []v1.Volume{{
				Name:         "npa-log",
				VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/aws-routed-eni", Type: &hostPathDir}},
			}},
		},
	}
}

// eventCounts returns how many Verdict DENY events and completed conntrack cleanup
// passes the log-reader has forwarded to its stdout since the run began, or (-1, -1)
// if the read failed so the caller can skip that poll rather than read it as data.
//
// The reader starts tailing at the end of the log, so its stdout only ever contains
// this run's events and no baselining is needed. A log read proved far more reliable
// than exec'ing a grep under this workload, but it reaches the kubelet by the same
// apiserver proxy, so it can still fail — hence the retries and the sentinel.
func eventCounts(checkPod *v1.Pod) (denies int, cleanups int) {
	var lastErr error
	for attempt := 0; attempt < logReadAttempts; attempt++ {
		logs, err := fw.PodManager.PodLogs(namespace, checkPod.Name)
		if err != nil {
			lastErr = err
			GinkgoWriter.Printf("eventCounts attempt %d/%d failed: %v\n",
				attempt+1, logReadAttempts, err)
			// No point backing off after the last attempt — the caller skips this
			// poll and retries on the next one.
			if attempt < logReadAttempts-1 {
				time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
			}
			continue
		}
		d, c := 0, 0
		for _, ln := range strings.Split(logs, "\n") {
			switch {
			case denyLogRE.MatchString(ln):
				d++
			case strings.Contains(ln, cleanupLogLine):
				c++
			}
		}
		return d, c
	}
	GinkgoWriter.Printf("eventCounts giving up after %d attempts, last error: %v\n",
		logReadAttempts, lastErr)
	return -1, -1
}

// statsOK sums the cumulative successful-request counters that the load-generating
// pods with the given app label print in their STATS log lines
// ("[STATS] ok=N err=M").
func statsOK(ns, appLabel string) int {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, ns, "app", appLabel)
	if err != nil {
		return 0
	}
	total := 0
	for _, p := range pods {
		logs, lerr := fw.PodManager.PodLogs(ns, p.Name)
		if lerr != nil {
			continue
		}
		// ok= is a cumulative counter, so only the last STATS line for this pod
		// is meaningful. Track it per pod and add it once; summing every line
		// would multiply-count the running total.
		podOK := 0
		for _, ln := range strings.Split(logs, "\n") {
			if idx := strings.LastIndex(ln, "ok="); idx >= 0 {
				rest := ln[idx+3:]
				end := strings.IndexAny(rest, " \t")
				if end < 0 {
					end = len(rest)
				}
				if v, e := strconv.Atoi(rest[:end]); e == nil {
					podOK = v
				}
			}
		}
		total += podOK
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
// runs reuserThreads threads opening short-lived TCP connections to the echo VIP,
// binding a cycled ephemeral port with SO_REUSEADDR to force reuse of TIME_WAIT
// ports. This is what makes the conntrack-cleanup snapshot go stale fast enough to
// exercise this path. See reuserReplicas for how the rate was chosen.
func buildReuserDeployment(node, target string, v6 bool) *appsv1.Deployment {
	replicas := int32(reuserReplicas)
	family, bindAddr := "AF_INET", ""
	if v6 {
		family, bindAddr = "AF_INET6", "::"
	}
	script := fmt.Sprintf(`import socket,time,itertools,threading
TARGET=(%q,%d)
pi=itertools.cycle(range(32768,60999))
lock=threading.Lock()
stats={"ok":0,"err":0}
def np():
 with lock:return next(pi)
def probe():
 while True:
  p=np();s=socket.socket(socket.%s,socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  try:
   s.bind((%q,p));s.settimeout(1);s.connect(TARGET);s.close()
   with lock:stats["ok"]+=1
  except Exception:
   with lock:stats["err"]+=1
  finally:
   try:s.close()
   except:pass
  time.sleep(%s)
for _ in range(%d):threading.Thread(target=probe,daemon=True).start()
while True:
 time.sleep(30)
 with lock:print("[STATS] ok=%%d err=%%d"%%(stats["ok"],stats["err"]),flush=True)`,
		target, echoPort, family, bindAddr, reuserSleepPerConn, reuserThreads)

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
