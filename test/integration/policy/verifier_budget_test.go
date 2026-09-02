package policy

// BPF verifier complexity budget test.
//
// The verifier abandons a program once it has processed
// BPF_COMPLEXITY_LIMIT_INSNS instructions and fails the load with E2BIG. A
// program that loads today can cross that ceiling after an innocuous-looking
// change to the policy loops, and the only symptom is that policy enforcement
// stops working on the node. This test measures how much of that budget each
// loaded program actually consumes.
//
// The number that matters is bpf_prog_info.verified_insns, the verifier's own
// processed-instruction count, not the static instruction count of the program.
// It is only meaningful on the kernel that did the verifying, which is why this
// is an integration test rather than a build-time check: two kernels reach
// different counts for the same object because their pruning heuristics differ.
//
// Note on what this does and does not catch. The gate is a fraction of the
// kernel's absolute limit, so it fires only once a program is close to failing
// to load. It is a backstop, not an early warning: because verifier cost grows
// multiplicatively with branch depth and pruning is heuristic, a change can
// multiply the count several times over and still pass. The measured counts are
// recorded in the spec report; nothing compares them across runs, so noticing a
// regression below the gate means someone reading two reports side by side. A
// checked-in baseline with a tolerance would close that gap, and its absence is
// a deliberate choice rather than an oversight.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	fwutils "github.com/aws/aws-network-policy-agent/test/framework/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The verifier's processed-instruction ceiling, BPF_COMPLEXITY_LIMIT_INSNS in
// include/linux/bpf.h. It is a compile-time constant with no userspace query.
// The value was 131072 before kernel 5.2 and has been 1,000,000 since. Because
// bpf_prog_info.verified_insns itself only exists from 5.16, every kernel on
// which this test can read a count is already past the last change to the
// limit, so this is exact rather than an assumption. Revisit if a kernel ever
// raises it, in which case the limit becomes kernel-dependent and has to be
// looked up per version.
const complexityLimitInsns = 1_000_000

// verified_insns was added to bpf_prog_info in 5.16. On anything older the
// kernel returns a shorter info struct and the count cannot be read at all, so
// the spec skips rather than failing.
const minKernelMajorForVerifiedInsns = 5
const minKernelMinorForVerifiedInsns = 16

// Fraction of the limit a single program may consume before this test fails.
// See the note at the top of the file about what this does and does not catch.
const defaultBudgetFraction = 0.9

const budgetFractionEnvVar = "NPA_VERIFIER_BUDGET_FRACTION"

// Image for the probe pod. It is not taken from --test-image-registry, because
// that registry holds the suite's purpose-built e2e images and the probe needs
// something with a python3 interpreter instead. Overridable for environments
// that cannot reach public ECR or that mirror it elsewhere. A substituted image
// must provide python3; if it does not, the probe pod fails and its log says so.
const probeImageEnvVar = "NPA_VERIFIER_PROBE_IMAGE"
const defaultProbeImage = "public.ecr.aws/amazonlinux/amazonlinux:2023"

// Per-attempt budget for the probe pod, including image pull. Deliberately well
// under pinReconcileTimeout: CreateAndWaitTillPodIsCompleted returns only on
// Succeeded or Failed, and a pod stuck in ImagePullBackOff is Pending, so it
// polls until this context expires. If the two budgets were equal, one slow pull
// would consume the whole retry loop and be reported as a pinning failure.
const probeTimeout = 75 * time.Second

// Total budget for the agent to reconcile the policy and pin its programs.
const pinReconcileTimeout = 4 * time.Minute
const pinReconcileInterval = 20 * time.Second

// insnProbeScript reads bpf_prog_info for every program pinned under the given
// directories and prints one JSON object per program plus a JSON summary.
//
// bpftool is not used because it does not print verified_insns: the string is
// absent from the binary AL2023 ships (v7.1.0), so the field is read straight
// from BPF_OBJ_GET_INFO_BY_FD. The offsets below are byte offsets into struct
// bpf_prog_info from include/uapi/linux/bpf.h. They are stable across kernels
// because the struct only ever grows at the tail, and they were verified
// against a running kernel by comparing prog_id, prog_name and
// xlated_prog_len against bpftool's output for the same programs.
const insnProbeScript = `
import ctypes, errno, json, os, platform, struct, sys

BPF_OBJ_GET = 7
BPF_OBJ_GET_INFO_BY_FD = 15

OFF_ID = 4
OFF_XLATED_PROG_LEN = 20
OFF_NAME, NAME_LEN = 64, 16
OFF_VERIFIED_INSNS = 216
# The kernel writes min(info_len, sizeof(its own struct)) bytes and reports the
# count back, so a struct that stops short of verified_insns is detectable. That
# happens on a kernel predating the field, and also if the fd is not a program.
MIN_INFO_LEN = OFF_VERIFIED_INSNS + 4

SYS_BPF = {"x86_64": 321, "aarch64": 280}
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]

def bpf(cmd, attr):
    nr = SYS_BPF.get(platform.machine())
    if nr is None:
        raise RuntimeError("unsupported architecture " + platform.machine())
    buf = ctypes.create_string_buffer(attr, len(attr))
    ret = libc.syscall(nr, cmd, ctypes.byref(buf), len(attr))
    return ret, ctypes.get_errno(), buf.raw

def prog_fd_from_pin(path):
    path_buf = ctypes.create_string_buffer(path.encode())
    # struct { __aligned_u64 pathname; __u32 bpf_fd; __u32 file_flags; }
    fd, err, _ = bpf(BPF_OBJ_GET, struct.pack("QII", ctypes.addressof(path_buf), 0, 0))
    if fd < 0:
        raise OSError(err, "BPF_OBJ_GET failed: " + os.strerror(err))
    return fd

def prog_info(fd):
    # Oversize the buffer so the kernel reports how much of its struct it wrote.
    info = ctypes.create_string_buffer(512)
    # struct { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; }
    attr = struct.pack("IIQ", fd, len(info), ctypes.addressof(info))
    ret, err, attr_out = bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    if ret != 0:
        raise OSError(err, "BPF_OBJ_GET_INFO_BY_FD failed: " + os.strerror(err))
    return info.raw, struct.unpack_from("I", attr_out, 4)[0]

results, errors, vanished, short = [], [], [], []
for pin_dir in sys.argv[1:]:
    if not os.path.isdir(pin_dir):
        # Not an error: the agent creates this directory when it first pins a
        # program, so an absent directory means nothing is loaded yet.
        continue
    for entry in sorted(os.listdir(pin_dir)):
        path = os.path.join(pin_dir, entry)
        try:
            fd = prog_fd_from_pin(path)
        except OSError as e:
            # A pin can disappear between listdir and open when a pod
            # terminates. That is routine on a live node, not a failure.
            if e.errno == errno.ENOENT:
                vanished.append(entry)
            else:
                errors.append(path + ": " + str(e))
            continue
        try:
            raw, written = prog_info(fd)
        except OSError as e:
            errors.append(path + ": " + str(e))
            continue
        finally:
            os.close(fd)
        if written < MIN_INFO_LEN:
            short.append({"pin_name": entry, "info_len": written})
            continue
        results.append({
            "pin_name": entry,
            "prog_id": struct.unpack_from("I", raw, OFF_ID)[0],
            "prog_name": raw[OFF_NAME:OFF_NAME + NAME_LEN].split(b"\x00")[0].decode(errors="replace"),
            "verified_insns": struct.unpack_from("I", raw, OFF_VERIFIED_INSNS)[0],
            "xlated_insns": struct.unpack_from("I", raw, OFF_XLATED_PROG_LEN)[0] // 8,
        })

for r in results:
    print(json.dumps(r))
print(json.dumps({"summary": True, "kernel": os.uname().release, "arch": platform.machine(),
                  "programs": len(results), "short_info": short,
                  "vanished": vanished, "errors": errors}))
`

type progInsns struct {
	PinName       string `json:"pin_name"`
	ProgID        int    `json:"prog_id"`
	ProgName      string `json:"prog_name"`
	VerifiedInsns int    `json:"verified_insns"`
	XlatedInsns   int    `json:"xlated_insns"`
}

// shortInfo is a pin whose bpf_prog_info stopped before verified_insns. The
// byte count distinguishes the causes: a length near sizeof(bpf_prog_info)
// means a kernel older than 5.16, while a much smaller one means the fd was
// not a program at all.
type shortInfo struct {
	PinName string `json:"pin_name"`
	InfoLen int    `json:"info_len"`
}

type probeSummary struct {
	Kernel    string      `json:"kernel"`
	Arch      string      `json:"arch"`
	Programs  int         `json:"programs"`
	ShortInfo []shortInfo `json:"short_info"`
	Vanished  []string    `json:"vanished"`
	Errors    []string    `json:"errors"`
}

var _ = Describe("BPF verifier complexity budget", func() {
	const (
		budgetServerName = "insn-budget-server"
		budgetPolicyName = "insn-budget-deny-all"
	)

	var (
		serverPod    *v1.Pod
		budgetPolicy *network.NetworkPolicy
		fraction     float64
	)

	// Declared before the BeforeEach that creates resources, because Ginkgo runs
	// BeforeEach nodes in declaration order. A bad env var therefore fails before
	// a pod or a policy exists, rather than after the server pod has come up.
	BeforeEach(func() {
		var err error
		fraction, err = budgetFraction()
		Expect(err).ToNot(HaveOccurred())
	})

	BeforeEach(func() {
		By("Deploying a server pod", func() {
			container := manifest.NewAgnHostContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Args([]string{"/agnhost netexec"}).
				AddContainerPort(v1.ContainerPort{ContainerPort: 8080}).
				Build()

			pod := manifest.NewDefaultPodBuilder().
				Name(budgetServerName).
				Namespace(namespace).
				AddLabel("app", budgetServerName).
				Container(container).
				Build()

			var err error
			serverPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())
		})

		By("Applying a policy with both directions so both TC programs are loaded", func() {
			budgetPolicy = manifest.NewNetworkPolicyBuilder().
				Namespace(namespace).
				Name(budgetPolicyName).
				PodSelector("app", budgetServerName).
				SetPolicyType(true, true).
				Build()

			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, budgetPolicy)).To(Succeed())
		})
	})

	AfterEach(func() {
		// Bound the teardown. DeleteAndWaitTillPodIsDeleted polls until its
		// context is done and takes no timeout of its own, and the suite's ctx
		// is context.Background(), so a pod stuck terminating would otherwise
		// hang here until Ginkgo's suite-level timeout with no indication of
		// which delete was responsible.
		cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		if budgetPolicy != nil {
			if err := fw.NetworkPolicyManager.DeleteNetworkPolicy(cleanupCtx, budgetPolicy); err != nil {
				fmt.Fprintf(GinkgoWriter, "cleanup: deleting policy %s: %v\n", budgetPolicyName, err)
			}
			budgetPolicy = nil
		}
		if serverPod != nil {
			if err := fw.PodManager.DeleteAndWaitTillPodIsDeleted(cleanupCtx, serverPod); err != nil {
				fmt.Fprintf(GinkgoWriter, "cleanup: deleting pod %s: %v\n", budgetServerName, err)
			}
			serverPod = nil
		}

		// runInsnProbe deletes its own pod on every return path, including a
		// failed assertion, but a plain defer does not run if Ginkgo abandons the
		// spec's goroutine on interrupt or timeout. Sweep by label so such a pod
		// does not keep a bpffs mount alive for the rest of the suite.
		// Own context: this sweep is the safety net for a probe pod that outlived
		// runInsnProbe's defer, so a slow server-pod delete above must not be able
		// to consume its budget. The cases that strand a probe pod are the same
		// cases that make the deletes above slow.
		sweepCtx, sweepCancel := context.WithTimeout(ctx, 1*time.Minute)
		defer sweepCancel()

		probePods, err := fw.PodManager.GetPodsWithLabel(sweepCtx, namespace,
			fwutils.BPFFSReaderPodLabelKey, fwutils.BPFFSReaderPodLabelValue)
		if err != nil {
			fmt.Fprintf(GinkgoWriter, "cleanup: listing probe pods: %v\n", err)
			return
		}
		for i := range probePods {
			if err := fw.PodManager.DeleteAndWaitTillPodIsDeleted(sweepCtx, &probePods[i]); err != nil {
				fmt.Fprintf(GinkgoWriter, "cleanup: sweeping probe pod %s: %v\n", probePods[i].Name, err)
			}
		}
	})

	It("should keep every loaded program within its share of the kernel's processed-instruction limit", func() {
		budget := int(complexityLimitInsns * fraction)

		nodeName := serverPod.Spec.NodeName
		Expect(nodeName).ToNot(BeEmpty(), "server pod has no node assigned")

		var kernelVersion string
		By("Reading the node's kernel version", func() {
			node := &v1.Node{}
			Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Name: nodeName}, node)).To(Succeed())
			kernelVersion = node.Status.NodeInfo.KernelVersion
			Expect(kernelVersion).ToNot(BeEmpty())
			AddReportEntry("kernel", kernelVersion)
		})

		if !kernelReportsVerifiedInsns(kernelVersion) {
			Skip(fmt.Sprintf("kernel %s predates bpf_prog_info.verified_insns, which was added in %d.%d",
				kernelVersion, minKernelMajorForVerifiedInsns, minKernelMinorForVerifiedInsns))
		}

		// The agent pins one program per direction per pod identifier, so the
		// pin directory holds programs for every policy-selected pod on the
		// node. Identify this spec's own pins so the measurement cannot be
		// satisfied by programs belonging to unrelated pods.
		podID := utils.GetPodIdentifier(budgetServerName, namespace)
		wantPins := []string{
			filepath.Base(utils.GetBPFPinPathFromPodIdentifier(podID, "ingress")),
			filepath.Base(utils.GetBPFPinPathFromPodIdentifier(podID, "egress")),
		}

		var progs []progInsns
		var summary probeSummary
		var vanished []string
		By("Reading bpf_prog_info for every pinned program on the node", func() {
			// Poll rather than sleeping a fixed interval: the wait is for the
			// agent to reconcile the new policy and pin its programs, and how
			// long that takes is not something this spec can predict.
			Eventually(func(g Gomega) {
				progs, summary = runInsnProbe(g, nodeName)

				// Vanished pins are per-attempt, so accumulate them rather than
				// letting the last attempt overwrite what earlier ones saw.
				vanished = append(vanished, summary.Vanished...)

				// A probe error or a short bpf_prog_info is structural: retrying
				// cannot fix either, and if they are only checked after the loop
				// then an empty progs list fails the pin check first and reports
				// "never pinned", which is the wrong cause. StopTrying aborts
				// immediately with the real explanation.
				if len(summary.Errors) > 0 {
					StopTrying(fmt.Sprintf("probe could not read pinned programs: %v",
						summary.Errors)).Now()
				}
				if len(summary.ShortInfo) > 0 {
					StopTrying(fmt.Sprintf(
						"kernel %s returned a bpf_prog_info shorter than the offset of verified_insns "+
							"for %v. A length near sizeof(bpf_prog_info) means the kernel predates the "+
							"field; a much smaller one means the pin was not a program.",
						kernelVersion, summary.ShortInfo)).Now()
				}

				g.Expect(pinNames(progs)).To(ContainElements(wantPins),
					"agent has not pinned this spec's programs on node %s yet", nodeName)
			}, pinReconcileTimeout, pinReconcileInterval).Should(Succeed())
		})

		if len(vanished) > 0 {
			AddReportEntry("pins-vanished-during-probe", vanished)
		}

		// Sanity-check the fields the probe reads at fixed offsets before
		// asserting on them. Every real program has a non-zero id, a non-zero
		// processed count and at least one instruction, so a zero here means the
		// numbers are not what they claim to be. Two ways that happens: the
		// struct offsets have drifted from this kernel's bpf_prog_info, or the
		// probe lost CAP_BPF, which makes the kernel zero xlated_prog_len while
		// still returning verified_insns. Both were observed during development,
		// and without this check the second one reports every program as having
		// 0 static instructions and still passes.
		//
		// Programs are identified by pin filename, not by prog_name: the agent
		// loads them through a prog-load attr that carries no name, so the
		// kernel records an empty one for all of them. An empty name here is
		// expected, not a defect.
		for _, p := range progs {
			Expect(p.ProgID).To(BeNumerically(">", 0),
				"%s reported prog_id 0, so the probe is misreading bpf_prog_info", p.PinName)
			Expect(p.VerifiedInsns).To(BeNumerically(">", 0),
				"%s reported 0 processed instructions, so the probe is misreading bpf_prog_info", p.PinName)
			Expect(p.XlatedInsns).To(BeNumerically(">", 0),
				"%s reported 0 static instructions. The kernel zeroes xlated_prog_len for a caller "+
					"without CAP_BPF, so either the probe pod lost that capability or the struct "+
					"offsets no longer match this kernel's bpf_prog_info.", p.PinName)
		}

		for _, p := range progs {
			pct := 100 * float64(p.VerifiedInsns) / float64(complexityLimitInsns)
			line := fmt.Sprintf("%s (id %d, name %q): %d verified insns, %.1f%% of the %d limit, %d xlated insns",
				p.PinName, p.ProgID, p.ProgName, p.VerifiedInsns, pct, complexityLimitInsns, p.XlatedInsns)
			AddReportEntry("verified-insns", line)
			fmt.Fprintln(GinkgoWriter, line)

			Expect(p.VerifiedInsns).To(BeNumerically("<=", budget),
				"%s consumed %d of the %d processed-instruction limit on kernel %s (%.1f%%), over the %.0f%% budget. "+
					"The program still loads, but the remaining headroom is too small to rely on: "+
					"a kernel with less aggressive state pruning, or one more unrolled comparison, will fail the load with E2BIG. "+
					"Either reduce verifier work in the policy loops or raise "+budgetFractionEnvVar+" deliberately.",
				p.PinName, p.VerifiedInsns, complexityLimitInsns, kernelVersion, pct, 100*fraction)
		}
	})
})

// runInsnProbe schedules a probe pod on nodeName, reads its output, and deletes
// it. It is safe to call repeatedly: each call uses a fresh pod name and cleans
// up after itself, so a retry does not leak pods or collide.
func runInsnProbe(g Gomega, nodeName string) ([]progInsns, probeSummary) {
	probePod := fwutils.BuildBPFFSReaderPod(namespace, nodeName, probeImage(),
		[]string{"python3", "-c", insnProbeScript, utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY})

	waitCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	_, runErr := fw.PodManager.CreateAndWaitTillPodIsCompleted(waitCtx, probePod)

	// Read the log before asserting on runErr, because that is where a python
	// traceback or a missing interpreter shows up. Without it the only signal
	// is "pod failed to start".
	out, logErr := fw.PodManager.PodLogs(namespace, probePod.Name)

	// PodLogs returns a placeholder string rather than "" when it cannot open the
	// stream, so out is only meaningful while logErr is nil. When it is not, logErr
	// carries the API server's reason the container never produced a log, which for
	// an unpullable image or a missing interpreter is the actual diagnosis.
	logDetail := out
	if logErr != nil {
		logDetail = fmt.Sprintf("<no log: %v>", logErr)
	}

	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cleanupCancel()
		if err := fw.PodManager.DeleteAndWaitTillPodIsDeleted(cleanupCtx, probePod); err != nil {
			fmt.Fprintf(GinkgoWriter, "cleanup: deleting probe pod %s: %v\n", probePod.Name, err)
		}
	}()

	g.Expect(runErr).ToNot(HaveOccurred(), "probe pod did not complete; %s", logDetail)
	g.Expect(logErr).ToNot(HaveOccurred(), "could not read probe pod log")

	progs, summary, err := parseInsnProbeOutput(out)
	g.Expect(err).ToNot(HaveOccurred(), "unparseable probe output: %s", out)
	return progs, summary
}

func pinNames(progs []progInsns) []string {
	names := make([]string, 0, len(progs))
	for _, p := range progs {
		names = append(names, p.PinName)
	}
	return names
}

// kernelReportsVerifiedInsns reports whether a node kernel version string such
// as "6.1.177" or "5.10.245-240.1.amzn2" is new enough to populate
// bpf_prog_info.verified_insns. An unparseable version is treated as new
// enough, so a naming scheme this does not anticipate produces a real failure
// rather than a silent skip.
func kernelReportsVerifiedInsns(kernelVersion string) bool {
	parts := strings.SplitN(kernelVersion, ".", 3)
	if len(parts) < 2 {
		return true
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return true
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return true
	}
	if major != minKernelMajorForVerifiedInsns {
		return major > minKernelMajorForVerifiedInsns
	}
	return minor >= minKernelMinorForVerifiedInsns
}

func probeImage() string {
	if img := os.Getenv(probeImageEnvVar); img != "" {
		return img
	}
	return defaultProbeImage
}

func budgetFraction() (float64, error) {
	raw := os.Getenv(budgetFractionEnvVar)
	if raw == "" {
		return defaultBudgetFraction, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number: %w", budgetFractionEnvVar, raw, err)
	}
	if f <= 0 || f > 1 {
		return 0, fmt.Errorf("%s=%q must be greater than 0 and at most 1", budgetFractionEnvVar, raw)
	}
	return f, nil
}

// parseInsnProbeOutput splits the probe's JSON lines into per-program records
// and the trailing summary. A missing summary means the probe died partway, so
// the per-program records cannot be trusted to be complete.
func parseInsnProbeOutput(out string) ([]progInsns, probeSummary, error) {
	var progs []progInsns
	var summary probeSummary
	sawSummary := false

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var probe struct {
			Summary bool `json:"summary"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			return nil, summary, fmt.Errorf("bad JSON line %q: %w", line, err)
		}
		if probe.Summary {
			if err := json.Unmarshal([]byte(line), &summary); err != nil {
				return nil, summary, fmt.Errorf("bad summary %q: %w", line, err)
			}
			sawSummary = true
			continue
		}
		var p progInsns
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			return nil, summary, fmt.Errorf("bad program record %q: %w", line, err)
		}
		progs = append(progs, p)
	}

	if !sawSummary {
		return nil, summary, fmt.Errorf("probe printed no summary line")
	}
	if len(progs) != summary.Programs {
		return nil, summary, fmt.Errorf("probe reported %d programs but printed %d records",
			summary.Programs, len(progs))
	}
	return progs, summary, nil
}
