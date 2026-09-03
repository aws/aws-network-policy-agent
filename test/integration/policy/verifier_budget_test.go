package policy

// Measures how much of the kernel's BPF verifier budget the agent's TC programs
// consume. The verifier gives up after BPF_COMPLEXITY_LIMIT_INSNS processed
// instructions and fails the load with E2BIG.
//
// The number read here is bpf_prog_info.verified_insns, the verifier's processed
// count, not the program's static instruction count. It is a property of the
// kernel that did the verifying, so this has to run on a node.

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

// BPF_COMPLEXITY_LIMIT_INSNS from include/linux/bpf.h. Userspace cannot query
// it. It was 131072 before kernel 5.2 and 1,000,000 since, and verified_insns
// only exists from 5.16, so every kernel this test can run on uses this value.
const complexityLimitInsns = 1_000_000

// Older kernels return a bpf_prog_info that stops before verified_insns.
const minKernelMajorForVerifiedInsns = 5
const minKernelMinorForVerifiedInsns = 16

// Only fires once a program is close to failing to load, so treat a failure as
// already urgent rather than as an early warning.
const defaultBudgetFraction = 0.9

const budgetFractionEnvVar = "NPA_VERIFIER_BUDGET_FRACTION"

// Not --test-image-registry: that holds the suite's e2e images, and the probe
// just needs a python3 interpreter.
const probeImageEnvVar = "NPA_VERIFIER_PROBE_IMAGE"
const defaultProbeImage = "public.ecr.aws/amazonlinux/amazonlinux:2023"

// Must stay well under pinReconcileTimeout. A pod stuck pulling its image is
// Pending, which CreateAndWaitTillPodIsCompleted waits out in full, so equal
// budgets would spend the whole retry loop on one attempt.
const probeTimeout = 75 * time.Second

const pinReconcileTimeout = 4 * time.Minute
const pinReconcileInterval = 20 * time.Second

// Prints one JSON object per pinned program, then a summary object.
//
// bpftool is not used because the version AL2023 ships (v7.1.0) does not print
// verified_insns. The offsets are byte offsets into struct bpf_prog_info from
// include/uapi/linux/bpf.h; they are safe to hardcode because the struct only
// grows at the tail.
const insnProbeScript = `
import ctypes, errno, json, os, platform, struct, sys

BPF_OBJ_GET = 7
BPF_OBJ_GET_INFO_BY_FD = 15

OFF_ID = 4
OFF_XLATED_PROG_LEN = 20
OFF_NAME, NAME_LEN = 64, 16
OFF_VERIFIED_INSNS = 216
# The kernel writes min(info_len, its own struct size) and reports the count
# back, so a struct ending before verified_insns is detectable.
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
    # Oversized so the kernel reports how much of its struct it wrote.
    info = ctypes.create_string_buffer(512)
    # struct { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; }
    attr = struct.pack("IIQ", fd, len(info), ctypes.addressof(info))
    ret, err, attr_out = bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    if ret != 0:
        raise OSError(err, "BPF_OBJ_GET_INFO_BY_FD failed: " + os.strerror(err))
    return info.raw, struct.unpack_from("I", attr_out, 4)[0]

results, errors, vanished, short = [], [], [], []
for pin_dir in sys.argv[1:]:
    # The agent creates this directory with its first pin, so a missing one just
    # means nothing is loaded yet.
    if not os.path.isdir(pin_dir):
        continue
    for entry in sorted(os.listdir(pin_dir)):
        path = os.path.join(pin_dir, entry)
        try:
            fd = prog_fd_from_pin(path)
        except OSError as e:
            # A terminating pod can unpin between listdir and open.
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

// A pin whose bpf_prog_info ended before verified_insns. InfoLen tells the
// causes apart: near sizeof(bpf_prog_info) means an old kernel, much smaller
// means the pin was not a program.
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

	// Ginkgo runs BeforeEach in declaration order, so keeping this first makes a
	// bad env var fail before any resource is created.
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
		// The delete helpers poll until their context is done, and the suite's ctx
		// never expires, so give teardown its own deadline.
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

		// runInsnProbe deletes its own pod, but its defer does not run if Ginkgo
		// abandons the spec's goroutine. Sweep on a separate deadline so a slow
		// delete above cannot starve it.
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

		// Pins are per pod identifier, so the directory also holds programs for
		// unrelated pods on this node. Name this spec's own so the check below
		// cannot be satisfied by someone else's.
		podID := utils.GetPodIdentifier(budgetServerName, namespace)
		wantPins := []string{
			filepath.Base(utils.GetBPFPinPathFromPodIdentifier(podID, "ingress")),
			filepath.Base(utils.GetBPFPinPathFromPodIdentifier(podID, "egress")),
		}

		var progs []progInsns
		var summary probeSummary
		var vanished []string
		By("Reading bpf_prog_info for every pinned program on the node", func() {
			Eventually(func(g Gomega) {
				progs, summary = runInsnProbe(g, nodeName)
				vanished = append(vanished, summary.Vanished...)

				// Retrying cannot fix either of these, and leaving them until
				// after the loop would let the pin check fail first and blame the
				// agent for not pinning.
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

		// A zero in any of these means the probe is reading the wrong offsets, or
		// lost CAP_BPF, which makes the kernel zero xlated_prog_len while still
		// returning verified_insns.
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

		// prog_name is empty for every program: the agent's load path does not set
		// one, so pin filename is the only identifier.
		for _, p := range progs {
			pct := 100 * float64(p.VerifiedInsns) / float64(complexityLimitInsns)
			line := fmt.Sprintf("%s (id %d, name %q): %d verified insns, %.1f%% of the %d limit, %d xlated insns",
				p.PinName, p.ProgID, p.ProgName, p.VerifiedInsns, pct, complexityLimitInsns, p.XlatedInsns)
			AddReportEntry("verified-insns", line)
			fmt.Fprintln(GinkgoWriter, line)

			Expect(p.VerifiedInsns).To(BeNumerically("<=", budget),
				"%s consumed %d of the %d processed-instruction limit on kernel %s (%.1f%%), over the %.0f%% budget. "+
					"It still loads, but a kernel with less aggressive pruning or one more unrolled comparison "+
					"will fail with E2BIG. Reduce verifier work in the policy loops, or raise "+
					budgetFractionEnvVar+" deliberately.",
				p.PinName, p.VerifiedInsns, complexityLimitInsns, kernelVersion, pct, 100*fraction)
		}
	})
})

// Safe to call repeatedly: each call names its pod uniquely and deletes it.
func runInsnProbe(g Gomega, nodeName string) ([]progInsns, probeSummary) {
	probePod := fwutils.BuildBPFFSReaderPod(namespace, nodeName, probeImage(),
		[]string{"python3", "-c", insnProbeScript, utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY})

	waitCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	_, runErr := fw.PodManager.CreateAndWaitTillPodIsCompleted(waitCtx, probePod)

	// Fetch the log before asserting, so a python traceback survives the failure.
	// PodLogs returns a placeholder string on error, so prefer logErr, which
	// carries the reason the container produced no log at all.
	out, logErr := fw.PodManager.PodLogs(namespace, probePod.Name)
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

// Handles versions like "6.1.177" and "5.10.245-240.1.amzn2". An unparseable
// version returns true, so an unfamiliar format fails loudly instead of skipping.
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

// A missing summary line means the probe died partway, so the records before it
// cannot be assumed complete.
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
