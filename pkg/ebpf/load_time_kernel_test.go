package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestProbeLoadTimeKernel times loading each TC object the agent loads for a
// new pod, on the host kernel, so a probe C change (more verifier work) or an
// SDK change shows its load-time cost in the test output. Each load uses a new
// pin prefix, as a new podIdentifier does, so the loader creates fresh maps
// instead of reusing pinned ones.
//
// It needs root and the built objects (see requireBPFKernelTests). The
// ceiling only catches a gross regression on a shared CI runner; the logged
// p50/p99 are the numbers to compare across changes.
//
//	BPF_LOAD_TIME_ITERATIONS  loads per object (default 20)
//	BPF_LOAD_TIME_MAX_P99     ceiling for each object's p99 (default 2s)
func TestProbeLoadTimeKernel(t *testing.T) {
	dir, required := requireBPFKernelTests(t)
	iterations := envInt(t, "BPF_LOAD_TIME_ITERATIONS", 20)
	maxP99 := envDuration(t, "BPF_LOAD_TIME_MAX_P99", 2*time.Second)

	loader := newProbeLoader(t, dir, required)
	for _, fam := range loadTimeFamilies {
		t.Run(fam.name, func(t *testing.T) {
			for _, binary := range loader.prepare(t, fam) {
				t.Run(binary, func(t *testing.T) {
					times := make([]time.Duration, iterations)
					for i := range times {
						times[i] = loader.timeLoad(t, binary, fmt.Sprintf("LOADTIME%s%d", fam.name, i))
					}
					slices.Sort(times)
					p50, p99 := nearestRank(times, 0.50), nearestRank(times, 0.99)
					t.Logf("%s load time over %d loads: p50=%v p99=%v max=%v",
						binary, iterations, p50, p99, times[len(times)-1])
					require.LessOrEqual(t, p99, maxP99, "%s p99 load time", binary)
				})
			}
		})
	}
}

// BenchmarkProbeLoad reports the time to load each per-pod TC object, as
// Go benchmark output (ns/op), so `go test -bench ProbeLoad` results can be
// compared across changes with benchstat. Like TestProbeLoadTimeKernel it
// needs root and the built objects, and skips otherwise; CI does not run
// benchmarks.
func BenchmarkProbeLoad(b *testing.B) {
	dir, required := requireBPFKernelTests(b)
	loader := newProbeLoader(b, dir, required)
	for _, fam := range loadTimeFamilies {
		b.Run(fam.name, func(b *testing.B) {
			for _, binary := range loader.prepare(b, fam) {
				b.Run(binary, func(b *testing.B) {
					i := 0
					for b.Loop() {
						b.StopTimer()
						prefix := fmt.Sprintf("LOADBENCH%s%d", fam.name, i)
						i++
						b.StartTimer()
						loader.timeLoad(b, binary, prefix)
					}
				})
			}
		})
	}
}

// loadTimeFamily is one address family's per-pod TC objects, with the events
// binary whose global maps they reference.
type loadTimeFamily struct {
	name, eventsBinary string
	binaries           []string
	ctDenyBinary       string
}

var loadTimeFamilies = []loadTimeFamily{
	{"v4", EVENTS_BINARY, []string{TC_INGRESS_BINARY, TC_EGRESS_BINARY}, TC_INGRESS_CT_DENY_BINARY},
	{"v6", EVENTS_V6_BINARY, []string{TC_V6_INGRESS_BINARY, TC_V6_EGRESS_BINARY}, TC_V6_INGRESS_CT_DENY_BINARY},
}

// probeLoader loads TC objects the way the agent does for a new pod.
type probeLoader struct {
	dir       string
	sdk       goelf.BpfSDKClient
	kfuncsErr error
}

func newProbeLoader(tb testing.TB, dir string, required bool) *probeLoader {
	tb.Helper()
	kfuncsErr := checkKfuncs(ctDenyKfuncs)
	if kfuncsErr != nil && required {
		tb.Fatalf("kernel lacks the conntrack kfuncs the ct-deny variants need (modprobe nf_conntrack): %v", kfuncsErr)
	}
	return &probeLoader{dir: dir, sdk: goelf.New(goelf.Config{NamespacedMaps: utils.NamespacedBPFMaps}), kfuncsErr: kfuncsErr}
}

// prepare loads the family's events and shared objects, which the agent
// creates once per node and so are not timed, and returns the per-pod objects
// to time. Their FDs stay open until tb ends, as in the agent: the loader
// resolves the TC objects' references to their maps through them.
func (l *probeLoader) prepare(tb testing.TB, fam loadTimeFamily) []string {
	tb.Helper()
	for j, binary := range []string{fam.eventsBinary, TC_SHARED_BINARY} {
		closeFDs := l.load(tb, binary, fmt.Sprintf("LOADTIME%sGLOBAL%d", fam.name, j))
		tb.Cleanup(closeFDs)
	}
	if l.kfuncsErr != nil {
		tb.Logf("skipping %s: kernel lacks the conntrack kfuncs: %v", fam.ctDenyBinary, l.kfuncsErr)
		return fam.binaries
	}
	return append(slices.Clone(fam.binaries), fam.ctDenyBinary)
}

// timeLoad loads binary under a new pin prefix, as for a new pod identifier,
// closes what it opened, and returns how long the load took.
func (l *probeLoader) timeLoad(tb testing.TB, binary, pinPrefix string) time.Duration {
	tb.Helper()
	start := time.Now()
	closeFDs := l.load(tb, binary, pinPrefix)
	elapsed := time.Since(start)
	closeFDs()
	return elapsed
}

// load loads binary and returns a func that closes what it opened.
func (l *probeLoader) load(tb testing.TB, binary, pinPrefix string) func() {
	tb.Helper()
	progs, maps, err := l.sdk.LoadBpfFile(filepath.Join(l.dir, binary), testPinPrefix+pinPrefix)
	require.NoError(tb, err, "load %s", binary)
	return func() {
		for _, p := range progs {
			unix.Close(p.Program.ProgFD)
		}
		for _, m := range maps {
			unix.Close(int(m.MapFD))
		}
	}
}

// nearestRank returns the p-th percentile of sorted by the nearest-rank
// method: the smallest value with at least p of the values at or below it.
func nearestRank(sorted []time.Duration, p float64) time.Duration {
	rank := int(float64(len(sorted))*p+0.999999) - 1
	return sorted[max(0, min(rank, len(sorted)-1))]
}

func TestNearestRank(t *testing.T) {
	ms := func(v ...int) []time.Duration {
		out := make([]time.Duration, len(v))
		for i, x := range v {
			out[i] = time.Duration(x) * time.Millisecond
		}
		return out
	}
	twenty := ms(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
	for _, tc := range []struct {
		name   string
		sorted []time.Duration
		p      float64
		want   time.Duration
	}{
		{"one value", ms(7), 0.99, 7 * time.Millisecond},
		{"median of twenty", twenty, 0.50, 10 * time.Millisecond},
		{"p99 of twenty is the max", twenty, 0.99, 20 * time.Millisecond},
		{"p0 is the min", twenty, 0, 1 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, nearestRank(tc.sorted, tc.p))
		})
	}
}

func envInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	require.NoError(t, err, "%s", name)
	require.Positive(t, n, "%s", name)
	return n
}

func envDuration(t *testing.T, name string, def time.Duration) time.Duration {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	require.NoError(t, err, "%s", name)
	return d
}
