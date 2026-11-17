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

	kfuncsErr := checkKfuncs(ctDenyKfuncs)
	if kfuncsErr != nil && required {
		t.Fatalf("kernel lacks the conntrack kfuncs the ct-deny variants need (modprobe nf_conntrack): %v", kfuncsErr)
	}
	families := []struct {
		name, eventsBinary string
		binaries           []string
		ctDenyBinary       string
	}{
		{"v4", EVENTS_BINARY, []string{TC_INGRESS_BINARY, TC_EGRESS_BINARY}, TC_INGRESS_CT_DENY_BINARY},
		{"v6", EVENTS_V6_BINARY, []string{TC_V6_INGRESS_BINARY, TC_V6_EGRESS_BINARY}, TC_V6_INGRESS_CT_DENY_BINARY},
	}

	sdk := goelf.New(goelf.Config{NamespacedMaps: utils.NamespacedBPFMaps})
	// load loads binary and returns how long it took and a func that closes
	// what it opened.
	load := func(t *testing.T, binary, pinPrefix string) (time.Duration, func()) {
		t.Helper()
		start := time.Now()
		progs, maps, err := sdk.LoadBpfFile(filepath.Join(dir, binary), testPinPrefix+pinPrefix)
		elapsed := time.Since(start)
		require.NoError(t, err, "load %s", binary)
		return elapsed, func() {
			for _, p := range progs {
				unix.Close(p.Program.ProgFD)
			}
			for _, m := range maps {
				unix.Close(int(m.MapFD))
			}
		}
	}

	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			// The TC programs reference the global and shared maps, which
			// the agent creates once per node, so they are not timed. Their
			// FDs stay open while the TC objects load, as in the agent: the
			// loader resolves the references through them.
			for j, binary := range []string{fam.eventsBinary, TC_SHARED_BINARY} {
				_, closeFDs := load(t, binary, fmt.Sprintf("LOADTIME%sGLOBAL%d", fam.name, j))
				t.Cleanup(closeFDs)
			}

			binaries := fam.binaries
			if kfuncsErr == nil {
				binaries = append(slices.Clone(binaries), fam.ctDenyBinary)
			} else {
				t.Logf("skipping %s: kernel lacks the conntrack kfuncs: %v", fam.ctDenyBinary, kfuncsErr)
			}
			for _, binary := range binaries {
				t.Run(binary, func(t *testing.T) {
					times := make([]time.Duration, iterations)
					for i := range times {
						var closeFDs func()
						times[i], closeFDs = load(t, binary, fmt.Sprintf("LOADTIME%s%d", fam.name, i))
						closeFDs()
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
