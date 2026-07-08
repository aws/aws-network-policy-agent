// Package soak holds the NPA soak test: a long-running, configurable mixed-traffic
// and churn workload that detects slow or timing-dependent agent failures the
// point-in-time integration suites miss. Its design is documented in DESIGN.md.
//
// This file owns configuration only. The soak is driven by a single duration knob
// (--soak-duration, default 4h); every periodic activity's cadence is derived from
// it by the schedule package, so the same suite is meaningful whether it runs as a
// short CI smoke or a multi-hour pre-release soak.
package soak

import (
	"flag"
	"time"

	"github.com/aws/aws-network-policy-agent/test/integration/soak/driver"
	"github.com/aws/aws-network-policy-agent/test/integration/soak/schedule"
)

// Config is the resolved soak configuration. It is built from flags in init and
// consumed by the suite. Keeping the cadence schedule and the repro-driver config
// as already-validated values means the suite fails at setup, not mid-run, on a
// bad configuration.
type Config struct {
	// Duration is the steady-state soak window, excluding setup and teardown.
	Duration time.Duration

	// NodeCount is how many worker nodes the soak spreads workloads across.
	// Cross-node traffic needs at least two.
	NodeCount int

	// ReconcileInterval mirrors the agent's conntrack-cache-cleanup-period so the
	// schedule can guarantee the run spans enough cleanup cycles for the #462
	// race to be reachable.
	ReconcileInterval time.Duration

	// MemoryGrowthLimit is the maximum allowed growth in the NPA container's
	// working-set memory over the run, post-warmup. Exceeding it fails the soak.
	MemoryGrowthLimit int64 // bytes

	// ProgrammingLatencyLimit is the maximum allowed policy-apply-to-enforced
	// latency observed via probes.
	ProgrammingLatencyLimit time.Duration

	// RaceWindow is the maximum delete->deny gap that counts as the #462 race
	// when scanning agent logs.
	RaceWindow time.Duration

	// Aggressive compresses the #462 repro: shorter reuse interval and, where the
	// run has node access, a lowered kernel TIME_WAIT. It trades fidelity to the
	// customer's exact shape for a faster, denser reproduction.
	Aggressive bool

	// Enable462Guard controls whether the #462 port-reuse driver and log scan are
	// deployed. Default false for Tier 1: the detection code has known defects
	// (ctrace regex matches IPv6 not IPv4; driver timing prevents the race; the
	// behavioral detector cannot fire). Tier 2 work re-enables after fixing those.
	Enable462Guard bool

	// schedule and driver are derived, validated values. They are unexported so
	// callers go through Schedule and PortReuse, which cannot return an
	// unvalidated configuration.
	schedule *schedule.Schedule
	driver   driver.PortReuseConfig
}

// raw holds the flag-bound primitives before they are assembled and validated
// into a Config. Overridable cadences are bound here and folded into the schedule.
type raw struct {
	duration          time.Duration
	nodeCount         int
	reconcileInterval time.Duration
	memoryGrowthMiB   int64
	progLatencyLimit  time.Duration
	raceWindow        time.Duration
	aggressive        bool

	killInterval         time.Duration
	policyUpdateInterval time.Duration
	nsChurnInterval      time.Duration
	probeInterval        time.Duration
	sampleInterval       time.Duration

	reuseInterval  time.Duration
	enable462Guard bool
}

// globalRaw is bound by init and resolved by Load after flag.Parse.
var globalRaw raw

const (
	defaultNodeCount        = 2
	defaultMemoryGrowthMiB  = 50 // the >50 MiB criterion from ORR X-2
	defaultProgLatencyLimit = 10 * time.Second
	mib                     = 1 << 20
)

func init() {
	flag.DurationVar(&globalRaw.duration, "soak-duration", schedule.DefaultDuration,
		"steady-state soak window (excludes setup/teardown); the master knob all cadences derive from")
	flag.IntVar(&globalRaw.nodeCount, "soak-node-count", defaultNodeCount,
		"number of worker nodes to spread soak workloads across (>=2 for cross-node traffic)")
	flag.DurationVar(&globalRaw.reconcileInterval, "soak-reconcile-interval", schedule.DefaultReconcileInterval,
		"agent conntrack-cache-cleanup-period; used to guarantee the run spans enough cleanup cycles for the #462 race")
	flag.Int64Var(&globalRaw.memoryGrowthMiB, "soak-memory-growth-mib", defaultMemoryGrowthMiB,
		"max allowed NPA container working-set growth over the run, in MiB")
	flag.DurationVar(&globalRaw.progLatencyLimit, "soak-programming-latency-limit", defaultProgLatencyLimit,
		"max allowed policy-apply-to-enforced latency observed via probes")
	flag.DurationVar(&globalRaw.raceWindow, "soak-race-window", ctraceDefaultWindow,
		"max conntrack-delete-to-ingress-deny gap that counts as the #462 race")
	flag.BoolVar(&globalRaw.aggressive, "soak-aggressive", false,
		"compress the #462 repro (shorter reuse interval, lower TIME_WAIT where possible)")

	// Per-cadence overrides. Zero means "derive from duration".
	flag.DurationVar(&globalRaw.killInterval, "soak-kill-interval", 0,
		"override agent-kill cadence (default derived as duration/4)")
	flag.DurationVar(&globalRaw.policyUpdateInterval, "soak-policy-update-interval", 0,
		"override policy-hot-update cadence (default derived as duration/20, clamped 1-5m)")
	flag.DurationVar(&globalRaw.nsChurnInterval, "soak-ns-churn-interval", 0,
		"override namespace-churn cadence (default derived as duration/8)")
	flag.DurationVar(&globalRaw.probeInterval, "soak-probe-interval", 0,
		"override probe-sweep cadence (default derived as duration/120, clamped 15s-2m)")
	flag.DurationVar(&globalRaw.sampleInterval, "soak-sample-interval", 0,
		"override trend-sample cadence (default derived as duration/48, clamped 1-5m)")

	flag.DurationVar(&globalRaw.reuseInterval, "soak-reuse-interval", 0,
		"override #462 port-reuse connection interval (default 200ms, or 50ms when --soak-aggressive)")
	flag.BoolVar(&globalRaw.enable462Guard, "soak-enable-462-guard", false,
		"enable the #462 conntrack-race continuous guard (default off for Tier 1; the "+
			"detection code has known defects that produce false greens)")
}

// ctraceDefaultWindow duplicates ctrace.DefaultWindow as a flag default to avoid a
// config->ctrace import purely for a constant; the value is asserted equal in the
// suite's tests.
const ctraceDefaultWindow = 5 * time.Second

// Load assembles globalRaw into a validated Config. It must be called after flags
// are parsed (Ginkgo parses them before the suite runs). harnessTimeout is the
// deadline the test runner will actually enforce (Ginkgo's suite timeout); the
// schedule rejects a duration that cannot finish inside it, so a 4h soak is never
// silently truncated by Ginkgo's 1h default. Pass 0 when no deadline applies.
//
// It returns an error so the suite can fail fast and clearly on an unworkable
// configuration rather than starting a multi-hour run that cannot achieve its
// purpose.
func Load(harnessTimeout time.Duration) (*Config, error) {
	r := globalRaw

	sched, err := schedule.New(schedule.Options{
		Total:             r.duration,
		ReconcileInterval: r.reconcileInterval,
		Timeout:           harnessTimeout,
		Overrides:         overridesFrom(r),
	})
	if err != nil {
		return nil, err
	}

	reuseInterval := r.reuseInterval
	if reuseInterval <= 0 {
		reuseInterval = driver.DefaultInterval
		if r.aggressive {
			reuseInterval = 50 * time.Millisecond
		}
	}

	cfg := &Config{
		Duration:                sched.Total(),
		NodeCount:               r.nodeCount,
		ReconcileInterval:       r.reconcileInterval,
		MemoryGrowthLimit:       r.memoryGrowthMiB * mib,
		ProgrammingLatencyLimit: r.progLatencyLimit,
		RaceWindow:              r.raceWindow,
		Aggressive:              r.aggressive,
		Enable462Guard:          r.enable462Guard,
		schedule:                sched,
		driver: driver.PortReuseConfig{
			// TargetHost/TargetPort are filled in by the suite once the protected
			// server pod exists; Interval is the part configuration controls.
			Interval: reuseInterval,
		},
	}
	return cfg, nil
}

func overridesFrom(r raw) map[schedule.Cadence]time.Duration {
	overrides := make(map[schedule.Cadence]time.Duration)
	if r.killInterval > 0 {
		overrides[schedule.AgentKill] = r.killInterval
	}
	if r.policyUpdateInterval > 0 {
		overrides[schedule.PolicyHotUpdate] = r.policyUpdateInterval
	}
	if r.nsChurnInterval > 0 {
		overrides[schedule.NamespaceChurn] = r.nsChurnInterval
	}
	if r.probeInterval > 0 {
		overrides[schedule.ProbeSweep] = r.probeInterval
	}
	if r.sampleInterval > 0 {
		overrides[schedule.TrendSample] = r.sampleInterval
	}
	return overrides
}

// Schedule returns the resolved cadence schedule.
func (c *Config) Schedule() *schedule.Schedule { return c.schedule }

// PortReuse returns the #462 repro driver config with the target server bound to
// host:port. The interval and aggression were already resolved in Load; this only
// completes the target, which is not known until the protected server pod exists.
func (c *Config) PortReuse(host string, port int) driver.PortReuseConfig {
	d := c.driver
	d.TargetHost = host
	d.TargetPort = port
	return d
}
