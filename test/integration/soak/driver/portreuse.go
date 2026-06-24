// Package driver builds the in-pod traffic generators the soak loop runs. Its
// centerpiece is the port-reuse driver that reproduces the conntrack-cleanup race
// in github.com/aws/aws-network-policy-agent#462.
//
// The race needs source-port reuse at a short interval against a pod whose ingress
// is policy-controlled, so that return traffic depends on the agent's eBPF
// conntrack entry. This package constructs the shell command that drives exactly
// that pattern; the command generation is pure and unit-tested so the repro recipe
// is verifiable without a cluster. Execution is the suite's job.
//
// The technique — pinning the client's source port and looping short-lived
// connections — follows kubernetes/test/e2e/network/conntrack.go (`nc -p <fixed>`)
// and cilium/test/k8s/service_helpers.go (`curl --local-port`, cycling a small
// port set), adapted to NPA's return-traffic-via-conntrack failure mode.
package driver

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PortReuseConfig parameterizes the #462 repro driver. The defaults reproduce the
// customer's reported shape; the knobs exist so a run can trade fidelity for a
// faster, more aggressive repro (more ports in flight, shorter interval).
type PortReuseConfig struct {
	// TargetHost and TargetPort are the policy-protected server the client
	// repeatedly connects to. The server must sit behind an ingress NetworkPolicy
	// that does not explicitly allow the return path, so it relies on NPA's
	// conntrack map (this is condition 1 of the race in #462).
	TargetHost string
	TargetPort int

	// SourcePorts is the small set of fixed local ports the client cycles
	// through. Reusing a fixed port forces the same 5-tuple to recur, which is
	// what lands a reused connection inside the agent's cleanup delete window.
	// Cycling a few ports (rather than one) raises the odds of overlapping the
	// window on several flows at once.
	SourcePorts []int

	// Interval is the gap between connection attempts. It must be short relative
	// to the kernel's TIME_WAIT (nf_conntrack_tcp_timeout_time_wait, default
	// 120s) so ports are reused while the eBPF entry may still be mid-cleanup.
	Interval time.Duration

	// ConnectTimeout bounds each individual connection attempt so a single
	// dropped return packet (the bug firing) does not stall the whole loop.
	ConnectTimeout time.Duration
}

// Default values for the repro driver.
const (
	// DefaultInterval keeps connections frequent enough to reuse ports well
	// inside TIME_WAIT, while staying cheap enough to run for hours.
	DefaultInterval = 200 * time.Millisecond
	// DefaultConnectTimeout is short: a return-traffic drop should fail fast and
	// be retried, not block the generator.
	DefaultConnectTimeout = 2 * time.Second
)

// DefaultSourcePorts cycles three high, fixed ports — the same shape Cilium's
// service tests use to provoke source-port collisions.
var DefaultSourcePorts = []int{60000, 61000, 62000}

// withDefaults returns a copy of c with unset fields filled in.
func (c PortReuseConfig) withDefaults() PortReuseConfig {
	if len(c.SourcePorts) == 0 {
		c.SourcePorts = DefaultSourcePorts
	}
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
	return c
}

// Validate reports why the config cannot drive the repro, so a misconfigured run
// fails at construction rather than silently generating traffic that never
// reproduces the race.
func (c PortReuseConfig) Validate() error {
	if c.TargetHost == "" {
		return fmt.Errorf("port-reuse driver: TargetHost is required")
	}
	if c.TargetPort <= 0 || c.TargetPort > 65535 {
		return fmt.Errorf("port-reuse driver: TargetPort %d out of range", c.TargetPort)
	}
	cfg := c.withDefaults()
	for _, p := range cfg.SourcePorts {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("port-reuse driver: source port %d out of range", p)
		}
	}
	// A reuse interval at or beyond TIME_WAIT defeats the purpose: the kernel
	// entry would expire between reuses, so the same-5-tuple-during-cleanup race
	// cannot occur. Guard the common misconfiguration.
	if cfg.Interval >= timeWaitFloor {
		return fmt.Errorf(
			"port-reuse driver: interval %s is too long to reuse ports within TIME_WAIT (~%s); "+
				"shorten it or the race cannot reproduce", cfg.Interval, timeWaitFloor)
	}
	return nil
}

// timeWaitFloor is a conservative lower bound on the kernel TCP TIME_WAIT timeout.
// Reuse intervals must stay well under this for the race to be reachable.
const timeWaitFloor = 30 * time.Second

// Command renders the bash command (for `sh -c`) that runs the port-reuse loop
// from inside a client pod. The loop, per cycle, walks the fixed source-port set
// and opens a short-lived connection from each, pausing Interval between attempts.
//
// It uses `curl --local-port` so a clean exit means the connection (and its
// policy-permitted return traffic) succeeded, and a non-zero exit means it was
// dropped — the signal the long-lived disruption detector keys on if this driver
// is wrapped in a liveness-bound pod. The loop runs until the pod is deleted.
//
// busybox nc is the fallback when curl is unavailable; we standardize on curl
// because its `--local-port` is reliable across the test image and its exit codes
// are unambiguous.
func (c PortReuseConfig) Command() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	cfg := c.withDefaults()

	ports := make([]string, len(cfg.SourcePorts))
	for i, p := range cfg.SourcePorts {
		ports[i] = fmt.Sprintf("%d", p)
	}

	// Sub-second sleeps need a fractional value; render millis as seconds with
	// enough precision that a 200ms interval becomes "0.2", not "0".
	sleepSecs := strconv.FormatFloat(cfg.Interval.Seconds(), 'f', -1, 64)
	connectSecs := int(cfg.ConnectTimeout.Round(time.Second).Seconds())
	if connectSecs < 1 {
		connectSecs = 1
	}

	// The script is intentionally simple and dependency-light. `set -u` catches
	// an unset variable; we deliberately do NOT `set -e` because a dropped
	// connection (curl non-zero) is an expected, countable event, not a reason to
	// exit the generator.
	script := fmt.Sprintf(`set -u
target=%q
port=%d
connect_timeout=%d
sleep_secs=%s
src_ports="%s"
echo "port-reuse driver: target=${target}:${port} src_ports=[${src_ports}] interval=${sleep_secs}s"
while true; do
  for sp in ${src_ports}; do
    if curl -s -o /dev/null --max-time ${connect_timeout} --local-port ${sp} "http://${target}:${port}/"; then
      :
    else
      echo "DROP local-port=${sp} -> ${target}:${port}"
    fi
    sleep ${sleep_secs}
  done
done`,
		cfg.TargetHost, cfg.TargetPort, connectSecs,
		sleepSecs,
		strings.Join(ports, " "),
	)
	return script, nil
}
