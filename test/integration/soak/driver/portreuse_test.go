package driver

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommand_EncodesReproRecipe(t *testing.T) {
	cfg := PortReuseConfig{
		TargetHost:  "10.0.0.5",
		TargetPort:  80,
		SourcePorts: []int{60000, 61000, 62000},
		Interval:    200 * time.Millisecond,
	}
	cmd, err := cfg.Command()
	require.NoError(t, err)

	// The fixed source ports must be pinned via --local-port: this is what forces
	// the same 5-tuple to recur and is the heart of the #462 repro.
	assert.Contains(t, cmd, "--local-port")
	assert.Contains(t, cmd, "60000 61000 62000")

	// A sub-second interval must render as a fraction, not truncate to 0 (which
	// would busy-loop and change the timing characteristics of the repro).
	assert.Contains(t, cmd, "sleep_secs=0.2")
	assert.NotContains(t, cmd, "sleep_secs=0\n")

	// A dropped connection must be reported, not fatal — the generator has to keep
	// running for hours through transient drops.
	assert.Contains(t, cmd, "DROP local-port=")
	assert.NotContains(t, cmd, "set -e")
}

func TestCommand_AppliesDefaults(t *testing.T) {
	cmd, err := PortReuseConfig{TargetHost: "svc", TargetPort: 8080}.Command()
	require.NoError(t, err)
	assert.Contains(t, cmd, "60000 61000 62000") // DefaultSourcePorts
	assert.Contains(t, cmd, "sleep_secs=0.2")    // DefaultInterval
}

func TestValidate_RequiresTarget(t *testing.T) {
	err := PortReuseConfig{TargetPort: 80}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TargetHost")
}

func TestValidate_RejectsBadPorts(t *testing.T) {
	tests := []struct {
		name string
		cfg  PortReuseConfig
	}{
		{"target port zero", PortReuseConfig{TargetHost: "h", TargetPort: 0}},
		{"target port too high", PortReuseConfig{TargetHost: "h", TargetPort: 70000}},
		{"source port out of range", PortReuseConfig{TargetHost: "h", TargetPort: 80, SourcePorts: []int{99999}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.cfg.Validate())
		})
	}
}

func TestValidate_RejectsIntervalBeyondTimeWait(t *testing.T) {
	// An interval at/above the TIME_WAIT floor means ports expire between reuses,
	// so the race cannot reproduce — must be rejected with a clear reason.
	cfg := PortReuseConfig{
		TargetHost: "h",
		TargetPort: 80,
		Interval:   30 * time.Second,
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TIME_WAIT")
}

func TestValidate_AcceptsAggressiveInterval(t *testing.T) {
	cfg := PortReuseConfig{
		TargetHost: "h",
		TargetPort: 80,
		Interval:   50 * time.Millisecond,
	}
	assert.NoError(t, cfg.Validate())
}

func TestCommand_ConnectTimeoutFloorsAtOneSecond(t *testing.T) {
	// A sub-second connect timeout would render as 0 for curl --max-time, which
	// curl treats as "no timeout" — the opposite of intent. It must floor to 1s.
	cfg := PortReuseConfig{
		TargetHost:     "h",
		TargetPort:     80,
		ConnectTimeout: 100 * time.Millisecond,
	}
	cmd, err := cfg.Command()
	require.NoError(t, err)
	assert.Contains(t, cmd, "connect_timeout=1")
}

func TestCommand_TargetIsShellQuoted(t *testing.T) {
	// The target is interpolated into a shell script; %q quoting guards against a
	// hostile or malformed host string breaking out of the assignment.
	cfg := PortReuseConfig{TargetHost: `h"; rm -rf /`, TargetPort: 80}
	cmd, err := cfg.Command()
	require.NoError(t, err)
	// The dangerous payload must be inside a quoted literal, not bare.
	assert.NotContains(t, cmd, "target=h\"; rm -rf /\n")
	assert.Contains(t, cmd, `target="h\"; rm -rf /"`)
}

func TestCommand_CyclesSinglePort(t *testing.T) {
	cfg := PortReuseConfig{
		TargetHost:  "h",
		TargetPort:  80,
		SourcePorts: []int{55555},
	}
	cmd, err := cfg.Command()
	require.NoError(t, err)
	assert.Contains(t, cmd, `src_ports="55555"`)
	// Loop body still walks the (single-element) set.
	assert.Contains(t, cmd, "for sp in ${src_ports}")
}

func TestCommand_LoopRunsForever(t *testing.T) {
	cmd, err := PortReuseConfig{TargetHost: "h", TargetPort: 80}.Command()
	require.NoError(t, err)
	assert.Contains(t, cmd, "while true; do")
	assert.True(t, strings.Count(cmd, "sleep ${sleep_secs}") >= 1)
}
