package soak

import (
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/test/integration/soak/ctrace"
	"github.com/aws/aws-network-policy-agent/test/integration/soak/driver"
	"github.com/aws/aws-network-policy-agent/test/integration/soak/schedule"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The flag default for the race window is duplicated as a local constant to keep
// config from importing ctrace just for one value. This test guarantees the two
// never drift apart.
func TestCtraceDefaultWindowMatches(t *testing.T) {
	assert.Equal(t, ctrace.DefaultWindow, ctraceDefaultWindow)
}

func TestOverridesFrom_OnlyIncludesSetValues(t *testing.T) {
	r := raw{
		killInterval:  90 * time.Minute,
		probeInterval: 30 * time.Second,
		// the rest left zero -> must be absent so the schedule derives them
	}
	overrides := overridesFrom(r)

	require.Contains(t, overrides, schedule.AgentKill)
	require.Contains(t, overrides, schedule.ProbeSweep)
	assert.Equal(t, 90*time.Minute, overrides[schedule.AgentKill])

	assert.NotContains(t, overrides, schedule.PolicyHotUpdate)
	assert.NotContains(t, overrides, schedule.NamespaceChurn)
	assert.NotContains(t, overrides, schedule.TrendSample)
}

func TestPortReuse_CompletesTarget(t *testing.T) {
	c := &Config{driver: driver.PortReuseConfig{Interval: 200 * time.Millisecond}}
	d := c.PortReuse("10.0.0.5", 8080)
	assert.Equal(t, "10.0.0.5", d.TargetHost)
	assert.Equal(t, 8080, d.TargetPort)
	// The configured interval is preserved when the target is completed.
	assert.Equal(t, 200*time.Millisecond, d.Interval)
}
