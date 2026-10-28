package config

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestParsePolicyEventLogsScope(t *testing.T) {
	tests := []struct {
		raw          string
		wantDenyOnly bool
		wantValid    bool
	}{
		{"all", false, true},
		{"", false, true},
		{"  ALL ", false, true},
		{"deny", true, true},
		{"DENY", true, true},
		{" Deny\t", true, true},
		{"deny-only", false, false},
		{"accept", false, false},
		{"derived", false, false},
		{"bogus", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			denyOnly, valid := ParsePolicyEventLogsScope(tt.raw)
			assert.Equal(t, tt.wantDenyOnly, denyOnly)
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}

func TestPolicyEventLogsScopeFlagDefault(t *testing.T) {
	var cfg ControllerConfig
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	cfg.BindFlags(fs)
	assert.NoError(t, fs.Parse(nil))
	assert.Equal(t, "all", cfg.PolicyEventLogsScope)
	denyOnly, valid := ParsePolicyEventLogsScope(cfg.PolicyEventLogsScope)
	assert.False(t, denyOnly, "default must keep ACCEPT and DENY events")
	assert.True(t, valid)

	assert.NoError(t, fs.Parse([]string{"--policy-event-logs-scope=deny"}))
	denyOnly, valid = ParsePolicyEventLogsScope(cfg.PolicyEventLogsScope)
	assert.True(t, denyOnly)
	assert.True(t, valid)
}
