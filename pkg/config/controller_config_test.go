package config

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnableTCPResetOnDenyFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"off by default", nil, false},
		{"enabled", []string{"--enable-tcp-reset-on-deny=true"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := pflag.NewFlagSet("agent", pflag.ContinueOnError)
			var cfg ControllerConfig
			cfg.BindFlags(fs)
			require.NoError(t, fs.Parse(tt.args))
			assert.Equal(t, tt.want, cfg.EnableTCPResetOnDeny)
		})
	}
}
