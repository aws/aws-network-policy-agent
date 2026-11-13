package events

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/logger"
)

// Non-DENY events produce output only at debug level and only when the scope
// is not deny-only.
func TestConsumeNonDeny(t *testing.T) {
	tests := []struct {
		debug, denyOnly, want bool
	}{
		{debug: true, denyOnly: false, want: true},
		{debug: true, denyOnly: true, want: false},
		{debug: false, denyOnly: false, want: false},
		{debug: false, denyOnly: true, want: false},
	}
	for _, tt := range tests {
		if got := consumeNonDeny(tt.debug, tt.denyOnly); got != tt.want {
			t.Errorf("consumeNonDeny(debug=%v, denyOnly=%v) = %v, want %v", tt.debug, tt.denyOnly, got, tt.want)
		}
	}
}

// ACCEPT events are consumed only when the flow logger writes Debug lines and
// the scope is not deny-only.
func TestAcceptEventsConsumed(t *testing.T) {
	tests := []struct {
		level    string
		denyOnly bool
		want     bool
	}{
		{level: "debug", denyOnly: false, want: true},
		{level: "debug", denyOnly: true, want: false},
		{level: "info", denyOnly: false, want: false},
		{level: "info", denyOnly: true, want: false},
		{level: "warn", denyOnly: false, want: false},
		{level: "error", denyOnly: false, want: false},
	}
	for _, tt := range tests {
		logger.New(tt.level, "stdout", logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
		if got := AcceptEventsConsumed(tt.denyOnly); got != tt.want {
			t.Errorf("AcceptEventsConsumed(level=%s, denyOnly=%v) = %v, want %v", tt.level, tt.denyOnly, got, tt.want)
		}
	}
}
