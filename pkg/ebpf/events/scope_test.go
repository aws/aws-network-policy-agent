package events

import "testing"

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
