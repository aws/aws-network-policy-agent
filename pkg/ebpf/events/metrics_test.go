package events

import "testing"

// TestDropCounterLabels verifies that the always-on drop counters carry
// {direction, protocol} labels. WithLabelValues panics when the value count
// doesn't match the registration, so a passing test proves the label set.
func TestDropCounterLabels(t *testing.T) {
	// Must not panic.
	dropCountTotal.WithLabelValues("ingress", "TCP").Inc()
	dropBytesTotal.WithLabelValues("egress", "UDP").Add(100)
	dropCountTotal.WithLabelValues("egress", "TCP").Inc()
	dropBytesTotal.WithLabelValues("ingress", "SCTP").Add(500)
}
