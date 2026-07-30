package utils

import "time"

const (
	PollIntervalShort = 2 * time.Second

	// Probe timing for polling live connectivity while a network policy converges.
	EnforcementTimeout = 90 * time.Second // wait for policy to be programmed into the datapath
	ProbeTimeout       = 30 * time.Second // probe once enforcement is expected to be active
	StabilityWindow    = 10 * time.Second // window over which a converged verdict must hold
	ProbeInterval      = 3 * time.Second
)
