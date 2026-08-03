package version

import "fmt"

var (
	GitVersion     = "unknown"
	BuildDate      = "unknown"
	EbpfSDKVersion = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (built: %s, ebpf-sdk: %s)", GitVersion, BuildDate, EbpfSDKVersion)
}
