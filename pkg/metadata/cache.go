package metadata

// PodMetadata holds Kubernetes metadata for a Pod IP.
type PodMetadata struct {
	PodName      string
	Namespace    string
	WorkloadKind string
	WorkloadName string
}

// LookupByIP returns metadata for a given IP.
// Currently returns nil as a placeholder.
func LookupByIP(ip string) *PodMetadata {
	return nil
}
