package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	npautils "github.com/aws/aws-network-policy-agent/pkg/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HostVethName returns the host veth a pod's TC programs attach to, using the
// VPC CNI naming convention. It delegates to the production
// utils.BuildHostVethName so the test and the agent share one definition of the
// convention; the pure (no local link check) variant is used because the test
// driver runs off-node and only needs the name to pass into an on-node command.
//
// prefix is normally "eni" for regular pods and "vlan" for branch-ENI pods;
// interfaceIndex 0 is the primary interface.
func HostVethName(namespace, podName, prefix string, interfaceIndex int) string {
	return npautils.BuildHostVethName(podName, namespace, prefix, interfaceIndex)
}

// tcFilterProgIDRe matches the "id <N>" that `tc filter show` prints for a BPF
// filter, e.g. "filter ... bpf ... id 1446 tag ...".
var tcFilterProgIDRe = regexp.MustCompile(`\bid\s+(\d+)\b`)

// ParseTCFilterProgIDs extracts the BPF program IDs attached at a TC hook from
// the output of `tc filter show dev <veth> {ingress|egress}`. A hook with no BPF
// filter yields an empty slice. Multiple IDs are returned in first-seen order.
func ParseTCFilterProgIDs(output string) []int {
	var ids []int
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "bpf") {
			continue
		}
		if m := tcFilterProgIDRe.FindStringSubmatch(line); m != nil {
			if id, err := strconv.Atoi(m[1]); err == nil {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// BuildBPFCheckPod creates a privileged pod that can inspect BPF state on a node
// via chroot into the host filesystem.
//
// Uses the netshoot debug image so the pod ships its own network tooling
// (curl, wget, iproute2/tc, bpftool, jq) rather than relying on the host or a
// runtime package install. Host BPF state is still read via `chroot /host`;
// self-contained tools (e.g. curl for scraping the agent metrics endpoint) run
// directly in the pod.
func BuildBPFCheckPod(namespace, nodeName string) *v1.Pod {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("bpf-check-%d", time.Now().UnixNano()), Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName, HostPID: true, HostNetwork: true, RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name: "check", Image: "nicolaka/netshoot:latest",
				Command:         []string{"sleep", "300"},
				SecurityContext: &v1.SecurityContext{Privileged: &privileged},
				VolumeMounts:    []v1.VolumeMount{{Name: "host-root", MountPath: "/host"}},
			}},
			Volumes: []v1.Volume{{
				Name:         "host-root",
				VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/", Type: &hostPathDir}},
			}},
		},
	}
}

// BPFState is the parsed view of `aws-eks-na-cli ebpf loaded-ebpfdata` output.
type BPFState struct {
	ProgIDs        map[string]int    // pinPath basename -> prog ID
	MapIDs         map[string]int    // "podIdentifier/mapName" -> map ID
	GlobalMaps     map[string]int    // global map name -> map ID
	PodIdentifiers map[string]string // pinPath basename -> parsed pod identifier
}

// ParseLoadedEBPFData parses the output of `aws-eks-na-cli ebpf loaded-ebpfdata`.
// Returns an error on malformed input (unparseable ID, missing Map ID after Map Name)
// so callers can fail fast instead of silently treating zero IDs as legitimate.
//
// Format:
//
//	PinPath:  /sys/fs/bpf/globals/aws/programs/podid_handle_ingress
//	Pod Identifier : podid  Direction : ingress
//	Prog ID:  1446
//	Associated Maps ->
//	Map Name:  ingress_map
//	Map ID:  517
//	Map Name:  aws_conntrack_map
//	Map ID:  514
//	===...===
func ParseLoadedEBPFData(output string) (BPFState, error) {
	state := BPFState{
		ProgIDs:        make(map[string]int),
		MapIDs:         make(map[string]int),
		GlobalMaps:     make(map[string]int),
		PodIdentifiers: make(map[string]string),
	}

	var currentPinName, currentPodID string
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.HasPrefix(line, "PinPath:") {
			pinPath := strings.TrimSpace(strings.TrimPrefix(line, "PinPath:"))
			segments := strings.Split(pinPath, "/")
			currentPinName = segments[len(segments)-1]
		}

		if strings.HasPrefix(line, "Pod Identifier :") {
			parts := strings.Split(line, "Direction")
			if len(parts) > 0 {
				currentPodID = strings.TrimSpace(strings.TrimPrefix(parts[0], "Pod Identifier :"))
				// Record the parser-produced identifier against the pin it belongs
				// to. currentPinName was set by the preceding "PinPath:" line.
				if currentPinName != "" {
					state.PodIdentifiers[currentPinName] = currentPodID
				}
			}
		}

		if strings.HasPrefix(line, "Prog ID:") {
			idStr := strings.TrimSpace(strings.TrimPrefix(line, "Prog ID:"))
			id, err := strconv.Atoi(idStr)
			if err != nil {
				return state, fmt.Errorf("parse Prog ID %q: %w", idStr, err)
			}
			if currentPinName != "" {
				state.ProgIDs[currentPinName] = id
			}
		}

		if strings.HasPrefix(line, "Map Name:") {
			mapName := strings.TrimSpace(strings.TrimPrefix(line, "Map Name:"))
			if i+1 >= len(lines) {
				return state, fmt.Errorf("Map Name %q has no following line", mapName)
			}
			nextLine := strings.TrimSpace(lines[i+1])
			if !strings.HasPrefix(nextLine, "Map ID:") {
				return state, fmt.Errorf("Map Name %q not followed by Map ID (got %q)", mapName, nextLine)
			}
			idStr := strings.TrimSpace(strings.TrimPrefix(nextLine, "Map ID:"))
			id, err := strconv.Atoi(idStr)
			if err != nil {
				return state, fmt.Errorf("parse Map ID %q for %q: %w", idStr, mapName, err)
			}
			// CLI sometimes emits "Map Name:" with an empty value for older pinned
			// programs whose name metadata wasn't recorded. Skip these — we have
			// no key to track them under.
			if mapName != "" {
				if isGlobalMap(mapName) {
					state.GlobalMaps[mapName] = id
				} else if currentPodID != "" {
					state.MapIDs[currentPodID+"/"+mapName] = id
				}
			}
			i++
		}
	}
	return state, nil
}

func isGlobalMap(name string) bool {
	return name == "aws_conntrack_map" || name == "policy_events"
}
