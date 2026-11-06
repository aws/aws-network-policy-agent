package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Pod-state map keys (the __u32 key of ingress_pod_state_map / egress_pod_state_map)
// and the pod_state.state byte values, mirrored from pkg/ebpf/c/tc.*.bpf.c. Used by
// tests to assert a pod's policy tier is actually programmed into the datapath, not
// just created in the Kubernetes API.
const (
	NetworkPolicyPodStateKey       = 0
	ClusterPolicyPodStateKey       = 1
	PodStatePoliciesApplied  uint8 = 0
	PodStateDefaultAllow     uint8 = 1
	PodStateDefaultDeny      uint8 = 2
)

// ParsePodStateFromMapDump reads the output of
// `aws-eks-na-cli ebpf dump-maps <mapID>` for a pod_state map (a HASH map keyed by a
// __u32 with a single-byte pod_state.state value) and returns the state byte stored
// under the given key. The CLI prints each entry as:
//
//	Key :  1
//	State -  0
//	*******************************
//
// Returns an error if the key is absent so callers can retry while the agent programs it.
func ParsePodStateFromMapDump(output string, key int) (uint8, error) {
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "Key :") {
			continue
		}
		kStr := strings.TrimSpace(strings.TrimPrefix(line, "Key :"))
		k, err := strconv.Atoi(kStr)
		if err != nil {
			return 0, fmt.Errorf("parse pod_state key %q: %w", kStr, err)
		}
		if k != key {
			continue
		}
		if i+1 >= len(lines) {
			return 0, fmt.Errorf("pod_state key %d has no following State line", key)
		}
		stateLine := strings.TrimSpace(lines[i+1])
		if !strings.HasPrefix(stateLine, "State -") {
			return 0, fmt.Errorf("pod_state key %d not followed by State line (got %q)", key, stateLine)
		}
		sStr := strings.TrimSpace(strings.TrimPrefix(stateLine, "State -"))
		s, err := strconv.ParseUint(sStr, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("parse pod_state value %q for key %d: %w", sStr, key, err)
		}
		return uint8(s), nil
	}
	return 0, fmt.Errorf("no pod_state entry for key %d (map not yet programmed)", key)
}

// BuildBPFCheckPod creates a privileged pod that can inspect BPF state on a node
// via chroot into the host filesystem.
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
				Name: "check", Image: "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
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

// Mounted at the host's own path so callers can pass the agent's pin paths as-is.
const bpffsMountPath = "/sys/fs/bpf"

// Not "app": callers sweep by this label, and "app" is reused across the suite.
const BPFFSReaderPodLabelKey = "test.npa/role"
const BPFFSReaderPodLabelValue = "bpffs-reader"

// BuildBPFFSReaderPod runs command to completion on nodeName with the host's
// bpffs mounted read-only, for inspecting pinned BPF objects. Callers read the
// result from the pod log.
//
// Not privileged, unlike BuildBPFCheckPod. CAP_BPF is enough, but it is required
// rather than optional: without it the kernel zeroes xlated_prog_len and the
// other dump-gated fields instead of returning an error, so a caller that drops
// it silently reads zeros.
func BuildBPFFSReaderPod(namespace, nodeName, image string, command []string) *v1.Pod {
	hostPathDir := v1.HostPathDirectory
	allowPrivilegeEscalation := false
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("bpffs-reader-%d", time.Now().UnixNano()), Namespace: namespace,
			Labels: map[string]string{BPFFSReaderPodLabelKey: BPFFSReaderPodLabelValue},
		},
		Spec: v1.PodSpec{
			NodeName: nodeName, RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name: "reader", Image: image, ImagePullPolicy: v1.PullIfNotPresent,
				Command: command,
				SecurityContext: &v1.SecurityContext{
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
					Capabilities: &v1.Capabilities{
						Drop: []v1.Capability{"ALL"},
						Add:  []v1.Capability{"BPF"},
					},
				},
				VolumeMounts: []v1.VolumeMount{
					{Name: "host-bpffs", MountPath: bpffsMountPath, ReadOnly: true},
				},
			}},
			Volumes: []v1.Volume{{
				Name: "host-bpffs",
				VolumeSource: v1.VolumeSource{
					HostPath: &v1.HostPathVolumeSource{Path: bpffsMountPath, Type: &hostPathDir},
				},
			}},
		},
	}
}

// BPFState is the parsed view of `aws-eks-na-cli ebpf loaded-ebpfdata` output.
type BPFState struct {
	ProgIDs    map[string]int // pinPath basename -> prog ID
	MapIDs     map[string]int // "podIdentifier/mapName" -> map ID
	GlobalMaps map[string]int // global map name -> map ID
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
		ProgIDs:    make(map[string]int),
		MapIDs:     make(map[string]int),
		GlobalMaps: make(map[string]int),
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
