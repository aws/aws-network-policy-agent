package ebpf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

const cniIpamStatePath = "/var/run/aws-node/ipam.json"
const formatV2MarkerPath = "/var/run/aws-node/.npa_format_v2"

type ipamAllocation struct {
	Metadata struct {
		K8sPodName      string `json:"k8sPodName"`
		K8sPodNamespace string `json:"k8sPodNamespace"`
	} `json:"metadata"`
}

type ipamStateFile struct {
	Version     string           `json:"version"`
	Allocations []ipamAllocation `json:"allocations"`
}

// v2GetPodIdentifier computes the "@"-format identifier that the forward
// migration (PR #576) produces. Self-contained so this branch has no
// dependency on the forward-fix branch.
func v2GetPodIdentifier(podName, podNamespace string) string {
	if strings.Contains(podName, ".") {
		podName = strings.Replace(podName, ".", "-", -1)
	}
	podIdentifierPrefix := podName
	if strings.Contains(podName, "-") {
		tmpName := strings.Split(podName, "-")
		podIdentifierPrefix = strings.Join(tmpName[:len(tmpName)-1], "-")
	}
	return podIdentifierPrefix + "@" + podNamespace
}

// legacyGetPodIdentifier computes the legacy "-"-format identifier (same as
// the current GetPodIdentifier on main). Self-contained so the reverse
// migration logic doesn't depend on the public function's signature.
func legacyGetPodIdentifier(podName, podNamespace string) string {
	if strings.Contains(podName, ".") {
		podName = strings.Replace(podName, ".", "_", -1)
	}
	podIdentifierPrefix := podName
	if strings.Contains(podName, "-") {
		tmpName := strings.Split(podName, "-")
		podIdentifierPrefix = strings.Join(tmpName[:len(tmpName)-1], "-")
	}
	return podIdentifierPrefix + "-" + podNamespace
}

// migrateReversePinsFromCNIState renames per-pod bpffs pin files from the
// new "@" separator format back to the legacy "-" format. This enables a
// clean downgrade to a pre-fix NPA version without workload restart.
//
// Only runs if the forward migration marker (.npa_format_v2) is present.
// The v2 marker is the sole idempotency guard: once removed at the end,
// subsequent calls are no-ops.
func migrateReversePinsFromCNIState(progsDir, mapsDir, ipamPath, v2MarkerPath string) error {
	if _, err := os.Stat(v2MarkerPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("checking v2 marker %s: %w", v2MarkerPath, err)
	}

	raw, err := os.ReadFile(ipamPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read CNI ipam state %s: %w", ipamPath, err)
	}

	var state ipamStateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("parse CNI ipam state %s: %w", ipamPath, err)
	}

	type migration struct {
		newID    string
		legacyID string
		ns       string
		name     string
	}
	seen := map[string]bool{}
	var migrations []migration
	for _, a := range state.Allocations {
		if a.Metadata.K8sPodName == "" || a.Metadata.K8sPodNamespace == "" {
			continue
		}
		v2ID := v2GetPodIdentifier(a.Metadata.K8sPodName, a.Metadata.K8sPodNamespace)
		if seen[v2ID] {
			continue
		}
		seen[v2ID] = true
		legacyID := legacyGetPodIdentifier(a.Metadata.K8sPodName, a.Metadata.K8sPodNamespace)
		if v2ID == legacyID {
			continue
		}
		migrations = append(migrations, migration{
			newID:    v2ID,
			legacyID: legacyID,
			ns:       a.Metadata.K8sPodNamespace,
			name:     a.Metadata.K8sPodName,
		})
	}

	for _, m := range migrations {
		if cleaned := reverseRenamePinFamily(progsDir, mapsDir, m.newID, m.legacyID); cleaned > 0 {
			log().Infof("reverse-migrated %d bpffs pin file(s) for %s/%s: %s -> %s",
				cleaned, m.ns, m.name, m.newID, m.legacyID)
		}
	}

	if err := os.Remove(v2MarkerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log().Warnf("reverse migration: failed to remove v2 marker %s: %v", v2MarkerPath, err)
	}
	log().Infof("reverse pin migration complete; v2 marker removed at %s", v2MarkerPath)
	return nil
}

func reverseRenamePinFamily(progsDir, mapsDir, srcID, dstID string) int {
	cleaned := 0
	for _, dir := range []string{"ingress", "egress"} {
		progName := utils.TC_INGRESS_PROG
		if dir == "egress" {
			progName = utils.TC_EGRESS_PROG
		}
		if reverseRenamePinIfExists(progsDir+srcID+"_"+progName, progsDir+dstID+"_"+progName) {
			cleaned++
		}
	}
	for _, mapName := range []string{
		utils.TC_INGRESS_MAP,
		utils.TC_EGRESS_MAP,
		utils.TC_CLUSTER_POLICY_INGRESS_MAP,
		utils.TC_CLUSTER_POLICY_EGRESS_MAP,
		utils.TC_INGRESS_POD_STATE_MAP,
		utils.TC_EGRESS_POD_STATE_MAP,
	} {
		if reverseRenamePinIfExists(mapsDir+srcID+"_"+mapName, mapsDir+dstID+"_"+mapName) {
			cleaned++
		}
	}
	return cleaned
}

// reverseRenamePinIfExists renames src → dst, but if dst already exists
// (the pre-fix agent created it with current rules), it removes the orphan
// src instead to avoid overwriting active state.
func reverseRenamePinIfExists(src, dst string) bool {
	if _, err := os.Stat(src); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log().Warnf("reverse pin migration: stat %s: %v", src, err)
		}
		return false
	}
	if _, err := os.Stat(dst); err == nil {
		if err := os.Remove(src); err != nil {
			log().Warnf("reverse pin migration: remove orphan %s: %v", src, err)
		}
		return true
	}
	if err := os.Rename(src, dst); err != nil {
		log().Warnf("reverse pin migration: rename %s -> %s: %v", src, dst, err)
		return false
	}
	return true
}
