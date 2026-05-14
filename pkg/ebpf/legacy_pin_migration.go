package ebpf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

// cniIpamStatePath is VPC CNI's per-pod allocation checkpoint; already on a
// path the NPA container mounts.
const cniIpamStatePath = "/var/run/aws-node/ipam.json"

// formatV2MarkerPath is the sentinel file written after a successful one-shot
// legacy-format migration. Its presence makes the migration a no-op on every
// subsequent agent restart.
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

// migrateLegacyPinsFromCNIState renames per-pod bpffs pin files from the
// legacy "-" separator format to the new "_" format. Runs once per node;
// the markerPath sentinel makes it a no-op on subsequent restarts.
func migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath string) error {
	if _, err := os.Stat(markerPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking migration marker %s: %w", markerPath, err)
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

	byLegacyID := map[string][]ipamAllocation{}
	for _, a := range state.Allocations {
		if a.Metadata.K8sPodName == "" || a.Metadata.K8sPodNamespace == "" {
			continue
		}
		legacyID := utils.LegacyGetPodIdentifier(a.Metadata.K8sPodName, a.Metadata.K8sPodNamespace)
		byLegacyID[legacyID] = append(byLegacyID[legacyID], a)
	}

	var totalFailed int
	for legacyID, pods := range byLegacyID {
		// Sort by pod name so the choice of inheriting pod is deterministic.
		// For multi-replica workloads all pods produce the same new ID, so
		// order is irrelevant. For true cross-namespace collisions the first
		// pod's pin gets renamed; the other pods will get fresh per-pod pins
		// via the reconcile loop's normal attach path.
		sort.Slice(pods, func(i, j int) bool {
			return pods[i].Metadata.K8sPodName < pods[j].Metadata.K8sPodName
		})
		p := pods[0]
		newID := utils.GetPodIdentifier(p.Metadata.K8sPodName, p.Metadata.K8sPodNamespace)

		if len(pods) > 1 {
			log().Infof("legacy pin %s shared by %d local pods; inheriting to first pod %s/%s (%s); other pods get fresh pins via reconcile",
				legacyID, len(pods), p.Metadata.K8sPodNamespace, p.Metadata.K8sPodName, newID)
		}
		renamed, failed := renamePinFamily(progsDir, mapsDir, legacyID, newID)
		totalFailed += failed
		if renamed > 0 {
			log().Infof("migrated %d bpffs pin file(s) for %s/%s: %s -> %s",
				renamed, p.Metadata.K8sPodNamespace, p.Metadata.K8sPodName, legacyID, newID)
		}
	}

	if totalFailed > 0 {
		return fmt.Errorf("legacy pin migration incomplete: %d rename(s) failed; will retry on next restart", totalFailed)
	}

	if err := os.MkdirAll(filepath.Dir(markerPath), 0755); err != nil {
		return fmt.Errorf("ensure marker dir for %s: %w", markerPath, err)
	}
	if err := os.WriteFile(markerPath, []byte("v2\n"), 0644); err != nil {
		return fmt.Errorf("write migration marker %s: %w", markerPath, err)
	}
	log().Infof("legacy pin migration complete; marker written at %s", markerPath)
	return nil
}

func renamePinFamily(progsDir, mapsDir, legacyID, newID string) (renamed int, failed int) {
	for _, dir := range []string{"ingress", "egress"} {
		progName := utils.TC_INGRESS_PROG
		if dir == "egress" {
			progName = utils.TC_EGRESS_PROG
		}
		switch renamePinIfExists(progsDir+legacyID+"_"+progName, progsDir+newID+"_"+progName) {
		case renameOK:
			renamed++
		case renameFailed:
			failed++
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
		switch renamePinIfExists(mapsDir+legacyID+"_"+mapName, mapsDir+newID+"_"+mapName) {
		case renameOK:
			renamed++
		case renameFailed:
			failed++
		}
	}
	return renamed, failed
}

type renameResult int

const (
	renameSkipped renameResult = iota // source does not exist
	renameOK                          // rename succeeded
	renameFailed                      // source exists but rename failed
)

func renamePinIfExists(src, dst string) renameResult {
	if _, err := os.Stat(src); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log().Warnf("legacy pin migration: stat %s: %v", src, err)
			return renameFailed
		}
		return renameSkipped
	}
	if err := os.Rename(src, dst); err != nil {
		log().Warnf("legacy pin migration: rename %s -> %s: %v", src, dst, err)
		return renameFailed
	}
	return renameOK
}
