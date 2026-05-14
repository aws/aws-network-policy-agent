package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// writeIpam writes a minimal ipam.json with the given (podName, podNamespace) pairs.
func writeIpam(t *testing.T, dir string, pods [][2]string) string {
	t.Helper()
	allocs := ""
	for i, p := range pods {
		if i > 0 {
			allocs += ","
		}
		allocs += `{"metadata":{"k8sPodName":"` + p[0] + `","k8sPodNamespace":"` + p[1] + `"}}`
	}
	path := filepath.Join(dir, "ipam.json")
	body := `{"version":"vpc-cni-ipam/1","allocations":[` + allocs + `]}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write ipam: %v", err)
	}
	return path
}

func TestMigrateLegacyPinsFromCNIState_HappyPath(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{
		{"deny-me-0", "ns1"},
		{"web-frontend-0", "my-namespace"},
		// Namespace containing "-" — boundary must be the prefix/ns join,
		// the "-" inside the namespace must be PRESERVED.
		{"aws-node-xyz", "kube-system"},
	})

	legacyFiles := []struct{ dir, name string }{
		{progsDir, "deny-me-ns1_" + utils.TC_INGRESS_PROG},
		{progsDir, "deny-me-ns1_" + utils.TC_EGRESS_PROG},
		{mapsDir, "deny-me-ns1_" + utils.TC_INGRESS_MAP},
		{mapsDir, "deny-me-ns1_" + utils.TC_EGRESS_POD_STATE_MAP},
		{progsDir, "web-frontend-my-namespace_" + utils.TC_INGRESS_PROG},
		{mapsDir, "web-frontend-my-namespace_" + utils.TC_CLUSTER_POLICY_INGRESS_MAP},
		{progsDir, "aws-node-kube-system_" + utils.TC_INGRESS_PROG},
		{mapsDir, "aws-node-kube-system_" + utils.TC_INGRESS_MAP},
	}
	for _, f := range legacyFiles {
		assert.NoError(t, os.WriteFile(f.dir+f.name, []byte("x"), 0644))
	}

	if err := migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, filepath.Join(t.TempDir(), ".npa_format_v2")); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	expectations := map[string]bool{
		// deny-me/ns1
		progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG:        false,
		progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG:        true,
		progsDir + "deny-me@ns1_" + utils.TC_EGRESS_PROG:         true,
		mapsDir + "deny-me@ns1_" + utils.TC_INGRESS_MAP:          true,
		mapsDir + "deny-me@ns1_" + utils.TC_EGRESS_POD_STATE_MAP: true,
		// web-frontend/my-namespace
		progsDir + "web-frontend@my-namespace_" + utils.TC_INGRESS_PROG:              true,
		mapsDir + "web-frontend@my-namespace_" + utils.TC_CLUSTER_POLICY_INGRESS_MAP: true,
		progsDir + "web-frontend-my-namespace_" + utils.TC_INGRESS_PROG:              false,
		// aws-node/kube-system — boundary must become "@" but "kube-system" stays intact
		progsDir + "aws-node-kube-system_" + utils.TC_INGRESS_PROG: false,
		progsDir + "aws-node@kube-system_" + utils.TC_INGRESS_PROG: true,
		mapsDir + "aws-node@kube-system_" + utils.TC_INGRESS_MAP:   true,
		// Anti-assertion: must NOT corrupt "kube-system" by changing its internal "-"
		progsDir + "aws-node@kube_system_" + utils.TC_INGRESS_PROG: false,
		mapsDir + "aws-node@kube_system_" + utils.TC_INGRESS_MAP:   false,
	}
	for path, shouldExist := range expectations {
		_, err := os.Stat(path)
		if shouldExist {
			assert.NoError(t, err, "expected %s to exist", path)
		} else {
			assert.True(t, os.IsNotExist(err), "expected %s to be gone", path)
		}
	}
}

// When two pods share a legacy identifier (the cross-namespace bypass case),
// the legacy pin is renamed to the first pod's new identifier (sorted by name).
// The other pod will get a fresh per-pod pin via the reconcile loop.
func TestMigrateLegacyPinsFromCNIState_CollisionRenamesToFirstPod(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{
		{"deny-me-x", "ns1"}, // legacy: deny-me-ns1, new: deny-me@ns1
		{"deny-x", "me-ns1"}, // legacy: deny-me-ns1, new: deny@me-ns1
	})

	legacyPin := progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(legacyPin, []byte("x"), 0644))

	if err := migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, filepath.Join(t.TempDir(), ".npa_format_v2")); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Legacy pin no longer exists — it was renamed.
	_, err := os.Stat(legacyPin)
	assert.True(t, os.IsNotExist(err), "legacy pin must be renamed away")
	// First pod by name is "deny-me-x" → new id "deny-me@ns1" inherits the pin.
	_, err = os.Stat(progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG)
	assert.NoError(t, err, "first pod's new pin must exist after rename")
	// Second pod's new pin must NOT have been created by the migration; the
	// reconcile loop is responsible for creating it.
	_, err = os.Stat(progsDir + "deny@me-ns1_" + utils.TC_INGRESS_PROG)
	assert.True(t, os.IsNotExist(err), "non-inheriting pod's new pin must not be created by migration")
}

func TestMigrateLegacyPinsFromCNIState_MissingIpamIsNoOp(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := filepath.Join(t.TempDir(), "does-not-exist.json")

	keep := progsDir + "untouched-ns_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(keep, []byte("x"), 0644))

	if err := migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, filepath.Join(t.TempDir(), ".npa_format_v2")); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_, err := os.Stat(keep)
	assert.NoError(t, err)
}

func TestMigrateLegacyPinsFromCNIState_OrphanLeftAlone(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{
		{"alive-pod-0", "ns1"},
	})
	orphan := progsDir + "ghost-ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(orphan, []byte("x"), 0644))

	if err := migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, filepath.Join(t.TempDir(), ".npa_format_v2")); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_, err := os.Stat(orphan)
	assert.NoError(t, err, "orphan pin not owned by any local pod must be preserved")
}

// Second call must be a no-op once the marker file exists.
func TestMigrateLegacyPinsFromCNIState_RunsOnlyOnce(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	markerDir := t.TempDir()
	markerPath := filepath.Join(markerDir, ".npa_format_v2")
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"deny-me-0", "ns1"}})

	legacyPin := progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(legacyPin, []byte("x"), 0644))

	// First run: migration happens, marker is written
	assert.NoError(t, migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath))
	_, err := os.Stat(markerPath)
	assert.NoError(t, err, "marker must be written after first run")
	_, err = os.Stat(progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG)
	assert.NoError(t, err, "first run must rename the pin")

	// Seed a fresh legacy pin to prove the second run does NOT touch it
	stale := progsDir + "another-ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(stale, []byte("x"), 0644))

	assert.NoError(t, migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath))
	_, err = os.Stat(stale)
	assert.NoError(t, err, "second run must skip migration once marker is present")
}

// If a rename fails, the marker must NOT be written so the next restart retries.
// All pins are still attempted (no short-circuit on first failure).
func TestMigrateLegacyPinsFromCNIState_NoMarkerOnRenameFail(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	markerDir := t.TempDir()
	markerPath := filepath.Join(markerDir, ".npa_format_v2")
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"deny-me-0", "ns1"}})

	legacyPin := progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(legacyPin, []byte("x"), 0644))

	// Block rename by making the destination a non-empty directory
	// (os.Rename cannot overwrite a non-empty directory).
	destBlocker := progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.MkdirAll(destBlocker+"/subdir", 0755))

	err := migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath)
	assert.Error(t, err, "migration must report failure when renames fail")
	assert.Contains(t, err.Error(), "incomplete")

	_, statErr := os.Stat(markerPath)
	assert.True(t, os.IsNotExist(statErr), "marker must NOT be written when renames fail")

	// Legacy pin must still be present (was not successfully renamed)
	_, statErr = os.Stat(legacyPin)
	assert.NoError(t, statErr, "legacy pin must be preserved on failed rename")
}

func TestLegacyGetPodIdentifier(t *testing.T) {
	cases := []struct {
		name, ns, want string
	}{
		{"deny-me-0", "ns1", "deny-me-ns1"},
		{"deny-0", "me-ns1", "deny-me-ns1"},
		{"web-frontend-0", "my-namespace", "web-frontend-my-namespace"},
		{"aws-node-xyz", "kube-system", "aws-node-kube-system"},
		{"my.pod-x", "ns1", "my_pod-ns1"},
		{"foo", "bar", "foo-bar"},
	}
	for _, c := range cases {
		got := utils.LegacyGetPodIdentifier(c.name, c.ns)
		assert.Equal(t, c.want, got, "%s / %s", c.name, c.ns)
	}
}
