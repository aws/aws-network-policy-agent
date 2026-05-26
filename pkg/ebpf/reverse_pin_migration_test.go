package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

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

func TestMigrateReversePins_HappyPath(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	markerDir := t.TempDir()
	v2Marker := filepath.Join(markerDir, ".npa_format_v2")

	ipamPath := writeIpam(t, t.TempDir(), [][2]string{
		{"deny-me-0", "ns1"},
		{"web-frontend-0", "my-namespace"},
		{"aws-node-xyz", "kube-system"},
	})

	assert.NoError(t, os.WriteFile(v2Marker, []byte("v2\n"), 0644))

	atFiles := []struct{ dir, name string }{
		{progsDir, "deny-me@ns1_" + utils.TC_INGRESS_PROG},
		{progsDir, "deny-me@ns1_" + utils.TC_EGRESS_PROG},
		{mapsDir, "deny-me@ns1_" + utils.TC_INGRESS_MAP},
		{mapsDir, "deny-me@ns1_" + utils.TC_EGRESS_POD_STATE_MAP},
		{progsDir, "web-frontend@my-namespace_" + utils.TC_INGRESS_PROG},
		{mapsDir, "web-frontend@my-namespace_" + utils.TC_CLUSTER_POLICY_INGRESS_MAP},
		{progsDir, "aws-node@kube-system_" + utils.TC_INGRESS_PROG},
		{mapsDir, "aws-node@kube-system_" + utils.TC_INGRESS_MAP},
	}
	for _, f := range atFiles {
		assert.NoError(t, os.WriteFile(f.dir+f.name, []byte("x"), 0644))
	}

	err := migrateReversePinsFromCNIState(progsDir, mapsDir, ipamPath, v2Marker)
	assert.NoError(t, err)

	expectations := map[string]bool{
		progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG:                            false,
		progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG:                            true,
		progsDir + "deny-me-ns1_" + utils.TC_EGRESS_PROG:                             true,
		mapsDir + "deny-me-ns1_" + utils.TC_INGRESS_MAP:                              true,
		mapsDir + "deny-me-ns1_" + utils.TC_EGRESS_POD_STATE_MAP:                     true,
		progsDir + "web-frontend@my-namespace_" + utils.TC_INGRESS_PROG:              false,
		progsDir + "web-frontend-my-namespace_" + utils.TC_INGRESS_PROG:              true,
		mapsDir + "web-frontend@my-namespace_" + utils.TC_CLUSTER_POLICY_INGRESS_MAP: false,
		mapsDir + "web-frontend-my-namespace_" + utils.TC_CLUSTER_POLICY_INGRESS_MAP: true,
		progsDir + "aws-node@kube-system_" + utils.TC_INGRESS_PROG:                   false,
		progsDir + "aws-node-kube-system_" + utils.TC_INGRESS_PROG:                   true,
		mapsDir + "aws-node@kube-system_" + utils.TC_INGRESS_MAP:                     false,
		mapsDir + "aws-node-kube-system_" + utils.TC_INGRESS_MAP:                     true,
	}
	for path, shouldExist := range expectations {
		_, err := os.Stat(path)
		if shouldExist {
			assert.NoError(t, err, "expected %s to exist", path)
		} else {
			assert.True(t, os.IsNotExist(err), "expected %s to be gone", path)
		}
	}

	_, err = os.Stat(v2Marker)
	assert.True(t, os.IsNotExist(err), "v2 marker must be removed after reverse migration")
}

func TestMigrateReversePins_NoV2MarkerIsNoOp(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	markerDir := t.TempDir()
	v2Marker := filepath.Join(markerDir, ".npa_format_v2")
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"deny-me-0", "ns1"}})

	keep := progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(keep, []byte("x"), 0644))

	err := migrateReversePinsFromCNIState(progsDir, mapsDir, ipamPath, v2Marker)
	assert.NoError(t, err)

	_, err = os.Stat(keep)
	assert.NoError(t, err, "pin file must be untouched when no v2 marker exists")
}

func TestMigrateReversePins_IdempotentAfterV2MarkerRemoved(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	markerDir := t.TempDir()
	v2Marker := filepath.Join(markerDir, ".npa_format_v2")
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"deny-me-0", "ns1"}})

	assert.NoError(t, os.WriteFile(v2Marker, []byte("v2\n"), 0644))

	pin := progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(pin, []byte("x"), 0644))

	assert.NoError(t, migrateReversePinsFromCNIState(progsDir, mapsDir, ipamPath, v2Marker))
	_, err := os.Stat(progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG)
	assert.NoError(t, err, "first run must reverse the pin")
	_, err = os.Stat(v2Marker)
	assert.True(t, os.IsNotExist(err), "v2 marker must be gone after first run")

	fresh := progsDir + "another@ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(fresh, []byte("x"), 0644))

	assert.NoError(t, migrateReversePinsFromCNIState(progsDir, mapsDir, ipamPath, v2Marker))
	_, err = os.Stat(fresh)
	assert.NoError(t, err, "second run must not process pins since v2 marker is absent")
}

func TestMigrateReversePins_DoesNotOverwriteExistingLegacyPins(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	markerDir := t.TempDir()
	v2Marker := filepath.Join(markerDir, ".npa_format_v2")
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"deny-me-0", "ns1"}})

	assert.NoError(t, os.WriteFile(v2Marker, []byte("v2\n"), 0644))

	orphan := progsDir + "deny-me@ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(orphan, []byte("stale-data"), 0644))

	active := progsDir + "deny-me-ns1_" + utils.TC_INGRESS_PROG
	assert.NoError(t, os.WriteFile(active, []byte("current-rules"), 0644))

	assert.NoError(t, migrateReversePinsFromCNIState(progsDir, mapsDir, ipamPath, v2Marker))

	_, err := os.Stat(orphan)
	assert.True(t, os.IsNotExist(err), "orphan @ pin must be removed")

	content, err := os.ReadFile(active)
	assert.NoError(t, err)
	assert.Equal(t, "current-rules", string(content), "active - pin must not be overwritten")
}
