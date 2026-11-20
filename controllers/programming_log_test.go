package controllers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProgramIdentifier_FailedPassLogsOneError covers what a failing stage-2 pass writes to the
// agent log. The queue retries a failing identifier with backoff starting at
// programmingRetryBaseDelay, so every error line a pass logs repeats on each retry.
func TestProgramIdentifier_FailedPassLogsOneError(t *testing.T) {
	writeFailed := errors.New("map write failed")
	podIdentifier := identifierOf("logonce-aaa")

	t.Run("network policies", func(t *testing.T) {
		logFile := captureAgentLog(t)
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: "np-log-aaaaa", parent: "np-log",
			pods:    []podRef{localPod("logonce-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}})
		fx.bpf.UpdateEbpfMapsErrFor = map[string]error{podIdentifier: writeFailed}

		err := fx.reconcile("np-log-aaaaa")
		require.ErrorIs(t, err, writeFailed)
		assert.Contains(t, err.Error(), podIdentifier, "controller-runtime logs the returned error too")
		assert.Len(t, errorLinesNaming(t, logFile, podIdentifier), 1)
	})

	t.Run("cluster policies", func(t *testing.T) {
		logFile := captureAgentLog(t)
		fx := newCPEFixture(t)
		fx.setSlices(sliceSpec{name: "cnp-log-aaaaa", parent: "cnp-log", priority: 1,
			pods:    []podRef{localPod("logonce-aaa", "10.1.1.2")},
			ingress: []ruleRef{deny("192.168.90.1/32")}})
		fx.bpf.UpdateClusterPolicyEbpfMapsErrFor = map[string]error{podIdentifier: writeFailed}

		err := fx.reconcile("cnp-log-aaaaa")
		require.ErrorIs(t, err, writeFailed)
		assert.Contains(t, err.Error(), podIdentifier, "controller-runtime logs the returned error too")
		assert.Len(t, errorLinesNaming(t, logFile, podIdentifier), 1)
	})
}

// captureAgentLog points the agent logger at a new file until the test ends.
func captureAgentLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.log")
	logger.New("info", path, logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
	t.Cleanup(func() {
		logger.New(logger.DEFAULT_LOG_LEVEL, logger.DEFAULT_LOG_LOCATION,
			logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
	})
	return path
}

// errorLinesNaming returns the error lines in the log file that mention podIdentifier.
func errorLinesNaming(t *testing.T, path, podIdentifier string) []string {
	t.Helper()
	logger.Sync()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, `"level":"error"`) && strings.Contains(line, podIdentifier) {
			lines = append(lines, line)
		}
	}
	return lines
}
