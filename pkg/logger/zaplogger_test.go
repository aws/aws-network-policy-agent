package logger

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fileLoggers returns an agent logger and a controller-runtime logger configured the way main
// configures them, on one file: the agent's with the given size limit, controller-runtime's
// with the package defaults, as GetControllerRuntimeLogger does.
func fileLoggers(t *testing.T, path string, maxSizeMB int) (*structuredLogger, *zap.Logger) {
	t.Helper()
	t.Cleanup(closeFileWriters)
	agent := (&Configuration{
		LogLevel: "info", LogLocation: path, LogFileMaxSize: maxSizeMB, LogFileMaxBackups: 2,
	}).newZapLogger()
	controllerRuntime := (&Configuration{
		LogLevel: DEFAULT_LOG_LEVEL, LogLocation: path,
		LogFileMaxSize: DEFAULT_LOG_FILE_MAX_SIZE, LogFileMaxBackups: DEFAULT_LOG_FILE_MAX_BACKUPS,
	}).newZapLoggerForControllerRuntime()
	return agent, controllerRuntime
}

func syncLoggers(t *testing.T, agent *structuredLogger, controllerRuntime *zap.Logger) {
	t.Helper()
	require.NoError(t, agent.zapLogger.Sync())
	require.NoError(t, controllerRuntime.Sync())
}

// readLogLines returns the messages in a log file, failing on any line that is not one
// complete JSON entry.
func readLogLines(t *testing.T, path string) []string {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var msgs []string
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		var entry struct {
			Msg string `json:"msg"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &entry), "log line is not one JSON entry: %q", line)
		msgs = append(msgs, entry.Msg)
	}
	return msgs
}

// writeSyscalls reads this process's write(2) count from /proc/self/io.
func writeSyscalls(t *testing.T) int64 {
	t.Helper()
	f, err := os.Open("/proc/self/io")
	if err != nil {
		t.Skip("needs /proc/self/io (Linux)")
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "syscw: "); ok {
			n, err := strconv.ParseInt(value, 10, 64)
			require.NoError(t, err)
			return n
		}
	}
	t.Fatal("no syscw in /proc/self/io")
	return 0
}

// The file writer's lock is held across each write(2), so a write per log line makes every
// goroutine that logs wait for every other goroutine's syscall.
func TestFileLogger_WritesManyLinesPerSyscall(t *testing.T) {
	agent, _ := fileLoggers(t, filepath.Join(t.TempDir(), "npa.log"), DEFAULT_LOG_FILE_MAX_SIZE)
	agent.Info("open the file")
	require.NoError(t, agent.zapLogger.Sync())

	const lines = 20000
	before := writeSyscalls(t)
	for i := 0; i < lines; i++ {
		agent.Infof("Total no.of clusterPolicy ingressRules %d egressRules %d", i, i)
	}
	require.NoError(t, agent.zapLogger.Sync())
	writes := writeSyscalls(t) - before
	t.Logf("%d write syscalls for %d log lines", writes, lines)
	assert.Less(t, writes, int64(lines/50), "%d write syscalls for %d log lines", writes, lines)
}

// main writes the agent's lines and controller-runtime's to the same file. Lines from both
// must stay whole and in the file, from the first line on.
func TestFileLogger_LoggersOnOneFileKeepEachOthersLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "npa.log")
	agent, controllerRuntime := fileLoggers(t, path, DEFAULT_LOG_FILE_MAX_SIZE)

	agent.Info("Starting network policy agent")
	controllerRuntime.Info("Starting EventSource")
	agent.Info("Network Policy is enabled, registering controllers")
	controllerRuntime.Info("Starting workers")
	syncLoggers(t, agent, controllerRuntime)

	assert.Equal(t, []string{
		"Starting network policy agent",
		"Starting EventSource",
		"Network Policy is enabled, registering controllers",
		"Starting workers",
	}, readLogLines(t, path))
}

// Once the file rotates, both loggers must write the new file. A logger that kept writing the
// rotated backup would lose its lines when the backup is compressed and removed. The file
// rotates at the agent's size limit, since main creates the agent's logger first.
func TestFileLogger_LoggersOnOneFileFollowRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "npa.log")
	agent, controllerRuntime := fileLoggers(t, path, 1)
	// lumberjack compresses the rotated file in the background; let it finish before the
	// temporary directory is removed.
	t.Cleanup(func() {
		assert.Eventually(t, func() bool {
			backups, _ := filepath.Glob(filepath.Join(dir, "npa-*.log"))
			return len(backups) == 0
		}, 10*time.Second, 10*time.Millisecond, "the rotated file was not compressed")
	})
	agent.Info("Starting network policy agent")
	controllerRuntime.Info("Starting EventSource")

	// 1.2 MB, past the agent's 1 MB limit.
	line := strings.Repeat("x", 1024)
	for i := 0; i < 1200; i++ {
		agent.Info(line)
	}
	controllerRuntime.Info("Reconciler error")
	agent.Info("Processing Policy Endpoint")
	syncLoggers(t, agent, controllerRuntime)

	msgs := readLogLines(t, path)
	assert.Less(t, len(msgs), 1200, "the file did not rotate")
	assert.Equal(t, []string{"Reconciler error", "Processing Policy Endpoint"}, msgs[len(msgs)-2:])
}

// A failed write, from a full disk say, loses the lines it carried and no others.
func TestFileLogger_WritesResumeAfterAFailedWrite(t *testing.T) {
	dir := t.TempDir()
	// The log directory's path is taken by a file, so the log file cannot be created.
	blocker := filepath.Join(dir, "aws-routed-eni")
	require.NoError(t, os.WriteFile(blocker, nil, 0o644))
	path := filepath.Join(blocker, "npa.log")
	agent, _ := fileLoggers(t, path, DEFAULT_LOG_FILE_MAX_SIZE)

	agent.Info("written while the file cannot be created")
	_ = agent.zapLogger.Sync()
	require.NoError(t, os.Remove(blocker))

	agent.Info("written once the file can be created")
	require.NoError(t, agent.zapLogger.Sync())
	assert.Equal(t, []string{"written once the file can be created"}, readLogLines(t, path))
}

const exitHelperEnv = "NPA_LOGGER_EXIT_HELPER"

// runExitHelper re-runs this test binary to log through a file logger and end the process
// the way main can: os.Exit after an error, or a panic that unwinds main's deferred Sync.
func runExitHelper(t *testing.T, mode string) (exitCode int, msgs []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "npa.log")
	cmd := exec.Command(os.Args[0], "-test.run=^TestExitHelper$")
	cmd.Env = append(os.Environ(), exitHelperEnv+"="+mode+":"+path)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "helper did not exit with an error: %v\n%s", err, out)
	return exitErr.ExitCode(), readLogLines(t, path)
}

func TestExitHelper(t *testing.T) {
	mode, path, ok := strings.Cut(os.Getenv(exitHelperEnv), ":")
	if !ok {
		t.Skip("runs only as runExitHelper's subprocess")
	}
	l := New("info", path, DEFAULT_LOG_FILE_MAX_SIZE, DEFAULT_LOG_FILE_MAX_BACKUPS)
	switch mode {
	case "error-exit":
		l.Infof("Trying to establish GRPC connection to ipamd")
		l.Errorf("unable to create controller %s", "PolicyEndpoints")
		os.Exit(1)
	case "panic":
		defer Sync()
		l.Infof("Network Policy is enabled, registering controllers...")
		panic("lo.Must: imds unavailable")
	}
}

// main logs an error and calls os.Exit, which runs no deferred calls. The error, and the lines
// logged before it, must be in the file when the process ends.
func TestFileLogger_ErrorIsWrittenBeforeExit(t *testing.T) {
	code, msgs := runExitHelper(t, "error-exit")
	assert.Equal(t, 1, code)
	assert.Equal(t, []string{
		"Trying to establish GRPC connection to ipamd",
		"unable to create controller PolicyEndpoints",
	}, msgs)
}

// A panic in main, such as a failed lo.Must, runs main's deferred Sync before the process ends.
func TestSync_WritesLinesBeforeAPanicEndsTheProcess(t *testing.T) {
	code, msgs := runExitHelper(t, "panic")
	assert.Equal(t, 2, code)
	assert.Equal(t, []string{"Network Policy is enabled, registering controllers..."}, msgs)
}
