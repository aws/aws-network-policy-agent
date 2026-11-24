package logger

import (
	"path/filepath"
	"testing"
)

// BenchmarkFileLoggerParallel logs one Info line per op from parallel goroutines through the
// file writer the agent uses. Run with -cpu 1,2,4,8 to see whether log calls serialize, and
// with -mutexprofile/-blockprofile to see where they wait:
//
//	go test ./pkg/logger/ -run '^$' -bench BenchmarkFileLoggerParallel -cpu 1,2,4,8 -benchmem
func BenchmarkFileLoggerParallel(b *testing.B) {
	b.Cleanup(closeFileWriters)
	l := (&Configuration{
		LogLevel:    "info",
		LogLocation: filepath.Join(b.TempDir(), "network-policy-agent.log"),
		// Large enough that the file does not rotate during the benchmark, so lumberjack's
		// background compression of the rotated file neither competes for CPU nor races
		// the temporary directory's removal.
		LogFileMaxSize:    1 << 20,
		LogFileMaxBackups: 1,
	}).newZapLogger()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Infof("Total no.of clusterPolicy ingressRules %d egressRules %d", 10, 20)
		}
	})
	b.StopTimer()
	_ = l.zapLogger.Sync()
}
