// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package logger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	// fileBufferSize is how many bytes of log lines a log file's writer holds before it writes
	// them to the file in one write(2).
	fileBufferSize = 64 * 1024
	// fileFlushInterval is how often a log file's writer writes out the lines it holds. With
	// fileBufferSize it bounds the lines lost when the process ends without an error log or a
	// Sync, as on SIGKILL or a panic outside main.
	fileFlushInterval = 100 * time.Millisecond
)

var (
	fileWritersMu sync.Mutex
	// fileWriters holds one writer per log file. Every logger writing a file shares its
	// writer, so all their lines go through one buffer and one lumberjack.Logger, which
	// tracks the file's size and rotates it. A second lumberjack.Logger on the same file
	// would write at its own offset, over the other's lines, and would keep writing the
	// rotated backup, which is then compressed and removed.
	fileWriters = map[string]*fileWriter{}
)

type structuredLogger struct {
	zapLogger *zap.SugaredLogger
}

// Configuration stores the config for the logger
type Configuration struct {
	LogLevel          string
	LogLocation       string
	LogFileMaxSize    int
	LogFileMaxBackups int
}

// getZapLevel converts log level string to zapcore.Level
func getZapLevel(inputLogLevel string) zapcore.Level {
	lvl := strings.ToLower(inputLogLevel)

	switch lvl {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.DebugLevel
	}
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
}

// buildZapCore creates the common zapcore.Core used by all loggers
func (logConfig *Configuration) buildZapCore() zapcore.Core {
	var cores []zapcore.Core

	logLevel := getZapLevel(logConfig.LogLevel)

	writer := getLogFilePath(logConfig.LogLocation, logConfig.LogFileMaxSize, logConfig.LogFileMaxBackups)

	core := zapcore.NewCore(getEncoder(), writer, logLevel)
	if fw, ok := writer.(*fileWriter); ok {
		core = zapcore.RegisterHooks(core, fw.syncOnError)
	}
	cores = append(cores, core)

	return zapcore.NewTee(cores...)
}

func (logConfig *Configuration) newZapLogger() *structuredLogger { //Logger {
	logger := zap.New(logConfig.buildZapCore(),
		zap.AddCaller(),
		zap.AddCallerSkip(2),
	)

	sugar := logger.Sugar()
	return &structuredLogger{
		zapLogger: sugar,
	}
}

// newZapLoggerForControllerRuntime creates a zap logger for controller-runtime
// without AddCallerSkip since zapr handles caller skip internally
func (logConfig *Configuration) newZapLoggerForControllerRuntime() *zap.Logger {
	return zap.New(logConfig.buildZapCore(), zap.AddCaller())
}

// getLogFilePath returns the writer
func getLogFilePath(logFilePath string, logFileMaxSize int, logFileMaxBackups int) zapcore.WriteSyncer {
	var writer zapcore.WriteSyncer

	if logFilePath == "" {
		writer = zapcore.Lock(os.Stderr)
	} else if strings.ToLower(logFilePath) != "stdout" {
		writer = getLogWriter(logFilePath, logFileMaxSize, logFileMaxBackups)
	} else {
		writer = zapcore.Lock(os.Stdout)
	}

	return writer
}

// getLogWriter returns the writer for logFilePath, creating it on the first call for that
// file. The size and backup limits of that first call apply to every logger writing the file.
func getLogWriter(logFilePath string, logFileMaxSize int, logFileMaxBackups int) zapcore.WriteSyncer {
	key := filepath.Clean(logFilePath)
	fileWritersMu.Lock()
	defer fileWritersMu.Unlock()
	if fw, ok := fileWriters[key]; ok {
		return fw
	}
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    logFileMaxSize,
		MaxBackups: logFileMaxBackups,
		MaxAge:     30,
		Compress:   true,
	}
	fw := &fileWriter{
		BufferedWriteSyncer: &zapcore.BufferedWriteSyncer{
			WS:            zapcore.AddSync(reportingWriter{lumberJackLogger}),
			Size:          fileBufferSize,
			FlushInterval: fileFlushInterval,
		},
		file: lumberJackLogger,
	}
	fileWriters[key] = fw
	return fw
}

// fileWriter buffers log lines for one rotating log file. A log call copies its line into the
// buffer; the buffer is written to the file when it fills, every fileFlushInterval, after an
// entry at ErrorLevel or above, and on Sync.
type fileWriter struct {
	*zapcore.BufferedWriteSyncer
	file *lumberjack.Logger
}

// syncOnError writes out the buffer after an entry at ErrorLevel or above. main logs an
// error before each os.Exit, which skips deferred calls and stops the flush goroutine, so
// this keeps the error and the lines before it.
func (fw *fileWriter) syncOnError(entry zapcore.Entry) error {
	if entry.Level < zapcore.ErrorLevel {
		return nil
	}
	return fw.Sync()
}

// reportingWriter writes to the log file and reports a failed write on stderr instead of
// returning it. The buffer in front of it accepts no more lines once a write returns an
// error, so returning one would stop all logging after a transient failure such as a full
// disk. A failed write loses the lines it carried.
type reportingWriter struct {
	file *lumberjack.Logger
}

func (w reportingWriter) Write(p []byte) (int, error) {
	if _, err := w.file.Write(p); err != nil {
		fmt.Fprintf(os.Stderr, "%v write error: %v\n", time.Now(), err)
	}
	return len(p), nil
}

// Sync writes out the lines buffered for every log file.
func Sync() error {
	fileWritersMu.Lock()
	defer fileWritersMu.Unlock()
	var err error
	for _, fw := range fileWriters {
		err = errors.Join(err, fw.Sync())
	}
	return err
}

func (l *structuredLogger) Debugf(format string, args ...interface{}) {
	l.zapLogger.Debugf(format, args...)
}

func (l *structuredLogger) Debug(msg string) {
	l.zapLogger.Desugar().Debug(msg)
}

func (l *structuredLogger) Infof(format string, args ...interface{}) {
	l.zapLogger.Infof(format, args...)
}

func (l *structuredLogger) Info(msg string) {
	l.zapLogger.Desugar().Info(msg)
}

func (l *structuredLogger) Warnf(format string, args ...interface{}) {
	l.zapLogger.Warnf(format, args...)
}

func (l *structuredLogger) Warn(msg string) {
	l.zapLogger.Desugar().Warn(msg)
}

func (l *structuredLogger) Errorf(format string, args ...interface{}) {
	l.zapLogger.Errorf(format, args...)
}

func (l *structuredLogger) Error(msg string) {
	l.zapLogger.Desugar().Error(msg)
}

func (l *structuredLogger) Fatalf(format string, args ...interface{}) {
	l.zapLogger.Fatalf(format, args...)
}

func (l *structuredLogger) Panicf(format string, args ...interface{}) {
	l.zapLogger.Panicf(format, args...)
}

func (logf *structuredLogger) WithFields(fields Fields) Logger {
	var f = make([]interface{}, 0)
	for k, v := range fields {
		f = append(f, k)
		f = append(f, v)
	}
	newLogger := logf.zapLogger.With(f...)
	return &structuredLogger{newLogger}
}
