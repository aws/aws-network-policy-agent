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
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
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

func (logConfig *Configuration) newZapLogger() *structuredLogger { //Logger {
	var cores []zapcore.Core

	logLevel := getZapLevel(logConfig.LogLevel)

	writer := getLogFilePath(logConfig.LogLocation, logConfig.LogFileMaxSize, logConfig.LogFileMaxBackups)

	cores = append(cores, zapcore.NewCore(getEncoder(), writer, logLevel))

	combinedCore := zapcore.NewTee(cores...)

	logger := zap.New(combinedCore,
		zap.AddCaller(),
		zap.AddCallerSkip(2),
	)
	defer logger.Sync()

	sugar := logger.Sugar()
	return &structuredLogger{
		zapLogger: sugar,
	}
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

// getLogWriter is for lumberjack
func getLogWriter(logFilePath string, logFileMaxSize int, logFileMaxBackups int) zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    logFileMaxSize,
		MaxBackups: logFileMaxBackups,
		MaxAge:     30,
		Compress:   true,
	}
	return zapcore.AddSync(lumberJackLogger)
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
