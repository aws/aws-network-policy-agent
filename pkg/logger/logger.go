package logger

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
)

var log Logger

type Fields map[string]interface{}

type Logger interface {
	Debugf(format string, args ...interface{})
	Debug(msg string)
	Infof(format string, args ...interface{})
	Info(msg string)
	Warnf(format string, args ...interface{})
	Warn(msg string)
	Errorf(format string, args ...interface{})
	Error(msg string)
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})
	WithFields(keyValues Fields) Logger
}

var (
	DEFAULT_LOG_LEVEL    = "info"
	DEFAULT_LOG_LOCATION = "/var/log/aws-routed-eni/network-policy-agent.log"
)

func New(logLevel string, logLocation string) Logger {
	inputLogConfig := &Configuration{
		LogLevel:    logLevel,
		LogLocation: logLocation,
	}
	log = inputLogConfig.newZapLogger()
	return log
}

func Get() Logger {
	if log == nil {
		log = New(DEFAULT_LOG_LEVEL, DEFAULT_LOG_LOCATION)
		log.Warn("Logger was not initialized explicitly, using default logger.")
	}
	return log
}

func GetControllerRuntimeLogger() logr.Logger {
	zapSugared := Get().(*structuredLogger).zapLogger
	return zapr.NewLogger(zapSugared.Desugar())
}
