package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetControllerRuntimeLogger(t *testing.T) {
	// Initialize a logger first
	log := New("info", "", 200, 8)
	assert.NotNil(t, log)

	// Get the controller runtime logger
	// This should not produce "failed to get caller" error
	ctrlLogger := GetControllerRuntimeLogger()
	assert.NotNil(t, ctrlLogger)

	// Test that logging works without errors
	// The zapr logger should now have correct caller skip
	ctrlLogger.Info("test log message")
	ctrlLogger.V(1).Info("test verbose log message")
	ctrlLogger.WithValues("key", "value").Info("test log with values")
}

func TestLoggerCallerSkip(t *testing.T) {
	// Create a logger with default settings
	log := New("debug", "", 200, 8)
	assert.NotNil(t, log)

	// Verify that the structured logger works
	log.Info("structured logger test")
	log.Debugf("structured logger debug: %s", "test")

	// Get controller runtime logger
	ctrlLogger := GetControllerRuntimeLogger()

	// This should work without "failed to get caller" error
	// The fix adjusts the caller skip count to work correctly with zapr
	ctrlLogger.Info("controller runtime logger test")
	ctrlLogger.Error(nil, "controller runtime error test")
}
