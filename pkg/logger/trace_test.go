package logger

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"pgregory.net/rapid"
)

// TestPropertyContextRoundTrip verifies that for any trace ID string,
// storing it in a context via WithTraceID and retrieving it via
// TraceIDFromContext returns the original trace ID.
func TestPropertyContextRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		traceID := rapid.String().Draw(t, "traceID")
		ctx := WithTraceID(context.Background(), traceID)
		got := TraceIDFromContext(ctx)
		if got != traceID {
			t.Fatalf("round-trip failed: stored %q but got %q", traceID, got)
		}
	})
}

// TestPropertyTraceIDFormat verifies that for any trace ID produced by
// NewTraceID, the result is exactly 8 characters long and consists only
// of lowercase hexadecimal characters [0-9a-f].
func TestPropertyTraceIDFormat(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := NewTraceID()
		if len(id) != 8 {
			t.Fatalf("expected length 8, got %d for trace ID %q", len(id), id)
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("invalid hex character %q in trace ID %q", string(c), id)
			}
		}
	})
}

// TestTraceIDFromContext_EmptyContext verifies that TraceIDFromContext
// returns an empty string when the context has no trace ID stored.
func TestTraceIDFromContext_EmptyContext(t *testing.T) {
	got := TraceIDFromContext(context.Background())
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// TestFromContext_EmptyContext verifies that FromContext with a context
// that has no trace ID returns a logger that does NOT include a trace_id field.
func TestFromContext_EmptyContext(t *testing.T) {
	// Set up an in-memory logger so we can capture output
	var buf zapBufferWriteSyncer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		&buf,
		zapcore.DebugLevel,
	)
	sugar := zap.New(core).Sugar()
	orig := log
	t.Cleanup(func() { log = orig })
	log = &structuredLogger{zapLogger: sugar}

	l := FromContext(context.Background())
	l.Info("test message")

	output := buf.String()
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("failed to parse log output as JSON: %v", err)
	}
	if _, exists := entry["trace_id"]; exists {
		t.Fatalf("expected no trace_id field in log output, but found one: %v", entry)
	}
}

// zapBufferWriteSyncer is a minimal WriteSyncer backed by a strings.Builder.
type zapBufferWriteSyncer struct {
	buf strings.Builder
}

func (w *zapBufferWriteSyncer) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *zapBufferWriteSyncer) Sync() error {
	return nil
}

func (w *zapBufferWriteSyncer) String() string {
	return w.buf.String()
}
