package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type contextKey struct{}

// NewTraceID generates an 8-character hex trace ID from 4 random bytes.
func NewTraceID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// WithTraceID returns a new context with the given trace ID stored in it.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, contextKey{}, traceID)
}

// TraceIDFromContext extracts the trace ID from the context.
// Returns empty string if no trace ID is present.
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKey{}).(string); ok {
		return v
	}
	return ""
}

// FromContext returns a Logger enriched with the trace ID from ctx.
// If ctx has no trace ID, returns the default logger.
func FromContext(ctx context.Context) Logger {
	l := Get()
	if traceID := TraceIDFromContext(ctx); traceID != "" {
		return l.WithFields(Fields{"trace_id": traceID})
	}
	return l
}
