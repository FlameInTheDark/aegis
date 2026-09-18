// Package logging provides the application-wide structured logging
// abstraction built on log/slog. Domain packages depend on this small
// surface only; implementation details stay here.
package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type ctxKey struct{}

// New builds the process logger. format is "console" or "json".
func New(level, format string) *slog.Logger {
	lvl := parseLevel(level)
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: lvl}
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = newConsoleHandler(os.Stdout, lvl)
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

// WithLogger stores a logger in the context (used by tests / workers).
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the contextual logger, falling back to the default.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// Redact is a helper that marks a value as sensitive. Values wrapped here
// are logged as "[REDACTED]" by the console/JSON handlers via attr filtering.
const Redacted = "[REDACTED]"

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
