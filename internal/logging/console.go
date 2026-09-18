package logging

import (
	"context"
	"io"
	"log/slog"
	"sync"
)

// consoleHandler renders slog records as compact, human-oriented lines:
//
//	2026-09-15T09:12:33Z INF http server started addr=:8080
//
// Secrets are never expected to reach the logger; the Redacted constant exists
// so call sites can make intent explicit. Attribute keys matching sensitive
// names are suppressed defensively here as well.
type consoleHandler struct {
	level slog.Level
	attrs []slog.Attr
	group string
	mu    *sync.Mutex
	w     io.Writer
}

var sensitiveKeys = map[string]struct{}{
	"password": {}, "secret": {}, "token": {}, "authorization": {},
	"api_key": {}, "apikey": {}, "cookie": {}, "private_key": {},
}

func newConsoleHandler(w io.Writer, level slog.Level) *consoleHandler {
	return &consoleHandler{level: level, mu: &sync.Mutex{}, w: w}
}

func (h *consoleHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf := make([]byte, 0, 256)
	buf = append(buf, r.Time.Format("2006-01-02T15:04:05Z")...)
	buf = append(buf, ' ')
	buf = append(buf, levelTag(r.Level)...)
	buf = append(buf, ' ')
	buf = append(buf, r.Message...)
	for _, a := range h.attrs {
		buf = appendAttr(buf, a, h.group)
	}
	r.Attrs(func(a slog.Attr) bool {
		buf = appendAttr(buf, a, h.group)
		return true
	})
	buf = append(buf, '\n')
	_, err := h.w.Write(buf)
	return err
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &nh
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	if h.group != "" {
		nh.group = h.group + "." + name
	} else {
		nh.group = name
	}
	return &nh
}

func appendAttr(buf []byte, a slog.Attr, group string) []byte {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return buf
	}
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	buf = append(buf, ' ')
	buf = append(buf, key...)
	buf = append(buf, '=')
	if _, bad := sensitiveKeys[key]; bad {
		buf = append(buf, Redacted...)
		return buf
	}
	if s, ok := a.Value.Any().(string); ok {
		buf = append(buf, s...)
		return buf
	}
	buf = append(buf, a.Value.String()...)
	return buf
}

func levelTag(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERR"
	case l >= slog.LevelWarn:
		return "WRN"
	case l >= slog.LevelInfo:
		return "INF"
	default:
		return "DBG"
	}
}
