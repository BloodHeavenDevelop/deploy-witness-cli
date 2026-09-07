// Package logging is a small leveled logger that writes to stderr.
//
// The platform's shared `utils/logger` is deliberately not used here. It writes
// to stdout unconditionally — which is where this tool's CSV goes under --stdout
// — and it ships every line to Loki when LOKI_URL is set, which would turn an
// offline audit into an outbound connection. It also pulls a web framework and a
// database driver into the dependency tree of a binary whose whole value is being
// small enough to read before running it on a production host.
package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level orders the verbosity settings.
type Level int

// Levels, quietest first.
const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// Logger emits timestamped lines to a writer.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	color bool
}

// New builds a logger. Colour is enabled only for a terminal, so a redirected
// stream stays free of escape sequences.
func New(out io.Writer, level Level) *Logger {
	color := false
	if f, ok := out.(*os.File); ok {
		info, err := f.Stat()
		color = err == nil && info.Mode()&os.ModeCharDevice != 0
	}
	return &Logger{out: out, level: level, color: color}
}

// Default logs at info level to stderr.
func Default() *Logger { return New(os.Stderr, LevelInfo) }

var levelNames = map[Level]struct {
	label string
	color string
}{
	LevelError: {"ERROR", "31"},
	LevelWarn:  {"WARN ", "33"},
	LevelInfo:  {"INFO ", "32"},
	LevelDebug: {"DEBUG", "34"},
}

func (l *Logger) emit(level Level, message string) {
	if l == nil || level > l.level {
		return
	}

	meta := levelNames[level]
	stamp := time.Now().UTC().Format("2006-01-02 15:04:05")

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.color {
		fmt.Fprintf(l.out, "\033[%sm%s %s\033[0m %s\n", meta.color, stamp, meta.label, message)
		return
	}
	fmt.Fprintf(l.out, "%s %s %s\n", stamp, meta.label, message)
}

// Error logs a failure.
func (l *Logger) Error(v ...any) { l.emit(LevelError, fmt.Sprint(v...)) }

// Warn logs a degraded condition.
func (l *Logger) Warn(v ...any) { l.emit(LevelWarn, fmt.Sprint(v...)) }

// Info logs progress.
func (l *Logger) Info(v ...any) { l.emit(LevelInfo, fmt.Sprint(v...)) }

// Debug logs detail useful only when diagnosing the tool itself.
func (l *Logger) Debug(v ...any) { l.emit(LevelDebug, fmt.Sprint(v...)) }

// Infof logs formatted progress.
func (l *Logger) Infof(format string, v ...any) { l.emit(LevelInfo, fmt.Sprintf(format, v...)) }
