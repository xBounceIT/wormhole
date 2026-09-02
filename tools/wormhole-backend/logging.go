package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// App logging mirrors the WinUI 3 Serilog sink: one shared daily file
// (<data>/logs/wormhole-yyyyMMdd.log), Information minimum level (no Debug noise), and a
// retained-file limit equal to the configured retention days. Go owns the file; the
// renderer and the Electron main process never write logs directly.
const (
	logFileNamePrefix       = "wormhole-"
	logFileNameSuffix       = ".log"
	maximumLogTracebackSize = 32 * 1024
)

// Log levels. The default is Info: only high-level lifecycle events (boot, connection,
// tunnel, errors) are written. Debug additionally writes the verbose per-operation
// trace intended for diagnosing failures. The minimum level is read from settings.json
// (see logLevelKey) at every backend process start.
const (
	logLevelInfo  = "info"
	logLevelDebug = "debug"
)

// appLog is replaced by initAppLogging on every backend process start. Its zero value is a
// safe no-op so logging failures can never fail an operation.
var appLog = &appLogger{}

type appLogger struct {
	mu        sync.Mutex
	directory string
	retention int
	level     string
	day       string
	file      *os.File
}

// initAppLogging prepares the daily log file for the given database path. It never returns
// an error: logging is best-effort and must not break backend operations.
func initAppLogging(databasePath string) {
	if databasePath == "" {
		return
	}
	logger, err := newAppLogger(databasePath)
	if err != nil {
		return
	}
	appLog = logger
}

func newAppLogger(databasePath string) (*appLogger, error) {
	directory := logsDirectoryPath(databasePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	retention := defaultLogRetentionDays
	if days, err := readLogRetentionDays(databasePath); err == nil && days >= minimumLogRetentionDays {
		retention = days
	}
	level := defaultLogLevel
	if configured, err := readLogLevel(databasePath); err == nil && configured != "" {
		level = configured
	}
	logger := &appLogger{directory: directory, retention: retention, level: level}
	if err := logger.reopen(); err != nil {
		return nil, err
	}
	return logger, nil
}

// reopen closes any previous file and opens today's file, rolling and pruning if the day
// changed since the logger was created (long-running processes can cross midnight).
func (l *appLogger) reopen() error {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	today := time.Now().Format("20060102")
	pruneLogFiles(l.directory, l.retention)
	path := filepath.Join(l.directory, logFileNamePrefix+today+logFileNameSuffix)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.day = today
	l.file = file
	return nil
}

func (l *appLogger) write(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return
	}
	if !l.allows(level) {
		return
	}
	if day := time.Now().Format("20060102"); day != l.day {
		_ = l.reopen()
		if l.file == nil {
			return
		}
	}
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf(
		"%s [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05.000 -07:00"),
		level,
		message,
	)
	if _, err := l.file.WriteString(line); err != nil {
		_ = l.reopen()
	}
}

// allows reports whether a message at the given level should be written under the
// configured minimum level. Info (the default) admits INFO and everything above
// (WRN, ERR); Debug admits everything, including the DEBUG trace.
func (l *appLogger) allows(level string) bool {
	if l.level == logLevelDebug {
		return true
	}
	switch level {
	case "ERR", "WRN", "INF":
		return true
	default:
		return false
	}
}

func (l *appLogger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

func logInfo(format string, args ...any)  { appLog.write("INF", format, args...) }
func logDebug(format string, args ...any) { appLog.write("DBG", format, args...) }
func logWarn(format string, args ...any)  { appLog.write("WRN", format, args...) }

// Error entries always carry a bounded Go traceback. ERR is admitted by both supported log
// levels, so failures remain diagnosable when the application is left at its default Info level.
func logError(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	traceback := strings.TrimSpace(string(debug.Stack()))
	if len(traceback) > maximumLogTracebackSize {
		traceback = traceback[:maximumLogTracebackSize] + "\n[traceback truncated]"
	}
	appLog.write("ERR", "%s\ntraceback:\n%s", message, traceback)
}

func closeAppLog() { appLog.close() }

// pruneLogFiles keeps the newest retentionCount daily files, deleting older ones. This
// mirrors Serilog's retainedFileCountLimit with daily rolling. Only wormhole-yyyyMMdd.log
// files are touched; everything else in the directory is left alone.
func pruneLogFiles(directory string, retentionCount int) {
	if retentionCount < 1 {
		retentionCount = defaultLogRetentionDays
	}
	matches, err := filepath.Glob(filepath.Join(directory, logFileNamePrefix+"*"+logFileNameSuffix))
	if err != nil {
		return
	}
	var daily []string
	for _, match := range matches {
		base := filepath.Base(match)
		stamp := strings.TrimSuffix(strings.TrimPrefix(base, logFileNamePrefix), logFileNameSuffix)
		if len(stamp) == 8 {
			if _, err := time.Parse("20060102", stamp); err == nil {
				daily = append(daily, match)
			}
		}
	}
	sort.Strings(daily)
	if len(daily) <= retentionCount {
		return
	}
	for _, old := range daily[:len(daily)-retentionCount] {
		_ = os.Remove(old)
	}
}
