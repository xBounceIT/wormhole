package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"modernc.org/sqlite"
)

const (
	logFileNamePrefix = "wormhole-"
	logFileNameSuffix = ".log"
	logLevelInfo      = "info"
	logLevelDebug     = "debug"
)

var appLog = &appLogger{}

type appLogger struct {
	mu                sync.Mutex
	databasePath      string
	directory         string
	fallback          io.Writer
	level             string
	retention         int
	settingsCheckedAt time.Time
	prunedDay         string
	pruneAttempt      time.Time
	sinkFailed        bool
	closed            bool
	recentErrors      map[repeatedLogError]logOccurrence
	recentDay         string
}

const logUnavailablePrefix = "Wormhole diagnostic log unavailable:"

type repeatedLogError struct {
	function string
	line     int
	message  string
}

type logOccurrence struct {
	at       time.Time
	repeated int
}

func newAppLogger(databasePath string, fallback io.Writer) *appLogger {
	return &appLogger{
		databasePath: databasePath,
		directory:    logsDirectoryPath(databasePath),
		fallback:     fallback,
		level:        defaultLogLevel,
		retention:    defaultLogRetentionDays,
	}
}

func (l *appLogger) refreshSettings() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.settingsCheckedAt = time.Time{}
}

func (l *appLogger) write(level, format string, args ...any) {
	l.writeRecord(level, fmt.Sprintf(format, args...), nil)
}

func (l *appLogger) writeRecord(level, message string, stack []uintptr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.directory == "" {
		return
	}

	now := time.Now()
	if now.Sub(l.settingsCheckedAt) >= time.Second {
		days, configuredLevel, err := readLogSettings(l.databasePath)
		if err == nil {
			if days != l.retention {
				l.prunedDay = ""
				l.pruneAttempt = time.Time{}
			}
			l.retention, l.level = days, configuredLevel
		}
		l.settingsCheckedAt = now
	}
	if level == "DBG" && l.level != logLevelDebug {
		return
	}

	day := now.Format("20060102")
	var key repeatedLogError
	if len(stack) != 0 {
		if l.recentDay != day {
			clear(l.recentErrors)
			l.recentDay = day
		}
		frame, _ := runtime.CallersFrames(stack).Next()
		key = repeatedLogError{function: frame.Function, line: frame.Line, message: message}
		if previous, ok := l.recentErrors[key]; ok {
			if now.Sub(previous.at) < 5*time.Second {
				previous.repeated++
				l.recentErrors[key] = previous
				return
			}
			if previous.repeated != 0 {
				message += fmt.Sprintf(" (repeated=%d)", previous.repeated)
			}
		}
		message += logTraceback(stack)
	}
	line := fmt.Sprintf("%s [%s] [go pid=%d] %s\n",
		now.Format("2006-01-02 15:04:05.000 -07:00"), level, os.Getpid(), message)
	path := dailyLogFilePath(l.directory, day)
	if err := appendLogLine(path, line); err != nil {
		if !l.sinkFailed && l.fallback != nil {
			// Emit a fixed diagnostic separately from the CLI's user-facing error.
			_, _ = fmt.Fprintln(l.fallback, logUnavailablePrefix, diagnosticCause(err))
		}
		l.sinkFailed = true
		return
	}
	if len(stack) != 0 {
		if l.recentErrors == nil {
			l.recentErrors = make(map[repeatedLogError]logOccurrence)
		} else if len(l.recentErrors) >= 256 {
			clear(l.recentErrors)
		}
		l.recentErrors[key] = logOccurrence{at: now}
	}
	if l.sinkFailed {
		l.sinkFailed = false
		_ = appendLogLine(path, fmt.Sprintf("%s [WRN] [go pid=%d] diagnostic log recovered after a write failure\n",
			now.Format("2006-01-02 15:04:05.000 -07:00"), os.Getpid()))
	}
	if day != l.prunedDay &&
		(l.pruneAttempt.Format("20060102") != day || now.Sub(l.pruneAttempt) >= time.Minute) &&
		time.Now().Format("20060102") == day {
		l.pruneAttempt = now
		if err := pruneLogFiles(l.directory, l.retention, day); err != nil {
			_ = appendLogLine(path, fmt.Sprintf("%s [WRN] [go pid=%d] log retention cleanup failed (cause=%s)\n",
				now.Format("2006-01-02 15:04:05.000 -07:00"), os.Getpid(), diagnosticCause(err)))
		} else {
			l.prunedDay = day
		}
	}
}

var errInvalidLogPath = errors.New("invalid log path")

func openLogDirectory(directory string) (*os.Root, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errInvalidLogPath
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, errors.Join(errInvalidLogPath, err)
	}
	return root, nil
}

func openDailyLog(path string) (*os.File, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	root, err := openLogDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := root.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if !errors.Is(createErr, os.ErrExist) {
			return file, createErr
		}
		info, err = root.Lstat(name) // Another writer created today's file.
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errInvalidLogPath
	}
	file, err := root.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.Join(errInvalidLogPath, err)
	}
	return file, nil
}

func appendLogLine(path, line string) error {
	// Open for each record so an externally removed or rotated file cannot strand
	// a long-lived service on a detached file. Append emits each record in one write.
	file, err := openDailyLog(path)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(line)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func (l *appLogger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
}

func logInfo(format string, args ...any)  { appLog.write("INF", format, args...) }
func logDebug(format string, args ...any) { appLog.write("DBG", format, args...) }
func logWarn(format string, args ...any)  { appLog.write("WRN", format, args...) }

func logError(format string, args ...any) {
	logErrorAtCaller(format, args...)
}

func logErrorAtCaller(format string, args ...any) {
	if appLog.directory == "" {
		return
	}
	var pcs [16]uintptr
	appLog.writeRecord("ERR", fmt.Sprintf(format, args...), pcs[:runtime.Callers(3, pcs[:])])
}

func logTraceback(stack []uintptr) string {
	frames := runtime.CallersFrames(stack)
	var traceback strings.Builder
	traceback.WriteString("\ntraceback:")
	for {
		frame, more := frames.Next()
		if frame.Function != "" {
			fmt.Fprintf(&traceback, "\n  %s:%d", frame.Function, frame.Line)
		}
		if !more {
			break
		}
	}
	return traceback.String()
}

// Error messages may embed arbitrary child-process, server, or credential data.
// Extract known error categories and numeric codes without calling Error().
func diagnosticCause(err error) string {
	var sqliteError *sqlite.Error
	var sftpError *sftp.StatusError
	var tunnelError *tunnelSidecarError
	var hostKeyError *sshHostKeyMismatchError
	var certificateError *sshCertificateAuthError
	var statusError *os.SyscallError
	var errno syscall.Errno
	var syntaxError *json.SyntaxError
	var exitError interface{ ExitCode() int }
	var timeout interface{ Timeout() bool }
	var dnsError *net.DNSError
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrNotExist):
		return "not-found"
	case errors.Is(err, errInvalidLogPath):
		return "invalid-path"
	case errors.As(err, &sqliteError):
		return fmt.Sprintf("sqlite-%d", sqliteError.Code())
	case errors.As(err, &sftpError):
		return fmt.Sprintf("sftp-%d", sftpError.Code)
	case errors.As(err, &tunnelError):
		return fmt.Sprintf("vpn-%s/exit-%d", tunnelError.reason, tunnelError.exitCode)
	case errors.As(err, &hostKeyError):
		return "ssh-host-key-mismatch"
	case errors.As(err, &certificateError):
		return "ssh-certificate"
	case errors.As(err, &errno):
		return fmt.Sprintf("os-%d", errno)
	case errors.As(err, &dnsError):
		return "dns"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.As(err, &syntaxError):
		return "invalid-json"
	case errors.As(err, &exitError):
		return fmt.Sprintf("exit-%d", exitError.ExitCode())
	case errors.As(err, &statusError):
		return "syscall"
	default:
		return "unspecified"
	}
}

func logOperationFailure(stage string, err error) {
	if errors.Is(err, context.Canceled) {
		logDebug("%s cancelled", stage)
		return
	}
	logErrorAtCaller("%s failed (cause=%s)", stage, diagnosticCause(err))
}

// pruneLogFiles keeps the newest daily files and leaves unrelated files alone.
func pruneLogFiles(directory string, retentionCount int, activeDay string) error {
	if retentionCount < 1 {
		retentionCount = defaultLogRetentionDays
	}
	root, err := openLogDirectory(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	var daily []string
	for _, entry := range entries {
		base := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(base, logFileNamePrefix) ||
			!strings.HasSuffix(base, logFileNameSuffix) {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(base, logFileNamePrefix), logFileNameSuffix)
		if _, err := time.Parse("20060102", stamp); err == nil {
			if stamp == activeDay {
				retentionCount--
				continue
			}
			daily = append(daily, base)
		}
	}
	sort.Strings(daily)
	var pruneErr error
	for _, old := range daily[:max(0, len(daily)-retentionCount)] {
		if err := root.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
			pruneErr = err
		}
	}
	return pruneErr
}
