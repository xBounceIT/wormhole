//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	committedMarker   = "committed-vfs-test-record"
	uncommittedMarker = "uncommitted-vfs-test-record"
	crashReady        = "transaction ready"
)

func TestSQLiteRecoversAfterWriterKill(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode, func(t *testing.T) {
			path := reserveDB(t, "crash.sqlite")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSQLiteCrashWriter$")
			cmd.Env = append(os.Environ(), "WORMHOLE_TEST_CRASH_DB="+path, "WORMHOLE_TEST_CRASH_MODE="+mode)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(stdout).ReadString('\n')
			killErr := cmd.Process.Kill()
			waitErr := cmd.Wait()
			if err != nil || strings.TrimSpace(line) != crashReady || killErr != nil || ctx.Err() != nil {
				t.Fatalf("kill with open transaction: line %q, read %v, kill %v, wait %v, stderr %q",
					line, err, killErr, waitErr, stderr.String())
			}
			sidecar := "-journal"
			if mode == "wal" {
				sidecar = "-wal"
			}
			scanCiphertext(t, path+sidecar, committedMarker, uncommittedMarker)
			db := openTestDB(t, registerTestDB(t, path, make([]byte, 32)))
			requireSQL(t, db, "PRAGMA integrity_check", "ok")
			requireSQL(t, db, "SELECT value FROM item", strings.Repeat(committedMarker, 1024))
		})
	}
}

// TestSQLiteCrashWriter runs exclusively in the crash test's child process.
func TestSQLiteCrashWriter(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_CRASH_DB")
	if path == "" {
		return
	}
	mode := os.Getenv("WORMHOLE_TEST_CRASH_MODE")
	if mode != "delete" && mode != "wal" {
		t.Fatal("invalid crash-test journal mode")
	}
	db := openTestDB(t, registerTestDB(t, path, make([]byte, 32)))
	requireSQL(t, db, "PRAGMA journal_mode="+mode, mode)
	execSQL(t, db, "PRAGMA wal_autocheckpoint=0")
	execSQL(t, db, "PRAGMA cache_size=4")
	execSQL(t, db, "CREATE TABLE item (value TEXT)")
	execSQL(t, db, "INSERT INTO item VALUES (?)", strings.Repeat(committedMarker, 1024))
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE item SET value=?", strings.Repeat(uncommittedMarker, 2048)); err != nil {
		t.Fatal(err)
	}
	fmt.Println(crashReady)
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	<-timer.C
	t.Fatal("parent failed to kill the writer")
}
