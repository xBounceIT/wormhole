//go:build (windows || linux || darwin) && (amd64 || arm64)

package encvfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const durablePayload = "power-loss-committed-epoch"

var powerLossFiles = [...]string{"", "-journal", "-wal"}

func powerLossValue(epoch, row int) string {
	return strings.Repeat(fmt.Sprintf("%s/%d/%d|", durablePayload, epoch, row), 240)
}

func TestSQLiteRecoversAfterPhysicalWriteFaults(t *testing.T) {
	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode, func(t *testing.T) {
			path := reserveDB(t, "powerloss.sqlite")
			key := make([]byte, 32)
			registration := registerTestDB(t, path, key)
			db := openTestDB(t, registration)
			requireSQL(t, db, "PRAGMA journal_mode="+mode, mode)
			execSQL(t, db, "CREATE TABLE item (id INTEGER PRIMARY KEY, value TEXT)")
			for row := 1; row <= 2; row++ {
				execSQL(t, db, "INSERT INTO item (id,value) VALUES (?,?)", row, powerLossValue(0, row))
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			stable := readPowerLossDisk(t, path)
			scanCiphertext(t, path, durablePayload, string(databaseMagic))
			trace, stop := traceNativeDisk(t, registration)
			db = openTestDB(t, registration)
			execSQL(t, db, "PRAGMA wal_autocheckpoint=0")
			execSQL(t, db, "PRAGMA cache_size=4")
			for epoch := 1; epoch <= 2; epoch++ {
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				for row := 1; row <= 2; row++ {
					if _, err := tx.Exec("UPDATE item SET value=? WHERE id=?", powerLossValue(epoch, row), row); err != nil {
						_ = tx.Rollback()
						t.Fatal(err)
					}
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				trace.ops = append(trace.ops, diskOperation{kind: "commit", offset: int64(epoch)})
			}
			if mode == "wal" {
				var busy, remaining, checkpointed int
				if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &remaining, &checkpointed); err != nil ||
					busy != 0 || remaining != 0 || checkpointed != 0 {
					t.Fatalf("WAL checkpoint did not complete: %d %d %d, %v", busy, remaining, checkpointed, err)
				}
			}
			// Whole-file close can checkpoint again. The trace ends before that
			// cleanup so the simulator can reconstruct the unclean disk state.
			ops := trace.ops
			assertCompleteDiskTrace(t, stable, ops, readPowerLossDisk(t, path))
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			stop()
			replayPowerLossCuts(t, key, stable, ops, mode)
		})
	}
}

func TestSQLiteFileBackedTempSpillIsEncrypted(t *testing.T) {
	path := reserveDB(t, "temp-spill.sqlite")
	registration := registerTestDB(t, path, make([]byte, 32))
	trace, stop := traceNativeDisk(t, registration)
	trace.temp = true
	db := openTestDB(t, registration)
	execSQL(t, db, "PRAGMA temp_store=FILE")
	execSQL(t, db, "PRAGMA temp.cache_size=4")
	execSQL(t, db, "CREATE TEMP TABLE spilled (value TEXT)")
	const marker = "private-temporary-payload"
	const repeat = 700
	value := strings.Repeat(marker, repeat)
	execSQL(t, db, `WITH RECURSIVE series(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM series WHERE i<80)
		INSERT INTO spilled SELECT ? FROM series;`, value)
	requireSQL(t, db, "SELECT count(*) FROM spilled", "80")
	requireSQL(t, db, "SELECT value FROM spilled WHERE rowid=37", value)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	stop()
	writes := 0
	for _, op := range trace.ops {
		if op.file != "temp" || op.kind != "write" {
			continue
		}
		writes++
		if len(op.data) != PageSize || bytes.Contains(op.data, []byte(marker)) {
			t.Fatal("SQLite spilled an unencrypted temporary sector")
		}
	}
	if writes == 0 {
		t.Fatal("fixture did not force SQLite to spill to an encrypted temporary file")
	}
}

func readPowerLossDisk(t *testing.T, path string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	for _, suffix := range powerLossFiles {
		data, err := os.ReadFile(path + suffix)
		if errors.Is(err, os.ErrNotExist) && suffix != "" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[suffix] = data
	}
	return files
}

func assertCompleteDiskTrace(t *testing.T, baseline map[string][]byte, ops []diskOperation, actual map[string][]byte) {
	t.Helper()
	full := make(map[string][]byte, len(baseline))
	for file, data := range baseline {
		full[file] = bytes.Clone(data)
	}
	for _, op := range ops {
		switch op.kind {
		case "write", "truncate":
			full[op.file] = persistDiskOperation(full[op.file], op)
		case "delete":
			delete(full, op.file)
		}
	}
	for _, file := range powerLossFiles {
		if !bytes.Equal(full[file], actual[file]) {
			t.Fatalf("incomplete physical trace for %q: replayed %d bytes, actual %d", file, len(full[file]), len(actual[file]))
		}
	}
}

// Each sync publishes all writes and truncations to that file. For every cut
// we drop any pending operations, or let the latest pending sector reach disk
// ahead of earlier writes, intact or torn. A successful xDelete is represented
// as a durable directory operation in this model.
func replayPowerLossCuts(t *testing.T, key []byte, stable map[string][]byte, ops []diskOperation, mode string) {
	t.Helper()
	pending := map[string][]diskOperation{}
	minimum := 0
	writes, reordered := 0, 0
	walTruncated := false
	syncedFiles := map[string]bool{}
	for i, op := range ops {
		switch op.kind {
		case "write":
			if len(op.data) != PageSize || op.offset%PageSize != 0 || bytes.Contains(op.data, []byte(durablePayload)) {
				t.Fatal("native parent did not receive one encrypted sector")
			}
			writes++
			pending[op.file] = append(pending[op.file], op)
		case "truncate":
			pending[op.file] = append(pending[op.file], op)
			walTruncated = walTruncated || op.file == "-wal"
		case "sync":
			syncedFiles[op.file] = true
			for _, dirty := range pending[op.file] {
				stable[op.file] = persistDiskOperation(stable[op.file], dirty)
			}
			delete(pending, op.file)
		case "delete":
			delete(stable, op.file)
			delete(pending, op.file)
		case "commit":
			minimum = int(op.offset)
			if minimum == 1 && mode == "wal" && len(stable["-wal"]) == 0 {
				t.Fatal("second transaction must exercise an existing committed WAL")
			}
		}
		maximum := min(2, minimum+1)
		if op.kind == "commit" {
			maximum = minimum
		}
		t.Run(fmt.Sprintf("%03d-%s%s/drop", i, op.kind, op.file), func(t *testing.T) {
			assertPowerLossRecovery(t, key, stable, minimum, maximum)
		})
		var faults []string
		switch op.kind {
		case "write":
			faults = []string{"reorder", "torn", "prefix-torn"}
			if len(pending[op.file]) > 1 {
				reordered++
			}
		case "truncate":
			faults = []string{"persist-truncate"}
		default:
			continue
		}
		for _, fault := range faults {
			t.Run(fmt.Sprintf("%03d-%s%s/%s", i, op.kind, op.file, fault), func(t *testing.T) {
				disk := make(map[string][]byte, len(stable)+1)
				for file, data := range stable {
					disk[file] = data
				}
				variant := op
				if fault == "prefix-torn" {
					for file, dirty := range pending {
						disk[file] = bytes.Clone(stable[file])
						if file == op.file {
							dirty = dirty[:len(dirty)-1]
						}
						for _, preceding := range dirty {
							disk[file] = persistDiskOperation(disk[file], preceding)
						}
					}
				}
				if fault == "torn" || fault == "prefix-torn" {
					variant.data = op.data[:PageSize/2]
				}
				disk[op.file] = persistDiskOperation(bytes.Clone(disk[op.file]), variant)
				assertPowerLossRecovery(t, key, disk, minimum, maximum)
			})
		}
	}
	sidecar := "-journal"
	if mode == "wal" {
		sidecar = "-wal"
		if !walTruncated {
			t.Fatal("trace did not exercise the WAL truncation")
		}
	}
	if writes < 4 || reordered == 0 || !syncedFiles[sidecar] || !syncedFiles[""] || minimum != 2 {
		t.Fatalf("trace omitted expected writes, reordering, syncs, or commits: %d %d %v %d", writes, reordered, syncedFiles, minimum)
	}
	t.Logf("checked %d physical writes across %d I/O and commit boundaries", writes, len(ops))
}

func persistDiskOperation(before []byte, op diskOperation) []byte {
	start := int(op.offset)
	if op.kind == "truncate" {
		if start > len(before) {
			before = append(before, make([]byte, start-len(before))...)
		}
		return before[:start]
	}
	end := start + len(op.data)
	if end > len(before) {
		before = append(before, make([]byte, end-len(before))...)
	}
	copy(before[start:end], op.data)
	return before
}

func assertPowerLossRecovery(t *testing.T, key []byte, disk map[string][]byte, minimum, maximum int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recovered.sqlite")
	for suffix, data := range disk {
		if err := os.WriteFile(path+suffix, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	db := openTestDB(t, registerTestDB(t, path, key))
	requireSQL(t, db, "PRAGMA integrity_check", "ok")
	var first, second string
	if err := db.QueryRow("SELECT (SELECT value FROM item WHERE id=1),(SELECT value FROM item WHERE id=2)").Scan(&first, &second); err != nil {
		t.Fatal(err)
	}
	for epoch := minimum; epoch <= maximum; epoch++ {
		if first == powerLossValue(epoch, 1) && second == powerLossValue(epoch, 2) {
			return
		}
	}
	t.Fatalf("expected one intact epoch in %d..%d, recovered %q / %q", minimum, maximum, first[:min(35, len(first))], second[:min(35, len(second))])
}
