package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const rootIntentCrashNode = "66666666-6666-4666-8666-666666666666"
const rootIntentCrashValue = "present before the writer was killed"

func TestVaultRootRotationIntentSurvivesProcessKill(t *testing.T) {
	for _, mode := range []string{"conversion", "rekey"} {
		for _, cut := range []string{"intent-slots", "copy-staged", "source-retired", "database-published"} {
			t.Run(mode+"/"+cut, func(t *testing.T) { checkKilledRootRotation(t, mode, cut) })
		}
	}
}

func checkKilledRootRotation(t *testing.T, mode, cut string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := filepath.Join(t.TempDir(), "workspace.db")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestVaultRootRotationIntentWriter$")
	cmd.Env = append(os.Environ(), "WORMHOLE_TEST_ROTATION_INTENT_FILE="+source,
		"WORMHOLE_TEST_ROTATION_MODE="+mode, "WORMHOLE_TEST_ROTATION_CUT="+cut)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, readErr := bufio.NewReader(stdout).ReadString('\n')
	killErr := cmd.Process.Kill()
	waitErr := cmd.Wait()
	if readErr != nil || strings.TrimSpace(line) != cut || killErr != nil || waitErr == nil || ctx.Err() != nil {
		t.Fatalf("writer did not reach the selected boundary: line %q, read %v, kill %v, wait %v, stderr %q",
			line, readErr, killErr, waitErr, stderr.String())
	}
	hint, err := discoverRootRotation(ctx, source)
	if err != nil || hint == nil || !hint.document.Encrypted {
		t.Fatal("interrupted rotation could not be discovered", err)
	}
	h := &vaultFoundationHandler{databasePath: source, migrationQuiesced: true}
	defer h.Close()
	if _, err := h.Handle(ctx, "rotation-resume", rootRotationUnlockInput(t, hint.document, true)); err != nil {
		t.Fatal("abruptly interrupted writer could not resume", err)
	}
	if got, err := h.owner.ReadNode(ctx, rootIntentCrashNode, 1); err != nil || got.Name != rootIntentCrashValue {
		t.Fatal("restart lost the committed source record", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	slots, err := readVaultSlotFile(source)
	if err != nil || !slots.Encrypted || slots.RootKeyVersion != 2 || slots.Rotation != nil {
		t.Fatal("restart did not finish the encrypted transition", err)
	}
	raw, err := os.ReadFile(source)
	if err != nil || len(raw) == 0 || bytes.Contains(raw, []byte(rootIntentCrashValue)) || bytes.HasPrefix(raw, []byte("SQLite format 3")) {
		t.Fatal("committed metadata was not encrypted on disk", err)
	}
	files, err := os.ReadDir(filepath.Dir(source))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.Contains(file.Name(), ".rotating-") || strings.Contains(file.Name(), ".retired-") {
			t.Fatal("rotation retained an obsolete copy after recovery", file.Name())
		}
	}
	if err := requireNoRootRotation(source); err != nil {
		t.Fatal(err)
	}
}

func TestVaultRootRotationIntentWriter(t *testing.T) {
	source := os.Getenv("WORMHOLE_TEST_ROTATION_INTENT_FILE")
	if source == "" {
		return
	}
	mode, cut := os.Getenv("WORMHOLE_TEST_ROTATION_MODE"), os.Getenv("WORMHOLE_TEST_ROTATION_CUT")
	if mode != "conversion" && mode != "rekey" {
		t.Fatal("unknown rotation mode")
	}
	f := nativeRootRotationAt(t, source, mode == "rekey")
	ctx := t.Context()
	node := vaultstore.NodeMetadata{ID: rootIntentCrashNode, Kind: 0, Name: rootIntentCrashValue}
	if _, err := f.owner.PutNode(ctx, node, nil, 0); err != nil {
		t.Fatal(err)
	}
	step := func(point string) error {
		if point == cut {
			fmt.Println(point)
			timer := time.NewTimer(2 * time.Minute)
			defer timer.Stop()
			<-timer.C
			t.Fatal("parent failed to kill the writer")
		}
		return nil
	}
	if err := beginLocalRootRotationMode(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), step, true); err != nil {
		t.Fatal(err)
	}
	if err := resumeLocalRootRotation(ctx, f.source, f.key, step); err != nil {
		t.Fatal(err)
	}
	t.Fatal("writer unexpectedly completed")
}
