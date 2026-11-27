package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
	"golang.org/x/sys/windows"
)

func TestWindowsInstallerHandoff(t *testing.T) {
	t.Setenv(bitwardenCliSessionEnvVar, "fixture-only")
	t.Setenv(bitwardenCliPasswordEnvVar, "fixture-only")
	dir := filepath.Join(t.TempDir(), "workspace with spaces")
	cache := updateCacheDirectory(filepath.Join(dir, "workspace.db"))
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fixture.exe")
	if out, err := exec.Command("go", "build", "-o", binary, "./testdata/update-installer").CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %v %s", err, out)
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	const tag = "v9.8.7"
	asset, manifest := signedUpdateFixture(t, tag, content)
	request := updateVerifyRequest{updateDownloadRequest: updateDownloadRequest{
		InstallerFileName: asset.Name, InstallerSize: asset.Size, InstallerSha256: asset.SHA256,
		InstallerUrl: signedAssetURL(tag, asset.Name), CurrentVersion: "9.8.6", SignedManifest: manifest,
	}}
	packet, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(cache, asset.Name)
	if err := os.WriteFile(executable, content, 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "workspace.db")
	// Request delete access without changing the directory. The inherited
	// read locks must protect its name after the verifying worker returns.
	openDirectory := func() error {
		name, err := windows.UTF16PtrFromString(cache)
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateFile(name, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err == nil {
			windows.CloseHandle(h)
		}
		return err
	}
	if err := openDirectory(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ mode, args string }{
		{"", ""}, {"X", ""}, {"RR", ""},
		{"C", "/SILENT /NORESTART /NORESTARTAPPLICATIONS"}, {"R", "/SILENT /RESTARTAPP"},
	} {
		t.Run("decision_"+tt.mode, func(t *testing.T) {
			input, decision := io.Pipe()
			defer decision.Close()
			ready, output := io.Pipe()
			defer ready.Close()
			done := make(chan error, 1)
			go func() {
				err := serveWindowsUpdateHandoff(db, input, output)
				input.Close()
				output.CloseWithError(err)
				done <- err
			}()
			if _, err := decision.Write(append(bytes.Clone(packet), '\n')); err != nil {
				t.Fatal(err)
			}
			var receipt [2]byte
			if _, err := io.ReadFull(ready, receipt[:]); err != nil || string(receipt[:]) != "V\n" {
				t.Fatalf("verification receipt %q: %v", receipt, err)
			}
			writer, err := os.OpenFile(executable, os.O_WRONLY, 0)
			if err == nil {
				writer.Close()
				t.Fatal("verified file accepted a writer before the decision")
			}
			if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				t.Fatal(err)
			}
			if _, err := io.WriteString(decision, tt.mode); err != nil {
				t.Fatal(err)
			}
			decision.Close()
			err = <-done
			record := executable + ".args"
			if tt.args == "" {
				if !errors.Is(err, updateauth.ErrArtifact) {
					t.Fatalf("unconfirmed handoff: %v", err)
				}
				if _, err := os.Stat(record); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unexpected launch", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for until := time.Now().Add(10 * time.Second); ; {
				got, err := os.ReadFile(record)
				if err == nil && string(got) == tt.args {
					break
				}
				if time.Now().After(until) {
					t.Fatalf("installer arguments %q: %v", got, err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := openDirectory(); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				t.Fatalf("installer did not retain the directory lock: %v", err)
			}
			if err := os.Remove(record); err != nil {
				t.Fatal(err)
			}
			for until := time.Now().Add(10 * time.Second); ; {
				if err := openDirectory(); err == nil {
					break
				}
				if time.Now().After(until) {
					t.Fatal("directory lock survived installer exit")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
	for _, input := range []string{"", "{}\n", "{\n", strings.Repeat("a", 16*1024) + "\n",
		strings.Replace(string(packet), asset.SHA256, strings.Repeat("0", 64), 1) + "\nR"} {
		var out, diag bytes.Buffer
		if code := runBackendCLI([]string{"--operation", "update-install-windows", "--database", db}, strings.NewReader(input), &out, &diag); code == 0 || out.Len() != 0 {
			t.Fatalf("invalid handoff returned exit %d and %q", code, &out)
		}
	}
}

func TestWindowsUpdateConfirmationRechecksApproval(t *testing.T) {
	request := updateDownloadRequest{InstallerUrl: " managed-update:release ", SignedManifest: []byte("approved manifest")}
	sum := sha256.Sum256(request.SignedManifest)
	approval := ospolicy.ManagedUpdate{Digest: hex.EncodeToString(sum[:])}
	prev := readManagedUpdatePolicy
	t.Cleanup(func() { readManagedUpdatePolicy = prev })
	readManagedUpdatePolicy = func(context.Context) (ospolicy.ManagedUpdate, error) { return approval, nil }
	var out bytes.Buffer
	restart, err := confirmWindowsUpdate(request, true, strings.NewReader("R"), &out)
	if err != nil || !restart || out.String() != "P\n" {
		t.Fatal(restart, err, out.String())
	}
	approval.Digest = ""
	if _, err := confirmWindowsUpdate(request, true, strings.NewReader("C"), io.Discard); !errors.Is(err, updateauth.ErrManifest) {
		t.Fatalf("withdrawn approval: %v", err)
	}
	in, closed := io.Pipe()
	in.Close()
	defer closed.Close()
	if _, err := confirmWindowsUpdate(request, false, strings.NewReader("R"), closed); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestWindowsInstallerHandoffPathErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.exe")
	if err := os.WriteFile(path, []byte("non-executable fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = startWindowsInstaller(file, true)
	windows.CloseHandle(h)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatal("busy parent directory", err)
	}
	if err := startWindowsInstaller(file, true); !errors.Is(err, windows.ERROR_BAD_EXE_FORMAT) && !errors.Is(err, windows.ERROR_EXE_MACHINE_TYPE_MISMATCH) {
		t.Fatal("invalid executable image", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := startWindowsInstaller(directory, false); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("directory image", err)
	}
	directory.Close()
	if err := startWindowsInstaller(directory, false); !errors.Is(err, updateauth.ErrArtifact) {
		t.Fatal("closed image", err)
	}
}
