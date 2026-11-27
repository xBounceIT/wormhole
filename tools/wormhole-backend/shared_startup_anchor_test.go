package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedStartupFixture(t *testing.T) (*recoveryFixture, *sharedpg.UnlockedDeviceAccount) {
	t.Helper()
	j, f, p, _ := preparedDeviceJoinFixture(t)
	if _, err := j.joinPrepared(context.Background(), f.o, p); err != nil {
		t.Fatal(err)
	}
	path := sharedDeviceEnrollmentPath(f.o.TrustPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = sharedpg.PrepareDevicePasswordFile(context.Background(), p.key, raw, p.slots.VaultID, p.slots.FileID, 1, []byte("recovery-test-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedTransitionBytes(path, raw); err != nil {
		t.Fatal(err)
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	selection := sharedpg.DeviceUnlockSelection{VaultID: slots.VaultID, FileID: slots.FileID, MinimumSequence: slots.Sequence}
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotPassword {
			selection.SlotID = slot.ID
		}
	}
	owner, err := sharedpg.OpenDeviceAccount(context.Background(), raw, selection, []byte("recovery-test-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	return f, owner
}

// Real authenticated encryption, with a deterministic test-only OS-store key.
func startupTestProtection() sharedStartupProtection {
	key := bytes.Repeat([]byte{43}, 32)
	return sharedStartupProtection{
		protect:   func(_ string, raw []byte) ([]byte, error) { return encryptAuthDocument(raw, key) },
		unprotect: func(_ string, raw []byte) ([]byte, error) { return decryptAuthDocument(raw, key) },
	}
}

func TestSharedStartupAnchorLifecycle(t *testing.T) {
	f, owner := sharedStartupFixture(t)
	p := startupTestProtection()
	anchor, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Test workspace", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Revision != 1 || anchor.MinimumSequence != 2 || anchor.Binding != f.o.Binding || anchor.LoginName != f.master.LoginName() {
		t.Fatal("wrong selection")
	}
	raw, err := os.ReadFile(sharedStartupAnchorPath(f.o.TrustPath))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Test workspace")) || bytes.Contains(raw, []byte(anchor.LoginName)) {
		t.Fatal("OS protection bypassed")
	}
	actual, err := readSharedStartupAnchor(f.o.TrustPath, p)
	if err != nil || !reflect.DeepEqual(actual, anchor) {
		t.Fatal("roundtrip", err)
	}
	if _, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Test workspace", 0, p); err != nil {
		t.Fatal("exact durability retry", err)
	}
	if _, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Changed", 0, p); err != errSharedTrustConflict {
		t.Fatal("lost CAS", err)
	}
	next, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Renamed", 1, p)
	if err != nil || next.Revision != 2 {
		t.Fatal("update", err)
	}
	if _, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Stale", 1, p); err != errSharedTrustConflict {
		t.Fatal("stale overwrite", err)
	}
	copyPath := filepath.Join(t.TempDir(), "other.trust")
	if err := os.WriteFile(sharedStartupAnchorPath(copyPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedStartupAnchor(copyPath, p); err == nil {
		t.Fatal("cross-path protected blob accepted")
	}
	// No account/password owner is needed to retrieve authenticated startup pins.
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedStartupAnchor(f.o.TrustPath, p); err != nil {
		t.Fatal("startup depends on old password", err)
	}
}

func TestSharedStartupAnchorWriteFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "nil-owner", "relative", "bad-display", "wrong-binding", "changed-device", "pending", "enrollment", "protect", "sync", "expected-missing", "locked", "missing-device", "missing-trust", "missing-transport", "cancel-protect", "nil-protect"} {
		t.Run(mode, func(t *testing.T) {
			f, owner := sharedStartupFixture(t)
			p := startupTestProtection()
			o := f.o
			name := "Workspace"
			var expected uint64
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			syncDir := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDir })
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "nil-owner":
				owner = nil
			case "relative":
				o.TrustPath = "relative"
			case "bad-display":
				name = "name\x00suffix"
			case "wrong-binding":
				o.Binding.KeyID = uuid.New()
			case "changed-device":
				if err := os.WriteFile(sharedDeviceEnrollmentPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(sharedTrustTransitionPath(o.TrustPath), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "enrollment":
				if err := os.WriteFile(sharedPendingEnrollmentPath(o.TrustPath), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "missing-device", "missing-trust", "missing-transport":
				path := o.TrustPath
				if mode == "missing-device" {
					path = sharedDeviceEnrollmentPath(path)
				} else if mode == "missing-transport" {
					path = sharedTransportSetupPath(path)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "cancel-protect":
				protect := p.protect
				p.protect = func(path string, raw []byte) ([]byte, error) {
					cancel()
					return protect(path, raw)
				}
			case "nil-protect":
				p.protect = nil
			case "protect":
				p.protect = func(string, []byte) ([]byte, error) { return nil, os.ErrPermission }
			case "sync":
				privateFileDirectorySync = func(string) error { return os.ErrPermission }
			case "expected-missing":
				expected = 1
			}
			anchor, err := writeSharedStartupAnchor(ctx, o, owner, name, expected, p)
			if err == nil {
				t.Fatal("failure accepted")
			}
			if mode == "sync" {
				if !errors.Is(err, errSharedTrustCommitUncertain) || anchor.Revision != 1 {
					t.Fatal("publication uncertainty lost", err)
				}
				privateFileDirectorySync = syncDir
				if _, err := writeSharedStartupAnchor(context.Background(), o, owner, name, 0, p); err != nil {
					t.Fatal("retry", err)
				}
			} else if _, err := os.Stat(sharedStartupAnchorPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed preflight wrote anchor", err)
			}
		})
	}
}

func TestSharedStartupAnchorCorruptionCannotBeReplaced(t *testing.T) {
	f, owner := sharedStartupFixture(t)
	p := startupTestProtection()
	path := sharedStartupAnchorPath(f.o.TrustPath)
	for _, raw := range [][]byte{[]byte("broken"), bytes.Repeat([]byte{1}, maxSharedStartupAnchorBytes*2+1)} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Workspace", 0, p); err == nil {
			t.Fatal("corrupted anchor replaced")
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, actual) {
			t.Fatal("evidence of corruption lost", err)
		}
	}
	if _, err := readSharedStartupAnchor("relative", p); err != sharedpg.ErrConfiguration {
		t.Fatal("relative path", err)
	}
	if _, err := readSharedStartupAnchor(f.o.TrustPath, sharedStartupProtection{}); err != sharedpg.ErrConfiguration {
		t.Fatal("missing OS protector", err)
	}
}

func TestSharedStartupAnchorParsingAndFloors(t *testing.T) {
	f, owner := sharedStartupFixture(t)
	p := startupTestProtection()
	a, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Workspace", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(a sharedStartupAnchor) []byte {
		t.Helper()
		raw, e := json.Marshal(a)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	for _, mode := range []string{"format", "purpose", "path", "revision", "vault", "file", "sequence", "binding", "login", "display", "account", "enrollment", "policy", "transport", "ask", "unknown-field", "trailing", "oversize", "unprotect"} {
		t.Run(mode, func(t *testing.T) {
			bad := a
			switch mode {
			case "format":
				bad.FormatVersion++
			case "purpose":
				bad.Purpose = "other"
			case "path":
				bad.PathDigest = nil
			case "revision":
				bad.Revision = 0
			case "vault":
				bad.VaultID = "not-a-uuid"
			case "file":
				bad.FileID = uuid.Nil.String()
			case "sequence":
				bad.MinimumSequence = 0
			case "binding":
				bad.Binding.DeviceID = uuid.New()
			case "login":
				bad.LoginName = "bad\x00login"
			case "display":
				bad.DisplayName = ""
			case "account":
				bad.Trust.Account = nil
			case "enrollment":
				bad.Trust.Enrollment = nil
			case "policy":
				bad.Trust.PolicyDigest = nil
			case "transport":
				bad.Transport = json.RawMessage("{}")
			case "ask":
				bad.KDF = "unknown"
			}
			raw := encode(bad)
			if mode == "unknown-field" {
				raw = append(bytes.Clone(raw[:len(raw)-1]), []byte(",\"extra\":1}")...)
			}
			if mode == "trailing" {
				raw = append(raw, ' ')
			}
			if mode == "oversize" {
				raw = bytes.Repeat([]byte{'x'}, maxSharedStartupAnchorBytes+1)
			}
			protected, e := p.protect("", raw)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "unprotect" {
				protected[0] ^= 1
			}
			if err := os.WriteFile(sharedStartupAnchorPath(f.o.TrustPath), protected, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSharedStartupAnchor(f.o.TrustPath, p); err == nil {
				t.Fatal("bad anchor accepted")
			}
		})
	}
	next := a
	next.Revision++
	if !startupAnchorAdvances(a, next) {
		t.Fatal("unchanged trust update")
	}
	for _, mode := range []string{"sequence", "identity", "derivation", "trust-floor", "trust-content"} {
		bad := next
		switch mode {
		case "sequence":
			bad.MinimumSequence--
		case "identity":
			bad.Binding.KeyID = uuid.New()
		case "derivation":
			bad.ASKRequired = !bad.ASKRequired
		case "trust-floor":
			bad.Trust.Revision--
		case "trust-content":
			bad.Trust.WrappingRevision++
		}
		if startupAnchorAdvances(a, bad) {
			t.Fatal(mode)
		}
	}
	advanced, err := a.Trust.AdvanceAccount(*a.Trust.Account, a.Trust.WrappingRevision+1)
	if err != nil {
		t.Fatal(err)
	}
	next.Trust = advanced
	if !startupAnchorAdvances(a, next) {
		t.Fatal("authenticated floors did not advance")
	}
}
