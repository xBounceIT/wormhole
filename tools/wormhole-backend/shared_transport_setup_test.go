package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func setupFileFixture(t *testing.T) (sharedAdmissionOptions, []byte, sharedpg.TrustState) {
	t.Helper()
	c, _, o, root, trust, _ := sharedControllerFixture(t, vault.Standard)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	o.TrustPath = filepath.Join(t.TempDir(), "setup.trust")
	return o, root, trust
}

func TestSharedTransportSetupDurability(t *testing.T) {
	o, root, trust := setupFileFixture(t)
	o.Settings.Changes = sharedpg.ChangePolicy{TransactionPooler: true, ConcurrentDevices: 450}
	if _, err := readSharedTransportSetup(o, root, trust); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := confirmSharedTransportSetup(o, root, trust); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	syncDirectory := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	if err := stageSharedTransportSetup(o, root, trust); err != errSharedTrustCommitUncertain {
		t.Fatal(err)
	}
	actual, err := readSharedTransportSetup(o, root, trust)
	if err != nil || !reflect.DeepEqual(actual.Endpoints, o.Settings.Endpoints) || actual.Changes != o.Settings.Changes {
		t.Fatal(err)
	}
	if err := confirmSharedTransportSetup(o, root, trust); err != errSharedTrustCommitUncertain {
		t.Fatal("readback hid failed sync", err)
	}
	privateFileDirectorySync = syncDirectory
	if err := confirmSharedTransportSetup(o, root, trust); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedTransportSetup(o, root, trust); err != errSharedTrustConflict {
		t.Fatal("replaced setup", err)
	}
	changed := o
	changed.Settings.Changes.TransactionPooler = false
	if err := confirmSharedTransportSetup(changed, root, trust); err != errSharedTrustConflict {
		t.Fatal("confirmed different deployment policy", err)
	}
	changed = o
	changed.Settings.Database = "different"
	if err := confirmSharedTransportSetup(changed, root, trust); err != errSharedTrustConflict {
		t.Fatal("confirmed different setup", err)
	}
	if _, err := os.Lstat(o.TrustPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup activated trust")
	}
}

func TestSharedTransportSetupBoundaries(t *testing.T) {
	for _, mode := range []string{"relative", "invalid", "active", "transition", "pending", "locked", "corrupt", "root", "parent-file"} {
		t.Run(mode, func(t *testing.T) {
			o, root, trust := setupFileFixture(t)
			if mode == "corrupt" || mode == "root" {
				if err := stageSharedTransportSetup(o, root, trust); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "relative":
				o.TrustPath = "relative"
			case "invalid":
				o.Settings.Endpoints = nil
			case "active":
				if err := writeSharedTrustFile(o.TrustPath, root, o.Binding, trust, 0); err != nil {
					t.Fatal(err)
				}
			case "transition":
				if err := os.WriteFile(sharedTrustTransitionPath(o.TrustPath), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(sharedPendingEnrollmentPath(o.TrustPath), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "corrupt":
				if err := os.WriteFile(sharedTransportSetupPath(o.TrustPath), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "root":
				root[0] ^= 1
			case "parent-file":
				if err := os.WriteFile(o.TrustPath, []byte("file"), 0600); err != nil {
					t.Fatal(err)
				}
				o.TrustPath = filepath.Join(o.TrustPath, "child")
			}
			if err := stageSharedTransportSetup(o, root, trust); err == nil {
				t.Fatal("unsafe stage")
			}
			if err := confirmSharedTransportSetup(o, root, trust); err == nil {
				t.Fatal("unsafe confirmation")
			}
			if mode == "relative" {
				if _, err := readSharedTransportSetup(o, root, trust); err != errSharedTrustStorage {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSharedTransportSetupManagedTLS(t *testing.T) {
	f := newRecoveryFixture(t)
	o := f.o
	o.TrustPath = filepath.Join(t.TempDir(), "managed.trust")
	sharedTLSFixture(t, &o, f.pending.Trust, f.org, 3)
	trust, err := f.pending.Trust.AdvanceTLS(o.Settings.TLSBundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageSharedTransportSetup(o, f.root, trust); err != nil {
		t.Fatal(err)
	}
	// The pending intent is staged only after transport setup, but may exist when
	// dispatch reconfirms that both records are durable.
	if err := os.WriteFile(sharedPendingEnrollmentPath(o.TrustPath), []byte("pending-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := confirmSharedTransportSetup(o, f.root, trust); err != nil {
		t.Fatal(err)
	}
	restored, err := readSharedTransportSetup(o, f.root, trust)
	if err != nil || restored.TLSBundle == nil || !reflect.DeepEqual(restored.TLSBundle.Encode(), o.Settings.TLSBundle.Encode()) {
		t.Fatal("managed TLS lost", err)
	}
	changed := o
	changed.Settings.Endpoints = nil
	if err := confirmSharedTransportSetup(changed, f.root, trust); err == nil {
		t.Fatal("confirmed invalid expected setup")
	}
}
