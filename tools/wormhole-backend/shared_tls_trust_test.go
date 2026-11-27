package main

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedTLSFixture(t *testing.T, o *sharedAdmissionOptions, state sharedpg.TrustState, org ed25519.PrivateKey, seq uint64) *sharedpg.VerifiedTLSBundle {
	t.Helper()
	block, _ := pem.Decode(sharedControllerCA(t))
	signer := vault.KeyRef{ID: uuid.MustParse(state.SignerKeyID), Version: state.SignerKeyVersion}
	b, err := sharedpg.SignTLSTrustBundle(sharedpg.TLSTrustBundle{FormatVersion: 1, WorkspaceID: state.WorkspaceID, Signer: signer, Sequence: seq, CAs: [][]byte{block.Bytes}, Hosts: []string{"localhost"}, Revoked: []sharedpg.TLSRevocation{}}, org)
	if err != nil {
		t.Fatal(err)
	}
	v, err := sharedpg.VerifyTLSTrustBundle(b, sharedpg.TLSTrustPin{WorkspaceID: state.WorkspaceID, Signer: signer, Organisation: state.PublicKey, MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	o.Settings.CAPEM = nil
	o.Settings.TLSBundle = v
	return v
}

func TestSharedTLSFloorPersistsBeforeDial(t *testing.T) {
	for _, mode := range []string{"success", "uncertain", "sync-failure", "floor-uncertain", "floor-sync-failure", "locked"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, master, _, org := sharedUnlockFixture(t)
			if err := c.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			previous := p
			lifetime, cancel := context.WithCancel(context.Background())
			p = &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: previous.response, loginMaterial: previous.loginMaterial, accountState: previous.accountState, accountMaterial: previous.accountMaterial}
			c = newSharedAdmissionControllerWithSession(p)
			t.Cleanup(func() {
				if err := c.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			v := sharedTLSFixture(t, &o, state, org, 3)
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			if mode == "uncertain" || mode == "sync-failure" {
				calls := 0
				privateFileDirectorySync = func(path string) error {
					calls++
					if mode == "sync-failure" || calls == 1 {
						return os.ErrPermission
					}
					return original(path)
				}
			}
			if mode == "floor-uncertain" || mode == "floor-sync-failure" {
				failed := false
				privateFileDirectorySync = func(path string) error {
					saved, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
					if e == nil && saved.TLSSequence == 3 && (mode == "floor-sync-failure" || !failed) {
						failed = true
						return os.ErrPermission
					}
					return original(path)
				}
			}
			if mode == "locked" {
				release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			p.open = func(_ context.Context, prepared sharedpg.Settings) error {
				saved, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
				if err != nil || saved.TLSSequence != 3 || saved.FormatVersion != 4 || prepared.TLSBundle != v {
					t.Fatal("dial before durable TLS floor", err)
				}
				return nil
			}
			err = c.Open(context.Background(), o, root, p.loginMaterial)
			if mode == "sync-failure" || mode == "floor-sync-failure" || mode == "locked" {
				if err == nil || p.opens.Load() != 0 {
					t.Fatal("dial after persistence failure", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
				t.Fatal(err)
			}
			saved, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if err != nil || saved.TLSSequence != 3 || saved.Account == nil || saved.FormatVersion != 4 {
				t.Fatal("unlock lost TLS floor", err)
			}
			if _, err := acceptSharedTLSBundle(o, root, saved); err != nil {
				t.Fatal("idempotent confirmation", err)
			}
			sharedTLSFixture(t, &o, state, org, 2)
			if _, err := acceptSharedTLSBundle(o, root, saved); err != sharedpg.ErrTrustRollback {
				t.Fatal("replay accepted", err)
			}
		})
	}
}

func TestSharedTLSRecoveryPreservesObservedFloor(t *testing.T) {
	for _, committed := range []bool{false, true} {
		c, p, o, master, newRoot, oldRoot, _, org := sharedRecoveryFixture(t, committed)
		pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
		if err != nil {
			t.Fatal(err)
		}
		sharedTLSFixture(t, &o, pending.ObservedTrust(), org, 5)
		p.open = func(context.Context, sharedpg.Settings) error {
			observed, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
			if err != nil || observed.ObservedTrust().TLSSequence != 5 {
				t.Fatal("recovery dial before observation", err)
			}
			return nil
		}
		credential := sharedRecoveryOldPassword
		root := oldRoot
		if committed {
			credential = sharedRecoveryNewPassword
			root = newRoot
		}
		if _, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, credential); err != nil {
			t.Fatal(err)
		}
		state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
		if err != nil || state.TLSSequence != 5 || state.FormatVersion != 4 {
			t.Fatal("finalization erased TLS floor", err)
		}
		if _, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); !errors.Is(err, errSharedTrustMissing) {
			t.Fatal("journal not retired", err)
		}
	}
}

func TestSharedTLSRecoveryRefusesUnpublishedObservation(t *testing.T) {
	for _, mode := range []string{"invalid-bundle", "sync-failure", "journal-sync-failure"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, master, newRoot, oldRoot, _, org := sharedRecoveryFixture(t, true)
			pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
			if err != nil {
				t.Fatal(err)
			}
			sharedTLSFixture(t, &o, pending.ObservedTrust(), org, 5)
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			if mode == "invalid-bundle" {
				o.Settings.TLSBundle = &sharedpg.VerifiedTLSBundle{}
			} else if mode == "journal-sync-failure" {
				privateFileDirectorySync = func(path string) error {
					observed, e := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
					if e == nil && observed.ObservedTrust().TLSSequence == 5 {
						return os.ErrPermission
					}
					return original(path)
				}
			} else {
				privateFileDirectorySync = func(string) error { return os.ErrPermission }
			}
			_, err = c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, sharedRecoveryNewPassword)
			if err == nil || p.opens.Load() != 0 {
				t.Fatal("network before valid durable observation", err)
			}
			if _, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); err != nil {
				t.Fatal("failure erased journal", err)
			}
		})
	}
}
